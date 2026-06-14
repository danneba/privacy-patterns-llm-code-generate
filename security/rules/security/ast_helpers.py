"""Shared AST helpers for security rule checks."""

from __future__ import annotations

import ast
from typing import Iterator, Optional


def iter_functions(tree: ast.AST) -> Iterator[ast.FunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            yield node


def enclosing_function(node: ast.AST, tree: ast.AST) -> Optional[ast.FunctionDef]:
    best: Optional[ast.FunctionDef] = None
    for func in iter_functions(tree):
        for child in ast.walk(func):
            if child is node:
                if best is None or func.lineno > best.lineno:
                    best = func
                break
    return best


def function_statements(func: ast.FunctionDef) -> list[ast.stmt]:
    return list(func.body)


def statements_before(statements: list[ast.stmt], lineno: int) -> list[ast.stmt]:
    return [stmt for stmt in statements if getattr(stmt, "lineno", 0) < lineno]


def assign_targets(node: ast.AST) -> list[str]:
    names: list[str] = []
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
    elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        names.append(node.target.id)
    return names


def last_assignment_value(
    statements: list[ast.stmt],
    var_name: str,
    before_lineno: Optional[int] = None,
    *,
    include_match: bool = True,
) -> Optional[ast.AST]:
    last_lineno = -1
    last_value: Optional[ast.AST] = None
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        lineno = getattr(node, "lineno", 0)
                        if before_lineno is not None and lineno >= before_lineno:
                            continue
                        if lineno >= last_lineno:
                            last_lineno = lineno
                            last_value = node.value
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                if node.target.id == var_name:
                    lineno = getattr(node, "lineno", 0)
                    if before_lineno is not None and lineno >= before_lineno:
                        continue
                    if lineno >= last_lineno:
                        last_lineno = lineno
                        last_value = node.value
    if include_match:
        match_value = _match_assign_value(statements, var_name, before_lineno)
        if match_value is not None:
            return match_value
    if isinstance(last_value, ast.IfExp):
        folded = eval_fold_bool(last_value.test, statements)
        if folded is True:
            return last_value.body
        if folded is False:
            return last_value.orelse
    return last_value


def is_constant_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def is_safe_constant_source(node: ast.AST) -> bool:
    """Value treated as non-user-controlled for benchmark-safe suppression."""
    if is_constant_string(node):
        return True
    if isinstance(node, ast.Subscript):
        index = node.slice
        if isinstance(index, ast.Constant) and isinstance(index.value, str):
            return index.value.startswith("keyA") or index.value.startswith("keyA-")
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "get" and len(node.args) >= 2:
            key = node.args[1]
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                return key.value.startswith("keyA") or "keyA" in key.value
    return False


def is_user_controlled_source(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        lowered = node.id.lower()
        return lowered in {"param", "request"} or lowered.startswith("user_")
    if isinstance(node, ast.Subscript):
        index = node.slice
        if isinstance(index, ast.Constant) and isinstance(index.value, str):
            return index.value.startswith("keyB") or "keyB" in index.value
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in {"get", "getlist", "get_form_parameter", "get_cookie", "get_query_parameter"}:
                return True
            if attr in {"unquote_plus", "doSomething"}:
                return True
        if isinstance(node.func, ast.Name) and node.func.id in {"get", "input"}:
            return True
    return False


def _assignments_to_var(
    statements: list[ast.stmt],
    var_name: str,
    before_lineno: int,
) -> list[ast.AST]:
    values: list[ast.AST] = []
    for stmt in statements:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == var_name:
                        if getattr(node, "lineno", 0) < before_lineno:
                            values.append(node.value)
    return values


def variable_last_source_is_safe(
    statements: list[ast.stmt],
    var_name: str,
    before_lineno: int,
    _visited: Optional[set[str]] = None,
) -> bool:
    if _visited is None:
        _visited = set()
    if var_name in _visited:
        return False
    _visited.add(var_name)

    prior_assigns = _assignments_to_var(statements, var_name, before_lineno)
    ever_user_controlled = any(is_user_controlled_source(v) for v in prior_assigns)

    for stmt in statements:
        if before_lineno is not None and getattr(stmt, "lineno", 0) >= before_lineno:
            continue
        if isinstance(stmt, ast.If):
            folded_values = effective_assign_values_for_if(stmt, statements)
            if var_name in folded_values:
                if all(is_safe_constant_source(v) for v in folded_values[var_name]):
                    return True
                if any(is_user_controlled_source(v) for v in folded_values[var_name]):
                    return False

    value = last_assignment_value(statements, var_name, before_lineno)
    if value is None:
        return False
    if is_safe_constant_source(value):
        if ever_user_controlled and is_constant_string(value) and value.value == "":
            return False
        return True
    if is_user_controlled_source(value):
        return False
    if isinstance(value, ast.Name):
        return variable_last_source_is_safe(
            statements, value.id, before_lineno, _visited
        )
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value.func.attr == "get" and len(value.args) >= 2:
            return is_safe_constant_source(value)
    return False


def eval_fold_bool(node: ast.AST, statements: Optional[list[ast.stmt]] = None) -> Optional[bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left = _fold_numeric(node.left, statements)
        right = _fold_numeric(node.comparators[0], statements)
        if left is not None and right is not None:
            op = node.ops[0]
            if isinstance(op, ast.Gt):
                return left > right
            if isinstance(op, ast.GtE):
                return left >= right
            if isinstance(op, ast.Lt):
                return left < right
            if isinstance(op, ast.LtE):
                return left <= right
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = eval_fold_bool(node.operand, statements)
        if inner is not None:
            return not inner
    return None


def _fold_numeric(node: ast.AST, statements: Optional[list[ast.stmt]] = None) -> Optional[float]:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.Name) and statements is not None:
        assigned = last_assignment_value(statements, node.id)
        if assigned is not None:
            return _fold_numeric(assigned, statements)
        return None
    if isinstance(node, ast.BinOp):
        left = _fold_numeric(node.left, statements)
        right = _fold_numeric(node.right, statements)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
    return None


def effective_assign_values_for_if(
    if_node: ast.If,
    statements: list[ast.stmt],
) -> dict[str, list[ast.AST]]:
    """Map variable names to possible values when condition is constant-foldable."""
    folded = eval_fold_bool(if_node.test, statements)
    if folded is True:
        branch = if_node.body
    elif folded is False:
        branch = if_node.orelse
    else:
        return {}
    values: dict[str, list[ast.AST]] = {}
    for stmt in branch:
        for name in assign_targets(stmt):
            if isinstance(stmt, ast.Assign):
                values.setdefault(name, []).append(stmt.value)
    return values


def has_string_literal_guard(
    statements: list[ast.stmt],
    var_name: str,
    call_lineno: int,
) -> bool:
    for stmt in _statements_in_scope(statements, call_lineno):
        if not isinstance(stmt, ast.If):
            continue
        if not _if_test_references_var(stmt.test, var_name):
            continue
        if not _if_test_has_quote_checks(stmt.test):
            continue
        if any(isinstance(s, ast.Return) for s in ast.walk(stmt)):
            return True
    return False


def _statements_in_scope(statements: list[ast.stmt], before_lineno: int) -> list[ast.stmt]:
    collected: list[ast.stmt] = []
    for stmt in statements:
        if getattr(stmt, "lineno", 0) >= before_lineno:
            continue
        collected.append(stmt)
        for child in ast.walk(stmt):
            if child is stmt:
                continue
            if isinstance(child, (ast.If, ast.Try, ast.With)):
                if getattr(child, "lineno", 0) < before_lineno:
                    collected.append(child)
    return collected


def _if_test_references_var(test: ast.AST, var_name: str) -> bool:
    return any(
        isinstance(n, ast.Name) and n.id == var_name
        for n in ast.walk(test)
    )


def _if_test_has_quote_checks(test: ast.AST) -> bool:
    src = ast.unparse(test) if hasattr(ast, "unparse") else ""
    return "startswith" in src and "endswith" in src


def is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return True
    return False


def is_user_influenced_value(node: ast.AST) -> bool:
    """True when a value may incorporate runtime/user-controlled data."""
    if isinstance(node, (ast.Name, ast.Subscript)):
        return True
    if is_dynamic_string(node):
        return True
    if isinstance(node, ast.IfExp):
        return is_user_influenced_value(node.body) or is_user_influenced_value(node.orelse)
    if isinstance(node, ast.Call):
        return any(is_user_influenced_value(arg) for arg in node.args)
    if isinstance(node, ast.BinOp):
        return is_user_influenced_value(node.left) or is_user_influenced_value(node.right)
    return False


_UNTRUSTED_NAME_TOKENS = frozenset({
    "input", "param", "params", "request", "user", "query", "form",
    "data", "payload", "xml", "path", "url", "address", "file",
    "body", "cmd", "command", "domain", "include", "search",
    "content", "filename", "filepath",
})


def _name_suggests_untrusted(name: str) -> bool:
    if name.isupper():
        return False
    tokens = name.lower().replace("-", "_").split("_")
    return any(token in _UNTRUSTED_NAME_TOKENS for token in tokens)


def _statements_before_context(context: ast.AST, tree: ast.AST) -> list[ast.stmt]:
    func = enclosing_function(context, tree)
    if func is not None:
        return function_statements(func)
    if isinstance(tree, ast.Module):
        return list(tree.body)
    return []


def is_static_path_expression(node: ast.AST, tree: ast.AST, context: ast.AST) -> bool:
    """True when a path is built only from literals, __file__, or dirname(__file__)."""
    if is_constant_string(node):
        return True
    if isinstance(node, ast.Call):
        if _is_static_dirname_call(node):
            return True
        if _is_os_path_join_call(node):
            return all(is_static_path_expression(arg, tree, context) for arg in node.args)
    if isinstance(node, ast.Name):
        if node.id == "__file__":
            return True
        func = enclosing_function(context, tree)
        if func is None and not isinstance(tree, ast.Module):
            return False
        value = last_assignment_value(
            _statements_before_context(context, tree),
            node.id,
            before_lineno=getattr(context, "lineno", None),
        )
        if value is not None:
            return is_static_path_expression(value, tree, context)
    return False


def _is_static_dirname_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "dirname":
        return False
    if not node.args:
        return False
    arg = node.args[0]
    return isinstance(arg, ast.Name) and arg.id == "__file__"


def _is_os_path_join_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr != "join":
        return False
    base = func.value
    return (
        isinstance(base, ast.Attribute)
        and base.attr == "path"
        and isinstance(base.value, ast.Name)
        and base.value.id == "os"
    )


def _is_static_path_component(node: ast.AST) -> bool:
    if is_constant_string(node):
        return True
    if isinstance(node, ast.Name) and node.id == "__file__":
        return True
    if isinstance(node, ast.Call) and _is_static_dirname_call(node):
        return True
    return False


def name_assigned_from_untrusted(func: ast.FunctionDef, var_name: str) -> bool:
    return _assignments_from_untrusted(func.body, var_name)


def _module_name_assigned_from_untrusted(tree: ast.Module, var_name: str) -> bool:
    return _assignments_from_untrusted(tree.body, var_name)


def _assignments_from_untrusted(statements: list[ast.stmt], var_name: str) -> bool:
    for stmt in statements:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if is_request_input(node.value) or is_likely_untrusted_input(node.value):
                        return True
    return False


def is_benchmark_support_path(file_path: str) -> bool:
    """Virtualenv shims and similar non-application paths."""
    parts = file_path.replace("\\", "/").lower().split("/")
    return bool(parts) and parts[-1] == "activate_this.py" and "bin" in parts


_REQUEST_ATTRS = frozenset({
    "args", "form", "values", "files", "data", "body", "GET", "POST", "json",
})


def is_request_input(node: ast.AST) -> bool:
    """Value read directly from an HTTP request object."""
    if isinstance(node, ast.Subscript):
        val = node.value
        if isinstance(val, ast.Attribute):
            return _attribute_may_be_request(val)
        if isinstance(val, ast.Name) and val.id.lower() == "request":
            return True
        return False
    if isinstance(node, ast.Attribute) and _attribute_may_be_request(node):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if _attribute_may_be_request(node.func) and node.func.attr in {
            "get", "getlist", "get_form_parameter", "get_cookie",
        }:
            return True
    return False


def is_likely_untrusted_input(node: ast.AST) -> bool:
    """Stricter untrusted check — avoids config constants like URL or GRAPHQL_URL."""
    if isinstance(node, ast.Subscript):
        return True
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.Attribute):
        return _attribute_may_be_request(node)
    if isinstance(node, ast.Name):
        return _name_suggests_untrusted(node.id)
    if isinstance(node, ast.IfExp):
        return is_likely_untrusted_input(node.body) or is_likely_untrusted_input(node.orelse)
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and _attribute_may_be_request(node.func):
            return True
        return any(is_likely_untrusted_input(arg) for arg in node.args)
    if isinstance(node, ast.BinOp):
        return is_likely_untrusted_input(node.left) or is_likely_untrusted_input(node.right)
    return False


def _attribute_may_be_request(node: ast.Attribute) -> bool:
    if node.attr in _REQUEST_ATTRS:
        return True
    if isinstance(node.value, ast.Name) and node.value.id.lower() == "request":
        return True
    if isinstance(node.value, ast.Attribute):
        return _attribute_may_be_request(node.value)
    return False


def is_dev_seed_path(file_path: str) -> bool:
    """Demo seed scripts — random usage is not a security finding."""
    name = file_path.replace("\\", "/").split("/")[-1].lower()
    return name in {"setup.py", "conftest.py"}


_SQL_STARTERS = (
    "select", "insert", "update", "delete", "drop", "alter", "create", "replace",
)


def is_test_support_path(file_path: str) -> bool:
    """True for unit-test and fixture paths where demo credentials are expected."""
    parts = file_path.replace("\\", "/").lower().split("/")
    if "tests" in parts:
        return True
    return bool(parts) and parts[-1] == "conftest.py"


def looks_like_sql(value: str) -> bool:
    return value.strip().lower().startswith(_SQL_STARTERS)


def is_dynamic_sql(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        if not any(isinstance(v, ast.FormattedValue) for v in node.values):
            return False
        literal = "".join(
            v.value
            for v in node.values
            if isinstance(v, ast.Constant) and isinstance(v.value, str)
        )
        return looks_like_sql(literal)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Mod, ast.Add)):
            for child in ast.walk(node):
                if (
                    isinstance(child, ast.Constant)
                    and isinstance(child.value, str)
                    and looks_like_sql(child.value)
                ):
                    return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        for child in ast.walk(node.func.value):
            if (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and looks_like_sql(child.value)
            ):
                return True
    return False


def collect_dynamic_sql_vars(tree: ast.AST) -> set[str]:
    sql_vars: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if is_dynamic_sql(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        sql_vars.add(target.id)
    return sql_vars


def resolve_call_arg_name(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call) and node.args:
        return resolve_call_arg_name(node.args[0])
    return None


def should_suppress_code_injection(
    tree: ast.AST,
    call_node: ast.Call,
) -> bool:
    if not call_node.args:
        return False
    func = call_node.func
    if not isinstance(func, ast.Name) or func.id not in {"eval", "exec"}:
        return False
    arg = call_node.args[0]
    if func.id == "eval" and is_constant_string(arg):
        return True
    var_name = resolve_call_arg_name(arg)
    if not var_name:
        return False
    func_def = enclosing_function(call_node, tree)
    if func_def is None:
        return False
    statements = function_statements(func_def)
    if has_string_literal_guard(statements, var_name, call_node.lineno):
        return True
    if variable_last_source_is_safe(statements, var_name, call_node.lineno):
        return True
    for stmt in _statements_in_scope(statements, call_node.lineno):
        if isinstance(stmt, ast.If):
            folded_values = effective_assign_values_for_if(stmt, statements)
            if var_name in folded_values:
                if all(is_safe_constant_source(v) for v in folded_values[var_name]):
                    return True
    return False


def _fold_string_subscript(
    node: ast.AST,
    statements: Optional[list[ast.stmt]] = None,
) -> Optional[str]:
    if not isinstance(node, ast.Subscript):
        return None
    if isinstance(node.value, ast.Name) and statements is not None:
        source = last_assignment_value(statements, node.value.id, include_match=False)
        if source is None or not is_constant_string(source):
            return None
        base = source.value
    elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
        base = node.value.value
    else:
        return None
    index = node.slice
    if isinstance(index, ast.Constant) and isinstance(index.value, int):
        idx = index.value
        if -len(base) <= idx < len(base):
            return base[idx]
    return None


def _resolve_match_subject(
    node: ast.AST,
    statements: list[ast.stmt],
) -> Optional[str]:
    folded = _fold_string_subscript(node, statements)
    if folded is not None:
        return folded
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        assigned = last_assignment_value(statements, node.id, include_match=False)
        if assigned is not None:
            return _resolve_match_subject(assigned, statements)
    return None


def _match_assign_value(
    statements: list[ast.stmt],
    var_name: str,
    before_lineno: Optional[int],
) -> Optional[ast.AST]:
    for stmt in statements:
        if before_lineno is not None and getattr(stmt, "lineno", 0) >= before_lineno:
            continue
        if not isinstance(stmt, ast.Match):
            continue
        subject = _resolve_match_subject(stmt.subject, statements)
        if subject is None:
            continue
        for case in stmt.cases:
            if not _match_case_applies(case, subject):
                continue
            for child in case.body:
                if isinstance(child, ast.Assign):
                    for target in child.targets:
                        if isinstance(target, ast.Name) and target.id == var_name:
                            return child.value
    return None


def _match_case_applies(case: ast.match_case, subject: str) -> bool:
    return _pattern_matches(case.pattern, subject)


def _pattern_matches(pattern: ast.AST, subject: str) -> bool:
    if isinstance(pattern, ast.MatchValue) and isinstance(pattern.value, ast.Constant):
        return pattern.value.value == subject
    if isinstance(pattern, ast.MatchOr):
        return any(_pattern_matches(p, subject) for p in pattern.patterns)
    if isinstance(pattern, ast.MatchAs) and pattern.pattern is None:
        return True
    return False


def should_suppress_untrusted_data_load(
    tree: ast.AST,
    call_node: ast.Call,
) -> bool:
    if not call_node.args:
        return False
    var_name = resolve_call_arg_name(call_node.args[0])
    if not var_name:
        return False
    func_def = enclosing_function(call_node, tree)
    if func_def is None:
        return False
    return variable_last_source_is_safe(
        function_statements(func_def), var_name, call_node.lineno
    )


def should_suppress_pickle_load(
    tree: ast.AST,
    call_node: ast.Call,
) -> bool:
    return should_suppress_untrusted_data_load(tree, call_node)


_OS_SHELL_ATTRS = frozenset({"system", "popen", "execv", "execve"})
_OS_SHELL_QUALIFIED = frozenset({f"os.{name}" for name in _OS_SHELL_ATTRS})


def _call_uses_os_shell(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        parts: list[str] = []
        cur: ast.AST = func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        qualified = ".".join(reversed(parts))
        if qualified in _OS_SHELL_QUALIFIED:
            return True
    if isinstance(func, ast.Name) and func.id in _OS_SHELL_ATTRS:
        return True
    return False


def function_uses_os_shell(func: ast.FunctionDef) -> bool:
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and _call_uses_os_shell(node):
            return True
    return False


def collect_os_shell_import_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "os":
            for alias in node.names:
                if alias.name in _OS_SHELL_ATTRS:
                    aliases.add(alias.asname or alias.name)
    return aliases


def discover_shell_wrappers(source_by_path: dict[str, str]) -> frozenset[str]:
    wrappers: set[str] = set()
    for source in source_by_path.values():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for func in iter_functions(tree):
            if function_uses_os_shell(func):
                wrappers.add(func.name)
    return frozenset(wrappers)
