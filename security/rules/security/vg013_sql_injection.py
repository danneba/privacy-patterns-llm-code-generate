import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import (
    collect_dynamic_sql_vars,
    is_dynamic_sql,
    is_likely_untrusted_input,
    looks_like_sql,
)
from security.rules.security.base import SecurityRule

_SQL_METHODS = frozenset({"execute", "executemany"})
_ORM_RAW_METHODS = frozenset({"raw"})
_TEXT_CALLEE = frozenset({"text"})


class SqlInjectionRule(SecurityRule):
    rule_id = "sql_query_construction"
    title = "Dynamic SQL Query Construction"
    description = "Constructing SQL queries with string interpolation can allow injection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        sql_vars = collect_dynamic_sql_vars(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and self._is_dynamic_sql_value(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        findings.append(self._sql_finding(node, file_path, source_lines, is_assign=True))
                        break
            if isinstance(node, ast.Call) and self._is_dynamic_text_call(node):
                findings.append(self._sql_finding(node, file_path, source_lines))
                continue
            if isinstance(node, ast.Call) and self._is_dynamic_raw_call(node, sql_vars):
                findings.append(self._sql_finding(node, file_path, source_lines))
                continue
            if not isinstance(node, ast.Call) or not self._is_execute_call(node):
                continue
            if not node.args:
                continue
            if len(node.args) >= 2:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Name) and arg.id in sql_vars:
                continue
            is_dynamic = (
                is_dynamic_sql(arg)
                or (isinstance(arg, ast.Name) and arg.id in sql_vars)
                or self._is_concatenated_sql(arg)
            )
            if not is_dynamic:
                continue

            findings.append(self._sql_finding(node, file_path, source_lines))
        return findings

    def _sql_finding(
        self,
        node: ast.AST,
        file_path: str,
        source_lines: List[str],
        *,
        is_assign: bool = False,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=(
                "SQL string is built with string interpolation or concatenation."
                if is_assign
                else "SQL query is built with string interpolation or concatenation before execution."
            ),
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Use parameterized queries and pass user values separately from the SQL string.",
            snippet=self._snippet(source_lines, node.lineno),
        )

    def _is_dynamic_sql_value(self, node: ast.AST) -> bool:
        return is_dynamic_sql(node) or self._is_concatenated_sql(node)

    def _is_dynamic_text_call(self, node: ast.Call) -> bool:
        if not node.args:
            return False
        func = node.func
        is_text = (
            (isinstance(func, ast.Name) and func.id in _TEXT_CALLEE)
            or (isinstance(func, ast.Attribute) and func.attr in _TEXT_CALLEE)
        )
        if not is_text:
            return False
        arg = node.args[0]
        if isinstance(arg, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in arg.values)
        return is_dynamic_sql(arg) or (
            isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod)
        )

    def _is_execute_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _SQL_METHODS:
            return True
        if isinstance(func, ast.Name) and func.id in {"run_query", "execute_query"}:
            return True
        return False

    def _is_dynamic_raw_call(self, node: ast.Call, sql_vars: set[str]) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr not in _ORM_RAW_METHODS:
            return False
        if not node.args:
            return False
        arg = node.args[0]
        if isinstance(arg, ast.Name) and arg.id in sql_vars:
            return False
        return (
            is_dynamic_sql(arg)
            or (isinstance(arg, ast.Name) and arg.id in sql_vars)
            or self._is_concatenated_sql(arg)
        )

    def _is_concatenated_sql(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
            return False
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and looks_like_sql(child.value)
            ):
                return is_likely_untrusted_input(node)
        return False
