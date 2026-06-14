import ast
from typing import List, Optional

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import (
    enclosing_function,
    function_statements,
    is_dynamic_string,
    is_likely_untrusted_input,
    last_assignment_value,
    variable_last_source_is_safe,
)
from security.rules.security.base import SecurityRule

_SUBPROCESS_FUNCS = frozenset({
    "run", "call", "Popen", "check_call", "check_output",
    "getoutput", "getstatusoutput",
})


class SubprocessShellRule(SecurityRule):
    rule_id = "subprocess_shell_true"
    title = "Dangerous Subprocess Usage"
    description = "Using shell=True in subprocess calls exposes the command to shell injection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        imported_aliases: set[str] = set()
        tainted_lists: set[str] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "subprocess":
                for alias in node.names:
                    if alias.name in _SUBPROCESS_FUNCS:
                        imported_aliases.add(alias.asname if alias.asname else alias.name)

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append"
                and isinstance(node.func.value, ast.Name)
                and node.args
                and is_dynamic_string(node.args[0])
            ):
                tainted_lists.add(node.func.value.id)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not self._is_subprocess_call(node, imported_aliases):
                continue

            if self._list_command_injection(node, tainted_lists):
                findings.append(self._finding(
                    file_path, source_lines, node.lineno,
                    "subprocess_shell_command_injection",
                    "Subprocess invoked with a command list containing interpolated shell commands.",
                    "Avoid passing interpolated strings to sh -c / cmd.exe -c style command lists.",
                ))
                continue

            if not self._has_shell_true(node):
                continue
            if self._shell_command_is_safe(tree, node):
                continue
            findings.append(self._finding(
                file_path, source_lines, node.lineno,
                self.rule_id,
                (
                    "subprocess called with shell=True, which passes the command through "
                    "a shell and may allow command injection. Pass a list of arguments instead."
                ),
                "Pass a list of arguments instead of shell=True.",
            ))

        return findings

    def _finding(
        self,
        file_path: str,
        source_lines: List[str],
        lineno: int,
        rule_id: str,
        message: str,
        suggestion: str,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=self.title,
            message=message,
            severity=self.severity,
            file=file_path,
            line=lineno,
            suggestion=suggestion,
            snippet=self._snippet(source_lines, lineno),
        )

    def _is_subprocess_call(self, node: ast.Call, imported_aliases: set[str]) -> bool:
        func = node.func
        return (
            (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
                and func.attr in _SUBPROCESS_FUNCS
            )
            or (isinstance(func, ast.Name) and func.id in imported_aliases)
        )

    def _has_shell_true(self, node: ast.Call) -> bool:
        return any(
            kw.arg == "shell"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords
        )

    def _list_command_injection(self, node: ast.Call, tainted_lists: set[str]) -> bool:
        if self._has_shell_true(node):
            return False
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.Name) and first.id in tainted_lists:
            return True
        if isinstance(first, ast.List):
            return any(
                is_dynamic_string(elt)
                or (isinstance(elt, ast.Name) and is_likely_untrusted_input(elt))
                for elt in first.elts
            )
        return False

    def _shell_command_is_safe(self, tree: ast.AST, node: ast.Call) -> bool:
        command_node = self._shell_command_arg(node)
        if command_node is None:
            return False
        func_def = enclosing_function(node, tree)
        if func_def is None:
            return False
        statements = function_statements(func_def)

        var_name = self._interpolated_var_name(command_node)
        if isinstance(command_node, ast.Name):
            command_value = last_assignment_value(
                statements, command_node.id, node.lineno
            )
            if command_value is not None:
                var_name = self._interpolated_var_name(command_value) or var_name
        if not var_name:
            return False
        return variable_last_source_is_safe(statements, var_name, node.lineno)

    def _shell_command_arg(self, node: ast.Call) -> Optional[ast.AST]:
        if node.args:
            return node.args[0]
        for kw in node.keywords:
            if kw.arg in {"args", "command"}:
                return kw.value
        return None

    def _interpolated_var_name(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                    return value.value.id
        if isinstance(node, ast.BinOp):
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    return child.id
        return None
