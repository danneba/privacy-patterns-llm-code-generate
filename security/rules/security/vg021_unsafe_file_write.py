import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import (
    enclosing_function,
    function_statements,
    is_request_input,
    is_test_support_path,
    last_assignment_value,
)
from security.rules.security.base import SecurityRule


class UnsafeFileWriteRule(SecurityRule):
    rule_id = "unsafe_file_write"
    title = "Unsafe File Write"
    description = "Writing request-controlled data to a file can allow arbitrary code or path abuse."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings: List[Finding] = []
        reported_functions: set[int] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = enclosing_function(node, tree)
            func_key = id(func) if func is not None else None
            if isinstance(node.func, ast.Attribute) and node.func.attr == "write" and node.args:
                if func_key in reported_functions:
                    continue
                if self._is_request_controlled(node.args[0], tree, node):
                    findings.append(self._finding(node, file_path, source_lines))
                    if func_key is not None:
                        reported_functions.add(func_key)
        return findings

    def _is_request_controlled(self, node: ast.AST, tree: ast.AST, context: ast.AST) -> bool:
        if is_request_input(node):
            return True
        if isinstance(node, ast.Name):
            func = enclosing_function(context, tree)
            if func is None:
                return False
            value = last_assignment_value(
                function_statements(func),
                node.id,
                before_lineno=getattr(context, "lineno", None),
            )
            if value is not None:
                return is_request_input(value)
        return False

    def _finding(self, node: ast.Call, file_path: str, source_lines: List[str]) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message="Request-controlled data is written to a file without validation.",
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Never write raw user input to executable paths; validate content and destination.",
            snippet=self._snippet(source_lines, node.lineno),
        )
