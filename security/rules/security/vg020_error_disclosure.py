import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_test_support_path
from security.rules.security.base import SecurityRule

_TRACEBACK_ATTRS = frozenset({
    "format_exc", "format_stack", "format_exception", "print_exc",
})


class VerboseErrorDisclosureRule(SecurityRule):
    rule_id = "verbose_error_disclosure"
    title = "Verbose Error Disclosure"
    description = "Stack traces or exception details may leak sensitive implementation information."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and node.value is not None:
                for child in ast.walk(node.value):
                    if isinstance(child, ast.Call) and self._is_traceback_call(child):
                        findings.append(self._finding(child, file_path, source_lines))
        return findings

    def _is_traceback_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _TRACEBACK_ATTRS:
            if isinstance(func.value, ast.Name) and func.value.id == "traceback":
                return True
        return isinstance(func, ast.Name) and func.id in _TRACEBACK_ATTRS

    def _finding(
        self,
        node: ast.Call,
        file_path: str,
        source_lines: List[str],
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message="Traceback or exception details are exposed in application output.",
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Return generic error messages to clients; log details server-side only.",
            snippet=self._snippet(source_lines, node.lineno),
        )
