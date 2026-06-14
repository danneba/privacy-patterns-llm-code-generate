import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.base import SecurityRule

_DEBUG_NAMES = frozenset({"debug", "DEBUG"})


class DebugModeRule(SecurityRule):
    rule_id = "debug_mode_enabled"
    title = "Debug Mode Enabled"
    description = "Production web servers must not run with debug mode enabled."
    severity = Severity.MEDIUM

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and self._has_debug_true(node) and self._looks_like_web_app_call(node):
                findings.append(self._finding(node, file_path, source_lines))
            elif isinstance(node, ast.Assign) and self._assigns_debug_true(node):
                findings.append(self._finding(node, file_path, source_lines))
        return findings

    def _finding(self, node: ast.AST, file_path: str, source_lines: List[str]) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message="Debug mode exposes detailed errors and interactive tooling that should not run in production.",
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Disable debug mode outside local development and control it through environment config.",
            snippet=self._snippet(source_lines, node.lineno),
        )

    def _assigns_debug_true(self, node: ast.Assign) -> bool:
        if not (isinstance(node.value, ast.Constant) and node.value.value is True):
            return False
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in _DEBUG_NAMES:
                return True
            if isinstance(target, ast.Attribute) and target.attr in _DEBUG_NAMES:
                return True
            if isinstance(target, ast.Subscript):
                key = target.slice
                if isinstance(key, ast.Constant) and key.value in _DEBUG_NAMES:
                    return True
        return False

    def _has_debug_true(self, node: ast.Call) -> bool:
        return any(
            keyword.arg == "debug"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    def _looks_like_web_app_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "run":
            return True
        return isinstance(func, ast.Name) and func.id in {"run", "FastAPI", "Flask"}
