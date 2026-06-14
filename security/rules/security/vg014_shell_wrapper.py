import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_dynamic_string
from security.rules.security.base import SecurityRule

_REPO_SHELL_WRAPPERS: frozenset[str] = frozenset()


def set_repo_shell_wrappers(wrappers: frozenset[str]) -> None:
    global _REPO_SHELL_WRAPPERS
    _REPO_SHELL_WRAPPERS = wrappers


class ShellWrapperCallRule(SecurityRule):
    rule_id = "shell_wrapper_call"
    title = "Shell Wrapper Call"
    description = "Calling a helper that executes os.system/popen with user-influenced input."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if not _REPO_SHELL_WRAPPERS:
            return []
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            name = self._callee_name(node.func)
            if name not in _REPO_SHELL_WRAPPERS:
                continue
            if not is_dynamic_string(node.args[0]) and not isinstance(node.args[0], ast.Name):
                continue
            if isinstance(node.args[0], ast.Constant):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"Call to '{name}()' passes dynamic input into a function that executes "
                        "operating-system shell commands."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Avoid shell wrappers; use parameterized APIs and validate input.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _callee_name(self, func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None
