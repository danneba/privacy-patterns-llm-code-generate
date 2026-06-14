import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_dynamic_string
from security.rules.security.base import SecurityRule

_SSTI_CALLEES = frozenset({"render_template_string"})


class ServerSideTemplateInjectionRule(SecurityRule):
    rule_id = "server_side_template_injection"
    title = "Server-Side Template Injection"
    description = "Rendering a user-influenced template string can allow template injection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            if not self._is_ssti_call(node):
                continue
            template_arg = node.args[0]
            if isinstance(template_arg, ast.Constant) and isinstance(template_arg.value, str):
                continue
            if not is_dynamic_string(template_arg) and not isinstance(template_arg, ast.Name):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        "render_template_string() is called with a template built from "
                        "dynamic input, which can enable server-side template injection."
                    ),
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Use static templates and pass user data as context variables.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _is_ssti_call(self, node: ast.Call) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id in _SSTI_CALLEES:
            return True
        return isinstance(func, ast.Attribute) and func.attr in _SSTI_CALLEES
