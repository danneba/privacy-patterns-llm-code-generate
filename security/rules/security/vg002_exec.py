import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import should_suppress_code_injection
from security.rules.security.base import SecurityRule


class ExecUsageRule(SecurityRule):
    rule_id = "eval_exec_usage"
    title = "Use of exec()"
    description = "Calling exec() executes arbitrary code and is a critical security risk."
    severity = Severity.CRITICAL

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name not in {"exec", "compile"}:
                continue
            if name == "compile" and node.args:
                from security.rules.security.ast_helpers import (
                    is_constant_string,
                    is_likely_untrusted_input,
                )
                if is_constant_string(node.args[0]) or not is_likely_untrusted_input(node.args[0]):
                    continue
            if should_suppress_code_injection(tree, node):
                continue
            title = f"Use of {name}()"
            message = (
                f"Use of {name}() is insecure and may allow arbitrary code execution."
            )
            findings.append(Finding(
                rule_id=self.rule_id,
                title=title,
                message=message,
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings
