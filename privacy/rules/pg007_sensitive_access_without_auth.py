import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import function_has_auth_guard, is_pii_name


class SensitiveAccessWithoutAuthRule(PrivacyRule):
    rule_id = "sensitive_access_without_auth"
    title = "Sensitive Data Access Without Auth Guard"
    description = "Reading sensitive personal fields without enforcement controls risks unauthorized disclosure."
    severity = Severity.HIGH
    privacy_strategy = "ENFORCE"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if function_has_auth_guard(node):
                continue
            sensitive_reads = self._sensitive_attribute_reads(node)
            if not sensitive_reads:
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message=(
                    f"Function '{node.name}' reads sensitive personal fields "
                    f"({', '.join(sorted(sensitive_reads))}) without an authentication or authorization guard."
                ),
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Enforce authentication and authorization before accessing sensitive personal data.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _sensitive_attribute_reads(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        reads: set[str] = set()
        for node in ast.walk(func):
            if isinstance(node, ast.Attribute) and is_pii_name(node.attr):
                reads.add(node.attr)
        return reads
