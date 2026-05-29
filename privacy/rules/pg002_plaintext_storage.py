import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import is_sensitive_storage_name


class PlaintextPiiStorageRule(PrivacyRule):
    rule_id = "plaintext_pii_storage"
    title = "Plaintext Sensitive Data Storage"
    description = "Storing passwords or identifiers in plaintext fails to hide sensitive data."
    severity = Severity.HIGH
    privacy_strategy = "HIDE"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not (
                isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value
            ):
                continue
            for target in node.targets:
                name = self._assignment_name(target)
                if name and is_sensitive_storage_name(name):
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=(
                            f"Variable '{name}' stores sensitive data as a plaintext string literal."
                        ),
                        severity=self.severity,
                        category=Category.PRIVACY,
                        file=file_path,
                        line=node.lineno,
                        privacy_strategy=self.privacy_strategy,
                        suggestion="Hash passwords and encrypt sensitive identifiers before storage.",
                        snippet=self._snippet(source_lines, node.lineno),
                    ))
        return findings

    def _assignment_name(self, target: ast.AST) -> str | None:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return target.attr
        return None
