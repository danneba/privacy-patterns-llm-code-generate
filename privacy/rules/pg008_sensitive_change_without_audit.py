import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import function_mentions_audit, is_sensitive_storage_name, node_name


class SensitiveChangeWithoutAuditRule(PrivacyRule):
    rule_id = "sensitive_change_without_audit"
    title = "Sensitive Data Change Without Audit Trail"
    description = "Modifying sensitive personal data without audit logging weakens accountability."
    severity = Severity.MEDIUM
    privacy_strategy = "DEMONSTRATE"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._modifies_sensitive_data(node):
                continue
            if function_mentions_audit(node):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message=(
                    f"Function '{node.name}' modifies sensitive personal data without an audit log call."
                ),
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Record audit events when sensitive personal data is created, updated, or deleted.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _modifies_sensitive_data(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for node in ast.walk(func):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    name = node_name(target)
                    if isinstance(target, ast.Attribute):
                        name = target.attr
                    if name and is_sensitive_storage_name(name):
                        return True
            if isinstance(node, ast.AugAssign):
                name = node_name(node.target)
                if isinstance(node.target, ast.Attribute):
                    name = node.target.attr
                if name and is_sensitive_storage_name(name):
                    return True
        return False
