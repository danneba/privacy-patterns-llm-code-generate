import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import function_mentions_consent, is_pii_name


class PiiWithoutConsentRule(PrivacyRule):
    rule_id = "pii_without_consent"
    title = "PII Processing Without Consent Handling"
    description = "Collecting personal data without consent checks fails to inform and obtain control."
    severity = Severity.MEDIUM
    privacy_strategy = "INFORM"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._accepts_pii(node):
                continue
            if function_mentions_consent(node):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message=(
                    f"Function '{node.name}' accepts personal data but does not reference "
                    "consent, opt-in, or permission handling."
                ),
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Record consent state and verify it before collecting or using personal data.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _accepts_pii(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(is_pii_name(arg.arg) for arg in func.args.args + func.args.kwonlyargs)
