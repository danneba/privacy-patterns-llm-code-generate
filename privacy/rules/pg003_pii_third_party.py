import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import call_target, expression_mentions_pii, iter_calls


class PiiToThirdPartyRule(PrivacyRule):
    rule_id = "pii_to_third_party"
    title = "PII Sent to Third-Party Service"
    description = "Transmitting personal data to external services without separation increases exposure."
    severity = Severity.HIGH
    privacy_strategy = "SEPARATE"

    _THIRD_PARTY_TARGETS = frozenset({
        "post",
        "put",
        "patch",
        "get",
        "request",
        "send",
        "track",
        "identify",
        "capture",
    })

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in iter_calls(tree):
            target = call_target(node)
            if not target or target not in self._THIRD_PARTY_TARGETS:
                continue
            payload_args = list(node.args[1:]) + [keyword.value for keyword in node.keywords]
            if not payload_args:
                continue
            if not any(expression_mentions_pii(arg) for arg in payload_args):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Personal data is included in a request or event sent to an external service.",
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Separate identity data from third-party payloads; use pseudonymous tokens.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings
