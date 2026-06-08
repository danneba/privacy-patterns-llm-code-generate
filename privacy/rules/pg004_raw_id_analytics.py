import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import _ANALYTICS_CALLS, call_target, expression_mentions_pii, iter_calls


class RawIdInAnalyticsRule(PrivacyRule):
    rule_id = "raw_id_in_analytics"
    title = "Identifiable Data in Analytics Event"
    description = "Shipping raw identifiers to analytics prevents meaningful aggregation."
    severity = Severity.MEDIUM
    privacy_strategy = "AGGREGATE"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in iter_calls(tree):
            target = call_target(node)
            if not target or target not in _ANALYTICS_CALLS:
                continue
            if not any(expression_mentions_pii(arg) for arg in node.args):
                continue
            if not any(
                isinstance(arg, ast.Dict) or expression_mentions_pii(arg)
                for arg in node.args
            ):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Analytics or telemetry call includes directly identifiable personal data.",
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Aggregate or bucket identifiers before sending analytics events.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings
