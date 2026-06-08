import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import _LOG_CALLS, call_target, expression_mentions_pii, iter_calls


class PiiInLogsRule(PrivacyRule):
    rule_id = "pii_in_logs"
    title = "PII in Logs or Print Output"
    description = "Logging or printing personally identifiable information violates data minimization."
    severity = Severity.HIGH
    privacy_strategy = "MINIMIZE"

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in iter_calls(tree):
            target = call_target(node)
            if not target or target not in _LOG_CALLS:
                continue
            if not node.args and not node.keywords:
                continue
            args = list(node.args) + [keyword.value for keyword in node.keywords]
            if not any(expression_mentions_pii(arg) for arg in args):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Personally identifiable information appears in log or print output.",
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Redact or pseudonymize PII before logging; log opaque user IDs instead.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings
