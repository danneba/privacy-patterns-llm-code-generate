import ast
from typing import List

from security.models.finding import Category, Finding, Severity
from privacy.rules.base import PrivacyRule
from privacy.rules.helpers import call_target, expression_mentions_pii, function_mentions_consent, iter_calls


class MarketingWithoutOptOutRule(PrivacyRule):
    rule_id = "marketing_without_opt_out"
    title = "Outbound Communication Without Opt-Out Check"
    description = "Sending messages using personal contact data without opt-out checks limits user control."
    severity = Severity.MEDIUM
    privacy_strategy = "CONTROL"

    _OUTBOUND_CALLS = frozenset({"send", "send_mail", "send_email", "send_message", "notify"})

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings = []
        for node in iter_calls(tree):
            target = call_target(node)
            if not target or target not in self._OUTBOUND_CALLS:
                continue
            if not any(expression_mentions_pii(arg) for arg in node.args):
                continue
            enclosing = self._enclosing_function(tree, node)
            if enclosing and function_mentions_consent(enclosing):
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message="Personal contact data is used for outbound communication without an opt-out check.",
                severity=self.severity,
                category=Category.PRIVACY,
                file=file_path,
                line=node.lineno,
                privacy_strategy=self.privacy_strategy,
                suggestion="Verify marketing consent or opt-out preferences before contacting users.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _enclosing_function(
        self,
        tree: ast.AST,
        call_node: ast.Call,
    ) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if child is call_node:
                    return node
        return None
