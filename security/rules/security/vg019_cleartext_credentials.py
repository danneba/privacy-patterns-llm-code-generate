import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_request_input, is_test_support_path
from security.rules.security.base import SecurityRule

_CREDENTIAL_KEYWORDS = frozenset({"password", "passwd", "secret", "token"})


class CleartextCredentialHandlingRule(SecurityRule):
    rule_id = "cleartext_credential_handling"
    title = "Cleartext Credential Handling"
    description = "Credentials from user input stored or passed without protection."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings: List[Finding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_call(node, file_path, source_lines)
                if finding:
                    findings.append(finding)
        return findings

    def _check_call(self, node: ast.Call, file_path: str, source_lines: List[str]) -> Finding | None:
        for keyword in node.keywords:
            if keyword.arg not in _CREDENTIAL_KEYWORDS:
                continue
            if self._is_request_credential_source(keyword.value):
                return self._finding(node, keyword.arg, file_path, source_lines)
        return None

    def _is_request_credential_source(self, node: ast.AST) -> bool:
        return is_request_input(node)

    def _finding(
        self,
        node: ast.Call,
        label: str,
        file_path: str,
        source_lines: List[str],
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=(
                f"Credential '{label}' is supplied from untrusted input and may be stored "
                "or handled in cleartext."
            ),
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Hash passwords before storage and never persist raw credentials.",
            snippet=self._snippet(source_lines, node.lineno),
        )
