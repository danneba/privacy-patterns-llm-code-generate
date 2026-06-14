import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_test_support_path
from security.rules.security.base import SecurityRule

_SENSITIVE_NAMES = frozenset({
    "password", "passwd", "secret", "api_key", "token",
    "private_key", "auth_token", "access_token", "secret_key",
})
_SENSITIVE_ATTRS = frozenset({
    "secret_key", "api_key", "password", "passwd", "token", "private_key",
})
_SENSITIVE_CONFIG_KEYS = frozenset({
    "SECRET_KEY", "secret_key", "API_KEY", "api_key", "PASSWORD", "password",
    "JWT_SECRET_KEY", "jwt_secret_key", "ACCESS_TOKEN_SALT", "access_token_salt",
})


class HardcodedSecretsRule(SecurityRule):
    rule_id = "hardcoded_secret"
    title = "Hardcoded Secret"
    description = (
        "Assigning a non-empty string literal to a variable with a sensitive name "
        "may expose credentials in source code."
    )
    severity = Severity.HIGH

    def _is_sensitive_name(self, name: str) -> bool:
        name_lower = name.lower()
        if name_lower == "key" or name_lower.endswith("_key"):
            return True
        return any(s in name_lower for s in _SENSITIVE_NAMES)

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings = []
        reported_lines: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for finding in self._findings_from_dict(node, file_path, source_lines):
                    self._append_finding(findings, reported_lines, finding)
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not self._is_non_empty_secret_literal(value):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and self._is_sensitive_name(target.id):
                    self._append_finding(
                        findings, reported_lines,
                        self._finding(node, target.id, file_path, source_lines),
                    )
                elif isinstance(target, ast.Attribute) and target.attr in _SENSITIVE_ATTRS:
                    self._append_finding(
                        findings, reported_lines,
                        self._finding(node, target.attr, file_path, source_lines),
                    )
                elif isinstance(target, ast.Subscript) and self._sensitive_subscript_key(target):
                    self._append_finding(
                        findings, reported_lines,
                        self._finding(node, "config secret", file_path, source_lines),
                    )
        return findings

    def _append_finding(
        self,
        findings: list[Finding],
        reported_lines: list[int],
        finding: Finding,
    ) -> None:
        line = finding.line or 0
        if any(abs(line - prior) <= 25 for prior in reported_lines):
            return
        reported_lines.append(line)
        findings.append(finding)

    def _findings_from_dict(
        self,
        node: ast.Dict,
        file_path: str,
        source_lines: List[str],
    ) -> List[Finding]:
        findings: List[Finding] = []
        for key, value in zip(node.keys, node.values):
            if key is None or value is None:
                continue
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if not self._is_sensitive_name(key.value):
                continue
            if not self._is_non_empty_secret_literal(value):
                continue
            findings.append(self._finding(node, key.value, file_path, source_lines))
            break
        return findings

    def _is_non_empty_secret_literal(self, value: ast.AST) -> bool:
        if not isinstance(value, ast.Constant):
            return False
        if isinstance(value.value, str):
            if self._looks_like_password_hash(value.value):
                return False
            return bool(value.value)
        if isinstance(value.value, bytes):
            return bool(value.value)
        return False

    def _looks_like_password_hash(self, value: str) -> bool:
        if len(value) < 32 or len(value) % 2 != 0:
            return False
        try:
            int(value, 16)
        except ValueError:
            return False
        return True

    def _sensitive_subscript_key(self, target: ast.Subscript) -> bool:
        key = target.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return key.value in _SENSITIVE_CONFIG_KEYS or self._is_sensitive_name(key.value)
        return False

    def _finding(
        self,
        node: ast.AST,
        label: str,
        file_path: str,
        source_lines: List[str],
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            message=(
                f"'{label}' appears to contain a hardcoded secret. "
                "Move credentials to environment variables or a secrets manager."
            ),
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            snippet=self._snippet(source_lines, node.lineno),
        )
