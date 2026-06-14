import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_test_support_path
from security.rules.security.base import SecurityRule

_WEAK_HASHES = {"md5", "sha1", "sha"}


class WeakHashRule(SecurityRule):
    rule_id = "weak_hash_algorithm"
    title = "Weak Hash Algorithm"
    description = "MD5/SHA-1 are cryptographically broken and must not be used for security purposes."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            weak_name = self._weak_hash_name(node)
            if weak_name is None:
                continue
            findings.append(Finding(
                rule_id=self.rule_id,
                title=self.title,
                message=f"hashlib.{weak_name}() uses a weak/broken hash algorithm.",
                severity=self.severity,
                file=file_path,
                line=node.lineno,
                suggestion="Use hashlib.sha256() or better. For passwords, use bcrypt/argon2.",
                snippet=self._snippet(source_lines, node.lineno),
            ))
        return findings

    def _weak_hash_name(self, node: ast.Call) -> str | None:
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
        ):
            if node.func.attr in _WEAK_HASHES:
                return node.func.attr
            if node.func.attr == "new" and node.args:
                first = node.args[0]
                if isinstance(first, ast.Constant) and isinstance(first.value, str):
                    algo = first.value.lower()
                    if algo in _WEAK_HASHES:
                        return algo
        return None
