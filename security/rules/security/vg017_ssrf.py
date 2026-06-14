import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_likely_untrusted_input, is_test_support_path
from security.rules.security.base import SecurityRule

_REQUESTS_METHODS = frozenset({
    "delete", "get", "head", "options", "patch", "post", "put", "request",
})
_URLOPEN_ATTRS = frozenset({"urlopen", "urlretrieve"})


class ServerSideRequestForgeryRule(SecurityRule):
    rule_id = "server_side_request_forgery"
    title = "Server-Side Request Forgery"
    description = "Fetching a URL built from untrusted input can allow SSRF."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings: List[Finding] = []
        urllib_aliases, urllib_methods = self._collect_urllib(tree)
        requests_aliases, requests_methods = self._collect_requests(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            label = self._ssrf_label(node, urllib_aliases, urllib_methods, requests_aliases, requests_methods)
            if label is None:
                continue
            if not is_likely_untrusted_input(node.args[0]):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"{label} may fetch an attacker-controlled URL (SSRF).",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Allowlist hosts/schemes, block internal IPs, and avoid passing raw user input to HTTP clients.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _collect_urllib(self, tree: ast.AST) -> tuple[set[str], set[str]]:
        modules: set[str] = set()
        direct: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"urllib.request", "urllib"}:
                        modules.add(alias.asname or alias.name.split(".")[-1])
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                if mod in {"urllib.request", "urllib"}:
                    base = mod.split(".")[-1]
                    for alias in node.names:
                        if alias.name in _URLOPEN_ATTRS:
                            direct.add(alias.asname or alias.name)
                    modules.add(base)
        return modules, direct

    def _collect_requests(self, tree: ast.AST) -> tuple[set[str], set[str]]:
        aliases: set[str] = set()
        direct: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "requests":
                        aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "requests":
                for alias in node.names:
                    if alias.name in _REQUESTS_METHODS:
                        direct.add(alias.asname or alias.name)
        return aliases, direct

    def _ssrf_label(
        self,
        node: ast.Call,
        urllib_modules: set[str],
        urllib_direct: set[str],
        requests_aliases: set[str],
        requests_direct: set[str],
    ) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in urllib_direct:
                return f"urllib.request.{func.id}()"
            if func.id in requests_direct:
                return f"requests.{func.id}()"
        if isinstance(func, ast.Attribute):
            if func.attr in _URLOPEN_ATTRS and isinstance(func.value, ast.Name):
                if func.value.id in urllib_modules or func.value.id == "urllib":
                    return f"urllib.request.{func.attr}()"
            if func.attr in _REQUESTS_METHODS and isinstance(func.value, ast.Name):
                if func.value.id in requests_aliases:
                    return f"requests.{func.attr}()"
        return None
