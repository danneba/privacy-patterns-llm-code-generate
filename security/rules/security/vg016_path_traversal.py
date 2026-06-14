import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import (
    enclosing_function,
    is_benchmark_support_path,
    is_likely_untrusted_input,
    is_request_input,
    is_static_path_expression,
    is_test_support_path,
    name_assigned_from_untrusted,
    _module_name_assigned_from_untrusted,
)
from security.rules.security.base import SecurityRule

_PATH_OPEN_ATTRS = frozenset({"open"})
_PATH_IO_ATTRS = frozenset({"open"})
_PATH_TARFILE_ATTRS = frozenset({"open", "TarFile"})
_FILENAME_ATTRS = frozenset({"name", "filename"})
_FILE_PARAM_HINTS = frozenset({"file", "upload", "filename", "attachment", "document"})


class PathTraversalRule(SecurityRule):
    rule_id = "path_traversal"
    title = "Path Traversal"
    description = "Opening files from a dynamic path can allow directory traversal."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path) or is_benchmark_support_path(file_path):
            return []
        findings: List[Finding] = []
        open_aliases = self._collect_open_aliases(tree)
        tarfile_aliases = self._collect_tarfile_aliases(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            join_label = self._path_join_label(node, tree)
            if join_label is not None:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title=self.title,
                        message=f"{join_label} uses a dynamic file path that may allow path traversal.",
                        severity=self.severity,
                        file=file_path,
                        line=node.lineno,
                        suggestion="Validate and canonicalize paths; reject '..' and absolute paths outside an allowlist.",
                        snippet=self._snippet(source_lines, node.lineno),
                    )
                )
                continue
            label = self._path_sink_label(node, open_aliases, tarfile_aliases)
            if label is None:
                continue
            if is_static_path_expression(node.args[0], tree, node):
                continue
            if not is_likely_untrusted_input(node.args[0]):
                continue
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=f"{label} uses a dynamic file path that may allow path traversal.",
                    severity=self.severity,
                    file=file_path,
                    line=node.lineno,
                    suggestion="Validate and canonicalize paths; reject '..' and absolute paths outside an allowlist.",
                    snippet=self._snippet(source_lines, node.lineno),
                )
            )
        return findings

    def _collect_open_aliases(self, tree: ast.AST) -> set[str]:
        aliases: set[str] = {"open"}
        has_io = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "io":
                for alias in node.names:
                    if alias.name in _PATH_IO_ATTRS:
                        aliases.add(alias.asname or alias.name)
                has_io = True
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "io":
                        has_io = True
        if has_io:
            aliases.add("io.open")
        return aliases

    def _collect_tarfile_aliases(self, tree: ast.AST) -> set[str]:
        aliases: set[str] = set()
        tarfile_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "tarfile":
                        tarfile_names.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module == "tarfile":
                for alias in node.names:
                    if alias.name in _PATH_TARFILE_ATTRS:
                        key = alias.asname or alias.name
                        if alias.name == "open":
                            aliases.add(key)
                        else:
                            aliases.add(f"{alias.asname or 'tarfile'}.{alias.name}")
                tarfile_names.add(node.module.split(".")[-1] if node.module else "tarfile")
        for name in tarfile_names:
            aliases.add(f"{name}.open")
            aliases.add(f"{name}.TarFile")
        return aliases

    def _path_sink_label(
        self,
        node: ast.Call,
        open_aliases: set[str],
        tarfile_aliases: set[str],
    ) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in open_aliases:
                return "open()"
            if func.id == "file":
                return "file()"
            if func.id in tarfile_aliases:
                return f"{func.id}()"
        if isinstance(func, ast.Attribute):
            full = self._full_attr(func)
            if full in open_aliases or full in tarfile_aliases:
                return f"{full}()"
            if func.attr in _PATH_OPEN_ATTRS and isinstance(func.value, ast.Name):
                if func.value.id == "io":
                    return "io.open()"
                if func.value.id == "tarfile":
                    return "tarfile.open()"
                if func.value.id == "tarfile" and func.attr == "TarFile":
                    return "tarfile.TarFile()"
        return None

    def _path_join_label(self, node: ast.Call, tree: ast.AST) -> str | None:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "join":
            return None
        base = func.value
        is_os_path = (
            isinstance(base, ast.Attribute)
            and base.attr == "path"
            and isinstance(base.value, ast.Name)
            and base.value.id == "os"
        )
        if not is_os_path:
            return None
        if len(node.args) < 2:
            return None
        for arg in node.args[1:]:
            if self._is_untrusted_path_segment(arg, tree, node):
                return "os.path.join()"
        return None

    def _is_untrusted_path_segment(self, arg: ast.AST, tree: ast.AST, context: ast.Call) -> bool:
        if isinstance(arg, ast.Attribute) and arg.attr in _FILENAME_ATTRS:
            if isinstance(arg.value, ast.Name):
                lower = arg.value.id.lower()
                if any(hint in lower for hint in _FILE_PARAM_HINTS):
                    return True
        if isinstance(arg, (ast.Subscript, ast.JoinedStr, ast.BinOp)):
            return True
        if is_request_input(arg):
            return True
        if isinstance(arg, ast.Name):
            func = enclosing_function(context, tree)
            if func is not None and name_assigned_from_untrusted(func, arg.id):
                return True
            if func is None and isinstance(tree, ast.Module):
                if _module_name_assigned_from_untrusted(tree, arg.id):
                    return True
        return False

    def _full_attr(self, node: ast.Attribute) -> str:
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
