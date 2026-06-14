import ast
from typing import List

from security.models.finding import Finding, Severity
from security.rules.security.ast_helpers import is_likely_untrusted_input, is_test_support_path
from security.rules.security.base import SecurityRule

_XML_PARSER_ATTRS = frozenset({"XMLParser", "parse", "fromstring"})
_UNSAFE_PARSER_KW = frozenset({
    "resolve_entities", "load_dtd", "no_network", "dtd_validation",
})


class XmlExternalEntityRule(SecurityRule):
    rule_id = "xml_external_entity"
    title = "XML External Entity"
    description = "Parsing XML with external entities enabled can allow XXE attacks."
    severity = Severity.HIGH

    def check(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        if is_test_support_path(file_path):
            return []
        findings: List[Finding] = []
        lxml_aliases = self._collect_lxml_aliases(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if self._is_unsafe_sax_set_feature(node):
                findings.append(self._finding(node, "xml.sax setFeature(external entities)", file_path, source_lines))
                continue
            if self._is_unsafe_parser_ctor(node, lxml_aliases):
                findings.append(self._finding(node, "Unsafe XMLParser configuration", file_path, source_lines))
                continue
            label = self._parse_call_label(node, lxml_aliases)
            if label is None:
                label = self._sax_parse_label(node)
            if label is None:
                continue
            if node.args and is_likely_untrusted_input(node.args[0]):
                if self._call_has_unsafe_parser_kw(node) or label.startswith("lxml") or label.startswith("xml.sax"):
                    findings.append(self._finding(node, label, file_path, source_lines))
        return findings

    def _is_unsafe_sax_set_feature(self, node: ast.Call) -> bool:
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "setFeature":
            return False
        if len(node.args) < 2:
            return False
        feature, enabled = node.args[0], node.args[1]
        if not (isinstance(enabled, ast.Constant) and enabled.value is True):
            return False
        if isinstance(feature, ast.Constant) and isinstance(feature.value, str):
            return "external" in feature.value.lower()
        if isinstance(feature, ast.Name) and "external" in feature.id.lower():
            return True
        return False

    def _sax_parse_label(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "parseString":
            return "xml.sax.parseString()"
        if isinstance(func, ast.Attribute) and func.attr == "parseString":
            return "xml.sax.parseString()"
        return None

    def _collect_lxml_aliases(self, tree: ast.AST) -> set[str]:
        aliases: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("lxml"):
                        aliases.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("lxml"):
                base = node.module.split(".")[-1]
                for alias in node.names:
                    if alias.name in _XML_PARSER_ATTRS:
                        aliases.add(f"{node.module}.{alias.name}")
                aliases.add(node.module)
                aliases.add(base)
        return aliases

    def _is_unsafe_parser_ctor(self, node: ast.Call, lxml_aliases: set[str]) -> bool:
        func = node.func
        if not isinstance(func, ast.Attribute) or func.attr != "XMLParser":
            return False
        if not self._is_lxml_ref(func.value, lxml_aliases):
            return False
        for kw in node.keywords:
            if kw.arg == "resolve_entities" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            if kw.arg == "load_dtd" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                return True
            if kw.arg == "no_network" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                return True
        return False

    def _parse_call_label(self, node: ast.Call, lxml_aliases: set[str]) -> str | None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"parse", "fromstring"}:
            if self._is_lxml_ref(func.value, lxml_aliases):
                return f"lxml.etree.{func.attr}()"
            if isinstance(func.value, ast.Name) and func.value.id == "etree":
                return f"etree.{func.attr}()"
        return None

    def _is_lxml_ref(self, node: ast.AST, lxml_aliases: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return node.id in lxml_aliases or node.id == "etree"
        if isinstance(node, ast.Attribute):
            full = self._full_attr(node)
            return full.startswith("lxml") or full.startswith("etree")
        return False

    def _call_has_unsafe_parser_kw(self, node: ast.Call) -> bool:
        for kw in node.keywords:
            if kw.arg not in _UNSAFE_PARSER_KW:
                continue
            if kw.arg in {"resolve_entities", "load_dtd", "dtd_validation"}:
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return True
            if kw.arg == "no_network":
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return True
        return len(node.args) >= 2 and isinstance(node.args[1], ast.Call)

    def _full_attr(self, node: ast.Attribute) -> str:
        parts: list[str] = []
        cur: ast.AST = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))

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
            message=f"{label} may resolve external XML entities (XXE).",
            severity=self.severity,
            file=file_path,
            line=node.lineno,
            suggestion="Disable external entities and DTD loading; use defusedxml where possible.",
            snippet=self._snippet(source_lines, node.lineno),
        )
