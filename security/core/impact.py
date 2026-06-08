from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from security.core.scanner import Scanner
from security.models.finding import Category, Finding, ScanResult, Severity


@dataclass
class ChangedLine:
    line_number: int
    before_text: str
    after_text: str

    def to_dict(self) -> dict:
        return {
            "line_number": self.line_number,
            "before_text": self.before_text,
            "after_text": self.after_text,
        }


@dataclass
class CodeChangeImpact:
    sample_label: str
    changed_lines: List[ChangedLine]
    before: ScanResult
    after: ScanResult
    resolved_findings: List[Finding] = field(default_factory=list)
    introduced_findings: List[Finding] = field(default_factory=list)
    before_privacy_count: int = 0
    after_privacy_count: int = 0
    before_security_count: int = 0
    after_security_count: int = 0
    before_total_count: int = 0
    after_total_count: int = 0
    resolved_privacy_count: int = 0
    resolved_security_count: int = 0

    def to_dict(self) -> dict:
        return {
            "sample_label": self.sample_label,
            "changed_lines": [line.to_dict() for line in self.changed_lines],
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "resolved_findings": [finding.to_dict() for finding in self.resolved_findings],
            "introduced_findings": [finding.to_dict() for finding in self.introduced_findings],
            "before_privacy_count": self.before_privacy_count,
            "after_privacy_count": self.after_privacy_count,
            "before_security_count": self.before_security_count,
            "after_security_count": self.after_security_count,
            "before_total_count": self.before_total_count,
            "after_total_count": self.after_total_count,
            "resolved_privacy_count": self.resolved_privacy_count,
            "resolved_security_count": self.resolved_security_count,
        }


def _finding_key(finding: Finding) -> Tuple[str, str, Optional[int], str]:
    snippet = (finding.snippet or "").strip()
    return (finding.rule_id, finding.file, finding.line, snippet)


def _loose_finding_key(finding: Finding) -> Tuple[str, Optional[int]]:
    return (finding.rule_id, finding.line)


def _count_category(findings: List[Finding], category: Category) -> int:
    return sum(1 for finding in findings if finding.category == category)


def detect_changed_lines(before_code: str, after_code: str) -> List[ChangedLine]:
    before_lines = before_code.splitlines()
    after_lines = after_code.splitlines()
    max_len = max(len(before_lines), len(after_lines))
    changed: List[ChangedLine] = []
    for index in range(max_len):
        before_text = before_lines[index] if index < len(before_lines) else ""
        after_text = after_lines[index] if index < len(after_lines) else ""
        if before_text != after_text:
            changed.append(
                ChangedLine(
                    line_number=index + 1,
                    before_text=before_text,
                    after_text=after_text,
                )
            )
    return changed


def _resolved_findings(before: ScanResult, after: ScanResult) -> List[Finding]:
    after_keys = {_finding_key(finding) for finding in after.findings}
    after_loose = {_loose_finding_key(finding) for finding in after.findings}
    resolved: List[Finding] = []
    seen: set[Tuple[str, Optional[int]]] = set()
    for finding in before.findings:
        if _finding_key(finding) in after_keys:
            continue
        loose = _loose_finding_key(finding)
        if loose in after_loose:
            continue
        if loose in seen:
            continue
        seen.add(loose)
        resolved.append(finding)
    return resolved


def _introduced_findings(before: ScanResult, after: ScanResult) -> List[Finding]:
    before_keys = {_finding_key(finding) for finding in before.findings}
    before_loose = {_loose_finding_key(finding) for finding in before.findings}
    introduced: List[Finding] = []
    seen: set[Tuple[str, Optional[int]]] = set()
    for finding in after.findings:
        if _finding_key(finding) in before_keys:
            continue
        loose = _loose_finding_key(finding)
        if loose in before_loose:
            continue
        if loose in seen:
            continue
        seen.add(loose)
        introduced.append(finding)
    return introduced


def run_code_change_impact(
    before_code: str,
    after_code: str,
    filename: str = "<code>",
    *,
    min_severity: Optional[Severity] = None,
    include_snippet: bool = True,
    sample_label: Optional[str] = None,
) -> CodeChangeImpact:
    """Compare guided analysis before and after a small source edit."""
    scanner = Scanner(
        min_severity=min_severity,
        include_snippet=include_snippet,
        enable_guidance=True,
        include_auxiliary_analyzers=False,
    )
    before = scanner.scan_source(before_code, filename)
    after = scanner.scan_source(after_code, filename)
    resolved = _resolved_findings(before, after)
    introduced = _introduced_findings(before, after)

    return CodeChangeImpact(
        sample_label=sample_label or filename,
        changed_lines=detect_changed_lines(before_code, after_code),
        before=before,
        after=after,
        resolved_findings=resolved,
        introduced_findings=introduced,
        before_privacy_count=_count_category(before.findings, Category.PRIVACY),
        after_privacy_count=_count_category(after.findings, Category.PRIVACY),
        before_security_count=_count_category(before.findings, Category.SECURITY),
        after_security_count=_count_category(after.findings, Category.SECURITY),
        before_total_count=len(before.findings),
        after_total_count=len(after.findings),
        resolved_privacy_count=_count_category(resolved, Category.PRIVACY),
        resolved_security_count=_count_category(resolved, Category.SECURITY),
    )
