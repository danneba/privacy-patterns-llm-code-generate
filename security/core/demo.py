from dataclasses import dataclass, field
from typing import List, Optional, Set

from security.core.scanner import Scanner
from security.models.finding import Category, Finding, ScanResult, Severity


@dataclass
class DemoDelta:
    additional_findings_count: int
    guidance_only_rule_ids: List[str] = field(default_factory=list)
    privacy_strategies_surfaced: List[str] = field(default_factory=list)
    baseline_finding_count: int = 0
    guided_finding_count: int = 0
    baseline_security_count: int = 0
    guided_security_count: int = 0
    guided_privacy_count: int = 0

    def to_dict(self) -> dict:
        return {
            "additional_findings_count": self.additional_findings_count,
            "guidance_only_rule_ids": self.guidance_only_rule_ids,
            "privacy_strategies_surfaced": self.privacy_strategies_surfaced,
            "baseline_finding_count": self.baseline_finding_count,
            "guided_finding_count": self.guided_finding_count,
            "baseline_security_count": self.baseline_security_count,
            "guided_security_count": self.guided_security_count,
            "guided_privacy_count": self.guided_privacy_count,
        }


@dataclass
class DemoComparison:
    sample_label: str
    baseline: ScanResult
    with_guidance: ScanResult
    delta: DemoDelta

    def to_dict(self) -> dict:
        return {
            "sample_label": self.sample_label,
            "baseline": self.baseline.to_dict(),
            "with_guidance": self.with_guidance.to_dict(),
            "delta": self.delta.to_dict(),
        }


def _finding_key(finding: Finding) -> tuple:
    return (finding.rule_id, finding.file, finding.line)


def _count_security(findings: List[Finding]) -> int:
    return sum(1 for f in findings if f.category == Category.SECURITY)


def _count_privacy(findings: List[Finding]) -> int:
    return sum(1 for f in findings if f.category == Category.PRIVACY)


def build_demo_delta(baseline: ScanResult, guided: ScanResult) -> DemoDelta:
    baseline_keys = {_finding_key(f) for f in baseline.findings}
    additional = [f for f in guided.findings if _finding_key(f) not in baseline_keys]
    guidance_only_rules = sorted({f.rule_id for f in additional})
    strategies: Set[str] = set()
    for finding in additional:
        if finding.privacy_strategy:
            strategies.add(finding.privacy_strategy)
    for finding in guided.findings:
        if finding.category == Category.PRIVACY and finding.privacy_strategy:
            strategies.add(finding.privacy_strategy)

    return DemoDelta(
        additional_findings_count=len(additional),
        guidance_only_rule_ids=guidance_only_rules,
        privacy_strategies_surfaced=sorted(strategies),
        baseline_finding_count=len(baseline.findings),
        guided_finding_count=len(guided.findings),
        baseline_security_count=_count_security(baseline.findings),
        guided_security_count=_count_security(guided.findings),
        guided_privacy_count=_count_privacy(guided.findings),
    )


def run_guidance_demo(
    code: str,
    filename: str = "<code>",
    *,
    min_severity: Optional[Severity] = None,
    include_snippet: bool = True,
    sample_label: Optional[str] = None,
) -> DemoComparison:
    """Run baseline (security-only) and guidance-enabled scans on the same source."""
    common = dict(
        min_severity=min_severity,
        include_snippet=include_snippet,
        include_auxiliary_analyzers=False,
    )
    baseline = Scanner(enable_guidance=False, **common).scan_source(code, filename)
    guided = Scanner(enable_guidance=True, **common).scan_source(code, filename)
    label = sample_label or filename
    return DemoComparison(
        sample_label=label,
        baseline=baseline,
        with_guidance=guided,
        delta=build_demo_delta(baseline, guided),
    )
