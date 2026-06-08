from security.core.demo import DemoComparison
from security.models.finding import Category, Finding, ScanResult


def _format_finding_line(index: int, finding: Finding) -> str:
    category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
    strategy = f" | {finding.privacy_strategy}" if finding.privacy_strategy else ""
    line = finding.line if finding.line is not None else "?"
    return (
        f"  {index:2}. [{finding.severity.value}][{category}] "
        f"{finding.rule_id}{strategy} — {finding.title} ({finding.file}:{line})"
    )


def _format_findings_block(findings: list[Finding], width: int) -> list[str]:
    if not findings:
        empty = "  (no findings)"
        return [empty.ljust(width)[:width]]
    lines = [_format_finding_line(i, f) for i, f in enumerate(findings, start=1)]
    return [line.ljust(width)[:width] for line in lines]


def _summary_line(result: ScanResult) -> str:
    summary = result.summary()
    by_cat = summary["by_category"]
    security = by_cat.get("SECURITY", 0)
    privacy = by_cat.get("PRIVACY", 0)
    risk = summary.get("risk", {})
    privacy_score = risk.get("privacy_score", 100) if risk else 100
    return (
        f"{len(result.findings)} finding(s) | security={security} privacy={privacy} "
        f"| privacy_score={privacy_score}/100"
    )


class DemoReporter:
    def report(self, comparison: DemoComparison) -> str:
        width = 48
        baseline_lines = _format_findings_block(comparison.baseline.findings, width)
        guided_lines = _format_findings_block(comparison.with_guidance.findings, width)
        row_count = max(len(baseline_lines), len(guided_lines), 1)

        while len(baseline_lines) < row_count:
            baseline_lines.append("".ljust(width))
        while len(guided_lines) < row_count:
            guided_lines.append("".ljust(width))

        lines: list[str] = []
        lines.append("=" * (width * 2 + 3))
        lines.append(" VibeCodeGuide — Privacy & Security Guidance Demo")
        lines.append(f" Sample: {comparison.sample_label}")
        lines.append("=" * (width * 2 + 3))
        lines.append("")
        lines.append(
            f" {'BASELINE (guidance OFF)':<{width}} | {'WITH GUIDANCE (ON)':<{width}}"
        )
        lines.append(f" {'-' * width} | {'-' * width}")
        lines.append(
            f" {_summary_line(comparison.baseline):<{width}} | "
            f"{_summary_line(comparison.with_guidance):<{width}}"
        )
        lines.append(f" {'-' * width} | {'-' * width}")

        for left, right in zip(baseline_lines, guided_lines):
            lines.append(f" {left} | {right}")

        delta = comparison.delta
        lines.append("")
        lines.append("=" * (width * 2 + 3))
        lines.append(" DELTA — value of the guidance module")
        lines.append("=" * (width * 2 + 3))
        lines.append(f" +{delta.additional_findings_count} additional finding(s) with guidance enabled")
        lines.append(
            f" Baseline: {delta.baseline_finding_count} total "
            f"({delta.baseline_security_count} security)  →  "
            f"Guided: {delta.guided_finding_count} total "
            f"({delta.guided_security_count} security + {delta.guided_privacy_count} privacy)"
        )
        if delta.guidance_only_rule_ids:
            lines.append(
                " Guidance-only rules: " + ", ".join(delta.guidance_only_rule_ids)
            )
        if delta.privacy_strategies_surfaced:
            lines.append(
                " Hoepman strategies surfaced: "
                + ", ".join(delta.privacy_strategies_surfaced)
            )
        lines.append("")
        lines.append(
            " Toggle guidance in the extension: "
            "VibeCodeGuide › Enable Privacy & Security Guidance"
        )
        lines.append(
            " CLI: vibecodeguide scan --no-guidance  |  "
            "vibecodeguide demo <file>"
        )
        lines.append("")
        return "\n".join(lines)
