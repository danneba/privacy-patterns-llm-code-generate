from security.core.demo import run_guidance_demo
from security.core.scanner import Scanner
from security.models.finding import Category
from security.reporters.demo import DemoReporter


SHOWCASE = "samples/privacy_showcase_vulnerable.py"


class TestGuidanceToggle:
    def test_guidance_off_excludes_privacy(self):
        code = 'print(email)\npassword = "secret"\n'
        baseline = Scanner(enable_guidance=False, include_auxiliary_analyzers=False).scan_source(code)
        guided = Scanner(enable_guidance=True, include_auxiliary_analyzers=False).scan_source(code)
        assert not any(f.category == Category.PRIVACY for f in baseline.findings)
        assert any(f.category == Category.PRIVACY for f in guided.findings)
        assert len(guided.findings) > len(baseline.findings)

    def test_demo_comparison_delta(self):
        from pathlib import Path

        code = Path(SHOWCASE).read_text(encoding="utf-8")
        comparison = run_guidance_demo(code, filename=SHOWCASE, sample_label=SHOWCASE)
        assert comparison.delta.baseline_finding_count >= 1
        assert comparison.delta.guided_privacy_count >= 6
        assert comparison.delta.additional_findings_count >= 5
        assert "MINIMIZE" in comparison.delta.privacy_strategies_surfaced

    def test_demo_reporter_renders_columns(self):
        from pathlib import Path

        code = Path(SHOWCASE).read_text(encoding="utf-8")
        comparison = run_guidance_demo(code, filename=SHOWCASE)
        text = DemoReporter().report(comparison)
        assert "BASELINE (guidance OFF)" in text
        assert "WITH GUIDANCE (ON)" in text
        assert "DELTA" in text
        assert "pii_in_logs" in text or "Guidance-only rules" in text
