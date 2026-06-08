from security.core.impact import run_code_change_impact


SHOWCASE = "samples/privacy_showcase_vulnerable.py"


class TestCodeChangeImpact:
    def test_commenting_pii_log_line_resolves_finding(self):
        from pathlib import Path

        before = Path(SHOWCASE).read_text(encoding="utf-8")
        lines = before.splitlines()
        target = next(i for i, line in enumerate(lines) if 'print(f"Login for {email}")' in line)
        after_lines = lines.copy()
        after_lines[target] = after_lines[target].replace("print", "# print", 1)
        if not after_lines[target].lstrip().startswith("#"):
            indent = len(after_lines[target]) - len(after_lines[target].lstrip())
            after_lines[target] = after_lines[target][:indent] + "# " + after_lines[target].lstrip()
        after = "\n".join(after_lines) + "\n"

        impact = run_code_change_impact(before, after, filename=SHOWCASE, sample_label=SHOWCASE)
        assert impact.before_privacy_count > impact.after_privacy_count
        assert impact.resolved_privacy_count >= 1
        assert any(finding.rule_id == "pii_in_logs" for finding in impact.resolved_findings)
        assert impact.changed_lines
        assert impact.changed_lines[0].line_number == target + 1

    def test_masked_logging_reduces_pii_findings(self):
        before = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def show(email):\n"
            "    print(f'Login for {email}')\n"
            "    logger.info('User profile loaded: %s', email)\n"
        )
        after = (
            "import logging\n"
            "logger = logging.getLogger(__name__)\n"
            "def show(email):\n"
            "    logger.info('User profile loaded')\n"
        )
        impact = run_code_change_impact(before, after, filename="demo.py")
        assert impact.resolved_findings
        assert impact.resolved_privacy_count >= 1
