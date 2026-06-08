import ast

from privacy.rules.pg001_pii_logging import PiiInLogsRule
from privacy.rules.pg002_plaintext_storage import PlaintextPiiStorageRule
from privacy.rules.pg003_pii_third_party import PiiToThirdPartyRule
from privacy.rules.pg004_raw_id_analytics import RawIdInAnalyticsRule
from privacy.rules.pg005_pii_without_consent import PiiWithoutConsentRule
from privacy.rules.pg006_marketing_without_opt_out import MarketingWithoutOptOutRule
from privacy.rules.pg007_sensitive_access_without_auth import SensitiveAccessWithoutAuthRule
from privacy.rules.pg008_sensitive_change_without_audit import SensitiveChangeWithoutAuditRule
from security.core.scanner import Scanner
from security.models.finding import Category


def _parse(code: str):
    return ast.parse(code), code.splitlines()


class TestPG001PiiInLogs:
    def test_detects_print_with_email(self):
        tree, lines = _parse('print(f"user email: {email}")')
        findings = PiiInLogsRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "pii_in_logs"
        assert findings[0].privacy_strategy == "MINIMIZE"

    def test_no_flag_unrelated_print(self):
        tree, lines = _parse('print("hello world")')
        assert PiiInLogsRule().check(tree, "test.py", lines) == []


class TestPG002PlaintextStorage:
    def test_detects_plaintext_password(self):
        tree, lines = _parse('password = "secret123"')
        findings = PlaintextPiiStorageRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].rule_id == "plaintext_pii_storage"
        assert findings[0].privacy_strategy == "HIDE"


class TestPG003PiiThirdParty:
    def test_detects_post_with_email(self):
        code = 'import requests\nrequests.post("https://api.example.com", json={"email": email})'
        tree, lines = _parse(code)
        findings = PiiToThirdPartyRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "SEPARATE"


class TestPG004RawIdAnalytics:
    def test_detects_track_with_email(self):
        code = "analytics.track('signup', {'email': email})"
        tree, lines = _parse(code)
        findings = RawIdInAnalyticsRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "AGGREGATE"


class TestPG005PiiWithoutConsent:
    def test_detects_function_without_consent(self):
        code = "def register(email, phone):\n    save(email, phone)"
        tree, lines = _parse(code)
        findings = PiiWithoutConsentRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "INFORM"

    def test_no_flag_when_consent_present(self):
        code = "def register(email, consent):\n    if consent:\n        save(email)"
        tree, lines = _parse(code)
        assert PiiWithoutConsentRule().check(tree, "test.py", lines) == []


class TestPG006MarketingWithoutOptOut:
    def test_detects_send_without_opt_out(self):
        code = "def notify(email):\n    mailer.send_email(email)"
        tree, lines = _parse(code)
        findings = MarketingWithoutOptOutRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "CONTROL"


class TestPG007SensitiveAccessWithoutAuth:
    def test_detects_password_read_without_auth(self):
        code = "def show(user):\n    return user.password"
        tree, lines = _parse(code)
        findings = SensitiveAccessWithoutAuthRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "ENFORCE"

    def test_no_flag_with_auth_guard(self):
        code = "def show(user):\n    assert user.is_authenticated\n    return user.password"
        tree, lines = _parse(code)
        assert SensitiveAccessWithoutAuthRule().check(tree, "test.py", lines) == []


class TestPG008SensitiveChangeWithoutAudit:
    def test_detects_password_update_without_audit(self):
        code = "def reset(user, new_password):\n    user.password = new_password"
        tree, lines = _parse(code)
        findings = SensitiveChangeWithoutAuditRule().check(tree, "test.py", lines)
        assert len(findings) == 1
        assert findings[0].privacy_strategy == "DEMONSTRATE"

    def test_no_flag_with_audit_log(self):
        code = (
            "def reset(user, new_password):\n"
            "    user.password = new_password\n"
            "    audit_log.record('password_reset', user.id)"
        )
        tree, lines = _parse(code)
        assert SensitiveChangeWithoutAuditRule().check(tree, "test.py", lines) == []


class TestPrivacyScannerIntegration:
    def test_privacy_showcase_triggers_privacy_findings(self):
        result = Scanner().scan("samples/privacy_showcase_vulnerable.py")
        privacy_findings = [f for f in result.findings if f.category == Category.PRIVACY]
        rule_ids = {finding.rule_id for finding in privacy_findings}
        assert "pii_in_logs" in rule_ids
        assert "plaintext_pii_storage" in rule_ids
        assert len(privacy_findings) >= 6

    def test_summary_includes_privacy_score(self):
        result = Scanner().scan_source('print(email)\npassword = "x"\n')
        risk = result.summary()["risk"]
        assert "privacy_score" in risk
        assert risk["privacy_score"] < 100
