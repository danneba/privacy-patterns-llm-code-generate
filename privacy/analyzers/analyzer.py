import ast
from typing import List

from privacy.rules.base import PrivacyRule
from privacy.rules.metadata import enrich_privacy_finding
from privacy.rules.pg001_pii_logging import PiiInLogsRule
from privacy.rules.pg002_plaintext_storage import PlaintextPiiStorageRule
from privacy.rules.pg003_pii_third_party import PiiToThirdPartyRule
from privacy.rules.pg004_raw_id_analytics import RawIdInAnalyticsRule
from privacy.rules.pg005_pii_without_consent import PiiWithoutConsentRule
from privacy.rules.pg006_marketing_without_opt_out import MarketingWithoutOptOutRule
from privacy.rules.pg007_sensitive_access_without_auth import SensitiveAccessWithoutAuthRule
from privacy.rules.pg008_sensitive_change_without_audit import SensitiveChangeWithoutAuditRule
from security.models.finding import Finding

_DEFAULT_RULES: List[PrivacyRule] = [
    PiiInLogsRule(),
    PlaintextPiiStorageRule(),
    PiiToThirdPartyRule(),
    RawIdInAnalyticsRule(),
    PiiWithoutConsentRule(),
    MarketingWithoutOptOutRule(),
    SensitiveAccessWithoutAuthRule(),
    SensitiveChangeWithoutAuditRule(),
]


class PrivacyAnalyzer:
    def __init__(self, rules: List[PrivacyRule] | None = None) -> None:
        self.rules = rules if rules is not None else _DEFAULT_RULES

    def analyze(self, tree: ast.AST, file_path: str, source_lines: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            for finding in rule.check(tree, file_path, source_lines):
                if finding.privacy_strategy is None:
                    finding.privacy_strategy = rule.privacy_strategy
                findings.append(enrich_privacy_finding(finding))
        return findings
