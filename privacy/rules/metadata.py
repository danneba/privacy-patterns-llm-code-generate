from dataclasses import dataclass

from security.models.finding import Confidence, Finding


@dataclass(frozen=True)
class PrivacyMetadata:
    confidence: Confidence
    risk_score: int
    privacy_strategy: str
    impact: str


_METADATA_BY_RULE: dict[str, PrivacyMetadata] = {
    "pii_in_logs": PrivacyMetadata(
        confidence=Confidence.HIGH,
        risk_score=82,
        privacy_strategy="MINIMIZE",
        impact="Logged personal data can be retained, copied, and exposed beyond its original purpose.",
    ),
    "plaintext_pii_storage": PrivacyMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=88,
        privacy_strategy="HIDE",
        impact="Plaintext storage makes credential and identifier theft easier after a breach.",
    ),
    "pii_to_third_party": PrivacyMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=80,
        privacy_strategy="SEPARATE",
        impact="Sharing identity data with third parties expands the trust boundary and breach surface.",
    ),
    "raw_id_in_analytics": PrivacyMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=65,
        privacy_strategy="AGGREGATE",
        impact="Raw identifiers in analytics enable tracking and re-identification across events.",
    ),
    "pii_without_consent": PrivacyMetadata(
        confidence=Confidence.LOW,
        risk_score=60,
        privacy_strategy="INFORM",
        impact="Processing personal data without consent handling undermines lawful and transparent use.",
    ),
    "marketing_without_opt_out": PrivacyMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=58,
        privacy_strategy="CONTROL",
        impact="Contacting users without opt-out checks removes meaningful control over communications.",
    ),
    "sensitive_access_without_auth": PrivacyMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=85,
        privacy_strategy="ENFORCE",
        impact="Missing access enforcement can expose sensitive personal data to unauthorized callers.",
    ),
    "sensitive_change_without_audit": PrivacyMetadata(
        confidence=Confidence.LOW,
        risk_score=55,
        privacy_strategy="DEMONSTRATE",
        impact="Changes to sensitive data without audit trails reduce accountability and incident response.",
    ),
}


def enrich_privacy_finding(finding: Finding) -> Finding:
    metadata = _METADATA_BY_RULE.get(finding.rule_id)
    if not metadata:
        return finding
    finding.confidence = metadata.confidence
    finding.risk_score = metadata.risk_score
    finding.privacy_strategy = metadata.privacy_strategy
    finding.impact = metadata.impact
    return finding
