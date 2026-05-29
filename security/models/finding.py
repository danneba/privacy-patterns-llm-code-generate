from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Category(str, Enum):
    SECURITY = "SECURITY"
    PRIVACY = "PRIVACY"
    CODE_SMELL = "CODE_SMELL"
    PERFORMANCE = "PERFORMANCE"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_gte(a: "Severity", b: "Severity") -> bool:
    return _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b]


@dataclass
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    file: str
    line: Optional[int]
    category: Category = Category.SECURITY
    col: Optional[int] = None
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    confidence: Optional[Confidence] = None
    risk_score: Optional[int] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    impact: Optional[str] = None
    privacy_strategy: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "suggestion": self.suggestion,
            "snippet": self.snippet,
            "confidence": self.confidence.value if self.confidence else None,
            "risk_score": self.risk_score,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "impact": self.impact,
            "privacy_strategy": self.privacy_strategy,
        }


@dataclass
class ParseError:
    file: str
    message: str

    def to_dict(self) -> dict:
        return {"file": self.file, "message": self.message}


@dataclass
class ScanResult:
    scanned_files: int = 0
    findings: List[Finding] = field(default_factory=list)
    parse_errors: List[ParseError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.parse_errors) == 0

    @property
    def error(self) -> Optional[str]:
        return self.parse_errors[0].message if self.parse_errors else None

    def summary(self) -> dict:
        by_severity = {s.value: 0 for s in Severity}
        by_category = {c.value: 0 for c in Category}
        for f in self.findings:
            by_severity[f.severity.value] += 1
            by_category[f.category.value] += 1
        return {
            "by_severity": by_severity,
            "by_category": by_category,
            "risk": self.risk_summary(),
        }

    def risk_summary(self) -> dict:
        security_findings = [
            f for f in self.findings if f.category == Category.SECURITY and f.risk_score is not None
        ]
        privacy_findings = [
            f for f in self.findings if f.category == Category.PRIVACY and f.risk_score is not None
        ]
        summary = {
            "security_score": 100,
            "privacy_score": 100,
            "max_risk_score": 0,
            "average_risk_score": 0,
            "high_confidence_count": 0,
        }
        if security_findings:
            security_scores = [f.risk_score for f in security_findings if f.risk_score is not None]
            max_security = max(security_scores)
            summary["security_score"] = max(0, 100 - max_security)
            summary["max_risk_score"] = max(summary["max_risk_score"], max_security)
            summary["average_risk_score"] = round(
                sum(security_scores) / len(security_scores), 1
            )
            summary["high_confidence_count"] += sum(
                1 for f in security_findings if f.confidence == Confidence.HIGH
            )
        if privacy_findings:
            privacy_scores = [f.risk_score for f in privacy_findings if f.risk_score is not None]
            max_privacy = max(privacy_scores)
            summary["privacy_score"] = max(0, 100 - max_privacy)
            summary["max_risk_score"] = max(summary["max_risk_score"], max_privacy)
            privacy_average = round(sum(privacy_scores) / len(privacy_scores), 1)
            if security_findings:
                summary["average_risk_score"] = round(
                    (summary["average_risk_score"] + privacy_average) / 2, 1
                )
            else:
                summary["average_risk_score"] = privacy_average
            summary["high_confidence_count"] += sum(
                1 for f in privacy_findings if f.confidence == Confidence.HIGH
            )
        return summary

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "findings": [f.to_dict() for f in self.findings],
            "parse_errors": [e.to_dict() for e in self.parse_errors],
            "summary": self.summary(),
        }
