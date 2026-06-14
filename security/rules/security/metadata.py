from dataclasses import dataclass

from security.models.finding import Confidence, Finding


@dataclass(frozen=True)
class SecurityMetadata:
    confidence: Confidence
    risk_score: int
    cwe: str
    owasp: str
    impact: str


_METADATA_BY_RULE: dict[str, SecurityMetadata] = {
    "eval_exec_usage": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=95,
        cwe="CWE-95",
        owasp="A03:2021 Injection",
        impact="User-controlled code execution can compromise the host process.",
    ),
    "hardcoded_secret": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=85,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        impact="Committed credentials can be reused by attackers and are difficult to rotate safely.",
    ),
    "insecure_random": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=55,
        cwe="CWE-338",
        owasp="A02:2021 Cryptographic Failures",
        impact="Predictable randomness can weaken tokens, session IDs, or security decisions.",
    ),
    "subprocess_shell_true": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="Shell execution can allow command injection when arguments include user-controlled data.",
    ),
    "subprocess_shell_command_injection": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="User-controlled data in subprocess arguments can allow command injection.",
    ),
    "shell_wrapper_call": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="Helper functions that wrap os.system/popen can execute attacker-controlled shell commands.",
    ),
    "server_side_template_injection": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=90,
        cwe="CWE-1336",
        owasp="A03:2021 Injection",
        impact="Dynamic template strings can allow server-side template injection and code execution.",
    ),
    "unsafe_deserialization": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=90,
        cwe="CWE-502",
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Unsafe deserialization can instantiate attacker-controlled objects or execute code.",
    ),
    "assert_used_for_validation": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=50,
        cwe="CWE-617",
        owasp="A04:2021 Insecure Design",
        impact="Validation can disappear when Python runs with optimizations enabled.",
    ),
    "weak_hash_algorithm": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=78,
        cwe="CWE-327",
        owasp="A02:2021 Cryptographic Failures",
        impact="Broken hash algorithms make integrity checks and password storage easier to attack.",
    ),
    "os_shell_execution": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-78",
        owasp="A03:2021 Injection",
        impact="Direct shell execution can run attacker-controlled commands.",
    ),
    "unsafe_yaml_load": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=82,
        cwe="CWE-502",
        owasp="A08:2021 Software and Data Integrity Failures",
        impact="Unsafe YAML loading can construct arbitrary Python objects from untrusted data.",
    ),
    "tls_verification_disabled": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=80,
        cwe="CWE-295",
        owasp="A02:2021 Cryptographic Failures",
        impact="Disabled certificate validation exposes HTTPS traffic to interception.",
    ),
    "debug_mode_enabled": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=60,
        cwe="CWE-489",
        owasp="A05:2021 Security Misconfiguration",
        impact="Debug mode can expose stack traces, internals, or interactive debugging surfaces.",
    ),
    "sql_query_construction": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=86,
        cwe="CWE-89",
        owasp="A03:2021 Injection",
        impact="Interpolated SQL can allow attackers to read or modify database records.",
    ),
    "path_traversal": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=80,
        cwe="CWE-22",
        owasp="A01:2021 Broken Access Control",
        impact="User-influenced file paths can expose arbitrary files on the server.",
    ),
    "server_side_request_forgery": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=82,
        cwe="CWE-918",
        owasp="A10:2021 Server-Side Request Forgery",
        impact="Attacker-controlled URLs can reach internal services or cloud metadata endpoints.",
    ),
    "xml_external_entity": SecurityMetadata(
        confidence=Confidence.HIGH,
        risk_score=88,
        cwe="CWE-611",
        owasp="A05:2021 Security Misconfiguration",
        impact="External entity resolution in XML parsers can leak files or enable SSRF.",
    ),
    "cleartext_credential_handling": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=75,
        cwe="CWE-256",
        owasp="A02:2021 Cryptographic Failures",
        impact="Storing or handling raw credentials from user input exposes account data.",
    ),
    "verbose_error_disclosure": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=55,
        cwe="CWE-209",
        owasp="A05:2021 Security Misconfiguration",
        impact="Detailed error output can reveal stack traces, paths, or internal state.",
    ),
    "unsafe_file_write": SecurityMetadata(
        confidence=Confidence.MEDIUM,
        risk_score=82,
        cwe="CWE-73",
        owasp="A03:2021 Injection",
        impact="Writing user-controlled content to disk can create executable code or overwrite sensitive files.",
    ),
}


def enrich_security_finding(finding: Finding) -> Finding:
    metadata = _METADATA_BY_RULE.get(finding.rule_id)
    if not metadata:
        return finding
    finding.confidence = metadata.confidence
    finding.risk_score = metadata.risk_score
    finding.cwe = metadata.cwe
    finding.owasp = metadata.owasp
    finding.impact = metadata.impact
    return finding
