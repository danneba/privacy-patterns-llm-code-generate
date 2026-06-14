"""Rules included in RealVuln benchmark scoring (mirrors OWASP category scoping).

RealVuln has no ground-truth labels for some rules we ship (e.g. assert / CWE-617).
Alerts from out-of-scope rules are excluded from matching so precision reflects
detection quality on labeled vulnerability classes, not code-style heuristics.
"""

from __future__ import annotations

REALVULN_SCORABLE_RULES = frozenset({
    "eval_exec_usage",
    "sql_query_construction",
    "subprocess_shell_true",
    "subprocess_shell_command_injection",
    "os_shell_execution",
    "shell_wrapper_call",
    "unsafe_deserialization",
    "unsafe_yaml_load",
    "weak_hash_algorithm",
    "insecure_random",
    "hardcoded_secret",
    "debug_mode_enabled",
    "tls_verification_disabled",
    "server_side_template_injection",
    "path_traversal",
    "server_side_request_forgery",
    "xml_external_entity",
    "cleartext_credential_handling",
    "verbose_error_disclosure",
    "unsafe_file_write",
})

REALVULN_OUT_OF_SCOPE_RULES = frozenset({
    "assert_used_for_validation",  # CWE-617 — not in RealVuln GT
})
