"""Map RealVuln expected_category values to VibeCodeGuide security rules.

Mirrors benchmarks/owasp_map.py: headline RealVuln metrics score only categories
we can detect with Python static analysis. XSS (HTML/templates) and auth (missing
access control) are out of scope for this rule set.
"""

from __future__ import annotations

REALVULN_CATEGORY_RULES: dict[str, frozenset[str]] = {
    "injection": frozenset({
        "eval_exec_usage",
        "sql_query_construction",
        "subprocess_shell_true",
        "subprocess_shell_command_injection",
        "os_shell_execution",
        "shell_wrapper_call",
        "unsafe_deserialization",
        "unsafe_yaml_load",
        "server_side_template_injection",
        "path_traversal",
        "unsafe_file_write",
        "server_side_request_forgery",
        "xml_external_entity",
    }),
    "data_exposure": frozenset({
        "hardcoded_secret",
        "debug_mode_enabled",
        "weak_hash_algorithm",
        "insecure_random",
        "tls_verification_disabled",
        "cleartext_credential_handling",
        "verbose_error_disclosure",
    }),
    "session_config": frozenset({
        "debug_mode_enabled",
        "insecure_random",
    }),
    "other": frozenset({
        "eval_exec_usage",
        "path_traversal",
        "server_side_request_forgery",
        "hardcoded_secret",
    }),
}

SUPPORTED_REALVULN_CATEGORIES = frozenset(REALVULN_CATEGORY_RULES.keys()) - frozenset({
    "session_config",  # mostly cookie flags / CSRF — not modeled yet
    "other",  # mixed CWEs; keep for category breakdown only
})

SCORED_REALVULN_CATEGORIES = frozenset({"injection", "data_exposure"})


def rule_ids_for_category(category: str) -> frozenset[str]:
    return REALVULN_CATEGORY_RULES.get(category.strip().lower(), frozenset())
