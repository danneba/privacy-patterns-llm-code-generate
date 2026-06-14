"""Map OWASP Benchmark for Python categories to VibeCodeGuide security rule slugs."""

from __future__ import annotations

OWASP_CATEGORY_RULES: dict[str, frozenset[str]] = {
    "sqli": frozenset({"sql_query_construction"}),
    "cmdi": frozenset({
        "subprocess_shell_true",
        "os_shell_execution",
        "subprocess_shell_command_injection",
    }),
    "codeinj": frozenset({"eval_exec_usage"}),
    "hash": frozenset({"weak_hash_algorithm"}),
    "weakrand": frozenset({"insecure_random"}),
    "deserialization": frozenset({"unsafe_deserialization", "unsafe_yaml_load"}),
}

SUPPORTED_OWASP_CATEGORIES = frozenset(OWASP_CATEGORY_RULES.keys())


def rule_ids_for_category(category: str) -> frozenset[str]:
    return OWASP_CATEGORY_RULES.get(category.strip().lower(), frozenset())
