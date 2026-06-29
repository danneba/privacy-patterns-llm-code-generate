"""Structured benchmark report envelope (JSON schema v1)."""

from __future__ import annotations

from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from benchmarks.owasp_map import OWASP_CATEGORY_RULES, SUPPORTED_OWASP_CATEGORIES
from benchmarks.realvuln.loader import REALVULN_HF_DATASET
from benchmarks.realvuln.scorable_rules import REALVULN_SCORABLE_RULES
from benchmarks.realvuln_map import REALVULN_CATEGORY_RULES, SCORED_REALVULN_CATEGORIES
from benchmarks.runner import BenchmarkReport, OWASP_REPO_URL

REPORT_SCHEMA_VERSION = "1.0"
TOOL_NAME = "VibeCodeGuide"
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def default_report_path(dataset: str) -> Path:
    """Default JSON report path for a benchmark --dataset value."""
    return DEFAULT_REPORTS_DIR / f"{dataset}-latest.json"


def _tool_version() -> str:
    try:
        return version("vibecodeguide")
    except PackageNotFoundError:
        return "0.1.0"


def _owasp_methodology(report: BenchmarkReport) -> dict[str, Any]:
    return {
        "benchmark_name": "OWASP Benchmark for Python",
        "benchmark_version": "0.1",
        "benchmark_repository": OWASP_REPO_URL,
        "scoring_unit": "test_case",
        "in_scope_categories": sorted(SUPPORTED_OWASP_CATEGORIES),
        "category_rule_mapping": {
            category: sorted(rules)
            for category, rules in sorted(OWASP_CATEGORY_RULES.items())
        },
        "out_of_scope_note": (
            "Categories without VibeCodeGuide rule mappings (e.g. XSS, XXE, path traversal) "
            "are excluded from scored metrics."
        ),
        "analyzer_mode": "security baseline (privacy/smell/performance disabled)",
        "definitions": {
            "true_positive": "Labeled vulnerable test with at least one mapped rule detected.",
            "false_negative": "Labeled vulnerable test with no mapped rule detected.",
            "false_positive": "Labeled safe test with at least one mapped rule detected.",
            "precision": "TP / (TP + FP)",
            "recall": "TP / (TP + FN)",
            "f1": "2 * precision * recall / (precision + recall)",
        },
    }


def _realvuln_methodology(report: BenchmarkReport) -> dict[str, Any]:
    return {
        "benchmark_name": "RealVuln",
        "benchmark_repository": f"https://huggingface.co/datasets/{REALVULN_HF_DATASET}",
        "scoring_unit": "ground_truth_finding",
        "matching": {
            "file_path": "repo-relative path must match",
            "cwe": "scanner CWE must be in acceptable_cwes",
            "line_tolerance": 10,
        },
        "false_positive_sources": [
            "Match to is_vulnerable=false ground truth entry",
            "Scanner alert with no matching ground truth entry",
        ],
        "analyzer_mode": "security baseline (privacy/smell/performance disabled)",
        "in_scope_rules": sorted(REALVULN_SCORABLE_RULES),
        "in_scope_categories": sorted(SCORED_REALVULN_CATEGORIES),
        "category_rule_mapping": {
            category: sorted(rules)
            for category, rules in sorted(REALVULN_CATEGORY_RULES.items())
            if category in SCORED_REALVULN_CATEGORIES
        },
        "out_of_scope_note": (
            "assert_used_for_validation (CWE-617) is excluded — RealVuln has no ground-truth "
            "labels for assert-based validation checks. Categories xss, auth, session_config, "
            "and other are excluded from headline metrics (same approach as OWASP category scoping)."
        ),
        "definitions": {
            "true_positive": "Vulnerable GT finding matched by a scanner alert.",
            "false_negative": "Vulnerable GT finding with no matching scanner alert.",
            "false_positive": "Safe GT finding matched, or unmatched scanner alert.",
            "precision": "TP / (TP + FP)",
            "recall": "TP / (TP + FN)",
            "f1": "2 * precision * recall / (precision + recall)",
        },
    }


def _run_summary(report: BenchmarkReport) -> dict[str, Any]:
    if report.dataset == "realvuln":
        passed = sum(1 for item in report.realvuln_findings if item.passed)
        failed = len(report.realvuln_findings) - passed
        return {
            "findings_total": report.sample_count,
            "findings_passed": passed,
            "findings_failed": failed,
            "pass_rate": round(passed / report.sample_count, 4) if report.sample_count else 1.0,
            "findings_total_in_benchmark": report.sample_count + report.out_of_scope_count,
            "findings_out_of_scope": report.out_of_scope_count,
            "repos_ready": report.realvuln_repos_ready,
            "repos_total": report.realvuln_repos_total,
            "unmatched_scanner_alerts": report.realvuln_unmatched_alerts,
        }
    if report.owasp_tests:
        passed = sum(1 for test in report.owasp_tests if test.passed)
        failed = len(report.owasp_tests) - passed
        return {
            "tests_total_in_benchmark": report.sample_count + report.out_of_scope_count,
            "tests_in_scope": report.sample_count,
            "tests_out_of_scope": report.out_of_scope_count,
            "tests_passed": passed,
            "tests_failed": failed,
            "pass_rate": round(passed / report.sample_count, 4) if report.sample_count else 1.0,
        }
    passed = sum(1 for sample in report.samples if sample.passed)
    return {
        "tests_in_scope": report.sample_count,
        "tests_passed": passed,
        "tests_failed": report.sample_count - passed,
        "pass_rate": round(passed / report.sample_count, 4) if report.sample_count else 1.0,
    }


def report_to_run_dict(report: BenchmarkReport) -> dict[str, Any]:
    """Single dataset run block for schema v1."""
    payload: dict[str, Any] = {
        "run_id": f"{report.dataset}-{report.scope}",
        "dataset": report.dataset,
        "scope": report.scope,
        "summary": _run_summary(report),
        "metrics": report.counts.to_dict(),
        "notes": report.notes,
    }

    if report.dataset == "owasp":
        payload["methodology"] = _owasp_methodology(report)
        payload["categories"] = [row.to_dict() for row in report.owasp_by_category]
        failures = [test.to_dict() for test in report.owasp_tests if not test.passed]
        payload["failures"] = {
            "count": len(failures),
            "items": failures,
        }
    elif report.dataset == "realvuln":
        payload["methodology"] = _realvuln_methodology(report)
        payload["categories"] = [row.to_dict() for row in report.owasp_by_category]
        failures = [item.to_dict() for item in report.realvuln_findings if not item.passed]
        payload["failures"] = {
            "count": len(failures),
            "items": failures[:100],
        }
    else:
        payload["samples"] = [sample.to_dict() for sample in report.samples]

    return payload


def build_benchmark_document(
    reports: list[BenchmarkReport],
    *,
    iteration_label: str | None = None,
    command: str | None = None,
) -> dict[str, Any]:
    """Build the top-level JSON document written by `vibecodeguide benchmark --format json`."""
    return {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "tool": {
            "name": TOOL_NAME,
            "version": _tool_version(),
            "command": command or "vibecodeguide benchmark",
        },
        "iteration_label": iteration_label,
        "runs": [report_to_run_dict(report) for report in reports],
    }
