from __future__ import annotations

import csv
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Literal

from benchmarks.dataset import SAMPLES, Sample
from benchmarks.metrics import ConfusionCounts, merge_counts
from benchmarks.owasp_map import SUPPORTED_OWASP_CATEGORIES, rule_ids_for_category
from security.core.scanner import Scanner
from security.models.finding import Category, Finding

Scope = Literal["security", "privacy", "all"]
DatasetName = Literal["internal", "owasp", "realvuln", "both", "all"]

OWASP_REPO_URL = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
DEFAULT_OWASP_PATH = Path(__file__).resolve().parent / "data" / "BenchmarkPython"
OWASP_EXPECTED_CSV = "expectedresults-0.1.csv"
OWASP_TESTCODE_DIR = "testcode"


@dataclass(frozen=True)
class OwaspBenchmarkStatus:
    state: Literal["ready", "missing", "incomplete"]
    path: Path
    test_file_count: int = 0
    expected_case_count: int = 0
    detail: str = ""

    @property
    def is_ready(self) -> bool:
        return self.state == "ready"


@dataclass(frozen=True)
class OwaspExpectedCase:
    test_name: str
    category: str
    is_vulnerable: bool
    cwe: str


@dataclass
class SampleEvaluation:
    sample_id: str
    label: str
    expected: list[str]
    detected: list[str]
    missed: list[str]
    extra: list[str]
    forbidden_hits: list[str]
    parse_errors: list[str]
    passed: bool

    def to_dict(self) -> dict:
        return {
            "sample_id": self.sample_id,
            "label": self.label,
            "expected": self.expected,
            "detected": self.detected,
            "missed": self.missed,
            "extra": self.extra,
            "forbidden_hits": self.forbidden_hits,
            "parse_errors": self.parse_errors,
            "passed": self.passed,
        }


@dataclass
class OwaspTestEvaluation:
    test_name: str
    category: str
    cwe: str
    is_vulnerable: bool
    detected_rules: list[str]
    relevant_hits: list[str]
    parse_errors: list[str]
    passed: bool

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "category": self.category,
            "cwe": self.cwe,
            "is_vulnerable": self.is_vulnerable,
            "detected_rules": self.detected_rules,
            "relevant_hits": self.relevant_hits,
            "parse_errors": self.parse_errors,
            "passed": self.passed,
        }


@dataclass
class RealVulnFindingEvaluation:
    finding_id: str
    repo_id: str
    file: str
    start_line: int
    is_vulnerable: bool
    primary_cwe: str
    expected_category: str
    matched: bool
    matched_rule: str | None
    scanner_line: int | None
    passed: bool

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "repo_id": self.repo_id,
            "file": self.file,
            "start_line": self.start_line,
            "is_vulnerable": self.is_vulnerable,
            "primary_cwe": self.primary_cwe,
            "expected_category": self.expected_category,
            "matched": self.matched,
            "matched_rule": self.matched_rule,
            "scanner_line": self.scanner_line,
            "passed": self.passed,
        }


@dataclass
class CategoryMetrics:
    category: str
    test_count: int
    counts: ConfusionCounts

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "test_count": self.test_count,
            "metrics": self.counts.to_dict(),
        }


@dataclass
class BenchmarkReport:
    dataset: str
    scope: str
    sample_count: int
    counts: ConfusionCounts
    samples: list[SampleEvaluation] = field(default_factory=list)
    owasp_tests: list[OwaspTestEvaluation] = field(default_factory=list)
    owasp_by_category: list[CategoryMetrics] = field(default_factory=list)
    realvuln_findings: list[RealVulnFindingEvaluation] = field(default_factory=list)
    realvuln_unmatched_alerts: int = 0
    realvuln_repos_ready: int = 0
    realvuln_repos_total: int = 0
    out_of_scope_count: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        from benchmarks.report_document import report_to_run_dict

        return report_to_run_dict(self)


def filter_internal_samples(scope: Scope) -> list[Sample]:
    if scope == "security":
        return [sample for sample in SAMPLES if "security" in sample.tags or sample.id == "S10"]
    if scope == "privacy":
        return [sample for sample in SAMPLES if sample.id.startswith("P")]
    return list(SAMPLES)


def _scanner_for_scope(scope: Scope) -> Scanner:
    if scope == "security":
        return Scanner(enable_guidance=False, include_auxiliary_analyzers=False)
    if scope == "privacy":
        return Scanner(enable_guidance=True, include_auxiliary_analyzers=False)
    return Scanner(enable_guidance=True, include_auxiliary_analyzers=True)


def _findings_for_scope(findings: Iterable[Finding], scope: Scope) -> set[str]:
    if scope == "security":
        return {finding.rule_id for finding in findings if finding.category == Category.SECURITY}
    if scope == "privacy":
        return {finding.rule_id for finding in findings if finding.category == Category.PRIVACY}
    return {finding.rule_id for finding in findings}


def _evaluate_internal_sample(
    sample: Sample,
    scope: Scope,
    scanner: Scanner,
) -> tuple[SampleEvaluation, ConfusionCounts]:
    result = scanner.scan_source(sample.code, filename=f"{sample.id}.py")
    detected = _findings_for_scope(result.findings, scope)
    expected = set(sample.expected_rules)
    forbidden = set(sample.forbidden_rules)

    missed = sorted(expected - detected)
    extra = sorted(detected - expected)
    forbidden_hits = sorted(detected & forbidden)
    parse_errors = [error.message for error in result.parse_errors]

    counts = ConfusionCounts(
        true_positives=len(expected & detected),
        false_negatives=len(missed),
        false_positives=len(extra) + len(forbidden_hits),
    )
    passed = not missed and not forbidden_hits and not parse_errors

    evaluation = SampleEvaluation(
        sample_id=sample.id,
        label=sample.label,
        expected=sorted(expected),
        detected=sorted(detected),
        missed=missed,
        extra=extra,
        forbidden_hits=forbidden_hits,
        parse_errors=parse_errors,
        passed=passed,
    )
    return evaluation, counts


def run_internal_benchmark(scope: Scope = "security") -> BenchmarkReport:
    samples = filter_internal_samples(scope)
    scanner = _scanner_for_scope(scope)
    evaluations: list[SampleEvaluation] = []
    total = ConfusionCounts()

    for sample in samples:
        evaluation, counts = _evaluate_internal_sample(sample, scope, scanner)
        evaluations.append(evaluation)
        total = merge_counts(total, counts)

    notes = [
        "Internal VibeCodeGuide benchmark (benchmarks/dataset.py).",
        "Metrics are aggregated at rule level across labeled samples.",
    ]
    if scope == "security":
        notes.append("Security scope uses baseline mode (no privacy/smell/performance analyzers).")
    elif scope == "privacy":
        notes.append("Privacy scope counts PG rule hits only.")

    return BenchmarkReport(
        dataset="internal",
        scope=scope,
        sample_count=len(samples),
        counts=total,
        samples=evaluations,
        notes=notes,
    )


def clone_owasp_benchmark(dest: Path = DEFAULT_OWASP_PATH) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth", "1", OWASP_REPO_URL, str(dest)],
        check=True,
    )
    return dest


def check_owasp_benchmark(root: Path = DEFAULT_OWASP_PATH) -> OwaspBenchmarkStatus:
    if not root.exists():
        return OwaspBenchmarkStatus(
            state="missing",
            path=root,
            detail="Not cloned yet.",
        )

    csv_path = root / OWASP_EXPECTED_CSV
    testcode_dir = root / OWASP_TESTCODE_DIR
    missing: list[str] = []

    if not csv_path.is_file():
        missing.append(OWASP_EXPECTED_CSV)
    if not testcode_dir.is_dir():
        missing.append(f"{OWASP_TESTCODE_DIR}/")
    else:
        test_file_count = len(list(testcode_dir.glob("BenchmarkTest*.py")))
        if test_file_count == 0:
            missing.append(f"{OWASP_TESTCODE_DIR}/BenchmarkTest*.py")

    if missing:
        return OwaspBenchmarkStatus(
            state="incomplete",
            path=root,
            detail=f"Incomplete clone — missing: {', '.join(missing)}",
        )

    expected_case_count = len(load_owasp_expected(csv_path))
    test_file_count = len(list(testcode_dir.glob("BenchmarkTest*.py")))
    return OwaspBenchmarkStatus(
        state="ready",
        path=root,
        test_file_count=test_file_count,
        expected_case_count=expected_case_count,
        detail=(
            f"Ready — {expected_case_count} labeled tests, "
            f"{test_file_count} Python files"
        ),
    )


def ensure_owasp_benchmark(
    root: Path = DEFAULT_OWASP_PATH,
    *,
    force: bool = False,
) -> OwaspBenchmarkStatus:
    status = check_owasp_benchmark(root)
    if status.is_ready and not force:
        return status

    if root.exists():
        shutil.rmtree(root)

    clone_owasp_benchmark(root)
    return check_owasp_benchmark(root)


def format_owasp_status(status: OwaspBenchmarkStatus) -> str:
    label = {
        "ready": "OK",
        "missing": "NOT CLONED",
        "incomplete": "INCOMPLETE",
    }[status.state]
    return f"OWASP benchmark [{label}] {status.path} — {status.detail}"


def load_owasp_expected(csv_path: Path) -> list[OwaspExpectedCase]:
    cases: list[OwaspExpectedCase] = []
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            test_name = row[0].strip()
            category = row[1].strip().lower()
            is_vulnerable = row[2].strip().lower() == "true"
            cwe = row[3].strip()
            cases.append(
                OwaspExpectedCase(
                    test_name=test_name,
                    category=category,
                    is_vulnerable=is_vulnerable,
                    cwe=cwe,
                )
            )
    return cases


def _resolve_owasp_paths(root: Path) -> tuple[Path, Path]:
    status = check_owasp_benchmark(root)
    if not status.is_ready:
        raise FileNotFoundError(
            f"{format_owasp_status(status)}. "
            "Run: vibecodeguide benchmark --clone-owasp"
        )
    csv_path = root / OWASP_EXPECTED_CSV
    testcode_dir = root / OWASP_TESTCODE_DIR
    return csv_path, testcode_dir


def _evaluate_owasp_case(
    case: OwaspExpectedCase,
    test_path: Path,
    scanner: Scanner,
) -> tuple[OwaspTestEvaluation, ConfusionCounts]:
    category_rules = rule_ids_for_category(case.category)
    result = scanner.scan(str(test_path))
    security_rules = {
        finding.rule_id
        for finding in result.findings
        if finding.category == Category.SECURITY
    }
    relevant_hits = sorted(security_rules & set(category_rules))
    parse_errors = [error.message for error in result.parse_errors]

    if case.is_vulnerable:
        passed = bool(relevant_hits) and not parse_errors
        counts = ConfusionCounts(
            true_positives=1 if relevant_hits else 0,
            false_negatives=0 if relevant_hits else 1,
            false_positives=0,
        )
    else:
        passed = not relevant_hits and not parse_errors
        counts = ConfusionCounts(
            true_positives=0,
            false_negatives=0,
            false_positives=1 if relevant_hits else 0,
        )

    evaluation = OwaspTestEvaluation(
        test_name=case.test_name,
        category=case.category,
        cwe=case.cwe,
        is_vulnerable=case.is_vulnerable,
        detected_rules=sorted(security_rules),
        relevant_hits=relevant_hits,
        parse_errors=parse_errors,
        passed=passed,
    )
    return evaluation, counts


def run_owasp_benchmark(owasp_path: Path = DEFAULT_OWASP_PATH) -> BenchmarkReport:
    csv_path, testcode_dir = _resolve_owasp_paths(owasp_path)
    cases = load_owasp_expected(csv_path)
    scanner = Scanner(enable_guidance=False, include_auxiliary_analyzers=False)

    evaluations: list[OwaspTestEvaluation] = []
    total = ConfusionCounts()
    by_category: dict[str, ConfusionCounts] = {}
    category_counts: dict[str, int] = {}
    out_of_scope = 0

    for case in cases:
        if case.category not in SUPPORTED_OWASP_CATEGORIES:
            out_of_scope += 1
            continue

        test_path = testcode_dir / f"{case.test_name}.py"
        if not test_path.exists():
            raise FileNotFoundError(f"Missing OWASP test file: {test_path}")

        evaluation, counts = _evaluate_owasp_case(case, test_path, scanner)
        evaluations.append(evaluation)
        total = merge_counts(total, counts)
        by_category[case.category] = merge_counts(by_category.get(case.category, ConfusionCounts()), counts)
        category_counts[case.category] = category_counts.get(case.category, 0) + 1

    category_metrics = [
        CategoryMetrics(
            category=category,
            test_count=category_counts[category],
            counts=by_category[category],
        )
        for category in sorted(by_category)
    ]

    notes = [
        "External OWASP Benchmark for Python v0.1.",
        "Scores only categories mapped to VibeCodeGuide security rules "
        f"({', '.join(sorted(SUPPORTED_OWASP_CATEGORIES))}).",
        f"Skipped {out_of_scope} out-of-scope tests (xss, xxe, pathtraver, etc.).",
        f"Source: {OWASP_REPO_URL}",
    ]

    return BenchmarkReport(
        dataset="owasp",
        scope="security",
        sample_count=len(evaluations),
        counts=total,
        owasp_tests=evaluations,
        owasp_by_category=category_metrics,
        out_of_scope_count=out_of_scope,
        notes=notes,
    )


def run_benchmarks(
    dataset: DatasetName = "both",
    scope: Scope = "security",
    owasp_path: Path = DEFAULT_OWASP_PATH,
    *,
    ensure_owasp: bool = True,
    realvuln_path: Path | None = None,
    realvuln_repo_ids: list[str] | None = None,
) -> list[BenchmarkReport]:
    from benchmarks.realvuln.loader import DEFAULT_REALVULN_ROOT
    from benchmarks.realvuln.runner import run_realvuln_benchmark

    reports: list[BenchmarkReport] = []
    if dataset in ("internal", "both", "all"):
        reports.append(run_internal_benchmark(scope=scope))
    if dataset in ("owasp", "both", "all"):
        if scope == "privacy":
            raise ValueError(
                "OWASP Benchmark for Python has no privacy labels. "
                "Use --dataset internal --scope privacy for PG evaluation."
            )
        if ensure_owasp:
            ensure_owasp_benchmark(owasp_path)
        reports.append(run_owasp_benchmark(owasp_path=owasp_path))
    if dataset in ("realvuln", "all"):
        if scope == "privacy":
            raise ValueError(
                "RealVuln has no privacy labels. Use --scope security for RealVuln evaluation."
            )
        reports.append(
            run_realvuln_benchmark(
                root=realvuln_path or DEFAULT_REALVULN_ROOT,
                repo_ids=realvuln_repo_ids,
            )
        )
    return reports


def format_report_text(reports: list[BenchmarkReport]) -> str:
    lines: list[str] = ["VibeCodeGuide Benchmark Evaluation", "=" * 36, ""]

    for report in reports:
        lines.append(f"Dataset: {report.dataset}  |  scope: {report.scope}")
        lines.append(f"Samples: {report.sample_count}")
        if report.out_of_scope_count:
            lines.append(f"Out of scope (skipped): {report.out_of_scope_count}")
        metrics = report.counts
        lines.append(
            f"TP={metrics.true_positives}  FP={metrics.false_positives}  "
            f"FN={metrics.false_negatives}"
        )
        lines.append(
            f"Precision={metrics.precision:.2%}  "
            f"Recall={metrics.recall:.2%}  F1={metrics.f1:.2%}"
        )
        for note in report.notes:
            lines.append(f"  • {note}")
        lines.append("")

        if report.samples:
            lines.append("Per-sample (internal):")
            for sample in report.samples:
                status = "PASS" if sample.passed else "FAIL"
                lines.append(f"  [{status}] {sample.sample_id} — {sample.label}")
                if sample.missed:
                    lines.append(f"        missed: {', '.join(sample.missed)}")
                if sample.extra:
                    lines.append(f"        extra: {', '.join(sample.extra)}")
                if sample.forbidden_hits:
                    lines.append(f"        forbidden: {', '.join(sample.forbidden_hits)}")
            lines.append("")

        if report.owasp_by_category and report.dataset == "owasp":
            lines.append("OWASP by category:")
            for row in report.owasp_by_category:
                lines.append(
                    f"  {row.category:16} n={row.test_count:3}  "
                    f"P={row.counts.precision:.1%}  R={row.counts.recall:.1%}  "
                    f"F1={row.counts.f1:.1%}"
                )
            failures = [test for test in report.owasp_tests if not test.passed]
            if failures:
                lines.append("")
                lines.append(f"Failed OWASP tests (showing up to 10 of {len(failures)}):")
                for test in failures[:10]:
                    expected = "vulnerable" if test.is_vulnerable else "safe"
                    lines.append(
                        f"  {test.test_name} [{test.category}, {expected}] "
                        f"hits={test.relevant_hits or test.detected_rules[:3]}"
                    )
            lines.append("")

        if report.dataset == "realvuln":
            if report.realvuln_repos_total:
                lines.append(
                    f"Repos ready: {report.realvuln_repos_ready} / {report.realvuln_repos_total}"
                )
            if report.realvuln_unmatched_alerts:
                lines.append(f"Unmatched scanner alerts (FP): {report.realvuln_unmatched_alerts}")
            if report.owasp_by_category:
                lines.append("RealVuln by expected_category:")
                for row in report.owasp_by_category:
                    lines.append(
                        f"  {row.category:16} n={row.test_count:3}  "
                        f"P={row.counts.precision:.1%}  R={row.counts.recall:.1%}  "
                        f"F1={row.counts.f1:.1%}"
                    )
            failures = [item for item in report.realvuln_findings if not item.passed]
            if failures:
                lines.append("")
                lines.append(f"Failed RealVuln findings (showing up to 10 of {len(failures)}):")
                for item in failures[:10]:
                    expected = "vulnerable" if item.is_vulnerable else "safe"
                    lines.append(
                        f"  {item.finding_id} [{item.expected_category}, {expected}] "
                        f"rule={item.matched_rule}"
                    )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
