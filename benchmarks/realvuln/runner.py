from __future__ import annotations

import warnings
from pathlib import Path

from benchmarks.metrics import ConfusionCounts, merge_counts
from benchmarks.realvuln.loader import (
    DEFAULT_REALVULN_ROOT,
    KNOWN_UNAVAILABLE_REPO_IDS,
    REALVULN_HF_DATASET,
    RealVulnFinding,
    is_repo_ready,
    load_realvuln_findings,
    load_realvuln_repos,
    repo_dir,
)
from benchmarks.realvuln.matcher import ScannerHit, match_finding_to_gt, normalize_path
from benchmarks.realvuln.scorable_rules import REALVULN_SCORABLE_RULES
from benchmarks.realvuln_map import SCORED_REALVULN_CATEGORIES
from benchmarks.runner import BenchmarkReport, CategoryMetrics, RealVulnFindingEvaluation
from security.core.scanner import Scanner
from security.models.finding import Category, Finding
from security.rules.security.ast_helpers import discover_shell_wrappers
from security.rules.security.vg014_shell_wrapper import set_repo_shell_wrappers
from security.utils.file_utils import collect_python_files


def _relative_file(repo_root: Path, absolute_path: str) -> str:
    try:
        return normalize_path(str(Path(absolute_path).resolve().relative_to(repo_root.resolve())))
    except ValueError:
        return normalize_path(absolute_path)


def _security_hits(
    repo_id: str,
    repo_root: Path,
    findings: list[Finding],
) -> list[ScannerHit]:
    hits: list[ScannerHit] = []
    for finding in findings:
        if finding.category != Category.SECURITY:
            continue
        if finding.rule_id not in REALVULN_SCORABLE_RULES:
            continue
        hits.append(
            ScannerHit(
                repo_id=repo_id,
                file=_relative_file(repo_root, finding.file),
                line=finding.line or 0,
                cwe=finding.cwe,
                rule_id=finding.rule_id,
            )
        )
    return hits


def _load_repo_sources(repo_path: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for file_path in collect_python_files(str(repo_path)):
        try:
            sources[file_path] = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return sources


def _scan_realvuln_repo(repo_path: Path, scanner: Scanner) -> list[Finding]:
    sources = _load_repo_sources(repo_path)
    wrappers = discover_shell_wrappers(sources)
    set_repo_shell_wrappers(wrappers)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            result = scanner.scan(str(repo_path))
    finally:
        set_repo_shell_wrappers(frozenset())
    return result.findings


def _match_hits_to_ground_truth(
    hits: list[ScannerHit],
    ground_truth: list[RealVulnFinding],
) -> tuple[dict[str, RealVulnFinding], list[ScannerHit]]:
    unmatched_gt = list(ground_truth)
    matched: dict[str, RealVulnFinding] = {}
    unmatched_hits: list[ScannerHit] = []

    for hit in hits:
        gt = match_finding_to_gt(hit, unmatched_gt)
        if gt is None:
            unmatched_hits.append(hit)
            continue
        matched[hit_key(hit)] = gt
        unmatched_gt.remove(gt)

    return matched, unmatched_hits


def hit_key(hit: ScannerHit) -> str:
    return f"{hit.repo_id}:{hit.file}:{hit.line}:{hit.rule_id}:{hit.cwe}"


def score_realvuln_matches(
    ground_truth: list[RealVulnFinding],
    matched: dict[str, RealVulnFinding],
    unmatched_hits: list[ScannerHit],
) -> ConfusionCounts:
    matched_gt_ids = {gt.finding_id for gt in matched.values()}
    tp = sum(1 for gt in ground_truth if gt.is_vulnerable and gt.finding_id in matched_gt_ids)
    fn = sum(1 for gt in ground_truth if gt.is_vulnerable and gt.finding_id not in matched_gt_ids)
    fp_on_traps = sum(
        1 for gt in ground_truth if not gt.is_vulnerable and gt.finding_id in matched_gt_ids
    )
    fp_unmatched = len(unmatched_hits)
    return ConfusionCounts(
        true_positives=tp,
        false_negatives=fn,
        false_positives=fp_on_traps + fp_unmatched,
    )


def run_realvuln_benchmark(
    root: Path = DEFAULT_REALVULN_ROOT,
    *,
    repo_ids: list[str] | None = None,
) -> BenchmarkReport:
    repos = load_realvuln_repos(root)
    if repo_ids:
        wanted = set(repo_ids)
        repos = [repo for repo in repos if repo.repo_id in wanted]

    all_gt = load_realvuln_findings(root)
    if repo_ids:
        wanted = set(repo_ids)
        all_gt = [finding for finding in all_gt if finding.repo_id in wanted]

    scanner = Scanner(enable_guidance=False, include_auxiliary_analyzers=False)
    all_hits: list[ScannerHit] = []
    ready_repos: list[str] = []
    skipped_repos: list[str] = []

    for repo in repos:
        if not is_repo_ready(root, repo):
            if repo.repo_id in KNOWN_UNAVAILABLE_REPO_IDS:
                skipped_repos.append(f"{repo.repo_id} (unavailable upstream)")
            else:
                skipped_repos.append(f"{repo.repo_id} (not present under {repo_dir(root, repo.repo_id)})")
            continue
        ready_repos.append(repo.repo_id)
        repo_path = repo_dir(root, repo.repo_id)
        findings = _scan_realvuln_repo(repo_path, scanner)
        all_hits.extend(_security_hits(repo.repo_id, repo_path, findings))

    gt_for_ready = [finding for finding in all_gt if finding.repo_id in ready_repos]
    out_of_scope = [
        finding for finding in gt_for_ready
        if (finding.expected_category or "other") not in SCORED_REALVULN_CATEGORIES
    ]
    scored_gt = [
        finding for finding in gt_for_ready
        if (finding.expected_category or "other") in SCORED_REALVULN_CATEGORIES
    ]
    matched, unmatched_hits = _match_hits_to_ground_truth(all_hits, gt_for_ready)
    counts = score_realvuln_matches(scored_gt, matched, unmatched_hits)

    hit_by_gt: dict[str, ScannerHit] = {}
    for hit in all_hits:
        gt = matched.get(hit_key(hit))
        if gt is not None:
            hit_by_gt[gt.finding_id] = hit

    evaluations: list[RealVulnFindingEvaluation] = []
    by_category: dict[str, ConfusionCounts] = {}
    category_counts: dict[str, int] = {}

    for gt in scored_gt:
        hit = hit_by_gt.get(gt.finding_id)
        is_matched = hit is not None
        if gt.is_vulnerable:
            passed = is_matched
            row_counts = ConfusionCounts(
                true_positives=1 if is_matched else 0,
                false_negatives=0 if is_matched else 1,
                false_positives=0,
            )
        else:
            passed = not is_matched
            row_counts = ConfusionCounts(
                false_positives=1 if is_matched else 0,
            )
        category = gt.expected_category or "other"
        by_category[category] = merge_counts(by_category.get(category, ConfusionCounts()), row_counts)
        category_counts[category] = category_counts.get(category, 0) + 1
        evaluations.append(
            RealVulnFindingEvaluation(
                finding_id=gt.finding_id,
                repo_id=gt.repo_id,
                file=gt.file,
                start_line=gt.start_line,
                is_vulnerable=gt.is_vulnerable,
                primary_cwe=gt.primary_cwe,
                expected_category=category,
                matched=is_matched,
                matched_rule=hit.rule_id if hit else None,
                scanner_line=hit.line if hit else None,
                passed=passed,
            )
        )

    category_metrics = [
        CategoryMetrics(
            category=category,
            test_count=category_counts[category],
            counts=by_category[category],
        )
        for category in sorted(by_category)
    ]

    notes = [
        "RealVuln — real-world Python vulnerability benchmark (Hugging Face).",
        f"Source: https://huggingface.co/datasets/{REALVULN_HF_DATASET}",
        "Matching: repo-relative file path + CWE in acceptable_cwes + line ±10.",
        "Unmatched scanner alerts count as false positives.",
        "Scored rules only (assert/CWE-617 excluded — not in RealVuln ground truth).",
        f"Scored categories only: {', '.join(sorted(SCORED_REALVULN_CATEGORIES))} "
        f"({len(out_of_scope)} findings out of scope: xss, auth, session_config, other).",
        "Python-only static analysis; non-Python ground truth (e.g. HTML XSS) may score as FN.",
        f"Repos evaluated: {len(ready_repos)} / {len(repos)}.",
        f"Ground-truth findings in evaluated repos: {len(gt_for_ready)} "
        f"({len(scored_gt)} in-scope for headline metrics).",
        f"Scanner alerts: {len(all_hits)} ({len(unmatched_hits)} unmatched).",
    ]
    if skipped_repos:
        notes.append(f"Skipped repos (not cloned): {', '.join(skipped_repos[:5])}")
        if len(skipped_repos) > 5:
            notes.append(f"… and {len(skipped_repos) - 5} more.")

    return BenchmarkReport(
        dataset="realvuln",
        scope="security",
        sample_count=len(scored_gt),
        counts=counts,
        realvuln_findings=evaluations,
        owasp_by_category=category_metrics,
        out_of_scope_count=len(out_of_scope),
        realvuln_unmatched_alerts=len(unmatched_hits),
        realvuln_repos_ready=len(ready_repos),
        realvuln_repos_total=len(repos),
        notes=notes,
    )
