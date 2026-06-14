from __future__ import annotations

from dataclasses import dataclass

from benchmarks.realvuln.loader import RealVulnFinding

LINE_TOLERANCE = 10


@dataclass(frozen=True)
class ScannerHit:
    repo_id: str
    file: str
    line: int
    cwe: str | None
    rule_id: str


def normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def cwe_matches(scanner_cwe: str | None, acceptable: frozenset[str]) -> bool:
    if not scanner_cwe or not acceptable:
        return False
    return scanner_cwe.upper() in acceptable


def line_matches(scanner_line: int | None, gt: RealVulnFinding) -> bool:
    if scanner_line is None:
        return True
    low = gt.start_line - LINE_TOLERANCE
    high = max(gt.end_line, gt.start_line) + LINE_TOLERANCE
    return low <= scanner_line <= high


def file_matches(scanner_file: str, gt_file: str) -> bool:
    return normalize_path(scanner_file) == normalize_path(gt_file)


def match_finding_to_gt(
    hit: ScannerHit,
    candidates: list[RealVulnFinding],
) -> RealVulnFinding | None:
    matches = [
        gt
        for gt in candidates
        if gt.repo_id == hit.repo_id
        and file_matches(hit.file, gt.file)
        and cwe_matches(hit.cwe, gt.acceptable_cwes)
        and line_matches(hit.line, gt)
    ]
    if not matches:
        return None
    vulnerable = [gt for gt in matches if gt.is_vulnerable]
    return vulnerable[0] if vulnerable else matches[0]
