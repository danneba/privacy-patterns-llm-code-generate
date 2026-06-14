from __future__ import annotations

import json
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REALVULN_HF_DATASET = "Kolega-Dev/RealVuln"
REALVULN_HF_BASE = f"https://huggingface.co/datasets/{REALVULN_HF_DATASET}/resolve/main"
DEFAULT_REALVULN_ROOT = Path(__file__).resolve().parent.parent / "data" / "RealVuln"
FINDINGS_JSONL = "findings.jsonl"
REPOS_JSONL = "repos.jsonl"

# Hugging Face labels still reference these repos, but upstream GitHub URLs are gone.
KNOWN_UNAVAILABLE_REPO_IDS = frozenset({
    "realvuln-python-app",
    "vulnerable-api",
    "vulnerable-python-apps",
})


@dataclass(frozen=True)
class RealVulnRepo:
    repo_id: str
    repo_url: str
    commit_sha: str
    language: str
    framework: str


@dataclass(frozen=True)
class RealVulnFinding:
    repo_id: str
    finding_id: str
    is_vulnerable: bool
    vulnerability_class: str
    primary_cwe: str
    acceptable_cwes: frozenset[str]
    file: str
    start_line: int
    end_line: int
    severity: str
    expected_category: str
    description: str


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": "VibeCodeGuide/0.1"})
    with urllib.request.urlopen(request, timeout=120) as response:
        dest.write_bytes(response.read())


def ensure_realvuln_labels(root: Path = DEFAULT_REALVULN_ROOT) -> Path:
    labels_dir = root / "labels"
    findings_path = labels_dir / FINDINGS_JSONL
    repos_path = labels_dir / REPOS_JSONL
    if not findings_path.is_file() or not repos_path.is_file():
        _download(f"{REALVULN_HF_BASE}/{FINDINGS_JSONL}", findings_path)
        _download(f"{REALVULN_HF_BASE}/{REPOS_JSONL}", repos_path)
    return labels_dir


def _parse_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def load_realvuln_repos(root: Path = DEFAULT_REALVULN_ROOT) -> list[RealVulnRepo]:
    labels_dir = ensure_realvuln_labels(root)
    return [
        RealVulnRepo(
            repo_id=row["repo_id"],
            repo_url=row["repo_url"],
            commit_sha=row["commit_sha"],
            language=row.get("language", "python"),
            framework=row.get("framework", ""),
        )
        for row in _parse_jsonl(labels_dir / REPOS_JSONL)
    ]


def load_realvuln_findings(root: Path = DEFAULT_REALVULN_ROOT) -> list[RealVulnFinding]:
    labels_dir = ensure_realvuln_labels(root)
    findings: list[RealVulnFinding] = []
    for row in _parse_jsonl(labels_dir / FINDINGS_JSONL):
        acceptable = row.get("acceptable_cwes") or [row.get("primary_cwe", "")]
        findings.append(
            RealVulnFinding(
                repo_id=row["repo_id"],
                finding_id=row["finding_id"],
                is_vulnerable=bool(row["is_vulnerable"]),
                vulnerability_class=row.get("vulnerability_class", ""),
                primary_cwe=row.get("primary_cwe", ""),
                acceptable_cwes=frozenset(str(c).upper() for c in acceptable if c),
                file=row["file"].replace("\\", "/"),
                start_line=int(row["start_line"]),
                end_line=int(row.get("end_line") or row["start_line"]),
                severity=row.get("severity", ""),
                expected_category=row.get("expected_category", ""),
                description=row.get("description", ""),
            )
        )
    return findings


def repo_dir(root: Path, repo_id: str) -> Path:
    return root / "repos" / repo_id


def is_repo_ready(root: Path, repo: RealVulnRepo) -> bool:
    path = repo_dir(root, repo.repo_id)
    if not path.is_dir():
        return False
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() == repo.commit_sha
    except subprocess.CalledProcessError:
        return False
