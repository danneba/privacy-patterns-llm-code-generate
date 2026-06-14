from benchmarks.realvuln.loader import RealVulnFinding
from benchmarks.realvuln.matcher import ScannerHit, match_finding_to_gt


def _gt(**kwargs) -> RealVulnFinding:
    defaults = {
        "repo_id": "test-repo",
        "finding_id": "test-001",
        "is_vulnerable": True,
        "vulnerability_class": "code_injection",
        "primary_cwe": "CWE-95",
        "acceptable_cwes": frozenset({"CWE-95", "CWE-94"}),
        "file": "app.py",
        "start_line": 120,
        "end_line": 120,
        "severity": "critical",
        "expected_category": "injection",
        "description": "",
    }
    defaults.update(kwargs)
    return RealVulnFinding(**defaults)


def test_match_finding_to_gt_by_file_cwe_line():
    gt = _gt()
    hit = ScannerHit(
        repo_id="test-repo",
        file="app.py",
        line=118,
        cwe="CWE-95",
        rule_id="eval_exec_usage",
    )
    assert match_finding_to_gt(hit, [gt]) is gt


def test_match_prefers_vulnerable_over_fp_trap():
    vuln = _gt(finding_id="vuln", is_vulnerable=True, start_line=50)
    trap = _gt(finding_id="trap", is_vulnerable=False, start_line=52)
    hit = ScannerHit(
        repo_id="test-repo",
        file="app.py",
        line=51,
        cwe="CWE-89",
        rule_id="sql_query_construction",
    )
    trap = _gt(
        finding_id="trap",
        is_vulnerable=False,
        start_line=52,
        primary_cwe="CWE-89",
        acceptable_cwes=frozenset({"CWE-89"}),
    )
    vuln = _gt(
        finding_id="vuln",
        is_vulnerable=True,
        start_line=50,
        primary_cwe="CWE-89",
        acceptable_cwes=frozenset({"CWE-89"}),
    )
    assert match_finding_to_gt(hit, [trap, vuln]) is vuln


def test_no_match_outside_line_tolerance():
    gt = _gt(start_line=120)
    hit = ScannerHit(
        repo_id="test-repo",
        file="app.py",
        line=100,
        cwe="CWE-95",
        rule_id="eval_exec_usage",
    )
    assert match_finding_to_gt(hit, [gt]) is None
