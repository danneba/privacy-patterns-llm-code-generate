from benchmarks.metrics import ConfusionCounts
from benchmarks.owasp_map import rule_ids_for_category
from benchmarks.runner import (
    check_owasp_benchmark,
    filter_internal_samples,
    load_owasp_expected,
    run_internal_benchmark,
)


def test_confusion_metrics():
    counts = ConfusionCounts(true_positives=8, false_positives=2, false_negatives=2)
    assert counts.precision == 0.8
    assert counts.recall == 0.8
    assert round(counts.f1, 2) == 0.8


def test_security_samples_include_baseline():
    samples = filter_internal_samples("security")
    ids = {sample.id for sample in samples}
    assert "S01" in ids
    assert "S10" in ids
    assert "P01" not in ids


def test_internal_security_benchmark_runs():
    report = run_internal_benchmark(scope="security")
    assert report.dataset == "internal"
    assert report.sample_count >= 7
    assert report.counts.true_positives > 0
    assert all(sample.sample_id for sample in report.samples)


def test_internal_privacy_benchmark_runs():
    report = run_internal_benchmark(scope="privacy")
    assert report.sample_count == 3
    assert all(sample.sample_id.startswith("P") for sample in report.samples)


def test_owasp_category_mapping():
    assert "sql_query_construction" in rule_ids_for_category("sqli")
    assert "eval_exec_usage" in rule_ids_for_category("codeinj")
    assert rule_ids_for_category("xss") == frozenset()


def test_load_owasp_expected(tmp_path):
    csv_path = tmp_path / "expectedresults-0.1.csv"
    csv_path.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n",
        encoding="utf-8",
    )
    cases = load_owasp_expected(csv_path)
    assert len(cases) == 2
    assert cases[0].test_name == "BenchmarkTest00001"
    assert cases[0].is_vulnerable is True


def test_check_owasp_benchmark_ready():
    status = check_owasp_benchmark()
    if status.is_ready:
        assert status.expected_case_count == 1230
        assert status.test_file_count >= 1200
    else:
        assert status.state in ("missing", "incomplete")
