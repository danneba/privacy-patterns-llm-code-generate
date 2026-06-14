# Benchmark reports

Structured evaluation outputs are written locally under `benchmarks/reports/` (gitignored). Regenerate them after rule changes; they are not committed to the repository.

## Headline results (iteration 7)

| Benchmark | Scope | F1 | Precision | Recall | Label |
|-----------|-------|-----|-----------|--------|-------|
| OWASP Benchmark for Python | 620 in-scope tests | **98.3%** | 96.6% | 100% | `owasp-iteration-2` |
| RealVuln | 396 in-scope findings | **56.4%** | 74.5% | 45.4% | `realvuln-iteration-7` |

RealVuln scores `injection` and `data_exposure` only (332 of 728 findings out-of-scope). **56.4% F1 is a development-benchmark result** — RealVuln informed rule design and final scoring on the same corpus; no repository holdout was performed.

Human-readable iteration history: `docs/internal/benchmark-iterations.md` (gitignored).

## Current report files

| File | Contents |
|------|----------|
| `benchmarks/reports/owasp-latest.json` | OWASP Benchmark for Python — schema v1 metrics and failures |
| `benchmarks/reports/realvuln-latest.json` | RealVuln — real-world Python repos (iteration 7) |

## Regenerate OWASP report

```bash
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset owasp \
  --format json \
  --iteration-label owasp-iteration-2 \
  --output benchmarks/reports/owasp-latest.json
```

Optional: clone the OWASP dataset first with `--clone-owasp`.

## Regenerate RealVuln report

Labels download from Hugging Face on first run. Clone vulnerable repos manually into `benchmarks/data/RealVuln/repos/<repo_id>/` (see [Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark)).

```bash
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset realvuln \
  --format json \
  --iteration-label realvuln-iteration-7 \
  --output benchmarks/reports/realvuln-latest.json
```

## Quick metrics

```bash
python3 -c "
import json
for path in ['benchmarks/reports/owasp-latest.json', 'benchmarks/reports/realvuln-latest.json']:
    d = json.load(open(path))
    for r in d['runs']:
        m = r['metrics']
        print(f\"{path} [{r['dataset']}]: F1={m['f1']:.2%} P={m['precision']:.2%} R={m['recall']:.2%}\")
"
```

## Schema

- `benchmarks/report.schema.json` — JSON envelope (committed)
- `benchmarks/report_document.py` — report builder

## Datasets (local, gitignored)

| Path | Source |
|------|--------|
| `benchmarks/data/BenchmarkPython/` | [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) |
| `benchmarks/data/RealVuln/labels/` | [RealVuln on Hugging Face](https://huggingface.co/datasets/Kolega-Dev/RealVuln) |
| `benchmarks/data/RealVuln/repos/` | Manually cloned application repositories |
