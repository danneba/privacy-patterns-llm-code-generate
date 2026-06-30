# VibeCodeGuide — Architecture Design

> Static security and privacy analyzer for AI-generated ("vibe-coded") Python.
> Privacy Engineering 2026 — Paris Lodron University of Salzburg.

This document describes the system architecture: the layered design, the core
analysis pipeline, the rule plugin model, and how each client (CLI, REST API,
VS Code extension) flows through the same engine.

For installation, usage, the rule catalog, and the REST API reference, see the
[project README](../README.md).

---

## 1. Design goals

| Goal | How the architecture supports it |
| ---- | -------------------------------- |
| **One engine, many clients** | CLI, REST API, and the editor extension all call the same `Scanner`. No detection logic is duplicated per client. |
| **Pluggable rules** | Every check is an independent rule class implementing a single `check()` method. Adding a rule does not touch the scanner. |
| **Zero required dependencies for the core** | The analyzer uses only the Python standard library (`ast`). FastAPI/uvicorn are needed *only* for the optional REST API. |
| **Separation of security and privacy** | Security (VG) and privacy (PG) rules live in distinct packages with their own analyzers, so privacy guidance can be toggled independently. |
| **Structured, reusable output** | All findings share one `Finding` dataclass that serializes to JSON, text, and editor diagnostics. |

---

## 2. Layered architecture

![VibeCodeGuide layered architecture: Input layer (CLI, REST API, VS Code/Cursor extension) feeding the Analysis layer (Scanner, Python AST, the Security/Privacy/Smell/Performance analyzers, and metadata enrichment), which produces the Output layer (text reporter, JSON reporter, editor diagnostics).](images/architecture-overview.png)

- **Input layer** — thin clients. The VS Code extension does not analyze code itself; it sends file/selection content to the REST API.
- **Analysis layer** — the `security/` Python package. This is the only place detection logic lives.
- **Output layer** — formatters that turn a `ScanResult` into text, JSON, or editor diagnostics.

---

## 3. Core analysis pipeline

The `Scanner` (`security/core/scanner.py`) is the orchestrator. Every scan — from
any client — follows the same steps:

![Core analysis pipeline: source code is collected into Python files, parsed to an AST (syntax errors become reported ParseErrors and the file is skipped), analyzers run, findings are enriched with CWE/OWASP/risk metadata, then filtered by minimum severity and by inline ignore comments, producing a ScanResult of findings, parse errors, and a summary.](images/analysis-pipeline.png)

### Analyzer execution order

`Scanner._run_all()` runs analyzers in a fixed order and concatenates their findings:

1. **`SecurityAnalyzer`** — always runs (VG001–VG021).
2. **`PrivacyAnalyzer`** — runs only when `enable_guidance=True` (the default). This is what `--no-guidance` / `X-Enable-Guidance: false` toggles.
3. **`SmellAnalyzer`** and **`PerformanceAnalyzer`** — auxiliary checks, run when `include_auxiliary_analyzers=True`.

This ordering is why "baseline vs. guided" comparison works: disabling guidance
simply skips the privacy analyzer, and the difference between the two runs is the
set of privacy findings (see the demo/impact flows below).

---

## 4. Rule plugin model

Each rule is a self-contained class. Security rules implement `SecurityRule`
(`security/rules/security/base.py`); privacy rules implement `PrivacyRule`. An
analyzer holds a list of rule instances and calls `check()` on each.

![Rule plugin model class diagram: abstract SecurityRule and PrivacyRule classes each define a check() method and are aggregated (many-to-one) by SecurityAnalyzer and PrivacyAnalyzer respectively. Both rule types emit the shared Finding dataclass, which carries rule_id, severity, category, optional CWE/OWASP/privacy_strategy fields, and a to_dict() serializer.](images/rule-plugin-model.png)

**Adding a new rule:**

1. Create `security/rules/security/vgNNN_<name>.py` with a class extending `SecurityRule` and implementing `check()`.
2. Register the instance in `_DEFAULT_RULES` in `security/analyzers/security/analyzer.py`.
3. Add CWE/OWASP/risk metadata so `enrich_security_finding()` can attach it.

No scanner or client code changes are required — this is the main extensibility point.

### The `Finding` contract

All rules emit the same `Finding` dataclass (`security/models/finding.py`). It is the
single data contract shared across the whole system, which is what lets one engine
feed three different output formats. Key fields: `rule_id`, `severity`, `category`
(`SECURITY` / `PRIVACY` / `CODE_SMELL` / `PERFORMANCE`), `cwe`, `owasp`,
`privacy_strategy` (Hoepman), `risk_score`, and `suggestion`.

---

## 5. Metadata enrichment

Raw rule output is minimal; analyzers pass each finding through an enrichment step
that attaches contextual metadata:

- **Security:** `enrich_security_finding()` adds CWE, OWASP category, confidence, and risk score.
- **Privacy:** `enrich_privacy_finding()` attaches the **Hoepman privacy design strategy** (MINIMIZE, HIDE, SEPARATE, AGGREGATE, INFORM, CONTROL, ENFORCE, DEMONSTRATE) and impact text.

This keeps rule classes focused on *detection*, while consistent reporting metadata
is applied in one place.

---

## 6. Suppression and filtering

After analyzers run, the scanner applies two post-processing filters:

1. **Severity filter** — drops findings below `min_severity` (CLI `--severity`, API `X-Min-Severity`).
2. **Inline suppression** — `Scanner._is_ignored()` checks the finding's line (and the line above) for an ignore marker:

```python
# vibecodeguide: ignore sql_query_construction
cursor.execute(query)
```

`ignore` with no rule id (or `ignore all`) suppresses every rule on that line.
Legacy markers `# vibeguard: ignore` and `# sppd: ignore` are also recognized.

---

## 7. Client flows

### 7.1 CLI

The CLI (`security/cli/main.py`) parses arguments, calls `Scanner.scan(path)`, and
formats the result with either the text or JSON reporter (`--format`), writing to
stdout or a file (`--output`). Entry points (`pyproject.toml`): `vibecodeguide` and
`security` both map to `security.cli.main:main`. Subcommands: `scan`, `demo`,
`benchmark`.

### 7.2 REST API

The FastAPI service (`security/api/main.py`) wraps `Scanner.scan_source()` and
returns Pydantic-validated JSON. Endpoints:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| `GET`  | `/health` | Liveness check |
| `POST` | `/analyze` | Analyze a snippet → findings |
| `POST` | `/analyze/demo` | Baseline vs. guided comparison |
| `POST` | `/analyze/impact` | Before/after change comparison |

### 7.3 VS Code / Cursor extension

![VS Code / Cursor extension flow: an editor command (Analyze File / Selection) sends an HTTP POST /analyze to the FastAPI service, which calls the Scanner and returns findings; the extension renders them in the Problems panel and the VibeCodeGuide output channel.](images/vscode-extension-flow.png)

The extension is a pure client: it serializes the active file or selection, calls
the API, and renders findings as VS Code diagnostics (with Hoepman strategy labels
on privacy issues). It never runs detection locally.

---

## 8. Comparison features (demo & impact)

Two higher-level flows reuse the scanner to show *change*, not just state:

- **Guidance demo** (`security/core/demo.py`, `POST /analyze/demo`) — runs the same
  code twice, once with `enable_guidance=False` and once with `True`, then reports
  the delta (the privacy findings that guidance adds).
- **Code-change impact** (`security/core/impact.py`, `POST /analyze/impact`) — scans
  a `before` and `after` version of a file and classifies findings as **resolved**,
  **introduced**, or **unchanged**.

Both are thin compositions over `Scanner`, requiring no new detection logic.

---

## 9. Evaluation harness

The `benchmarks/` package is a parallel subsystem that drives the scanner against
labeled datasets and computes precision/recall/F1.

![Evaluation harness flow: the internal, OWASP, and RealVuln datasets feed the benchmark runner, which runs the Scanner in baseline mode, matches findings against ground truth, computes metrics (TP/FP/FN → precision/recall/F1), and writes a schema-v1 JSON report to benchmarks/reports/<dataset>-latest.json.](images/evaluation-harness.png)

Reports conform to `benchmarks/report.schema.json`. See `benchmarks/REPORTS.md` for
the full workflow.

---

## 10. Module map

| Layer | Module | Responsibility |
| ----- | ------ | -------------- |
| Clients | `security/cli/main.py` | CLI argument parsing and dispatch |
| Clients | `security/api/main.py` | FastAPI service and request/response models |
| Clients | `vscode-extension/` | Editor integration (TypeScript) |
| Engine | `security/core/scanner.py` | Orchestration: parse → analyze → filter |
| Engine | `security/core/demo.py`, `impact.py` | Baseline-vs-guided and before/after comparisons |
| Engine | `security/analyzers/security/` | Security analyzer + VG rule registry |
| Engine | `privacy/analyzers/` | Privacy analyzer + PG rule registry |
| Engine | `security/analyzers/smells/`, `performance/` | Auxiliary analyzers |
| Rules | `security/rules/security/` | VG001–VG021 rule implementations + metadata |
| Rules | `privacy/rules/` | PG001–PG008 rule implementations + metadata |
| Model | `security/models/finding.py` | `Finding`, `ScanResult`, `Severity`, `Category` |
| Output | `security/reporters/` | Text, JSON, and demo formatters |
| Eval | `benchmarks/` | Datasets, runner, metrics, report schema |
