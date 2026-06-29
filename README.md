# VibeCodeGuide: Security and Privacy Analyzer for AI-Generated Code

> Privacy Engineering 2026 — Paris Lodron University of Salzburg  
> **Authors:** Haylemicheal Mekonnen, Daniel Wassie

VibeCodeGuide helps teams review **vibe-coded** Python before it ships. It statically analyzes source for **security vulnerabilities** and **privacy risks**—unsafe execution, secrets, weak crypto, insecure APIs, sensitive data handling, and related issues common in AI-generated code.

---

## Table of Contents

- [Problem Definition](#problem-definition)
- [Objectives](#objectives)
- [System Architecture](#system-architecture)
- [Current Stage](#current-stage)
- [Installation](#installation)
- [Usage](#usage)
- [Implemented Rules](#implemented-rules)
- [Example Output](#example-output)
- [Project Structure](#project-structure)
- [Running Tests](#running-tests)
- [Benchmark Evaluation](#benchmark-evaluation)
- [VS Code Extension](#vs-code-extension)
- [Team](#team)

---

## Problem Definition

AI-assisted tools make it easy to generate code quickly, often with little manual review. That speed comes with recurring **security** and **privacy** problems:

- **Security:** Unsafe input handling, `eval`/`exec`, shell injection, weak cryptography, disabled TLS verification, and insecure deserialization.
- **Privacy:** Hardcoded credentials and API keys, logging or exposing sensitive fields, and patterns that leak personal or authentication data.

Without targeted analysis, these issues can reach production unnoticed.

---

## Objectives

- Detect security vulnerabilities in Python source code
- Flag privacy-related risks (secrets, sensitive data exposure, unsafe handling)
- Surface findings in the CLI, JSON reports, REST API, and VS Code Problems panel
- Provide actionable remediation guidance (CWE, OWASP, suggestions)

---

## System Architecture

VibeCodeGuide’s **Security and Privacy analyzer** is a static analysis pipeline:

```
┌─────────────────────────────────────────┐
│             Input Layer                 │
│  CLI · VS Code extension · REST API     │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│   Security & Privacy Analysis Layer     │
│  • Parse Python into AST                │
│  • Run security & privacy rule packs    │
│  • Score risk and attach metadata       │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│            Output Layer                 │
│  • Text / JSON reports                  │
│  • Editor diagnostics & summaries       │
└─────────────────────────────────────────┘
```

The analyzer lives under `security/` in this repository (Python package). The VS Code extension and FastAPI service are thin clients that send editor or file content to that engine.

---

## Current Stage

VibeCodeGuide is a **working research prototype** with CLI, REST API, VS Code extension, and benchmark evaluation on OWASP and RealVuln datasets.

**Available now:**

- Static **security** rules (VG001–VG021) for Python
- **Privacy** rule pack (PG001–PG008) mapped to Hoepman privacy design strategies
- `PRIVACY` finding category in CLI/JSON reports with strategy metadata
- CLI (`vibecodeguide scan`), REST API (`security.api`), and VS Code extension
- Benchmark harness with structured JSON reports (schema v1)

**Evaluation results** (see [Benchmark Evaluation](#benchmark-evaluation) for methodology):

| Benchmark | Scope | F1 | Precision | Recall |
|-----------|-------|-----|-----------|--------|
| [OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython) | 620 in-scope tests | **98.3%** | 96.6% | 100% |
| [RealVuln](https://huggingface.co/datasets/Kolega-Dev/RealVuln) | 396 in-scope findings | **56.4%** | 74.5% | 45.4% |

RealVuln headline metrics cover `injection` and `data_exposure` categories only (same scoping principle as OWASP). XSS, authentication, and session-configuration findings are reported as out-of-scope.

**Interpretation:** RealVuln **56.4% F1** (iteration 7) is a **development-benchmark result** — RealVuln informed rule design (VG014–VG021) and final scoring on the same 23-repo corpus. It measures fit to RealVuln’s in-scope labels, not unbiased performance on unseen repositories. OWASP **98.3% F1** provides independent signal for the core rule set (VG001–VG013) on synthetic tests.

**Planned:**

- Additional rule families (authorization, template analysis)
- CI templates and policy gates

---

## Installation

```bash
pip install -e .
```

Requires Python 3.10+. Core analyzer has no required third-party dependencies. The API needs FastAPI (see [VS Code Extension](#vs-code-extension)).

---

## Usage

### Scan a file or directory

```bash
vibecodeguide scan ./project
vibecodeguide scan app/main.py
```

The `security` console script is an alias for the same entry point.

### Output formats

```bash
# Human-readable terminal output (default)
vibecodeguide scan ./project --format text

# Structured JSON (for CI pipelines, dashboards, etc.)
vibecodeguide scan ./project --format json
```

### Filter by severity

```bash
vibecodeguide scan ./project --severity high
vibecodeguide scan ./project --severity medium
```

### Save to a file

```bash
vibecodeguide scan ./project --output report.json --format json
vibecodeguide scan ./project --output report.txt
```

### Privacy & Security Guidance (baseline vs guided)

**Baseline** (`--no-guidance`): security rules only (VG001–VG021).

**Guided** (default): security + privacy guidance module (PG001–PG008, Hoepman strategies).

```bash
# Baseline only
vibecodeguide scan samples/privacy_showcase_vulnerable.py --no-guidance

# Full analysis (default)
vibecodeguide scan samples/privacy_showcase_vulnerable.py

# Side-by-side demo on the same file
vibecodeguide demo samples/privacy_showcase_vulnerable.py
vibecodeguide demo --format json --output demo-report.json
```

API header: `X-Enable-Guidance: true|false` on `POST /analyze`.

Side-by-side comparison: `POST /analyze/demo`.

### Other flags

```bash
--no-guidance     Baseline mode: disable privacy & security guidance module
--no-snippet      Exclude source code snippets from findings
--quiet           Suppress informational messages when using --output
```

### Exit codes

| Code | Meaning                                               |
| ---- | ----------------------------------------------------- |
| `0`  | Scan completed — no findings above selected threshold |
| `1`  | Scan completed — findings detected                    |
| `2`  | Operational error or invalid usage                    |

---

## Implemented Rules

| Rule ID | Title                                     | Severity | Focus              |
| ------- | ----------------------------------------- | -------- | ------------------ |
| VG001   | Use of `eval()`                           | CRITICAL | Security           |
| VG002   | Use of `exec()`                           | CRITICAL | Security           |
| VG003   | Hardcoded Secret                          | HIGH     | Security / Privacy |
| VG004   | Insecure Randomness                       | MEDIUM   | Security           |
| VG005   | Dangerous Subprocess Usage (`shell=True`) | HIGH     | Security           |
| VG006   | Pickle Deserialization                    | HIGH     | Security           |
| VG007   | Assert Used for Security Check            | MEDIUM   | Security           |
| VG008   | Weak Hash Algorithm                       | HIGH     | Security           |
| VG009   | OS Shell Execution                        | HIGH     | Security           |
| VG010   | Unsafe YAML Deserialization               | HIGH     | Security           |
| VG011   | TLS Verification Disabled                 | HIGH     | Security           |
| VG012   | Debug Mode Enabled                        | MEDIUM   | Security           |
| VG013   | Dynamic SQL Query Construction            | HIGH     | Security           |
| VG014   | Shell Wrapper Call                        | HIGH     | Security           |
| VG015   | Server-Side Template Injection            | HIGH     | Security           |
| VG016   | Path Traversal                            | HIGH     | Security           |
| VG017   | Server-Side Request Forgery               | HIGH     | Security           |
| VG018   | XML External Entity (XXE)                 | HIGH     | Security           |
| VG019   | Cleartext Credential Handling             | HIGH     | Security           |
| VG020   | Verbose Error Disclosure                  | MEDIUM   | Security           |
| VG021   | Unsafe File Write                         | HIGH     | Security           |

### Privacy rules

| Rule ID | Title                                        | Severity | Strategy    |
| ------- | -------------------------------------------- | -------- | ----------- |
| PG001   | PII in Logs or Print Output                  | HIGH     | MINIMIZE    |
| PG002   | Plaintext Sensitive Data Storage             | HIGH     | HIDE        |
| PG003   | PII Sent to Third-Party Service              | HIGH     | SEPARATE    |
| PG004   | Identifiable Data in Analytics Event         | MEDIUM   | AGGREGATE   |
| PG005   | PII Processing Without Consent Handling      | MEDIUM   | INFORM      |
| PG006   | Outbound Communication Without Opt-Out Check | MEDIUM   | CONTROL     |
| PG007   | Sensitive Data Access Without Auth Guard     | HIGH     | ENFORCE     |
| PG008   | Sensitive Data Change Without Audit Trail    | MEDIUM   | DEMONSTRATE |

Findings may include confidence, risk score, CWE, OWASP category, privacy strategy, impact, and remediation text.

### Suppressing intentional findings

```python
# vibecodeguide: ignore sql_query_construction
cursor.execute(query)
```

Legacy markers `# vibeguard: ignore` and `# sppd: ignore` are still recognized.

---

## Example Output

```
[HIGH] VG001 Use of eval()
  File: app/main.py:14
  Code: result = eval(user_input)
  Message: Use of eval() is insecure and may allow arbitrary code execution.

[HIGH] VG003 Hardcoded Secret
  File: app/config.py:3
  Code: password = "hunter2"
  Message: Variable 'password' appears to contain a hardcoded secret.

Scanned 4 file(s). Found 3 issue(s): 2 high, 1 medium, 0 low.
```

---

## Project Structure

```
privacy-patterns-llm-code-generate/
├── security/              Security, smell, and performance analyzer core
│   ├── api/               FastAPI service for editor/HTTP clients
│   ├── cli/               vibecodeguide CLI
│   ├── core/              Scanner orchestration
│   ├── rules/security/    Rule implementations VG001–VG021
│   ├── models/            Finding and scan result types
│   └── reporters/         Text and JSON formatters
├── privacy/               Privacy rule pack (PG001–PG008, Hoepman strategies)
│   ├── analyzers/         PrivacyAnalyzer
│   └── rules/             Privacy rule implementations
├── vscode-extension/      VibeCodeGuide VS Code / Cursor extension
├── samples/               Vulnerable examples for demos and tests
├── benchmarks/            Labeled samples for evaluation
└── tests/
```

---

## Running Tests

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install pytest
pip install -e .

PYTHONPATH=. pytest tests/ -v
```

---

## Benchmark Evaluation

VibeCodeGuide is evaluated on three datasets:

| Dataset | Description | Scoring scope |
|---------|-------------|---------------|
| **Internal** | Labeled samples in `benchmarks/dataset.py` | Security and privacy rules |
| **OWASP** | [OWASP Benchmark for Python v0.1](https://github.com/OWASP-Benchmark/BenchmarkPython) — 1,230 synthetic tests | 620 tests in mapped categories (`sqli`, `cmdi`, `codeinj`, `hash`, `weakrand`, `deserialization`) |
| **RealVuln** | [RealVuln](https://huggingface.co/datasets/Kolega-Dev/RealVuln) — 26 real vulnerable Python applications | 396 findings in `injection` and `data_exposure` (728 total; remaining categories out-of-scope) |

Reports use JSON schema v1 (`benchmarks/report.schema.json`) and are saved by default to `benchmarks/reports/<dataset>-latest.json`. Full workflow: **`benchmarks/REPORTS.md`**.

### Run benchmarks

```bash
source .venv/bin/activate

# OWASP only (writes benchmarks/reports/owasp-latest.json)
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset owasp \
  --clone-owasp

# RealVuln (repos must be cloned under benchmarks/data/RealVuln/repos/)
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset realvuln \
  --iteration-label realvuln-iteration-7

# All datasets (writes benchmarks/reports/all-latest.json)
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset all

# Human-readable terminal output instead of JSON
PYTHONPATH=. python3 -m security.cli.main benchmark \
  --dataset internal \
  --format text
```

Exit code `1` after a benchmark run indicates some tests or findings failed — that is expected when metrics are below 100%.

### Methodology notes

- **OWASP:** Categories without rule mappings (XSS, XXE, path traversal, etc.) are excluded from scored metrics — 610 of 1,230 tests are out-of-scope.
- **RealVuln:** Categories without rule mappings (XSS, auth, session configuration, other) are excluded — 332 of 728 findings are out-of-scope. Repos are cloned manually per [Real-Vuln-Benchmark](https://github.com/kolega-ai/Real-Vuln-Benchmark). Headline metrics use label **`realvuln-iteration-7`** (21 rules; rule families fixed after iteration 6).
- **Matching:** File path + CWE in acceptable set + line tolerance ±10. Unmatched scanner alerts count as false positives.
- **RealVuln interpretation:** Same corpus used for iterative rule development and final evaluation; no repository holdout was performed. Reported F1 is in-corpus fit, not an estimate for unseen apps.

Detailed iteration history: `docs/internal/benchmark-iterations.md` (local, gitignored).

---

## VS Code Extension

The `vscode-extension/` folder provides **VibeCodeGuide** in the editor: analyze the active Python file or selection against the analyzer API.

### Start the API

```bash
pip install -r security/api/requirements.txt
pip install -e .
uvicorn security.api.main:app --reload --port 8000
```

### Develop the extension

```bash
cd vscode-extension
npm install
npm run compile
```

Open `vscode-extension/` in VS Code, press **F5**, then on a Python file use:

- **VibeCodeGuide: Open Secure Code Chat** — sidebar chat to generate Python with OWASP, CWE, and privacy rules
- **VibeCodeGuide: Analyze File**
- **VibeCodeGuide: Analyze Selection**
- **VibeCodeGuide: Check API Health**
- **VibeCodeGuide: Set OpenAI API Key**

The **Secure Code Chat** panel uses OpenAI to generate Python code guided by OWASP Top 10, CWE rules (VG001–VG021), and privacy patterns. Generated code is automatically scanned by the analyzer; use **Fix Issues** to regenerate a compliant version.

Findings appear in **Problems** (security and privacy, with Hoepman strategy labels on privacy issues); full reports in the **VibeCodeGuide** output channel include privacy score and per-category counts.

**Guidance comparison demo:** run **VibeCodeGuide: Compare Guidance OFF vs ON** on a Python file. This opens a side-by-side **Before / After** panel with:

- Summary banner (Guidance OFF vs ON counts and +N privacy findings)
- Helper text explaining each mode
- **New with Guidance** badges on findings that only appear when guidance is enabled
- Problems panel entries tagged `VibeCodeGuide · New with Guidance` for the same items

**Code change impact demo** (automatic — no separate snapshot commands):

1. Open `samples/privacy_showcase_vulnerable.py` and run **VibeCodeGuide: Analyze File**
2. Comment out or fix a line (e.g. `# print(f"Login for {email}")`) and **save** (Cmd+S)
3. Run **Analyze File** again — the extension compares with your previous run on this file

The **Analysis changes** panel and output show **resolved**, **introduced**, and **unchanged** findings; Problems tags new issues as `New since last analysis`.

Settings: **VibeCodeGuide**

| Setting | Description |
| ------- | ----------- |
| `vibecodeguide.enablePrivacySecurityGuidance` | **Enable Privacy & Security Guidance** (default: on) |
| `vibecodeguide.securityApiUrl` | Analyzer API base URL |
| `vibecodeguide.minSeverity` | Minimum reported severity |
| `vibecodeguide.requestTimeoutMs` | HTTP timeout |
| `vibecodeguide.openaiModel` | OpenAI model for secure code generation |
| `vibecodeguide.openaiBaseUrl` | OpenAI API base URL |
| `vibecodeguide.autoAnalyzeGeneratedCode` | Auto-scan generated code after chat |

Store your OpenAI API key via **VibeCodeGuide: Set OpenAI API Key** (saved in VS Code Secret Storage).

### Install permanently

```bash
cd vscode-extension
npm run package
```

Install `vscode-extension/vibecodeguide-0.1.0.vsix` via **Extensions → Install from VSIX…** or:

```bash
code --install-extension vscode-extension/vibecodeguide-0.1.0.vsix
```

Keep the API running on port 8000 while using the extension. Use **VibeCodeGuide: Check API Health** to verify connectivity.

---

## Team

| Name                  | Institution                         |
| --------------------- | ----------------------------------- |
| Haylemicheal Mekonnen | Paris Lodron University of Salzburg |
| Daniel Wassie         | Paris Lodron University of Salzburg |
