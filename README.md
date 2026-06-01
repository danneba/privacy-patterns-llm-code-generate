# VibeCodeGuide: Security and Privacy Analyzer for AI-Generated Code

> Privacy Engineering 2026 — Paris Lodron University of Salzburg  
> **Authors:** Haylemicheal Mekonnen, Daniel

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

VibeCodeGuide is in an **early but working** stage.

**Available now:**

- Static **security** rules (VG001–VG013) for Python
- **Privacy** rule pack (PG001–PG008) mapped to Hoepman privacy design strategies
- `PRIVACY` finding category in CLI/JSON reports with strategy metadata
- CLI (`vibecodeguide scan`), REST API (`security.api`), and VS Code extension
- Benchmark dataset for measuring detection quality

**Planned:**

- Broader language and framework coverage
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

**Baseline** (`--no-guidance`): security rules only (VG001–VG013).

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
│   ├── rules/security/    Rule implementations VG001–VG013
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
pip install pytest
pytest tests/ -v
```

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

- **VibeCodeGuide: Analyze File**
- **VibeCodeGuide: Analyze Selection**
- **VibeCodeGuide: Check API Health**

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
