# VibeCodeGuide: Security and Privacy Analyzer for AI-Generated Code

> ASE 2026 — Paris Lodron University of Salzburg  
> **Authors:** Haylemicheal Mekonnen, Eslam Younis, Elbetel Reta

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
- **Privacy-oriented** checks via the same engine (e.g. hardcoded secrets, unsafe data handling patterns)
- CLI (`vibecodeguide scan`), REST API (`security.api`), and VS Code extension
- Benchmark dataset for measuring detection quality

**Planned:**

- Dedicated privacy rule pack and `PRIVACY` finding category in reports
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

### Other flags

```bash
--no-snippet      Exclude source code snippets from findings
--quiet           Suppress informational messages when using --output
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Scan completed — no findings above selected threshold |
| `1`  | Scan completed — findings detected |
| `2`  | Operational error or invalid usage |

---

## Implemented Rules

| Rule ID | Title | Severity | Focus |
|---------|-------|----------|--------|
| VG001 | Use of `eval()` | CRITICAL | Security |
| VG002 | Use of `exec()` | CRITICAL | Security |
| VG003 | Hardcoded Secret | HIGH | Security / Privacy |
| VG004 | Insecure Randomness | MEDIUM | Security |
| VG005 | Dangerous Subprocess Usage (`shell=True`) | HIGH | Security |
| VG006 | Pickle Deserialization | HIGH | Security |
| VG007 | Assert Used for Security Check | MEDIUM | Security |
| VG008 | Weak Hash Algorithm | HIGH | Security |
| VG009 | OS Shell Execution | HIGH | Security |
| VG010 | Unsafe YAML Deserialization | HIGH | Security |
| VG011 | TLS Verification Disabled | HIGH | Security |
| VG012 | Debug Mode Enabled | MEDIUM | Security |
| VG013 | Dynamic SQL Query Construction | HIGH | Security |

Findings may include confidence, risk score, CWE, OWASP category, impact, and remediation text.

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
generated-code-analyzer/
├── security/              Security & privacy analyzer (Python package)
│   ├── api/               FastAPI service for editor/HTTP clients
│   ├── cli/               vibecodeguide CLI
│   ├── core/              Scanner orchestration
│   ├── rules/security/    Rule implementations VG001–VG013
│   ├── models/            Finding and scan result types
│   └── reporters/         Text and JSON formatters
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

- **VibeCodeGuide: Open Secure Code Chat** — sidebar chat to generate Python with OWASP, CWE, and privacy rules
- **VibeCodeGuide: Analyze File**
- **VibeCodeGuide: Analyze Selection**
- **VibeCodeGuide: Check API Health**
- **VibeCodeGuide: Set OpenAI API Key**

The **Secure Code Chat** panel uses OpenAI to generate Python code guided by OWASP Top 10, CWE rules (VG001–VG013), and privacy patterns. Generated code is automatically scanned by the analyzer; use **Fix Issues** to regenerate a compliant version.

Settings: **VibeCodeGuide** (`vibecodeguide.securityApiUrl`, `vibecodeguide.minSeverity`, `vibecodeguide.requestTimeoutMs`, `vibecodeguide.openaiModel`, `vibecodeguide.openaiBaseUrl`, `vibecodeguide.autoAnalyzeGeneratedCode`). Store your OpenAI API key via **VibeCodeGuide: Set OpenAI API Key** (saved in VS Code Secret Storage).

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

| Name | Institution |
|---|---|
| Haylemicheal Mekonnen | Paris Lodron University of Salzburg |
| Eslam Younis | Paris Lodron University of Salzburg |
| Elbetel Reta | Paris Lodron University of Salzburg |
