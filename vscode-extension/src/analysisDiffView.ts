import * as vscode from "vscode";
import { countPrivacy, type AnalysisDiff } from "./analysisDiff";
import type { Finding } from "./types";

const PANEL_TYPE = "vibecodeguideAnalysisDiff";

const HELP = {
  overview:
    "Compared with your last Analyze File run on this file. Edit the code, save, and run Analyze File again to refresh this view.",
  resolved: "This warning disappeared after your code edit (for example a commented-out risky line).",
  introduced: "This warning is new compared with your previous analysis.",
  unchanged: "This warning was already present and is still reported.",
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function categoryLabel(category?: string): string {
  return category === "PRIVACY" ? "Privacy" : category === "SECURITY" ? "Security" : category ?? "Issue";
}

function renderFinding(
  finding: Finding,
  badge: { label: string; className: string; title: string },
): string {
  const category = categoryLabel(finding.category);
  const strategy = finding.privacy_strategy
    ? `<span class="strategy">${escapeHtml(finding.privacy_strategy)}</span>`
    : "";
  return `
    <article class="finding-card ${badge.className}">
      <div class="finding-head">
        <span class="badge" title="${escapeHtml(badge.title)}">${escapeHtml(badge.label)}</span>
        <span class="category">${escapeHtml(category)}</span>
        ${strategy}
        <span class="severity">${escapeHtml(finding.severity)}</span>
      </div>
      <h3>${escapeHtml(finding.title)}</h3>
      <p class="rule-id"><code>${escapeHtml(finding.rule_id)}</code> · line ${finding.line}</p>
      <p class="message">${escapeHtml(finding.message)}</p>
      ${
        finding.snippet
          ? `<pre class="snippet">${escapeHtml(String(finding.snippet).trim())}</pre>`
          : ""
      }
    </article>
  `;
}

function renderSection(
  title: string,
  helper: string,
  findings: Finding[],
  badge: { label: string; className: string; title: string },
): string {
  const cards =
    findings.length > 0
      ? findings.map((finding) => renderFinding(finding, badge)).join("")
      : `<p class="empty">None</p>`;
  return `
    <section class="section">
      <h2>${escapeHtml(title)} (${findings.length})</h2>
      <p class="helper">${escapeHtml(helper)}</p>
      <div class="finding-list">${cards}</div>
    </section>
  `;
}

function renderHtml(diff: AnalysisDiff): string {
  const prevPrivacy = countPrivacy(diff.previous.findings);
  const currPrivacy = countPrivacy(diff.current.findings);
  const resolvedPrivacy = countPrivacy(diff.resolved);
  const introducedPrivacy = countPrivacy(diff.introduced);

  const changedLines =
    diff.changedLines.length > 0
      ? diff.changedLines
          .map(
            (line) => `
      <div class="changed-line">
        <p><strong>Line ${line.line_number}</strong></p>
        <p class="label">Previous</p>
        <pre class="snippet before">${escapeHtml(line.before_text)}</pre>
        <p class="label">Current</p>
        <pre class="snippet after">${escapeHtml(line.after_text)}</pre>
      </div>`,
          )
          .join("")
      : `<p class="empty">No line differences detected between the two analysis runs.</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    :root {
      --bg: var(--vscode-editor-background);
      --fg: var(--vscode-editor-foreground);
      --muted: var(--vscode-descriptionForeground);
      --border: var(--vscode-panel-border, #444);
      --banner: var(--vscode-editorInfo-background, #264f78);
      --banner-fg: var(--vscode-editorInfo-foreground, #fff);
      --resolved-bg: color-mix(in srgb, var(--vscode-testing-iconPassed, #73c991) 22%, transparent);
      --resolved-border: var(--vscode-testing-iconPassed, #73c991);
      --introduced-bg: color-mix(in srgb, var(--vscode-inputValidation.warningBackground, #5a4a00) 28%, transparent);
      --introduced-border: var(--vscode-inputValidation-warningBorder, #cca700);
      --unchanged-bg: color-mix(in srgb, var(--border) 15%, transparent);
    }
    body { font-family: var(--vscode-font-family); color: var(--fg); background: var(--bg); margin: 0; padding: 16px; line-height: 1.45; }
    h1 { margin: 0 0 8px; font-size: 1.25rem; }
    .sample { color: var(--muted); margin-bottom: 16px; word-break: break-all; }
    .banner {
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px;
      background: var(--banner); color: var(--banner-fg); border-radius: 8px; padding: 14px 16px; margin-bottom: 16px;
    }
    .banner-item strong { display: block; font-size: 1.25rem; margin-top: 4px; }
    .banner-item span { font-size: 0.8rem; }
    .banner-wide { grid-column: 1 / -1; border-top: 1px solid rgba(255,255,255,0.2); padding-top: 10px; font-size: 0.9rem; }
    .helper-box { border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; font-size: 0.85rem; color: var(--muted); margin-bottom: 16px; }
    .section { border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-bottom: 14px; }
    .section h2 { margin: 0 0 8px; font-size: 1rem; }
    .helper { margin: 0 0 10px; font-size: 0.82rem; color: var(--muted); }
    .finding-list { display: flex; flex-direction: column; gap: 8px; }
    .finding-card { border: 1px solid var(--border); border-radius: 6px; padding: 10px 12px; }
    .finding-card.resolved { background: var(--resolved-bg); border-color: var(--resolved-border); }
    .finding-card.introduced { background: var(--introduced-bg); border-color: var(--introduced-border); }
    .finding-card.unchanged { background: var(--unchanged-bg); }
    .finding-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
    .badge { font-size: 0.72rem; padding: 2px 8px; border-radius: 999px; font-weight: 700; }
    .finding-card.resolved .badge { background: var(--resolved-border); color: #111; }
    .finding-card.introduced .badge { background: var(--introduced-border); color: #111; }
    .finding-card.unchanged .badge { background: var(--border); color: var(--fg); }
    .category, .severity, .strategy { font-size: 0.72rem; padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border); }
    .finding-card h3 { margin: 0 0 4px; font-size: 0.92rem; }
    .rule-id, .message { margin: 4px 0; font-size: 0.85rem; }
    .snippet { margin: 6px 0 0; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 0.8rem; background: color-mix(in srgb, var(--bg) 80%, var(--fg) 20%); }
    .changed-line { margin-bottom: 10px; }
    .label { margin: 6px 0 2px; font-size: 0.78rem; color: var(--muted); }
    .empty { color: var(--muted); font-style: italic; margin: 0; }
    @media (max-width: 900px) { .banner { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
  <h1>Code Change Impact</h1>
  <p class="sample">${escapeHtml(diff.fileName)}</p>

  <section class="banner">
    <div class="banner-item"><span>Before Change</span><strong>${diff.previous.findings.length}</strong> findings</div>
    <div class="banner-item"><span>After change</span><strong>${diff.current.findings.length}</strong> findings</div>
    <div class="banner-item"><span>Resolved</span><strong>${diff.resolved.length}</strong></div>
    <div class="banner-item"><span>Introduced</span><strong>${diff.introduced.length}</strong></div>
    <div class="banner-wide">
      Privacy findings: ${prevPrivacy} → ${currPrivacy}
      · Resolved ${resolvedPrivacy} privacy · Introduced ${introducedPrivacy} privacy
      · Unchanged ${diff.unchanged.length}
    </div>
  </section>

  <div class="helper-box">${escapeHtml(HELP.overview)}</div>

  <section class="section">
    <h2>Lines you changed</h2>
    <p class="helper">Edit the file, save (Cmd+S), then run Analyze File again.</p>
    ${changedLines}
  </section>

  ${renderSection("Resolved", HELP.resolved, diff.resolved, {
    label: "Resolved",
    className: "resolved",
    title: HELP.resolved,
  })}

  ${renderSection("Introduced", HELP.introduced, diff.introduced, {
    label: "New finding",
    className: "introduced",
    title: HELP.introduced,
  })}

  ${renderSection("Unchanged", HELP.unchanged, diff.unchanged, {
    label: "Still present",
    className: "unchanged",
    title: HELP.unchanged,
  })}
</body>
</html>`;
}

export class AnalysisDiffPanel {
  private static currentPanel: vscode.WebviewPanel | undefined;

  static show(context: vscode.ExtensionContext, diff: AnalysisDiff): void {
    const column = vscode.window.activeTextEditor?.viewColumn;

    if (AnalysisDiffPanel.currentPanel) {
      AnalysisDiffPanel.currentPanel.reveal(column);
    } else {
      AnalysisDiffPanel.currentPanel = vscode.window.createWebviewPanel(
        PANEL_TYPE,
        "Analysis: what changed",
        column ?? vscode.ViewColumn.Beside,
        { enableScripts: false, retainContextWhenHidden: true },
      );
      AnalysisDiffPanel.currentPanel.onDidDispose(() => {
        AnalysisDiffPanel.currentPanel = undefined;
      });
      context.subscriptions.push(AnalysisDiffPanel.currentPanel);
    }

    AnalysisDiffPanel.currentPanel.title = "Analysis: what changed";
    AnalysisDiffPanel.currentPanel.webview.html = renderHtml(diff);
  }
}
