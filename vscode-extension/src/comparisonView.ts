import * as vscode from "vscode";
import { buildComparisonViewModel, type ComparisonViewModel, type EnrichedFinding } from "./comparisonModel";
import type { DemoAnalyzeResponse, Finding } from "./types";

const PANEL_TYPE = "vibecodeguideGuidanceComparison";

const HELP = {
  guidanceOff:
    "Guidance OFF means only baseline analyzer checks are shown (standard security rules).",
  guidanceOn:
    "Guidance ON adds privacy and security recommendations from our guidance module (Hoepman strategies).",
  newWithGuidance:
    "New with Guidance means this issue was detected because the guidance module is enabled.",
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function severityClass(severity: string): string {
  return `severity-${severity.toLowerCase()}`;
}

function renderFindingCard(finding: Finding | EnrichedFinding, options?: { showBadge?: boolean }): string {
  const enriched = finding as EnrichedFinding;
  const isNew = Boolean(enriched.isNewWithGuidance);
  const category = finding.category ?? "SECURITY";
  const strategy = finding.privacy_strategy
    ? `<span class="strategy" title="Hoepman privacy design strategy">${escapeHtml(finding.privacy_strategy)}</span>`
    : "";
  const badge =
    isNew && options?.showBadge
      ? `<span class="badge-new" title="${escapeHtml(HELP.newWithGuidance)}">New with Guidance</span>`
      : "";
  const cardClass = isNew && options?.showBadge ? "finding-card finding-card-new" : "finding-card";

  return `
    <article class="${cardClass}">
      <div class="finding-head">
        <span class="severity ${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <span class="category">${escapeHtml(category)}</span>
        ${strategy}
        ${badge}
      </div>
      <h3>${escapeHtml(finding.title)}</h3>
      <p class="rule-id"><code>${escapeHtml(finding.rule_id)}</code> · line ${finding.line}</p>
      <p class="message">${escapeHtml(finding.message)}</p>
      ${
        finding.suggestion
          ? `<p class="suggestion"><strong>Fix:</strong> ${escapeHtml(finding.suggestion)}</p>`
          : ""
      }
      ${
        finding.snippet
          ? `<pre class="snippet">${escapeHtml(String(finding.snippet).trim())}</pre>`
          : ""
      }
    </article>
  `;
}

function renderColumn(title: string, tooltip: string, findings: Finding[], showBadge: boolean): string {
  const cards =
    findings.length > 0
      ? findings.map((finding) => renderFindingCard(finding, { showBadge })).join("")
      : `<p class="empty">No findings in this mode.</p>`;

  return `
    <section class="column">
      <header class="column-header">
        <h2 title="${escapeHtml(tooltip)}">${escapeHtml(title)}</h2>
        <p class="column-count">${findings.length} finding(s)</p>
        <p class="helper" title="${escapeHtml(tooltip)}">${escapeHtml(tooltip)}</p>
      </header>
      <div class="finding-list">${cards}</div>
    </section>
  `;
}

function renderHtml(model: ComparisonViewModel): string {
  const newFindings = model.guidedFindings.filter((finding) => finding.isNewWithGuidance);

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
      --new-bg: color-mix(in srgb, var(--vscode-inputValidation-warningBackground, #5a4a00) 35%, transparent);
      --new-border: var(--vscode-inputValidation-warningBorder, #cca700);
      --badge-bg: var(--vscode-badge-background, #4d4d4d);
      --badge-fg: var(--vscode-badge-foreground, #fff);
    }
    body {
      font-family: var(--vscode-font-family);
      color: var(--fg);
      background: var(--bg);
      margin: 0;
      padding: 16px;
      line-height: 1.45;
    }
    h1 { margin: 0 0 8px; font-size: 1.25rem; }
    .sample { color: var(--muted); margin-bottom: 16px; word-break: break-all; }
    .banner {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      background: var(--banner);
      color: var(--banner-fg);
      border-radius: 8px;
      padding: 14px 16px;
      margin-bottom: 16px;
    }
    .banner-item strong { display: block; font-size: 1.5rem; margin-top: 4px; }
    .banner-item span { font-size: 0.85rem; opacity: 0.95; }
    .banner-diff { grid-column: 1 / -1; border-top: 1px solid rgba(255,255,255,0.2); padding-top: 10px; font-size: 0.95rem; }
    .helpers {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-bottom: 16px;
    }
    .helper-box {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      font-size: 0.85rem;
      color: var(--muted);
    }
    .helper-box strong { color: var(--fg); display: block; margin-bottom: 4px; }
    .columns {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      align-items: start;
    }
    .column {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      min-width: 0;
    }
    .column-header {
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      background: color-mix(in srgb, var(--border) 20%, transparent);
    }
    .column-header h2 { margin: 0; font-size: 1rem; }
    .column-count { margin: 4px 0 0; color: var(--muted); font-size: 0.85rem; }
    .helper { margin: 8px 0 0; font-size: 0.8rem; color: var(--muted); }
    .finding-list { padding: 12px; display: flex; flex-direction: column; gap: 10px; }
    .finding-card {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 12px;
      background: color-mix(in srgb, var(--bg) 92%, var(--fg) 8%);
    }
    .finding-card-new {
      background: var(--new-bg);
      border-color: var(--new-border);
    }
    .finding-head { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 6px; }
    .severity, .category, .strategy {
      font-size: 0.72rem;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
    }
    .severity-high, .severity-critical { border-color: #f14c4c; }
    .severity-medium { border-color: #cca700; }
    .badge-new {
      font-size: 0.72rem;
      background: var(--badge-bg);
      color: var(--badge-fg);
      padding: 2px 8px;
      border-radius: 999px;
      font-weight: 600;
    }
    .finding-card h3 { margin: 0 0 4px; font-size: 0.95rem; }
    .rule-id, .message, .suggestion { margin: 4px 0; font-size: 0.85rem; }
    .snippet {
      margin: 8px 0 0;
      padding: 8px;
      border-radius: 4px;
      overflow-x: auto;
      font-size: 0.8rem;
      background: color-mix(in srgb, var(--bg) 80%, var(--fg) 20%);
    }
    .empty { color: var(--muted); font-style: italic; margin: 0; }
    .highlight-section {
      margin-top: 16px;
      border: 1px dashed var(--new-border);
      border-radius: 8px;
      padding: 12px 14px;
    }
    .highlight-section h2 { margin: 0 0 10px; font-size: 1rem; }
    @media (max-width: 900px) {
      .columns, .helpers, .banner { grid-template-columns: 1fr; }
      .banner-diff { grid-column: auto; }
    }
  </style>
</head>
<body>
  <h1>Privacy &amp; Security Guidance — Before / After Comparison</h1>
  <p class="sample">Sample: ${escapeHtml(model.sampleLabel)}</p>

  <section class="banner" aria-label="Summary">
    <div class="banner-item" title="${escapeHtml(HELP.guidanceOff)}">
      <span>Guidance OFF</span>
      <strong>${model.baselineCount}</strong>
      findings
    </div>
    <div class="banner-item" title="${escapeHtml(HELP.guidanceOn)}">
      <span>Guidance ON</span>
      <strong>${model.guidedCount}</strong>
      findings
    </div>
    <div class="banner-item">
      <span>Difference</span>
      <strong>+${model.additionalCount}</strong>
      additional finding(s)
    </div>
    <div class="banner-diff">
      <strong>+${model.additionalPrivacyCount} additional privacy finding(s)</strong>
      surfaced by the guidance module
      ${
        model.privacyStrategies.length
          ? ` · Hoepman strategies: ${escapeHtml(model.privacyStrategies.join(", "))}`
          : ""
      }
    </div>
  </section>

  <section class="helpers">
    <div class="helper-box" title="${escapeHtml(HELP.guidanceOff)}">
      <strong>Guidance OFF</strong>
      ${escapeHtml(HELP.guidanceOff)}
    </div>
    <div class="helper-box" title="${escapeHtml(HELP.guidanceOn)}">
      <strong>Guidance ON</strong>
      ${escapeHtml(HELP.guidanceOn)}
    </div>
  </section>

  <div class="columns">
    ${renderColumn("Step 1 · Guidance OFF", HELP.guidanceOff, model.baselineFindings, false)}
    ${renderColumn("Step 2 · Guidance ON", HELP.guidanceOn, model.guidedFindings, true)}
  </div>

  ${
    newFindings.length
      ? `<section class="highlight-section">
          <h2 title="${escapeHtml(HELP.newWithGuidance)}">Step 3 · Only with Guidance ON (${newFindings.length})</h2>
          <p class="helper">${escapeHtml(HELP.newWithGuidance)}</p>
          <div class="finding-list">
            ${newFindings.map((finding) => renderFindingCard(finding, { showBadge: true })).join("")}
          </div>
        </section>`
      : ""
  }
</body>
</html>`;
}

export class GuidanceComparisonPanel {
  private static currentPanel: vscode.WebviewPanel | undefined;

  static show(context: vscode.ExtensionContext, demo: DemoAnalyzeResponse): void {
    const model = buildComparisonViewModel(demo);
    const column = vscode.window.activeTextEditor?.viewColumn;

    if (GuidanceComparisonPanel.currentPanel) {
      GuidanceComparisonPanel.currentPanel.reveal(column);
    } else {
      GuidanceComparisonPanel.currentPanel = vscode.window.createWebviewPanel(
        PANEL_TYPE,
        "Guidance Comparison",
        column ?? vscode.ViewColumn.Beside,
        { enableScripts: false, retainContextWhenHidden: true },
      );
      GuidanceComparisonPanel.currentPanel.onDidDispose(() => {
        GuidanceComparisonPanel.currentPanel = undefined;
      });
      context.subscriptions.push(GuidanceComparisonPanel.currentPanel);
    }

    GuidanceComparisonPanel.currentPanel.title = "Guidance: Before / After";
    GuidanceComparisonPanel.currentPanel.webview.html = renderHtml(model);
  }
}
