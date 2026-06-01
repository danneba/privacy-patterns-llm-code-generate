import * as vscode from "vscode";
import { buildComparisonViewModel, type EnrichedFinding } from "./comparisonModel";
import type { AnalysisDiff } from "./analysisDiff";
import type { AnalyzeResponse, DemoAnalyzeResponse, Finding, Severity } from "./types";

const DIAGNOSTIC_SOURCE = "VibeCodeGuide";

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  INFO: vscode.DiagnosticSeverity.Information,
  LOW: vscode.DiagnosticSeverity.Hint,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  HIGH: vscode.DiagnosticSeverity.Error,
  CRITICAL: vscode.DiagnosticSeverity.Error,
};

function categoryPrefix(finding: Finding): string {
  if (finding.category === "PRIVACY") {
    return finding.privacy_strategy
      ? `Privacy (${finding.privacy_strategy})`
      : "Privacy";
  }
  if (finding.category === "SECURITY") {
    return "Security";
  }
  if (finding.category) {
    return finding.category;
  }
  return finding.privacy_strategy ? `Privacy (${finding.privacy_strategy})` : "Security";
}

const NEW_WITH_GUIDANCE = "New with Guidance";
const NEW_WITH_GUIDANCE_HELP =
  "This issue was detected because the privacy & security guidance module is enabled.";
const NEW_SINCE_LAST_ANALYSIS = "New since last analysis";
const NEW_SINCE_LAST_ANALYSIS_HELP =
  "This issue was not reported on your previous Analyze File run for this file.";

function looseFindingKey(finding: Finding): string {
  return `${finding.rule_id}|${finding.line ?? 0}`;
}

export class VibeCodeGuideDiagnostics {
  private readonly collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);

  dispose(): void {
    this.collection.dispose();
  }

  setFromAnalyze(
    uri: vscode.Uri,
    document: vscode.TextDocument,
    result: AnalyzeResponse,
    diff?: AnalysisDiff,
  ): void {
    const introducedKeys = diff
      ? new Set(diff.introduced.map((finding) => looseFindingKey(finding)))
      : undefined;
    const diagnostics: vscode.Diagnostic[] = [];

    for (const err of result.parse_errors) {
      diagnostics.push(
        new vscode.Diagnostic(
          new vscode.Range(0, 0, 0, 1),
          err.message,
          vscode.DiagnosticSeverity.Error,
        ),
      );
    }

    for (const finding of result.findings) {
      const isNewSinceLastAnalysis = introducedKeys?.has(looseFindingKey(finding)) ?? false;
      diagnostics.push(
        this.findingToDiagnostic(finding, document, {
          isNewWithGuidance: false,
          isNewSinceLastAnalysis,
        }),
      );
    }

    this.collection.set(uri, diagnostics);
  }

  setFromDemoComparison(
    uri: vscode.Uri,
    document: vscode.TextDocument,
    demo: DemoAnalyzeResponse,
  ): void {
    const model = buildComparisonViewModel(demo);
    const diagnostics: vscode.Diagnostic[] = [];

    for (const err of demo.baseline.parse_errors) {
      diagnostics.push(
        new vscode.Diagnostic(
          new vscode.Range(0, 0, 0, 1),
          err.message,
          vscode.DiagnosticSeverity.Error,
        ),
      );
    }

    for (const finding of model.guidedFindings) {
      diagnostics.push(
        this.findingToDiagnostic(finding, document, {
          isNewWithGuidance: finding.isNewWithGuidance,
        }),
      );
    }

    this.collection.set(uri, diagnostics);
  }

  private findingToDiagnostic(
    finding: Finding | EnrichedFinding,
    document: vscode.TextDocument,
    flags: { isNewWithGuidance?: boolean; isNewSinceLastAnalysis?: boolean } = {},
  ): vscode.Diagnostic {
    const line = Math.max(0, finding.line - 1);
    const lineText = document.lineAt(line).text;
    const range = new vscode.Range(line, 0, line, lineText.length);

    const prefix = categoryPrefix(finding);
    const badge = flags.isNewWithGuidance
      ? `[${NEW_WITH_GUIDANCE}] `
      : flags.isNewSinceLastAnalysis
        ? `[${NEW_SINCE_LAST_ANALYSIS}] `
        : "";
    const parts = [
      `${badge}[${prefix}] [${finding.rule_id}] ${finding.title}`,
      finding.message,
    ];
    if (flags.isNewWithGuidance) {
      parts.push(NEW_WITH_GUIDANCE_HELP);
    }
    if (flags.isNewSinceLastAnalysis) {
      parts.push(NEW_SINCE_LAST_ANALYSIS_HELP);
    }
    if (finding.impact) {
      parts.push(`Impact: ${finding.impact}`);
    }
    if (finding.suggestion) {
      parts.push(`Fix: ${finding.suggestion}`);
    }

    const diagnostic = new vscode.Diagnostic(
      range,
      parts.join(" — "),
      SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning,
    );
    if (flags.isNewWithGuidance) {
      diagnostic.source = `${DIAGNOSTIC_SOURCE} · ${NEW_WITH_GUIDANCE}`;
    } else if (flags.isNewSinceLastAnalysis) {
      diagnostic.source = `${DIAGNOSTIC_SOURCE} · ${NEW_SINCE_LAST_ANALYSIS}`;
    } else {
      diagnostic.source = DIAGNOSTIC_SOURCE;
    }
    diagnostic.code = finding.rule_id;
    return diagnostic;
  }
}
