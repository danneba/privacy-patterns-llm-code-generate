import * as vscode from "vscode";
import type { AnalyzeResponse, Finding, Severity } from "./types";

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

export class VibeCodeGuideDiagnostics {
  private readonly collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);

  dispose(): void {
    this.collection.dispose();
  }

  setFromAnalyze(
    uri: vscode.Uri,
    document: vscode.TextDocument,
    result: AnalyzeResponse,
  ): void {
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
      diagnostics.push(this.findingToDiagnostic(finding, document));
    }

    this.collection.set(uri, diagnostics);
  }

  private findingToDiagnostic(finding: Finding, document: vscode.TextDocument): vscode.Diagnostic {
    const line = Math.max(0, finding.line - 1);
    const lineText = document.lineAt(line).text;
    const range = new vscode.Range(line, 0, line, lineText.length);

    const prefix = categoryPrefix(finding);
    const parts = [`[${prefix}] [${finding.rule_id}] ${finding.title}`, finding.message];
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
    diagnostic.source = DIAGNOSTIC_SOURCE;
    diagnostic.code = finding.rule_id;
    return diagnostic;
  }
}
