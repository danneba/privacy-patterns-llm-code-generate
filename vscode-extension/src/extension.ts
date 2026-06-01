import * as vscode from "vscode";
import { analyzeCode, analyzeDemo, ApiError, checkHealth } from "./client";
import { buildAnalysisDiff } from "./analysisDiff";
import { AnalysisDiffPanel } from "./analysisDiffView";
import { getStoredAnalysis, saveStoredAnalysis } from "./analysisHistory";
import { GuidanceComparisonPanel } from "./comparisonView";
import { getConfig } from "./config";
import { VibeCodeGuideDiagnostics } from "./diagnostics";
import { buildComparisonViewModel } from "./comparisonModel";
import {
  countFindingsByCategory,
  formatAnalysisDiff,
  formatAnalyzeSummary,
  formatDemoComparison,
} from "./report";

const EXTENSION_NAME = "VibeCodeGuide";
const OUTPUT_CHANNEL = EXTENSION_NAME;

function getActivePythonEditor(): vscode.TextEditor | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Open a Python file to analyze.");
    return undefined;
  }
  if (editor.document.languageId !== "python") {
    vscode.window.showWarningMessage(`${EXTENSION_NAME} currently supports Python only.`);
    return undefined;
  }
  return editor;
}

function getCodeFromEditor(editor: vscode.TextEditor, selectionOnly: boolean): string | undefined {
  const doc = editor.document;
  if (selectionOnly && !editor.selection.isEmpty) {
    return doc.getText(editor.selection);
  }
  const code = doc.getText();
  if (!code.trim()) {
    vscode.window.showWarningMessage("Nothing to analyze — the editor is empty.");
    return undefined;
  }
  return code;
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL);
  const diagnostics = new VibeCodeGuideDiagnostics();

  function handleError(err: unknown, apiUrl: string): void {
    if (err instanceof ApiError) {
      const hint =
        err.status === undefined
          ? ` Is the API running at ${apiUrl}?`
          : "";
      vscode.window.showErrorMessage(`${EXTENSION_NAME}: ${err.message}${hint}`);
      return;
    }
    vscode.window.showErrorMessage(
      `${EXTENSION_NAME}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  async function runAnalyze(selectionOnly: boolean) {
    const editor = getActivePythonEditor();
    if (!editor) {
      return;
    }

    const code = getCodeFromEditor(editor, selectionOnly);
    if (!code) {
      return;
    }

    const config = getConfig();
    const uri = editor.document.uri;
    const uriKey = uri.toString();
    const fileName = editor.document.fileName || "<code>";
    const guidanceLabel = config.enablePrivacySecurityGuidance
      ? "with guidance"
      : "baseline only";
    const previous =
      !selectionOnly ? getStoredAnalysis(context, uriKey) : undefined;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: EXTENSION_NAME,
        cancellable: false,
      },
      async (progress) => {
        try {
          progress.report({ message: `Analyzing (${guidanceLabel})…` });
          const analyzeResult = await analyzeCode(config, code);

          const diff =
            !selectionOnly && previous && previous.code !== code
              ? buildAnalysisDiff(previous, code, analyzeResult)
              : undefined;

          diagnostics.setFromAnalyze(uri, editor.document, analyzeResult, diff);

          output.clear();
          if (diff) {
            output.appendLine(formatAnalysisDiff(diff));
            output.appendLine("");
          }
          output.appendLine(formatAnalyzeSummary(analyzeResult));
          output.show(true);

          if (diff) {
            AnalysisDiffPanel.show(context, diff);
          }

          const counts = countFindingsByCategory(analyzeResult);
          if (analyzeResult.parse_errors.length > 0) {
            vscode.window.showWarningMessage(
              `${EXTENSION_NAME}: parse error — see Problems panel.`,
            );
          } else if (diff) {
            vscode.window.showInformationMessage(
              `${EXTENSION_NAME}: ${counts.total} issue(s) (${guidanceLabel}) — ` +
                `resolved ${diff.resolved.length}, new ${diff.introduced.length}, ` +
                `unchanged ${diff.unchanged.length}. See Analysis changes panel.`,
            );
          } else if (counts.total === 0) {
            vscode.window.showInformationMessage(
              `${EXTENSION_NAME}: no issues found (${guidanceLabel}).` +
                (!selectionOnly && !previous
                  ? " Edit and run Analyze File again to see what changed."
                  : ""),
            );
          } else {
            const parts: string[] = [];
            if (counts.security > 0) {
              parts.push(`${counts.security} security`);
            }
            if (counts.privacy > 0) {
              parts.push(`${counts.privacy} privacy`);
            }
            if (counts.other > 0) {
              parts.push(`${counts.other} other`);
            }
            const changeHint =
              !selectionOnly && !previous
                ? " Edit, save, and analyze again to compare with this run."
                : !selectionOnly && previous && previous.code === code
                  ? " File unchanged since last analysis."
                  : "";
            vscode.window.showInformationMessage(
              `${EXTENSION_NAME}: ${counts.total} issue(s) (${parts.join(", ")}, ${guidanceLabel}) — see Problems.${changeHint}`,
            );
          }

          if (!selectionOnly) {
            await saveStoredAnalysis(context, uriKey, fileName, code, analyzeResult);
          }
        } catch (err) {
          handleError(err, config.securityApiUrl);
        }
      },
    );
  }

  async function runGuidanceDemo() {
    const editor = getActivePythonEditor();
    if (!editor) {
      return;
    }

    const code = getCodeFromEditor(editor, false);
    if (!code) {
      return;
    }

    const config = getConfig();
    const uri = editor.document.uri;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: EXTENSION_NAME,
        cancellable: false,
      },
      async (progress) => {
        try {
          progress.report({ message: "Step 1/3: Running baseline (guidance OFF)…" });
          progress.report({ message: "Step 2/3: Running with guidance ON…" });
          const demo = await analyzeDemo(config, code);
          const model = buildComparisonViewModel(demo);

          progress.report({ message: "Step 3/3: Building comparison view…" });
          diagnostics.setFromDemoComparison(uri, editor.document, demo);
          GuidanceComparisonPanel.show(context, demo);

          output.clear();
          output.appendLine(formatDemoComparison(demo));
          output.show(true);

          vscode.window.showInformationMessage(
            `${EXTENSION_NAME}: Guidance OFF ${model.baselineCount} → ON ${model.guidedCount} ` +
              `(+${model.additionalPrivacyCount} privacy findings). ` +
              "See comparison panel and Problems (★ New with Guidance).",
          );
        } catch (err) {
          handleError(err, config.securityApiUrl);
        }
      },
    );
  }

  context.subscriptions.push(
    output,
    diagnostics,
    vscode.commands.registerCommand("vibecodeguide.analyze", () => runAnalyze(false)),
    vscode.commands.registerCommand("vibecodeguide.analyzeSelection", () => runAnalyze(true)),
    vscode.commands.registerCommand("vibecodeguide.runGuidanceDemo", () => runGuidanceDemo()),
    vscode.commands.registerCommand("vibecodeguide.checkHealth", async () => {
      const config = getConfig();
      const securityOk = await checkHealth(config.securityApiUrl, config.requestTimeoutMs);

      const line = `VibeCodeGuide API (${config.securityApiUrl}): ${securityOk ? "ok" : "unreachable"}`;
      output.clear();
      output.appendLine(line);
      output.show(true);

      if (securityOk) {
        vscode.window.showInformationMessage(`${EXTENSION_NAME}: API is healthy.`);
      } else {
        vscode.window.showWarningMessage(`${EXTENSION_NAME}: API is unreachable.`);
      }
    }),
  );
}

export function deactivate(): void {}
