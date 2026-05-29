import * as vscode from "vscode";
import { analyzeCode, ApiError, checkHealth } from "./client";
import { getConfig } from "./config";
import { VibeCodeGuideDiagnostics } from "./diagnostics";
import { countFindingsByCategory, formatAnalyzeSummary } from "./report";

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

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: EXTENSION_NAME,
        cancellable: false,
      },
      async (progress) => {
        try {
          progress.report({ message: "Running security and privacy analysis…" });
          const analyzeResult = await analyzeCode(config, code);
          diagnostics.setFromAnalyze(uri, editor.document, analyzeResult);
          output.clear();
          output.appendLine(formatAnalyzeSummary(analyzeResult));
          output.show(true);

          const counts = countFindingsByCategory(analyzeResult);
          if (analyzeResult.parse_errors.length > 0) {
            vscode.window.showWarningMessage(
              `${EXTENSION_NAME}: parse error — see Problems panel.`,
            );
          } else if (counts.total === 0) {
            vscode.window.showInformationMessage(
              `${EXTENSION_NAME}: no security or privacy issues found.`,
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
            vscode.window.showWarningMessage(
              `${EXTENSION_NAME}: ${counts.total} issue(s) (${parts.join(", ")}) — see Problems panel.`,
            );
          }
        } catch (err) {
          handleError(err, config.securityApiUrl);
        }
      },
    );
  }

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

  context.subscriptions.push(
    output,
    diagnostics,
    vscode.commands.registerCommand("vibecodeguide.analyze", () => runAnalyze(false)),
    vscode.commands.registerCommand("vibecodeguide.analyzeSelection", () => runAnalyze(true)),
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
