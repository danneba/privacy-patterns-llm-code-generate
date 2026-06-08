import * as path from "path";
import * as vscode from "vscode";

export async function saveGeneratedPythonFile(
  code: string,
  filename: string,
  existingUri?: vscode.Uri,
): Promise<{ uri: vscode.Uri; relativePath: string }> {
  if (existingUri) {
    await vscode.workspace.fs.writeFile(existingUri, Buffer.from(code, "utf8"));
    return { uri: existingUri, relativePath: vscode.workspace.asRelativePath(existingUri) };
  }

  const workspaceFolder = getTargetFolder();
  const generatedDir = vscode.Uri.joinPath(workspaceFolder, "generated");
  await vscode.workspace.fs.createDirectory(generatedDir);

  const targetUri = await resolveUniqueFileUri(generatedDir, filename);
  await vscode.workspace.fs.writeFile(targetUri, Buffer.from(code, "utf8"));

  const relativePath = vscode.workspace.asRelativePath(targetUri);
  return { uri: targetUri, relativePath };
}

function getTargetFolder(): vscode.Uri {
  const editor = vscode.window.activeTextEditor;
  if (editor?.document.uri.scheme === "file") {
    return vscode.Uri.file(path.dirname(editor.document.uri.fsPath));
  }

  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  if (workspaceFolder) {
    return workspaceFolder.uri;
  }

  throw new Error("Open a folder or Python file so VibeCodeGuide can save generated code.");
}

async function resolveUniqueFileUri(directory: vscode.Uri, filename: string): Promise<vscode.Uri> {
  const stem = filename.replace(/\.py$/i, "");
  let candidate = vscode.Uri.joinPath(directory, filename);
  let counter = 1;

  while (true) {
    try {
      await vscode.workspace.fs.stat(candidate);
      candidate = vscode.Uri.joinPath(directory, `${stem}_${counter}.py`);
      counter += 1;
    } catch {
      return candidate;
    }
  }
}

export async function openSavedFile(uri: vscode.Uri): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(uri);
  await vscode.window.showTextDocument(doc, { preview: false });
}
