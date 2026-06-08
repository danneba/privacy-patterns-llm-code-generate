import * as vscode from "vscode";
import { analyzeCode, ApiError } from "./client";
import { extractPythonCode } from "./codeUtils";
import { getConfig } from "./config";
import { deriveFilenameFromPrompt, extractSuggestedFilename } from "./filenameUtils";
import { openSavedFile, saveGeneratedPythonFile } from "./fileUtils";
import { chatCompletion, OpenAiError, type ChatMessage } from "./openai";
import type { Finding } from "./types";

const VIEW_TYPE = "vibecodeguide.chatView";
const SECRET_KEY = "vibecodeguide.openaiApiKey";

type WebviewMessage =
  | { type: "sendPrompt"; prompt: string }
  | { type: "openSavedFile" }
  | { type: "fixIssues"; code: string; findings: Finding[] }
  | { type: "configureApiKey" }
  | { type: "clearChat" }
  | { type: "ready" };

type ExtensionMessage =
  | { type: "init"; apiKeyConfigured: boolean; autoAnalyze: boolean }
  | { type: "userMessage"; text: string }
  | { type: "assistantMessage"; text: string; code?: string; savedPath?: string }
  | { type: "analysisResult"; findings: Finding[]; clean: boolean }
  | { type: "status"; message: string; level: "info" | "error" | "loading" }
  | { type: "cleared" }
  | { type: "apiKeyConfigured"; configured: boolean };

export class ChatViewProvider implements vscode.WebviewViewProvider {
  private view?: vscode.WebviewView;
  private readonly history: ChatMessage[] = [];
  private generating = false;
  private lastSavedUri?: vscode.Uri;
  private lastPrompt = "";

  constructor(private readonly context: vscode.ExtensionContext) {}

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this.view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [],
    };
    webviewView.webview.html = getChatHtml();

    webviewView.webview.onDidReceiveMessage(async (msg: WebviewMessage) => {
      switch (msg.type) {
        case "ready":
          await this.postInit();
          break;
        case "sendPrompt":
          await this.handlePrompt(msg.prompt);
          break;
        case "fixIssues":
          await this.handleFix(msg.code, msg.findings);
          break;
        case "openSavedFile":
          await this.openLastSavedFile();
          break;
        case "configureApiKey":
          await this.promptForApiKey();
          break;
        case "clearChat":
          this.history.length = 0;
          this.post({ type: "cleared" });
          break;
      }
    });
  }

  private post(message: ExtensionMessage): void {
    void this.view?.webview.postMessage(message);
  }

  private async postInit(): Promise<void> {
    const apiKey = await this.getApiKey();
    const config = getConfig();
    this.post({
      type: "init",
      apiKeyConfigured: Boolean(apiKey),
      autoAnalyze: config.autoAnalyzeGeneratedCode,
    });
  }

  private async getApiKey(): Promise<string | undefined> {
    return this.context.secrets.get(SECRET_KEY);
  }

  async promptForApiKey(): Promise<void> {
    const key = await vscode.window.showInputBox({
      title: "VibeCodeGuide — OpenAI API Key",
      prompt: "Enter your OpenAI API key (stored securely in VS Code Secret Storage).",
      password: true,
      ignoreFocusOut: true,
      placeHolder: "sk-…",
    });
    if (!key?.trim()) {
      return;
    }
    await this.context.secrets.store(SECRET_KEY, key.trim());
    this.post({ type: "apiKeyConfigured", configured: true });
    vscode.window.showInformationMessage("VibeCodeGuide: OpenAI API key saved.");
  }

  private async handlePrompt(prompt: string): Promise<void> {
    const trimmed = prompt.trim();
    if (!trimmed || this.generating) {
      return;
    }
    this.lastPrompt = trimmed;
    this.lastSavedUri = undefined;
    await this.generate(trimmed, trimmed);
  }

  private async handleFix(code: string, findings: Finding[]): Promise<void> {
    if (this.generating || findings.length === 0) {
      return;
    }

    const findingSummary = findings
      .map(
        (f) =>
          `- [${f.severity}] ${f.rule_id} ${f.title} (line ${f.line}): ${f.message}` +
          (f.cwe ? ` (${f.cwe})` : "") +
          (f.owasp ? ` [${f.owasp}]` : ""),
      )
      .join("\n");

    const apiPrompt = `Fix all security and privacy issues in this Python code.

Issues found by VibeCodeGuide:
${findingSummary}

Code to fix:
\`\`\`python
${code}
\`\`\``;

    await this.generate("Fix security and privacy issues in the generated code.", apiPrompt);
  }

  private async generate(displayText: string, apiPrompt: string): Promise<void> {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      this.post({
        type: "status",
        message: "Set your OpenAI API key first (⚙ button).",
        level: "error",
      });
      return;
    }

    this.generating = true;
    this.history.push({ role: "user", content: apiPrompt });
    this.post({ type: "userMessage", text: displayText });
    this.post({ type: "status", message: "Generating secure Python code…", level: "loading" });

    try {
      const config = getConfig();
      const reply = await chatCompletion(
        {
          apiKey,
          baseUrl: config.openaiBaseUrl,
          model: config.openaiModel,
          timeoutMs: config.requestTimeoutMs,
        },
        this.history,
      );

      this.history.push({ role: "assistant", content: reply });
      const code = extractPythonCode(reply);
      let savedPath: string | undefined;

      if (code) {
        savedPath = await this.saveGeneratedCode(reply, code, displayText);
      }

      this.post({ type: "assistantMessage", text: reply, code, savedPath });

      if (code && config.autoAnalyzeGeneratedCode) {
        await this.analyzeAndReport(code, savedPath);
      } else if (savedPath) {
        this.post({
          type: "status",
          message: `Saved to ${savedPath}`,
          level: "info",
        });
      } else {
        this.post({ type: "status", message: "", level: "info" });
      }
    } catch (err) {
      this.history.pop();
      const message = err instanceof OpenAiError ? err.message : String(err);
      this.post({ type: "status", message, level: "error" });
    } finally {
      this.generating = false;
    }
  }

  private async analyzeAndReport(code: string, savedPath?: string): Promise<void> {
    const config = getConfig();
    this.post({ type: "status", message: "Scanning generated code…", level: "loading" });

    try {
      const result = await analyzeCode(config, code);
      const clean = result.findings.length === 0 && result.parse_errors.length === 0;
      this.post({ type: "analysisResult", findings: result.findings, clean });

      const savedNote = savedPath ? `Saved to ${savedPath}. ` : "";

      if (clean) {
        this.post({
          type: "status",
          message: `${savedNote}No security or privacy issues detected.`,
          level: "info",
        });
      } else {
        const count = result.findings.length + result.parse_errors.length;
        this.post({
          type: "status",
          message: `${savedNote}${count} issue(s) found — review below or click Fix Issues.`,
          level: "error",
        });
      }
    } catch (err) {
      const hint =
        err instanceof ApiError && err.status === undefined
          ? ` Is the analyzer API running at ${config.securityApiUrl}?`
          : "";
      const message = err instanceof ApiError ? `${err.message}${hint}` : String(err);
      this.post({ type: "status", message, level: "error" });
    }
  }

  private async saveGeneratedCode(reply: string, code: string, displayText: string): Promise<string | undefined> {
    const filename =
      extractSuggestedFilename(reply) ??
      extractSuggestedFilename(code) ??
      deriveFilenameFromPrompt(this.lastPrompt || displayText);

    try {
      const { uri, relativePath } = await saveGeneratedPythonFile(code, filename, this.lastSavedUri);
      this.lastSavedUri = uri;
      await openSavedFile(uri);
      return relativePath;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.post({ type: "status", message: `Could not save file: ${message}`, level: "error" });
      return undefined;
    }
  }

  private async openLastSavedFile(): Promise<void> {
    if (!this.lastSavedUri) {
      vscode.window.showWarningMessage("VibeCodeGuide: no saved file yet.");
      return;
    }
    await openSavedFile(this.lastSavedUri);
  }
}

export function registerChatView(context: vscode.ExtensionContext): void {
  const provider = new ChatViewProvider(context);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(VIEW_TYPE, provider),
    vscode.commands.registerCommand("vibecodeguide.openChat", () => {
      void vscode.commands.executeCommand("vibecodeguide.chatView.focus");
    }),
    vscode.commands.registerCommand("vibecodeguide.setOpenAiApiKey", () => provider.promptForApiKey()),
  );
}

function getChatHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';" />
  <style>
    :root {
      --gap: 8px;
      --radius: 6px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 12px;
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-sideBar-background);
      display: flex;
      flex-direction: column;
      height: 100vh;
      overflow: hidden;
    }
    .toolbar {
      display: flex;
      gap: var(--gap);
      margin-bottom: 10px;
      flex-shrink: 0;
    }
    .toolbar button {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
      border: none;
      border-radius: var(--radius);
      padding: 4px 10px;
      cursor: pointer;
      font-size: 12px;
    }
    .toolbar button:hover {
      background: var(--vscode-button-secondaryHoverBackground);
    }
    .toolbar .primary {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
    }
    .toolbar .primary:hover {
      background: var(--vscode-button-hoverBackground);
    }
    .banner {
      padding: 8px 10px;
      border-radius: var(--radius);
      font-size: 12px;
      margin-bottom: 10px;
      display: none;
      flex-shrink: 0;
    }
    .banner.info { display: block; background: var(--vscode-textBlockQuote-background); }
    .banner.error { display: block; background: var(--vscode-inputValidation-errorBackground); color: var(--vscode-inputValidation-errorForeground); }
    .banner.loading { display: block; background: var(--vscode-editorInfo-background, var(--vscode-textBlockQuote-background)); }
    .banner.warn { display: block; background: var(--vscode-inputValidation-warningBackground); }
    #messages {
      flex: 1;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-bottom: 10px;
      min-height: 0;
    }
    .msg {
      padding: 10px;
      border-radius: var(--radius);
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .msg.user {
      background: var(--vscode-input-background);
      border: 1px solid var(--vscode-input-border, transparent);
      align-self: flex-end;
      max-width: 92%;
    }
    .msg.assistant {
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-panel-border, transparent);
    }
    .msg .label {
      font-size: 11px;
      font-weight: 600;
      opacity: 0.7;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .code-block {
      margin-top: 8px;
      background: var(--vscode-textCodeBlock-background);
      border-radius: var(--radius);
      padding: 10px;
      font-family: var(--vscode-editor-font-family);
      font-size: 12px;
      overflow-x: auto;
      white-space: pre;
    }
    .actions {
      display: flex;
      gap: var(--gap);
      margin-top: 8px;
      flex-wrap: wrap;
    }
    .actions button {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: var(--radius);
      padding: 4px 10px;
      cursor: pointer;
      font-size: 12px;
    }
    .actions button:hover { background: var(--vscode-button-hoverBackground); }
    .actions button.secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .findings {
      margin-top: 8px;
      padding: 8px;
      border-radius: var(--radius);
      background: var(--vscode-inputValidation-warningBackground);
      font-size: 12px;
    }
    .findings ul { margin: 6px 0 0; padding-left: 18px; }
    .findings li { margin-bottom: 4px; }
    .findings .sev-CRITICAL, .findings .sev-HIGH { color: var(--vscode-errorForeground); font-weight: 600; }
    .input-area {
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      gap: var(--gap);
    }
    textarea {
      width: 100%;
      min-height: 72px;
      max-height: 160px;
      resize: vertical;
      padding: 8px 10px;
      border-radius: var(--radius);
      border: 1px solid var(--vscode-input-border, transparent);
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
    }
    textarea:focus {
      outline: 1px solid var(--vscode-focusBorder);
    }
    .send-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: var(--gap);
    }
    .hint { font-size: 11px; opacity: 0.65; }
    .saved-path {
      margin-top: 6px;
      font-size: 11px;
      opacity: 0.8;
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <button class="primary" id="configureKey" title="Set OpenAI API key">⚙ API Key</button>
    <button id="clearChat" title="Clear conversation">Clear</button>
  </div>
  <div id="banner" class="banner"></div>
  <div id="messages"><div class="empty">Describe the Python code you need.<br/>Generated code follows OWASP, CWE, and privacy rules.</div></div>
  <div class="input-area">
    <textarea id="prompt" placeholder="e.g. Create a function that validates JWT tokens from environment variables…" rows="3"></textarea>
    <div class="send-row">
      <span class="hint" id="keyStatus">API key not set</span>
      <button class="primary" id="send">Generate</button>
    </div>
  </div>
  <script>
    const vscode = acquireVsCodeApi();
    const messagesEl = document.getElementById("messages");
    const bannerEl = document.getElementById("banner");
    const promptEl = document.getElementById("prompt");
    const keyStatusEl = document.getElementById("keyStatus");
    let lastCode = "";
    let lastFindings = [];

    function setBanner(text, level) {
      bannerEl.textContent = text || "";
      bannerEl.className = "banner" + (text ? " " + level : "");
    }

    function escapeHtml(s) {
      return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    function stripFences(text) {
      return text.replace(/\`\`\`(?:python|py)?\\s*\\n([\\s\\S]*?)\`\`\`/gi, (_, c) => c.trim()).trim();
    }

    function appendUser(text) {
      document.querySelector(".empty")?.remove();
      const el = document.createElement("div");
      el.className = "msg user";
      el.innerHTML = '<div class="label">You</div>' + escapeHtml(text);
      messagesEl.appendChild(el);
      messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function appendAssistant(text, code, savedPath) {
      document.querySelector(".empty")?.remove();
      const el = document.createElement("div");
      el.className = "msg assistant";
      const prose = stripFences(text);
      let html = '<div class="label">VibeCodeGuide</div>' + escapeHtml(prose);
      if (code) {
        html += '<div class="code-block">' + escapeHtml(code) + '</div>';
        if (savedPath) {
          html += '<div class="saved-path">📄 Saved to <strong>' + escapeHtml(savedPath) + '</strong></div>';
        }
        html += '<div class="actions">';
        html += '<button data-action="open"' + (savedPath ? '' : ' style="display:none"') + '>Open Saved File</button>';
        html += '<button class="secondary" data-action="fix" style="display:none">Fix Issues</button>';
        html += '</div>';
        html += '<div class="findings" style="display:none"></div>';
        lastCode = code;
      }
      el.innerHTML = html;
      el.querySelector('[data-action="open"]')?.addEventListener("click", () => {
        vscode.postMessage({ type: "openSavedFile" });
      });
      el.querySelector('[data-action="fix"]')?.addEventListener("click", () => {
        vscode.postMessage({ type: "fixIssues", code: lastCode, findings: lastFindings });
      });
      messagesEl.appendChild(el);
      messagesEl.scrollTop = messagesEl.scrollHeight;
      return el;
    }

    function showFindings(findings, clean) {
      const assistantMsgs = messagesEl.querySelectorAll(".msg.assistant");
      const last = assistantMsgs[assistantMsgs.length - 1];
      if (!last) return;
      const box = last.querySelector(".findings");
      const fixBtn = last.querySelector('[data-action="fix"]');
      if (!box) return;
      lastFindings = findings;
      if (clean || findings.length === 0) {
        box.style.display = "none";
        if (fixBtn) fixBtn.style.display = "none";
        return;
      }
      const items = findings.map(f =>
        '<li><span class="sev-' + f.severity + '">[' + f.severity + ']</span> ' +
        escapeHtml(f.rule_id + " " + f.title + " — " + f.message) +
        (f.cwe ? ' <em>(' + escapeHtml(f.cwe) + ')</em>' : '') +
        '</li>'
      ).join("");
      box.innerHTML = "<strong>Analyzer findings:</strong><ul>" + items + "</ul>";
      box.style.display = "block";
      if (fixBtn) fixBtn.style.display = "inline-block";
    }

    document.getElementById("send").addEventListener("click", () => {
      const prompt = promptEl.value.trim();
      if (!prompt) return;
      vscode.postMessage({ type: "sendPrompt", prompt });
      promptEl.value = "";
    });

    promptEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        document.getElementById("send").click();
      }
    });

    document.getElementById("configureKey").addEventListener("click", () => {
      vscode.postMessage({ type: "configureApiKey" });
    });

    document.getElementById("clearChat").addEventListener("click", () => {
      vscode.postMessage({ type: "clearChat" });
    });

    window.addEventListener("message", (event) => {
      const msg = event.data;
      switch (msg.type) {
        case "init":
          keyStatusEl.textContent = msg.apiKeyConfigured ? "API key configured ✓" : "API key not set";
          break;
        case "apiKeyConfigured":
          keyStatusEl.textContent = msg.configured ? "API key configured ✓" : "API key not set";
          break;
        case "userMessage":
          appendUser(msg.text);
          break;
        case "assistantMessage":
          appendAssistant(msg.text, msg.code, msg.savedPath);
          break;
        case "analysisResult":
          showFindings(msg.findings, msg.clean);
          break;
        case "status":
          setBanner(msg.message, msg.level);
          break;
        case "cleared":
          messagesEl.innerHTML = '<div class="empty">Describe the Python code you need.<br/>Generated code follows OWASP, CWE, and privacy rules.</div>';
          lastCode = "";
          lastFindings = [];
          setBanner("", "info");
          break;
      }
    });

    vscode.postMessage({ type: "ready" });
  </script>
</body>
</html>`;
}
