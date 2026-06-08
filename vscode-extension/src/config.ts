import * as vscode from "vscode";
import type { Severity, VibeCodeGuideConfig } from "./types";

export function getConfig(): VibeCodeGuideConfig {
  const cfg = vscode.workspace.getConfiguration("vibecodeguide");
  return {
    securityApiUrl: cfg.get<string>("securityApiUrl", "http://127.0.0.1:8000").replace(/\/$/, ""),
    minSeverity: cfg.get<Severity>("minSeverity", "LOW"),
    requestTimeoutMs: cfg.get<number>("requestTimeoutMs", 60000),
    openaiModel: cfg.get<string>("openaiModel", "gpt-4o-mini"),
    openaiBaseUrl: cfg.get<string>("openaiBaseUrl", "https://api.openai.com/v1").replace(/\/$/, ""),
    autoAnalyzeGeneratedCode: cfg.get<boolean>("autoAnalyzeGeneratedCode", true),
    enablePrivacySecurityGuidance: cfg.get<boolean>("enablePrivacySecurityGuidance", true),
  };
}
