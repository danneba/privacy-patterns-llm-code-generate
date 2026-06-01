import * as vscode from "vscode";
import type { Severity, VibeCodeGuideConfig } from "./types";

export function getConfig(): VibeCodeGuideConfig {
  const cfg = vscode.workspace.getConfiguration("vibecodeguide");
  return {
    securityApiUrl: cfg.get<string>("securityApiUrl", "http://127.0.0.1:8000").replace(/\/$/, ""),
    minSeverity: cfg.get<Severity>("minSeverity", "LOW"),
    requestTimeoutMs: cfg.get<number>("requestTimeoutMs", 60000),
    enablePrivacySecurityGuidance: cfg.get<boolean>("enablePrivacySecurityGuidance", true),
  };
}
