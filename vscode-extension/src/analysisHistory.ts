import * as vscode from "vscode";
import type { AnalyzeResponse } from "./types";

const STORAGE_KEY = "vibecodeguide.previousAnalysisByUri";

export interface StoredAnalysis {
  fileUri: string;
  fileName: string;
  code: string;
  result: AnalyzeResponse;
  analyzedAt: string;
}

type StoredAnalysisMap = Record<string, StoredAnalysis>;

export function getStoredAnalysis(
  context: vscode.ExtensionContext,
  fileUri: string,
): StoredAnalysis | undefined {
  const map = context.workspaceState.get<StoredAnalysisMap>(STORAGE_KEY, {});
  return map[fileUri];
}

export async function saveStoredAnalysis(
  context: vscode.ExtensionContext,
  fileUri: string,
  fileName: string,
  code: string,
  result: AnalyzeResponse,
): Promise<void> {
  const map = context.workspaceState.get<StoredAnalysisMap>(STORAGE_KEY, {});
  map[fileUri] = {
    fileUri,
    fileName,
    code,
    result,
    analyzedAt: new Date().toISOString(),
  };
  await context.workspaceState.update(STORAGE_KEY, map);
}
