import type { AnalyzeResponse, Finding } from "./types";
import type { StoredAnalysis } from "./analysisHistory";

export interface ChangedLine {
  line_number: number;
  before_text: string;
  after_text: string;
}

export interface AnalysisDiff {
  fileName: string;
  previousCode: string;
  currentCode: string;
  previous: AnalyzeResponse;
  current: AnalyzeResponse;
  changedLines: ChangedLine[];
  resolved: Finding[];
  introduced: Finding[];
  unchanged: Finding[];
}

function findingKey(finding: Finding): string {
  return `${finding.rule_id}|${finding.line ?? 0}`;
}

function looseKey(finding: Finding): string {
  return `${finding.rule_id}|${finding.line ?? 0}`;
}

function detectChangedLines(beforeCode: string, afterCode: string): ChangedLine[] {
  const beforeLines = beforeCode.split(/\r?\n/);
  const afterLines = afterCode.split(/\r?\n/);
  const maxLen = Math.max(beforeLines.length, afterLines.length);
  const changed: ChangedLine[] = [];
  for (let index = 0; index < maxLen; index += 1) {
    const beforeText = beforeLines[index] ?? "";
    const afterText = afterLines[index] ?? "";
    if (beforeText !== afterText) {
      changed.push({
        line_number: index + 1,
        before_text: beforeText,
        after_text: afterText,
      });
    }
  }
  return changed;
}

function partitionFindings(
  previousFindings: Finding[],
  currentFindings: Finding[],
): Pick<AnalysisDiff, "resolved" | "introduced" | "unchanged"> {
  const previousByLoose = new Map<string, Finding>();
  for (const finding of previousFindings) {
    previousByLoose.set(looseKey(finding), finding);
  }

  const currentByLoose = new Map<string, Finding>();
  for (const finding of currentFindings) {
    currentByLoose.set(looseKey(finding), finding);
  }

  const previousKeys = new Set(previousFindings.map(findingKey));
  const currentKeys = new Set(currentFindings.map(findingKey));

  const resolved: Finding[] = [];
  const introduced: Finding[] = [];
  const unchanged: Finding[] = [];

  for (const finding of previousFindings) {
    if (!currentByLoose.has(looseKey(finding))) {
      resolved.push(finding);
    }
  }

  for (const finding of currentFindings) {
    if (!previousByLoose.has(looseKey(finding))) {
      introduced.push(finding);
    }
  }

  for (const finding of currentFindings) {
    if (previousKeys.has(findingKey(finding))) {
      unchanged.push(finding);
    }
  }

  return { resolved, introduced, unchanged };
}

export function buildAnalysisDiff(
  stored: StoredAnalysis,
  currentCode: string,
  current: AnalyzeResponse,
): AnalysisDiff {
  return {
    fileName: stored.fileName,
    previousCode: stored.code,
    currentCode,
    previous: stored.result,
    current,
    changedLines: detectChangedLines(stored.code, currentCode),
    ...partitionFindings(stored.result.findings, current.findings),
  };
}

export function countPrivacy(findings: Finding[]): number {
  return findings.filter((finding) => finding.category === "PRIVACY").length;
}
