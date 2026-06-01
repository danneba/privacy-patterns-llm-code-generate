import type { DemoAnalyzeResponse, Finding } from "./types";

export interface EnrichedFinding extends Finding {
  isNewWithGuidance: boolean;
}

export interface ComparisonViewModel {
  sampleLabel: string;
  baselineFindings: Finding[];
  guidedFindings: EnrichedFinding[];
  baselineCount: number;
  guidedCount: number;
  additionalCount: number;
  additionalPrivacyCount: number;
  guidanceOnlyRuleIds: string[];
  privacyStrategies: string[];
}

export function findingKey(finding: Finding): string {
  return `${finding.rule_id}|${finding.file}|${finding.line ?? 0}`;
}

export function buildComparisonViewModel(demo: DemoAnalyzeResponse): ComparisonViewModel {
  const baselineKeys = new Set(demo.baseline.findings.map(findingKey));
  const guidedFindings: EnrichedFinding[] = demo.with_guidance.findings.map((finding) => ({
    ...finding,
    isNewWithGuidance: !baselineKeys.has(findingKey(finding)),
  }));
  const additionalPrivacyCount = guidedFindings.filter(
    (finding) => finding.isNewWithGuidance && finding.category === "PRIVACY",
  ).length;

  return {
    sampleLabel: demo.sample_label,
    baselineFindings: demo.baseline.findings,
    guidedFindings,
    baselineCount: demo.delta.baseline_finding_count,
    guidedCount: demo.delta.guided_finding_count,
    additionalCount: demo.delta.additional_findings_count,
    additionalPrivacyCount,
    guidanceOnlyRuleIds: demo.delta.guidance_only_rule_ids,
    privacyStrategies: demo.delta.privacy_strategies_surfaced,
  };
}
