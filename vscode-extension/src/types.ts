export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type FindingCategory = "SECURITY" | "PRIVACY" | "CODE_SMELL" | "PERFORMANCE";

export interface Finding {
  rule_id: string;
  title: string;
  message: string;
  severity: Severity;
  file: string;
  line: number;
  category?: FindingCategory | string;
  snippet?: string | null;
  confidence?: "LOW" | "MEDIUM" | "HIGH" | null;
  risk_score?: number | null;
  cwe?: string | null;
  owasp?: string | null;
  impact?: string | null;
  suggestion?: string | null;
  privacy_strategy?: string | null;
}

export interface ParseError {
  file: string;
  message: string;
}

export interface RiskSummary {
  security_score: number;
  privacy_score: number;
  max_risk_score: number;
  average_risk_score: number;
  high_confidence_count: number;
}

export interface ScanSummary {
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  risk?: RiskSummary;
}

export interface AnalyzeResponse {
  ok: boolean;
  error_type?: string | null;
  error_message?: string | null;
  scanned_files: number;
  findings: Finding[];
  parse_errors: ParseError[];
  summary: ScanSummary;
  guidance_enabled?: boolean;
}

export interface DemoDelta {
  additional_findings_count: number;
  guidance_only_rule_ids: string[];
  privacy_strategies_surfaced: string[];
  baseline_finding_count: number;
  guided_finding_count: number;
  baseline_security_count: number;
  guided_security_count: number;
  guided_privacy_count: number;
}

export interface DemoAnalyzeResponse {
  ok: boolean;
  sample_label: string;
  baseline: AnalyzeResponse;
  with_guidance: AnalyzeResponse;
  delta: DemoDelta;
}

export interface ChangedLine {
  line_number: number;
  before_text: string;
  after_text: string;
}

export interface CodeChangeImpactResponse {
  ok: boolean;
  sample_label: string;
  changed_lines: ChangedLine[];
  before: AnalyzeResponse;
  after: AnalyzeResponse;
  resolved_findings: Finding[];
  introduced_findings: Finding[];
  before_privacy_count: number;
  after_privacy_count: number;
  before_security_count: number;
  after_security_count: number;
  before_total_count: number;
  after_total_count: number;
  resolved_privacy_count: number;
  resolved_security_count: number;
}

export interface VibeCodeGuideConfig {
  securityApiUrl: string;
  minSeverity: Severity;
  requestTimeoutMs: number;
  openaiModel: string;
  openaiBaseUrl: string;
  autoAnalyzeGeneratedCode: boolean;
  enablePrivacySecurityGuidance: boolean;
}
