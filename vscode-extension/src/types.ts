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
}

export interface VibeCodeGuideConfig {
  securityApiUrl: string;
  minSeverity: Severity;
  requestTimeoutMs: number;
}
