import type { AnalyzeResponse } from "./types";

export function formatAnalyzeSummary(result: AnalyzeResponse): string {
  const lines: string[] = ["=== VibeCodeGuide — Security & Privacy Analysis ===", ""];

  if (result.parse_errors.length > 0) {
    lines.push("Parse errors:");
    for (const err of result.parse_errors) {
      lines.push(`  • ${err.message}`);
    }
    lines.push("");
  }

  if (result.findings.length === 0) {
    lines.push("No security or privacy issues found.");
  } else {
    for (const f of result.findings) {
      lines.push(`[${f.severity}] ${f.rule_id} ${f.title}`);
      lines.push(`  Line ${f.line}: ${f.message}`);
      const metadata = [f.cwe, f.owasp, f.confidence ? `Confidence: ${f.confidence}` : undefined, f.risk_score ? `Risk: ${f.risk_score}/100` : undefined]
        .filter(Boolean)
        .join(" | ");
      if (metadata) {
        lines.push(`  ${metadata}`);
      }
      if (f.impact) {
        lines.push(`  Impact: ${f.impact}`);
      }
      if (f.snippet) {
        lines.push(`  Code: ${f.snippet.trim()}`);
      }
      if (f.suggestion) {
        lines.push(`  Fix: ${f.suggestion}`);
      }
      lines.push("");
    }
  }

  const summary = result.summary;
  if (summary && typeof summary === "object") {
    const bySeverity =
      "by_severity" in summary && typeof summary.by_severity === "object"
        ? (summary.by_severity as Record<string, number>)
        : (summary as Record<string, number>);
    const parts = Object.entries(bySeverity)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `${count} ${sev.toLowerCase()}`);
    if (parts.length > 0) {
      lines.push(`Summary: ${parts.join(", ")}`);
    }
    if ("risk" in summary && typeof summary.risk === "object" && summary.risk !== null) {
      const risk = summary.risk as Record<string, number>;
      lines.push(
        `Security score: ${risk.security_score}/100 | ` +
          `max risk=${risk.max_risk_score}/100 | avg risk=${risk.average_risk_score}/100`,
      );
    }
  }

  return lines.join("\n");
}
