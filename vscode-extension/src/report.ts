import type { AnalyzeResponse, Finding } from "./types";

const CATEGORY_LABELS: Record<string, string> = {
  SECURITY: "Security",
  PRIVACY: "Privacy",
  CODE_SMELL: "Code smell",
  PERFORMANCE: "Performance",
};

function categoryLabel(finding: Finding): string {
  const key = finding.category?.toUpperCase() ?? "SECURITY";
  return CATEGORY_LABELS[key] ?? finding.category ?? "Issue";
}

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
    const counts = countFindingsByCategory(result);
    const parts: string[] = [];
    if (counts.security > 0) {
      parts.push(`${counts.security} security`);
    }
    if (counts.privacy > 0) {
      parts.push(`${counts.privacy} privacy`);
    }
    if (counts.other > 0) {
      parts.push(`${counts.other} other`);
    }
    lines.push(`Found ${counts.total} issue(s): ${parts.join(", ")}.`);
    lines.push("");

    for (const f of result.findings) {
      const cat = categoryLabel(f);
      lines.push(`[${f.severity}] [${cat}] ${f.rule_id} — ${f.title}`);
      lines.push(`  Line ${f.line}: ${f.message}`);
      const metadata = [
        f.cwe,
        f.owasp,
        f.privacy_strategy ? `Strategy: ${f.privacy_strategy}` : undefined,
        f.confidence ? `Confidence: ${f.confidence}` : undefined,
        f.risk_score != null ? `Risk: ${f.risk_score}/100` : undefined,
      ]
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
  if (summary?.by_severity) {
    const parts = Object.entries(summary.by_severity)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `${count} ${sev.toLowerCase()}`);
    if (parts.length > 0) {
      lines.push(`By severity: ${parts.join(", ")}`);
    }
  }

  if (summary?.by_category) {
    const catParts = Object.entries(summary.by_category)
      .filter(([, count]) => count > 0)
      .map(([cat, count]) => `${count} ${cat.toLowerCase().replace("_", " ")}`);
    if (catParts.length > 0) {
      lines.push(`By category: ${catParts.join(", ")}`);
    }
  }

  if (summary?.risk) {
    const risk = summary.risk;
    lines.push(
      `Security score: ${risk.security_score}/100 | Privacy score: ${risk.privacy_score}/100 | ` +
        `max risk=${risk.max_risk_score}/100 | avg risk=${risk.average_risk_score}/100`,
    );
  }

  return lines.join("\n");
}

export function countFindingsByCategory(result: AnalyzeResponse): {
  security: number;
  privacy: number;
  other: number;
  total: number;
} {
  let security = 0;
  let privacy = 0;
  let other = 0;
  for (const f of result.findings) {
    if (f.category === "PRIVACY") {
      privacy += 1;
    } else if (f.category === "SECURITY" || (!f.category && !f.privacy_strategy)) {
      security += 1;
    } else {
      other += 1;
    }
  }
  return { security, privacy, other, total: result.findings.length };
}
