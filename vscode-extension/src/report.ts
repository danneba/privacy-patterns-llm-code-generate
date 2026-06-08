import { buildComparisonViewModel } from "./comparisonModel";
import type { AnalysisDiff } from "./analysisDiff";
import type { AnalyzeResponse, DemoAnalyzeResponse, Finding } from "./types";

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
  const mode =
    result.guidance_enabled === false
      ? "Mode: baseline (Privacy & Security Guidance disabled)\n\n"
      : result.guidance_enabled === true
        ? "Mode: full analysis (Privacy & Security Guidance enabled)\n\n"
        : "";
  const lines: string[] = [mode + "=== VibeCodeGuide — Security & Privacy Analysis ===", ""];

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

function formatFindingCompact(finding: Finding, index: number): string {
  const cat = categoryLabel(finding);
  const strategy = finding.privacy_strategy ? ` | ${finding.privacy_strategy}` : "";
  return (
    `  ${index}. [${finding.severity}][${cat}] ${finding.rule_id}${strategy} — ` +
    `${finding.title} (line ${finding.line})`
  );
}

export function formatDemoComparison(demo: DemoAnalyzeResponse): string {
  const model = buildComparisonViewModel(demo);
  const newFindings = model.guidedFindings.filter((finding) => finding.isNewWithGuidance);
  const width = 46;

  const pad = (text: string) => text.slice(0, width).padEnd(width);
  const lines: string[] = [
    "=== VibeCodeGuide — Guidance Before / After Comparison ===",
    `Sample: ${demo.sample_label}`,
    "",
    "SUMMARY",
    `  Guidance OFF : ${model.baselineCount} finding(s)`,
    `  Guidance ON  : ${model.guidedCount} finding(s)`,
    `  Difference   : +${model.additionalCount} additional finding(s)`,
    `  Privacy gain : +${model.additionalPrivacyCount} additional privacy finding(s)`,
    "",
    "HELP",
    "  Guidance OFF → only baseline analyzer checks are shown.",
    "  Guidance ON  → adds privacy/security recommendations from our guidance module.",
    "  [New with Guidance] → detected only when the guidance module is enabled.",
    "",
    pad("STEP 1 · GUIDANCE OFF") + " | " + pad("STEP 2 · GUIDANCE ON"),
    pad("-".repeat(width)) + " | " + pad("-".repeat(width)),
  ];

  const baselineLines = model.baselineFindings.length
    ? model.baselineFindings.map((f, i) => formatFindingCompact(f, i + 1))
    : ["  (no findings)"];
  const guidedLines = model.guidedFindings.length
    ? model.guidedFindings.map((f, i) => {
        const badge = f.isNewWithGuidance ? " ★ New with Guidance" : "";
        return formatFindingCompact(f, i + 1) + badge;
      })
    : ["  (no findings)"];
  const rows = Math.max(baselineLines.length, guidedLines.length);

  for (let i = 0; i < rows; i += 1) {
    lines.push(`${pad(baselineLines[i] ?? "")} | ${pad(guidedLines[i] ?? "")}`);
  }

  if (newFindings.length > 0) {
    lines.push("", "STEP 3 · ONLY WITH GUIDANCE ON");
    for (const [index, finding] of newFindings.entries()) {
      lines.push(`  ${index + 1}. ★ New with Guidance — ${formatFindingCompact(finding, index + 1).trim()}`);
      if (finding.privacy_strategy) {
        lines.push(`     Strategy: ${finding.privacy_strategy}`);
      }
    }
  }

  if (model.guidanceOnlyRuleIds.length > 0) {
    lines.push("", `Guidance-only rules: ${model.guidanceOnlyRuleIds.join(", ")}`);
  }
  if (model.privacyStrategies.length > 0) {
    lines.push(`Hoepman strategies: ${model.privacyStrategies.join(", ")}`);
  }
  lines.push("", "Open the Guidance Comparison panel for the visual side-by-side view.");
  lines.push("Toggle: Settings › VibeCodeGuide › Enable Privacy & Security Guidance");
  return lines.join("\n");
}

export function formatAnalysisDiff(diff: AnalysisDiff): string {
  const lines: string[] = [
    "=== VibeCodeGuide — Changes since last Analyze File ===",
    `File: ${diff.fileName}`,
    "",
    "SUMMARY",
    `  Before Change: ${diff.previous.findings.length} finding(s)`,
    `  After change:  ${diff.current.findings.length} finding(s)`,
    `  Resolved:     ${diff.resolved.length}`,
    `  Introduced:   ${diff.introduced.length}`,
    `  Unchanged:    ${diff.unchanged.length}`,
    "",
    "HELP",
    "  Edit the file, save, then run Analyze File again to refresh this comparison.",
    "",
    "CHANGED LINE(S)",
  ];

  for (const line of diff.changedLines) {
    lines.push(`  Line ${line.line_number}`);
    lines.push(`    Previous: ${line.before_text}`);
    lines.push(`    Current:  ${line.after_text}`);
    lines.push("");
  }

  const sections: Array<{ title: string; findings: Finding[] }> = [
    { title: "RESOLVED", findings: diff.resolved },
    { title: "INTRODUCED", findings: diff.introduced },
    { title: "UNCHANGED", findings: diff.unchanged },
  ];

  for (const section of sections) {
    lines.push(section.title);
    if (section.findings.length === 0) {
      lines.push("  (none)");
    } else {
      for (const [index, finding] of section.findings.entries()) {
        lines.push(formatFindingCompact(finding, index + 1));
        lines.push(`     ${finding.message}`);
      }
    }
    lines.push("");
  }

  lines.push("Open the Analysis changes panel for the visual comparison.");
  return lines.join("\n");
}
