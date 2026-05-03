import { execInSandbox } from "../utils/sandbox.js";
import type { Finding, Severity } from "../types/security.js";

interface SemgrepResult {
  results: {
    check_id: string;
    path: string;
    start: { line: number; col: number };
    end: { line: number; col: number };
    extra: {
      message: string;
      severity: string;
      metadata?: {
        cwe?: string[];
        owasp?: string[];
        confidence?: string;
        references?: string[];
      };
      lines: string;
      fix?: string;
    };
  }[];
}

function mapSeverity(semgrepSeverity: string): Severity {
  switch (semgrepSeverity.toUpperCase()) {
    case "ERROR": return "high";
    case "WARNING": return "medium";
    case "INFO": return "low";
    default: return "info";
  }
}

export async function runSemgrepScan(
  targetDir: string,
  severityThreshold: "info" | "warning" | "error" = "info"
): Promise<Finding[]> {
  const severityFilter = severityThreshold === "error" ? "--severity=ERROR"
    : severityThreshold === "warning" ? "--severity=WARNING,ERROR"
    : "";

  const args = [
    "scan",
    "--config=auto",
    "--json",
    "--no-git-ignore",
    "--max-target-bytes=1000000",
  ];

  if (severityFilter) args.push(severityFilter);
  args.push(targetDir);

  const result = await execInSandbox(
    process.env.SEMGREP_PATH || "semgrep",
    args,
    { timeout: 300_000 }
  );

  if (!result.stdout) return [];

  try {
    const parsed: SemgrepResult = JSON.parse(result.stdout);
    return parsed.results.map((r) => ({
      id: `semgrep-${r.check_id}-${r.path}-${r.start.line}`,
      title: r.check_id.split(".").pop() || r.check_id,
      description: r.extra.message,
      severity: mapSeverity(r.extra.severity),
      cwe_id: r.extra.metadata?.cwe?.[0],
      affected_system: r.path,
      affected_component: `${r.path}:${r.start.line}`,
      evidence: r.extra.lines,
      remediation: r.extra.fix || `Review and fix the security issue at ${r.path}:${r.start.line}`,
      references: r.extra.metadata?.references,
    }));
  } catch {
    return [];
  }
}
