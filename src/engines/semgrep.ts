import { execInSandbox } from "../utils/sandbox.js";
import * as fs from "fs";
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
  // Populated (alongside results, which may be []) when some rule files fail to
  // load — Semgrep exits 7 in that case. We log these but never fail the scan;
  // the valid rules still produce findings.
  errors?: { code?: number; level?: string; type?: string; message?: string; path?: string }[];
}

function mapSeverity(semgrepSeverity: string): Severity {
  switch (semgrepSeverity.toUpperCase()) {
    case "ERROR": return "high";
    case "WARNING": return "medium";
    case "INFO": return "low";
    default: return "info";
  }
}

// Semgrep stamps `extra.lines` with the literal "requires login" for some registry
// rules when run offline/unauthenticated — useless as evidence on a paid finding.
// When that happens (or lines are empty), reconstruct the matched source from the
// scanned file so the output shows the actual vulnerable code. Best-effort.
function resolveEvidence(lines: string | undefined, filePath: string, start: number, end: number): string {
  const trimmed = (lines || "").trim();
  if (trimmed && trimmed.toLowerCase() !== "requires login") return lines as string;
  try {
    const content = fs.readFileSync(filePath, "utf-8").split(/\r?\n/);
    const snippet = content.slice(Math.max(0, start - 1), end).join("\n").trim();
    return snippet || (lines || "");
  } catch {
    return lines || "";
  }
}

export async function runSemgrepScan(
  targetDir: string,
  severityThreshold: "info" | "warning" | "error" = "info"
): Promise<Finding[]> {
  const severityFilter = severityThreshold === "error" ? "--severity=ERROR"
    : severityThreshold === "warning" ? "--severity=WARNING,ERROR"
    : "";

  // Rules come from a curated, BUNDLED ruleset (SEMGREP_CONFIG — set in the Docker
  // image to /opt/aegis-rules, the security rule dirs cloned from semgrep-rules at
  // build time). We deliberately do NOT use --config=auto (it profiles the project,
  // resolving to ~no rules for our context-less temp dir) and do NOT point at the
  // semgrep-rules repo ROOT (its templates / jsonnet libs / test-fixture YAML are
  // invalid as standalone rules → Semgrep exits 7 with zero findings). The
  // p/default fallback needs registry egress the locked-down runtime lacks, so prod
  // must set SEMGREP_CONFIG. --metrics=off keeps Semgrep from phoning home.
  const config = process.env.SEMGREP_CONFIG || "p/default";
  const args = [
    "scan",
    `--config=${config}`,
    "--json",
    "--metrics=off",
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

  // Semgrep writes findings to stdout as JSON even on a non-zero exit. Exit 7 means
  // "≥1 rule in the config was invalid" — NON-FATAL: the valid rules still ran and
  // their findings are in stdout. So we parse stdout regardless of exit code and
  // only bail when there is genuinely no JSON to read.
  let parsed: SemgrepResult | null = null;
  if (result.stdout) {
    try {
      parsed = JSON.parse(result.stdout) as SemgrepResult;
    } catch {
      parsed = null;
    }
  }

  if (!parsed) {
    // No parseable output = a real engine failure. Note that `stderr` here is
    // usually just Node's "Command failed" wrapper (Semgrep reports detail in the
    // stdout JSON). Log for operators rather than 500-ing a paid call.
    console.error(
      `[semgrep] no parseable output (exit ${result.exitCode}): ${(result.stderr || "(no stderr)").slice(0, 500)}`
    );
    return [];
  }

  // Invalid/erroring rules land in parsed.errors (exit 7). Log a sample for
  // observability, but keep going — they don't invalidate the valid rules' findings.
  if (parsed.errors && parsed.errors.length > 0) {
    const sample = parsed.errors
      .slice(0, 5)
      .map((e) => e.message || e.type || JSON.stringify(e))
      .join(" | ");
    console.error(
      `[semgrep] ${parsed.errors.length} rule/scan error(s) (exit ${result.exitCode}): ${sample.slice(0, 800)}`
    );
  }

  return parsed.results.map((r) => ({
    id: `semgrep-${r.check_id}-${r.path}-${r.start.line}`,
    title: r.check_id.split(".").pop() || r.check_id,
    description: r.extra.message,
    severity: mapSeverity(r.extra.severity),
    cwe_id: r.extra.metadata?.cwe?.[0],
    affected_system: r.path,
    affected_component: `${r.path}:${r.start.line}`,
    evidence: resolveEvidence(r.extra.lines, r.path, r.start.line, r.end.line),
    remediation: r.extra.fix || `Review and fix the security issue at ${r.path}:${r.start.line}`,
    references: r.extra.metadata?.references,
  }));
}
