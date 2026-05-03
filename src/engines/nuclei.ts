import { execInSandbox } from "../utils/sandbox.js";
import { sanitizeShellArg } from "../utils/sanitize.js";
import type { Finding, Severity } from "../types/security.js";

export type NucleiScanDepth = "surface" | "standard" | "thorough";

interface NucleiResult {
  template_id: string;
  info: {
    name: string;
    severity: string;
    description?: string;
    reference?: string[];
    tags?: string[];
    classification?: {
      cve_id?: string[];
      cwe_id?: string[];
      cvss_score?: number;
    };
  };
  matched_at: string;
  matcher_name?: string;
  extracted_results?: string[];
}

function getTemplateArgs(depth: NucleiScanDepth): string[] {
  switch (depth) {
    case "surface":
      return ["-t", "http/misconfiguration/", "-t", "http/exposed-panels/", "-severity", "critical,high,medium"];
    case "standard":
      return ["-t", "http/vulnerabilities/", "-t", "http/misconfiguration/", "-t", "http/exposed-panels/", "-t", "http/cves/"];
    case "thorough":
      return ["-templates", "all"];
  }
}

function mapSeverity(nucleiSeverity: string): Severity {
  switch (nucleiSeverity.toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

export async function runNucleiScan(
  targetUrl: string,
  depth: NucleiScanDepth
): Promise<Finding[]> {
  const sanitizedTarget = sanitizeShellArg(targetUrl);
  const templateArgs = getTemplateArgs(depth);

  const args = [
    "-u", sanitizedTarget,
    "-jsonl",
    "-silent",
    "-no-color",
    ...templateArgs,
  ];

  const timeoutMs = depth === "thorough" ? 600_000 : 300_000;

  const result = await execInSandbox(
    process.env.NUCLEI_PATH || "nuclei",
    args,
    { timeout: timeoutMs }
  );

  const findings: Finding[] = [];
  const lines = result.stdout.split("\n").filter(Boolean);

  for (const line of lines) {
    try {
      const parsed: NucleiResult = JSON.parse(line);
      findings.push({
        id: `nuclei-${parsed.template_id}-${Date.now()}`,
        title: parsed.info.name,
        description: parsed.info.description || `Vulnerability detected by template: ${parsed.template_id}`,
        severity: mapSeverity(parsed.info.severity),
        cvss_score: parsed.info.classification?.cvss_score,
        cve_id: parsed.info.classification?.cve_id?.[0],
        cwe_id: parsed.info.classification?.cwe_id?.[0],
        affected_system: targetUrl,
        affected_component: parsed.matched_at,
        evidence: parsed.extracted_results?.join(", "),
        remediation: `Review and remediate ${parsed.info.name}. See references for details.`,
        references: parsed.info.reference,
      });
    } catch {
      // Skip malformed lines
    }
  }

  return findings;
}
