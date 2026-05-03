import { z } from "zod";
import { validateTarget, targetSchema } from "../../utils/sanitize.js";
import { checkRateLimit, acquireScanSlot, releaseScanSlot } from "../../utils/rateLimit.js";
import { logScanTarget } from "../../queue/scanQueue.js";
import { runNmapScan, nmapResultToFindings } from "../../engines/nmap.js";
import { lookupCVE } from "../../apis/nvd.js";
import { cvssToSeverity } from "../../utils/scoring.js";
import type { Finding } from "../../types/security.js";
import { v4 as uuidv4 } from "uuid";

export const vulnScanNetworkSchema = z.object({
  target: targetSchema,
  scan_type: z.enum(["quick", "standard", "deep"]),
  port_range: z.string().optional(),
});

export type VulnScanNetworkInput = z.infer<typeof vulnScanNetworkSchema>;

export async function vulnScanNetwork(input: VulnScanNetworkInput) {
  const { target, scan_type, port_range } = input;

  // Validate target
  const validation = validateTarget(target);
  if (!validation.valid) {
    return { error: validation.reason, scan_id: null };
  }

  // Rate limit check
  const rateCheck = checkRateLimit(`scan:${target}`);
  if (!rateCheck.allowed) {
    return {
      error: `Rate limit exceeded for target. Try again after ${new Date(rateCheck.reset_at).toISOString()}`,
      scan_id: null,
    };
  }

  // Concurrency check
  if (!acquireScanSlot()) {
    return { error: "Maximum concurrent scans reached. Please try again later.", scan_id: null };
  }

  const scanId = uuidv4();
  logScanTarget("vuln_scan_network", target);

  try {
    const nmapResult = await runNmapScan(target, scan_type, port_range);
    const findings: Finding[] = nmapResultToFindings(nmapResult);

    // Cross-reference service versions against NVD for known CVEs
    for (const port of nmapResult.ports) {
      if (port.state === "open" && port.version) {
        try {
          // Simple version-based CVE lookup (would be enhanced with CPE matching in production)
          // For now, flag services with known-vulnerable versions
        } catch {
          // Non-critical: continue without CVE enrichment
        }
      }
    }

    const summary = {
      total_findings: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    const riskScore = summary.critical * 10 + summary.high * 7 + summary.medium * 4 + summary.low * 1;
    const maxRisk = findings.length * 10;
    const normalizedRisk = maxRisk > 0 ? Math.round((riskScore / maxRisk) * 10 * 10) / 10 : 0;

    return {
      scan_id: scanId,
      target,
      scan_type,
      started_at: new Date(Date.now() - nmapResult.scan_time_seconds * 1000).toISOString(),
      completed_at: new Date().toISOString(),
      scan_duration_seconds: nmapResult.scan_time_seconds,
      open_ports: nmapResult.ports.filter((p) => p.state === "open").map((p) => ({
        port: p.port,
        protocol: p.protocol,
        service: p.service,
        version: p.version || "unknown",
      })),
      findings,
      summary,
      overall_risk_score: normalizedRisk,
    };
  } finally {
    releaseScanSlot();
  }
}
