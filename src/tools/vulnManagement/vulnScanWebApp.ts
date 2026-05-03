import { z } from "zod";
import { validateUrl, urlSchema } from "../../utils/sanitize.js";
import { checkRateLimit, acquireScanSlot, releaseScanSlot } from "../../utils/rateLimit.js";
import { logScanTarget } from "../../queue/scanQueue.js";
import { runNucleiScan } from "../../engines/nuclei.js";
import { v4 as uuidv4 } from "uuid";

export const vulnScanWebAppSchema = z.object({
  target_url: urlSchema,
  scan_depth: z.enum(["surface", "standard", "thorough"]),
  authentication: z.object({
    type: z.enum(["cookie", "bearer", "basic"]),
    credentials: z.string(),
  }).optional(),
  exclude_paths: z.array(z.string()).optional(),
});

export type VulnScanWebAppInput = z.infer<typeof vulnScanWebAppSchema>;

export async function vulnScanWebApp(input: VulnScanWebAppInput) {
  const { target_url, scan_depth } = input;

  const validation = validateUrl(target_url);
  if (!validation.valid) {
    return { error: validation.reason, scan_id: null };
  }

  const hostname = new URL(target_url).hostname;
  const rateCheck = checkRateLimit(`scan:${hostname}`);
  if (!rateCheck.allowed) {
    return { error: `Rate limit exceeded for target. Retry after ${new Date(rateCheck.reset_at).toISOString()}`, scan_id: null };
  }

  if (!acquireScanSlot()) {
    return { error: "Maximum concurrent scans reached. Please try again later.", scan_id: null };
  }

  const scanId = uuidv4();
  logScanTarget("vuln_scan_web_app", target_url);

  try {
    const startTime = Date.now();
    const findings = await runNucleiScan(target_url, scan_depth);
    const duration = (Date.now() - startTime) / 1000;

    // Categorize by OWASP Top 10
    const owaspCategories = {
      "A01:2021 Broken Access Control": findings.filter((f) => f.cwe_id?.includes("CWE-284") || f.title.toLowerCase().includes("access")),
      "A02:2021 Cryptographic Failures": findings.filter((f) => f.title.toLowerCase().includes("ssl") || f.title.toLowerCase().includes("crypto")),
      "A03:2021 Injection": findings.filter((f) => f.cwe_id?.includes("CWE-79") || f.cwe_id?.includes("CWE-89") || f.title.toLowerCase().includes("injection") || f.title.toLowerCase().includes("xss")),
      "A05:2021 Security Misconfiguration": findings.filter((f) => f.title.toLowerCase().includes("misconfig") || f.title.toLowerCase().includes("header")),
      "A06:2021 Vulnerable Components": findings.filter((f) => f.cve_id),
      "A07:2021 Authentication Failures": findings.filter((f) => f.title.toLowerCase().includes("auth")),
    };

    const summary = {
      total_findings: findings.length,
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
    };

    return {
      scan_id: scanId,
      target_url,
      scan_depth,
      started_at: new Date(startTime).toISOString(),
      completed_at: new Date().toISOString(),
      scan_duration_seconds: duration,
      findings,
      owasp_breakdown: Object.fromEntries(
        Object.entries(owaspCategories)
          .filter(([, v]) => v.length > 0)
          .map(([k, v]) => [k, v.length])
      ),
      summary,
    };
  } finally {
    releaseScanSlot();
  }
}
