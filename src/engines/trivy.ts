import { execInSandbox } from "../utils/sandbox.js";
import type { Finding, Severity } from "../types/security.js";

interface TrivyResult {
  Results: {
    Target: string;
    Type: string;
    Vulnerabilities?: {
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion?: string;
      Severity: string;
      Title?: string;
      Description?: string;
      References?: string[];
      PrimaryURL?: string;
      CVSS?: Record<string, { V3Score?: number }>;
    }[];
  }[];
}

function mapSeverity(trivySeverity: string): Severity {
  switch (trivySeverity.toUpperCase()) {
    case "CRITICAL": return "critical";
    case "HIGH": return "high";
    case "MEDIUM": return "medium";
    case "LOW": return "low";
    default: return "info";
  }
}

export async function runDependencyAudit(targetDir: string): Promise<Finding[]> {
  const args = [
    "fs",
    "--format", "json",
    "--scanners", "vuln",
    "--quiet",
    targetDir,
  ];

  const result = await execInSandbox(
    process.env.TRIVY_PATH || "trivy",
    args,
    { timeout: 300_000 }
  );

  if (!result.stdout) return [];

  try {
    const parsed: TrivyResult = JSON.parse(result.stdout);
    const findings: Finding[] = [];

    for (const target of parsed.Results) {
      if (!target.Vulnerabilities) continue;

      for (const vuln of target.Vulnerabilities) {
        const cvssScore = vuln.CVSS
          ? Math.max(...Object.values(vuln.CVSS).map((v) => v.V3Score || 0))
          : undefined;

        findings.push({
          id: `dep-${vuln.VulnerabilityID}-${vuln.PkgName}`,
          title: vuln.Title || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
          description: vuln.Description || `Vulnerability ${vuln.VulnerabilityID} found in ${vuln.PkgName}@${vuln.InstalledVersion}`,
          severity: mapSeverity(vuln.Severity),
          cvss_score: cvssScore,
          cve_id: vuln.VulnerabilityID,
          affected_system: target.Target,
          affected_component: `${vuln.PkgName}@${vuln.InstalledVersion}`,
          remediation: vuln.FixedVersion
            ? `Upgrade ${vuln.PkgName} from ${vuln.InstalledVersion} to ${vuln.FixedVersion}`
            : `No fix available yet for ${vuln.VulnerabilityID} in ${vuln.PkgName}. Monitor for updates.`,
          references: vuln.References || (vuln.PrimaryURL ? [vuln.PrimaryURL] : undefined),
        });
      }
    }

    return findings;
  } catch {
    return [];
  }
}
