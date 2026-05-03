import { z } from "zod";
import { logScanTarget } from "../../queue/scanQueue.js";
import { createTempDir, cleanupTempDir, cloneRepo } from "../../utils/sandbox.js";
import { runDependencyAudit } from "../../engines/trivy.js";
import { v4 as uuidv4 } from "uuid";
import * as fs from "fs/promises";
import * as path from "path";

export const dependencyAuditSchema = z.object({
  source: z.object({
    type: z.enum(["git_repo", "manifest"]),
    url: z.string().optional(),
    manifest: z.string().optional(),
    manifest_type: z.enum(["npm", "pip", "go", "ruby", "java", "cargo"]).optional(),
  }),
});

export type DependencyAuditInput = z.infer<typeof dependencyAuditSchema>;

export async function dependencyAudit(input: DependencyAuditInput) {
  const { source } = input;
  const scanId = uuidv4();
  let tempDir: string | null = null;

  try {
    if (source.type === "git_repo") {
      if (!source.url) return { error: "Git repository URL required", scan_id: scanId };

      logScanTarget("dependency_audit", source.url);
      tempDir = await createTempDir();
      const repoDir = path.join(tempDir, "repo");
      const cloneResult = await cloneRepo(source.url, repoDir);
      if (!cloneResult.success) {
        return { error: `Failed to clone repository: ${cloneResult.error}`, scan_id: scanId };
      }

      const findings = await runDependencyAudit(repoDir);
      return formatResults(scanId, "git_repo", source.url, findings);
    } else {
      if (!source.manifest) return { error: "Manifest content required", scan_id: scanId };

      logScanTarget("dependency_audit", `manifest:${source.manifest_type}`);
      tempDir = await createTempDir();

      const filename = getManifestFilename(source.manifest_type);
      await fs.writeFile(path.join(tempDir, filename), source.manifest, "utf-8");

      const findings = await runDependencyAudit(tempDir);
      return formatResults(scanId, "manifest", source.manifest_type || "unknown", findings);
    }
  } finally {
    if (tempDir) await cleanupTempDir(tempDir);
  }
}

function formatResults(scanId: string, sourceType: string, sourceRef: string, findings: any[]) {
  const critical = findings.filter((f) => f.severity === "critical");
  const high = findings.filter((f) => f.severity === "high");

  return {
    scan_id: scanId,
    source_type: sourceType,
    source_ref: sourceRef,
    findings,
    summary: {
      total_vulnerabilities: findings.length,
      critical: critical.length,
      high: high.length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      packages_affected: [...new Set(findings.map((f) => f.affected_component?.split("@")[0]))].length,
      fixable: findings.filter((f) => f.remediation?.includes("Upgrade")).length,
    },
    upgrade_actions: findings
      .filter((f) => f.remediation?.includes("Upgrade"))
      .reduce((acc: Record<string, string>, f) => {
        const pkg = f.affected_component?.split("@")[0];
        if (pkg) acc[pkg] = f.remediation;
        return acc;
      }, {}),
    immediate_actions: critical.map((f) => ({
      package: f.affected_component,
      cve: f.cve_id,
      fix: f.remediation,
    })),
  };
}

function getManifestFilename(type?: string): string {
  switch (type) {
    case "npm": return "package-lock.json";
    case "pip": return "requirements.txt";
    case "go": return "go.mod";
    case "ruby": return "Gemfile.lock";
    case "java": return "pom.xml";
    case "cargo": return "Cargo.lock";
    default: return "manifest.txt";
  }
}
