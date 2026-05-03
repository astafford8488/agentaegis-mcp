import { z } from "zod";
import { logScanTarget } from "../../queue/scanQueue.js";
import { createTempDir, cleanupTempDir, cloneRepo } from "../../utils/sandbox.js";
import { runSecretScan } from "../../engines/trufflehog.js";
import { v4 as uuidv4 } from "uuid";
import * as fs from "fs/promises";
import * as path from "path";

export const secretScanSchema = z.object({
  source: z.object({
    type: z.enum(["git_repo", "code_snippet"]),
    url: z.string().optional(),
    code: z.string().optional(),
  }),
  include_history: z.boolean().optional(),
});

export type SecretScanInput = z.infer<typeof secretScanSchema>;

export async function secretScan(input: SecretScanInput) {
  const { source, include_history } = input;
  const scanId = uuidv4();
  let tempDir: string | null = null;

  try {
    if (source.type === "git_repo") {
      if (!source.url) return { error: "Git repository URL required", scan_id: scanId };

      logScanTarget("secret_scan", source.url);
      tempDir = await createTempDir();
      const repoDir = path.join(tempDir, "repo");
      const cloneResult = await cloneRepo(source.url, repoDir);
      if (!cloneResult.success) {
        return { error: `Failed to clone repository: ${cloneResult.error}`, scan_id: scanId };
      }

      const findings = await runSecretScan(repoDir, include_history || false);

      return {
        scan_id: scanId,
        source_type: "git_repo",
        source_url: source.url,
        include_history: include_history || false,
        findings,
        summary: {
          total_secrets: findings.length,
          verified_active: findings.filter((f) => f.severity === "critical").length,
          unverified: findings.filter((f) => f.severity === "high").length,
          secret_types: [...new Set(findings.map((f) => f.title.replace("Hardcoded secret detected: ", "")))],
        },
        immediate_actions: findings
          .filter((f) => f.severity === "critical")
          .map((f) => `ROTATE NOW: ${f.title} in ${f.affected_system}`),
      };
    } else {
      if (!source.code) return { error: "Code content required for code_snippet type", scan_id: scanId };

      logScanTarget("secret_scan", "code_snippet");
      tempDir = await createTempDir();
      await fs.writeFile(path.join(tempDir, "code.txt"), source.code, "utf-8");

      const findings = await runSecretScan(tempDir, false);

      return {
        scan_id: scanId,
        source_type: "code_snippet",
        findings,
        summary: {
          total_secrets: findings.length,
          verified_active: findings.filter((f) => f.severity === "critical").length,
          unverified: findings.filter((f) => f.severity === "high").length,
        },
      };
    }
  } finally {
    if (tempDir) await cleanupTempDir(tempDir);
  }
}
