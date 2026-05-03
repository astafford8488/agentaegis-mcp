import { z } from "zod";
import { logScanTarget } from "../../queue/scanQueue.js";
import { createTempDir, cleanupTempDir, cloneRepo } from "../../utils/sandbox.js";
import { runSemgrepScan } from "../../engines/semgrep.js";
import { v4 as uuidv4 } from "uuid";
import * as fs from "fs/promises";
import * as path from "path";

export const sastScanSchema = z.object({
  source: z.object({
    type: z.enum(["git_repo", "code_snippet"]),
    url: z.string().optional(),
    code: z.string().optional(),
    language: z.string().optional(),
  }),
  severity_threshold: z.enum(["info", "warning", "error"]).optional(),
});

export type SASTScanInput = z.infer<typeof sastScanSchema>;

export async function sastScan(input: SASTScanInput) {
  const { source, severity_threshold } = input;
  const scanId = uuidv4();
  let tempDir: string | null = null;

  try {
    if (source.type === "git_repo") {
      if (!source.url) return { error: "Git repository URL required for git_repo type", scan_id: scanId };

      logScanTarget("sast_scan", source.url);
      tempDir = await createTempDir();
      const cloneResult = await cloneRepo(source.url, path.join(tempDir, "repo"));
      if (!cloneResult.success) {
        return { error: `Failed to clone repository: ${cloneResult.error}`, scan_id: scanId };
      }

      const findings = await runSemgrepScan(path.join(tempDir, "repo"), severity_threshold);

      return {
        scan_id: scanId,
        source_type: "git_repo",
        source_url: source.url,
        language: source.language || "auto-detected",
        findings,
        summary: {
          total_findings: findings.length,
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          low: findings.filter((f) => f.severity === "low").length,
        },
      };
    } else {
      if (!source.code) return { error: "Code content required for code_snippet type", scan_id: scanId };

      logScanTarget("sast_scan", "code_snippet");
      tempDir = await createTempDir();
      const ext = getFileExtension(source.language);
      const filePath = path.join(tempDir, `snippet${ext}`);
      await fs.writeFile(filePath, source.code, "utf-8");

      const findings = await runSemgrepScan(tempDir, severity_threshold);

      return {
        scan_id: scanId,
        source_type: "code_snippet",
        language: source.language || "unknown",
        findings,
        summary: {
          total_findings: findings.length,
          critical: findings.filter((f) => f.severity === "critical").length,
          high: findings.filter((f) => f.severity === "high").length,
          medium: findings.filter((f) => f.severity === "medium").length,
          low: findings.filter((f) => f.severity === "low").length,
        },
      };
    }
  } finally {
    if (tempDir) await cleanupTempDir(tempDir);
  }
}

function getFileExtension(language?: string): string {
  const map: Record<string, string> = {
    python: ".py",
    javascript: ".js",
    typescript: ".ts",
    java: ".java",
    go: ".go",
    ruby: ".rb",
    php: ".php",
    c: ".c",
    cpp: ".cpp",
    rust: ".rs",
  };
  return map[language?.toLowerCase() || ""] || ".txt";
}
