import { execInSandbox } from "../utils/sandbox.js";
import { redactSecret } from "../utils/sanitize.js";
import type { Finding } from "../types/security.js";

interface TrufflehogResult {
  SourceMetadata: {
    Data: {
      Git?: {
        file: string;
        line: number;
        commit: string;
        repository: string;
      };
      Filesystem?: {
        file: string;
        line: number;
      };
    };
  };
  DetectorName: string;
  Verified: boolean;
  Raw: string;
  RawV2?: string;
  ExtraData?: Record<string, string>;
}

export async function runSecretScan(
  targetDir: string,
  includeHistory: boolean = false
): Promise<Finding[]> {
  const args = ["filesystem", "--json", "--no-update"];

  if (includeHistory) {
    args[0] = "git";
    args.push("--since-commit=HEAD~100");
    args.push(`file://${targetDir}`);
  } else {
    args.push(targetDir);
  }

  const result = await execInSandbox(
    process.env.TRUFFLEHOG_PATH || "trufflehog",
    args,
    { timeout: 300_000 }
  );

  const findings: Finding[] = [];
  const lines = result.stdout.split("\n").filter(Boolean);

  for (const line of lines) {
    try {
      const parsed: TrufflehogResult = JSON.parse(line);
      const source = parsed.SourceMetadata.Data.Git || parsed.SourceMetadata.Data.Filesystem;
      const filePath = source?.file || "unknown";
      const lineNum = source?.line || 0;
      const commit = (parsed.SourceMetadata.Data.Git as any)?.commit;

      findings.push({
        id: `secret-${parsed.DetectorName}-${filePath}-${lineNum}`,
        title: `Hardcoded secret detected: ${parsed.DetectorName}`,
        description: `A ${parsed.DetectorName} secret was found${parsed.Verified ? " and verified as active" : ""}. Value: ${redactSecret(parsed.Raw)}`,
        severity: parsed.Verified ? "critical" : "high",
        affected_system: filePath,
        affected_component: `${filePath}:${lineNum}${commit ? ` (commit: ${commit.slice(0, 8)})` : ""}`,
        evidence: `Detector: ${parsed.DetectorName}, Verified: ${parsed.Verified}`,
        remediation: [
          `1. Immediately rotate/revoke the ${parsed.DetectorName} credential`,
          `2. Remove the secret from ${filePath}`,
          `3. Add the secret to a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)`,
          `4. Add a .gitignore rule to prevent future commits of sensitive files`,
          parsed.Verified ? "5. URGENT: This secret is verified active — rotate immediately" : "",
        ].filter(Boolean).join("\n"),
      });
    } catch {
      // Skip malformed lines
    }
  }

  return findings;
}
