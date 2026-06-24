// scan_skill — supply-chain trust scan for an AGENT SKILL before an agent
// installs/trusts it. A skill is a SKILL.md (instructions the agent will FOLLOW)
// plus optional bundled scripts (which run with the agent's tools + permissions).
//
// It reuses the scan_mcp_plugin engine + heuristic core verbatim (same Semgrep +
// secret scan + exfiltration/dangerous-capability/obfuscation/install-hook
// detection on any bundled code) and adds two skill-specific checks:
//   1. SKILL.md is INSTRUCTIONS the agent executes — so a prompt-injection /
//      hidden-unicode directive in it is hard-BLOCK (a skill whose own text tries
//      to override the agent is malicious by design), not just a weighted signal.
//   2. The frontmatter `allowed-tools` grant — a skill that asks for broad/
//      dangerous capabilities (Bash, Write/Edit, *) can run commands or modify
//      files with the agent's permissions; flagged and scored down.
//
// scoreSkill / analyzeSkillMd are pure so the policy is unit-testable.

import { z } from "zod";
import * as fs from "fs/promises";
import type { Dirent } from "fs";
import * as path from "path";
import { v4 as uuidv4 } from "uuid";
import { createTempDir, cleanupTempDir, cloneRepo } from "../../utils/sandbox.js";
import { runSemgrepScan } from "../../engines/semgrep.js";
import { runSecretScan } from "../../engines/trufflehog.js";
import { logScanTarget } from "../../queue/scanQueue.js";
import { walkAndScan, scanText, scoreMcpPlugin, type HeuristicFinding } from "./scanMcpPlugin.js";

export const scanSkillSchema = z.object({
  source: z.object({
    type: z.enum(["git_repo", "skill_md"]),
    url: z.string().optional(),
    skill_md: z.string().optional(),
  }),
});
export type ScanSkillInput = z.infer<typeof scanSkillSchema>;

export type SkillVerdict = "PROCEED" | "CAUTION" | "BLOCK";

// Tools that let a skill run commands or modify the host with the agent's
// permissions. Requesting them isn't malicious on its own (many legit skills
// need Bash), so it's a weighted/CAUTION signal, not a hard block.
const DANGEROUS_TOOLS = new Set(["bash", "write", "edit", "multiedit", "notebookedit", "execute", "shell", "computer"]);

/** Pull the `allowed-tools` list out of SKILL.md YAML frontmatter (handles both
 *  the inline `A, B, C` form and the `\n  - A\n  - B` block-list form). */
export function parseAllowedTools(skillMd: string): string[] {
  const fm = skillMd.match(/^---\s*[\r\n]([\s\S]*?)[\r\n]---/);
  if (!fm) return [];
  const block = fm[1];

  // Block-list form:  allowed-tools:\n  - Read\n  - Bash
  const list = block.match(/^[ \t]*allowed-tools[ \t]*:[ \t]*[\r\n]((?:[ \t]*-[ \t]*.+[\r\n]?)+)/im);
  if (list) {
    return list[1]
      .split(/[\r\n]+/)
      .map((l) => l.replace(/^[ \t]*-[ \t]*/, "").trim())
      .filter(Boolean);
  }
  // Inline form:  allowed-tools: Read, Grep, Bash   (also tolerates a [..] array)
  const inline = block.match(/^[ \t]*allowed-tools[ \t]*:[ \t]*(.+)$/im);
  if (inline) {
    return inline[1]
      .replace(/^\[|\]$/g, "")
      .split(",")
      .map((t) => t.trim().replace(/^["']|["']$/g, ""))
      .filter(Boolean);
  }
  return [];
}

export function overbroadTools(tools: string[]): string[] {
  return tools.filter((t) => {
    const base = t.toLowerCase().replace(/\(.*\)$/, "").trim(); // strip "Bash(git:*)" scoping
    return t.trim() === "*" || base === "*" || DANGEROUS_TOOLS.has(base);
  });
}

/** Pure analysis of a single SKILL.md string. */
export function analyzeSkillMd(content: string): {
  allowedTools: string[];
  overbroad: string[];
  instructionInjection: boolean;
} {
  const allowedTools = parseAllowedTools(content);
  const overbroad = overbroadTools(allowedTools);
  const instructionInjection = scanText(content, "SKILL.md").some((f) => f.category === "prompt_injection");
  return { allowedTools, overbroad, instructionInjection };
}

/** Skill verdict policy: the scan_mcp_plugin core score, then skill-specific
 *  escalation (instruction-file injection → BLOCK; broad tool grants → penalty). */
export function scoreSkill(s: {
  heuristics: HeuristicFinding[];
  sastHigh: number;
  sastCritical: number;
  verifiedSecrets: number;
  unverifiedSecrets: number;
  instructionInjection: boolean;
  overbroad: string[];
}): { trust_score: number; verdict: SkillVerdict; reasons: string[] } {
  const base = scoreMcpPlugin({
    heuristics: s.heuristics,
    sastHigh: s.sastHigh,
    sastCritical: s.sastCritical,
    verifiedSecrets: s.verifiedSecrets,
    unverifiedSecrets: s.unverifiedSecrets,
  });

  let trust_score = base.trust_score;
  let verdict: SkillVerdict = base.verdict;
  // Drop the "nothing found" placeholder once we have skill-specific signals.
  const reasons = base.reasons.filter(
    (r) => !(/^No exfiltration/.test(r) && (s.overbroad.length || s.instructionInjection)),
  );

  if (s.overbroad.length) {
    trust_score = Math.max(0, trust_score - 8 * s.overbroad.length);
    reasons.push(
      `Skill grants broad/dangerous tools (${s.overbroad.join(", ")}) — it can run commands or modify files with the agent's permissions.`,
    );
  }

  // Re-band after the tool penalty, unless the core already hard-blocked.
  if (verdict !== "BLOCK") verdict = trust_score < 50 ? "BLOCK" : trust_score < 80 ? "CAUTION" : "PROCEED";

  // A skill whose own instructions try to hijack the agent reading them is
  // malicious by design — hard BLOCK regardless of score.
  if (s.instructionInjection) {
    verdict = "BLOCK";
    reasons.unshift(
      "SKILL.md instructions contain prompt-injection / hidden-unicode directives — a skill whose own instructions try to override the agent is malicious by design.",
    );
  }

  return { trust_score, verdict, reasons };
}

const SKIP_DIRS = ["node_modules", ".git", "dist", "build", "vendor", "__pycache__", ".venv"];

async function findSkillMdFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const stack = [root];
  let visited = 0;
  while (stack.length && visited < 4000) {
    const cur = stack.pop()!;
    let entries: Dirent[];
    try { entries = await fs.readdir(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      visited++;
      const full = path.join(cur, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.includes(e.name)) stack.push(full); }
      else if (e.isFile() && e.name.toLowerCase() === "skill.md") out.push(full);
    }
  }
  return out;
}

export async function scanSkill(input: ScanSkillInput) {
  const { source } = input;
  const scanId = uuidv4();
  let tempDir: string | null = null;

  try {
    tempDir = await createTempDir();
    let scanRoot = tempDir;
    let sourceRef = "skill_md";

    if (source.type === "git_repo") {
      if (!source.url) return { error: "Git repository URL required for git_repo type", scan_id: scanId };
      logScanTarget("scan_skill", source.url);
      sourceRef = source.url;
      const repoDir = path.join(tempDir, "repo");
      const clone = await cloneRepo(source.url, repoDir);
      if (!clone.success) return { error: `Failed to clone repository: ${clone.error}`, scan_id: scanId };
      scanRoot = repoDir;
    } else {
      if (!source.skill_md) return { error: "skill_md content required for skill_md type", scan_id: scanId };
      logScanTarget("scan_skill", "skill_md");
      await fs.writeFile(path.join(tempDir, "SKILL.md"), source.skill_md, "utf-8");
    }

    const [heur, sastFindings, secretFindings, skillMdFiles] = await Promise.all([
      walkAndScan(scanRoot),
      runSemgrepScan(scanRoot).catch(() => []),
      runSecretScan(scanRoot, false).catch(() => []),
      findSkillMdFiles(scanRoot),
    ]);

    // Skill-specific pass over every SKILL.md found.
    let instructionInjection = false;
    const allowedTools = new Set<string>();
    const overbroad = new Set<string>();
    for (const f of skillMdFiles) {
      const content = await fs.readFile(f, "utf-8").catch(() => "");
      if (!content) continue;
      const a = analyzeSkillMd(content);
      a.allowedTools.forEach((t) => allowedTools.add(t));
      a.overbroad.forEach((t) => overbroad.add(t));
      if (a.instructionInjection) instructionInjection = true;
    }

    const sastHigh = sastFindings.filter((f) => f.severity === "high").length;
    const sastCritical = sastFindings.filter((f) => f.severity === "critical").length;
    const verifiedSecrets = secretFindings.filter((f) => f.severity === "critical").length;
    const unverifiedSecrets = secretFindings.filter((f) => f.severity === "high").length;

    const { trust_score, verdict, reasons } = scoreSkill({
      heuristics: heur.findings,
      sastHigh,
      sastCritical,
      verifiedSecrets,
      unverifiedSecrets,
      instructionInjection,
      overbroad: [...overbroad],
    });

    const byCat = (c: HeuristicFinding["category"]) => heur.findings.filter((h) => h.category === c).length;

    return {
      scan_id: scanId,
      source_type: source.type,
      source_ref: sourceRef,
      verdict,
      trust_score,
      reasons,
      summary: {
        files_scanned: heur.filesScanned,
        skill_md_found: skillMdFiles.length > 0,
        instruction_injection: instructionInjection,
        allowed_tools: [...allowedTools],
        overbroad_tools: [...overbroad],
        exfiltration: byCat("exfiltration"),
        prompt_injection: byCat("prompt_injection"),
        dangerous_capabilities: byCat("dangerous_capability"),
        install_hooks: byCat("install_hook"),
        obfuscation: byCat("obfuscation"),
        sast_high: sastHigh,
        sast_critical: sastCritical,
        secrets_verified: verifiedSecrets,
        secrets_unverified: unverifiedSecrets,
      },
      mcp_findings: heur.findings.slice(0, 50),
      static_findings: sastFindings.slice(0, 25),
      secret_findings: secretFindings.slice(0, 25),
      disclaimer:
        "Heuristic + static analysis — a CAUTION/PROCEED verdict is not a guarantee of safety. A skill runs with the agent's tools + permissions and its SKILL.md is executed as instructions; review BLOCK findings before trusting it.",
    };
  } finally {
    if (tempDir) await cleanupTempDir(tempDir);
  }
}
