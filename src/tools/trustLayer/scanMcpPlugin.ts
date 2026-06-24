// scan_mcp_plugin — supply-chain trust scan for an MCP server or agent skill,
// BEFORE an agent installs/trusts it.
//
// The agent ecosystem's biggest unguarded surface is the code it loads: an MCP
// server or skill runs with the agent's tools + credentials. This composes our
// existing static analysis (Semgrep + trufflehog) with MCP-specific heuristics
// the generic scanners miss — exfiltration (secrets/env to the network), prompt-
// injection sinks hidden in tool descriptions, dangerous capabilities, npm
// install hooks, and obfuscation — into a single PROCEED / CAUTION / BLOCK verdict.
//
// The scorer (scoreMcpPlugin) is a pure function so the verdict policy is
// unit-testable without cloning or running engines.

import { z } from "zod";
import * as fs from "fs/promises";
import type { Dirent, Stats } from "fs";
import * as path from "path";
import { v4 as uuidv4 } from "uuid";
import { createTempDir, cleanupTempDir, cloneRepo } from "../../utils/sandbox.js";
import { runSemgrepScan } from "../../engines/semgrep.js";
import { runSecretScan } from "../../engines/trufflehog.js";
import { logScanTarget } from "../../queue/scanQueue.js";

export const scanMcpPluginSchema = z.object({
  source: z.object({
    type: z.enum(["git_repo", "code_snippet"]),
    url: z.string().optional(),
    code: z.string().optional(),
    language: z.string().optional(),
  }),
});
export type ScanMcpPluginInput = z.infer<typeof scanMcpPluginSchema>;

export type McpVerdict = "PROCEED" | "CAUTION" | "BLOCK";
type HeuristicCategory = "exfiltration" | "prompt_injection" | "dangerous_capability" | "install_hook" | "obfuscation";
type HeuristicSeverity = "critical" | "high" | "medium" | "low";

export interface HeuristicFinding {
  category: HeuristicCategory;
  severity: HeuristicSeverity;
  title: string;
  file: string;
  line: number;
  evidence: string;
}

// ---- Pattern library (per-line) -------------------------------------------
// NB: forms ending in "(" must NOT carry a trailing \b — a word boundary can't
// match between "(" and a quote, so /fetch\s*\(\b/ would miss fetch('url').
const NETWORK_RE = /\bfetch\s*\(|\b(axios|XMLHttpRequest|dgram|WebSocket)\b|\bhttps?\.request\b|\bnet\.(connect|createConnection)\b|\bnavigator\.sendBeacon\b/;
const SECRET_READ_RE = /process\.env\b|os\.environ|\.ssh\/|\.aws\/credentials|id_rsa|\bAKIA[0-9A-Z]{16}\b|readFileSync?\([^)]*\.(env|pem|key)/i;
// Zero-width / bidi-override code points used to smuggle hidden instructions:
// U+200B-U+200F (zero-width + directional marks), U+202A-U+202E (bidi
// embed/override), U+2060 (word joiner), U+FEFF (BOM / zero-width no-break).
// Built from a string of \u escapes so the source carries NO literal invisible
// characters (a formatter/encoding pass can't silently mangle the class).
const HIDDEN_UNICODE_RE = new RegExp("[\\u200b-\\u200f\\u202a-\\u202e\\u2060\\ufeff]");

const LINE_PATTERNS: { category: HeuristicCategory; severity: HeuristicSeverity; title: string; re: RegExp }[] = [
  { category: "prompt_injection", severity: "high", title: "Prompt-injection phrase in code/description", re: /ignore\s+(all\s+|the\s+|your\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)|disregard\s+(your\s+|all\s+)?(instructions|rules)|you\s+are\s+now\b|new\s+system\s+prompt|<\|im_start\|>|\[\/?(system|inst)\]/i },
  { category: "prompt_injection", severity: "high", title: "Hidden / zero-width unicode (possible smuggled instructions)", re: HIDDEN_UNICODE_RE },
  { category: "dangerous_capability", severity: "high", title: "Dynamic code execution (eval/Function/vm)", re: /\beval\s*\(|new\s+Function\s*\(|\bvm\.runIn\w+/ },
  { category: "dangerous_capability", severity: "medium", title: "Shell / process execution", re: /\bchild_process\b|\bexec(Sync|File)?\s*\(|\bspawn(Sync)?\s*\(|subprocess\.(Popen|call|run)|os\.system\s*\(/ },
  { category: "obfuscation", severity: "high", title: "Obfuscated decode-then-execute", re: /(eval|Function)\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape)\s*\(|exec\s*\(\s*(base64|atob)/i },
  { category: "obfuscation", severity: "medium", title: "Long hex/unicode-escaped string blob", re: /(\\x[0-9a-fA-F]{2}){12,}|(\\u[0-9a-fA-F]{4}){10,}/ },
];

const SCAN_EXTS = new Set([".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py", ".json", ".md", ".sh", ".rb", ".go", ".txt", ".yaml", ".yml"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", "vendor", "__pycache__", ".venv"]);
const MAX_FILE_BYTES = 256 * 1024;
const MAX_FILES = 600;
const MAX_INPUT_BYTES = 2 * 1024 * 1024; // cap a single inline code_snippet input

// Exported for unit testing (the detection layer is pure — no I/O).
export function scanText(text: string, relFile: string): HeuristicFinding[] {
  const findings: HeuristicFinding[] = [];
  const lines = text.split(/\r?\n/);
  let hasNetwork = false;
  let hasSecretRead = false;
  let networkLine = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 4000) continue; // minified blob — handled below, skip per-line regex
    if (NETWORK_RE.test(line)) { hasNetwork = true; if (!networkLine) networkLine = i + 1; }
    if (SECRET_READ_RE.test(line)) hasSecretRead = true;
    for (const p of LINE_PATTERNS) {
      if (p.re.test(line)) {
        findings.push({ category: p.category, severity: p.severity, title: p.title, file: relFile, line: i + 1, evidence: line.trim().slice(0, 200) });
      }
    }
  }

  // Minified/obfuscated single-line bomb (very long lines = packed payload).
  if (lines.some((l) => l.length > 8000) && /\.(js|mjs|cjs|ts)$/.test(relFile)) {
    findings.push({ category: "obfuscation", severity: "medium", title: "Minified/packed source (hard to audit)", file: relFile, line: 1, evidence: "line length > 8000 chars" });
  }

  // File-level exfiltration heuristic: a file that BOTH reads secrets/env AND
  // talks to the network is the classic credential-exfiltration shape.
  if (hasNetwork && hasSecretRead) {
    findings.push({ category: "exfiltration", severity: "critical", title: "Reads secrets/env AND sends to the network (exfiltration pattern)", file: relFile, line: networkLine || 1, evidence: "outbound network call + secret/env read in the same file" });
  }
  return findings;
}

// Exported for unit testing — install-hook detection on a package.json string.
export function scanPackageJson(text: string, relFile: string): HeuristicFinding[] {
  const findings: HeuristicFinding[] = [];
  try {
    const pkg = JSON.parse(text) as { scripts?: Record<string, string> };
    for (const hook of ["preinstall", "install", "postinstall", "prepare", "prepublish"]) {
      const cmd = pkg.scripts?.[hook];
      if (cmd) {
        findings.push({ category: "install_hook", severity: "high", title: `npm "${hook}" lifecycle script (runs code on install)`, file: relFile, line: 1, evidence: `${hook}: ${cmd.slice(0, 160)}` });
      }
    }
  } catch { /* not valid JSON — ignore */ }
  return findings;
}

// Exported so scan_skill can reuse the same directory walk + detection.
export async function walkAndScan(dir: string): Promise<{ findings: HeuristicFinding[]; filesScanned: number }> {
  const findings: HeuristicFinding[] = [];
  let filesScanned = 0;
  const stack = [dir];
  while (stack.length && filesScanned < MAX_FILES) {
    const cur = stack.pop()!;
    let entries: Dirent[];
    try { entries = await fs.readdir(cur, { withFileTypes: true }); } catch { continue; }
    for (const ent of entries) {
      const full = path.join(cur, ent.name);
      if (ent.isDirectory()) { if (!SKIP_DIRS.has(ent.name)) stack.push(full); continue; }
      if (!ent.isFile()) continue;
      const ext = path.extname(ent.name).toLowerCase();
      if (!SCAN_EXTS.has(ext)) continue;
      let stat: Stats;
      try { stat = await fs.stat(full); } catch { continue; }
      if (stat.size > MAX_FILE_BYTES) continue;
      let text: string;
      try { text = await fs.readFile(full, "utf-8"); } catch { continue; }
      const rel = path.relative(dir, full).replace(/\\/g, "/");
      findings.push(...scanText(text, rel));
      if (ent.name === "package.json") findings.push(...scanPackageJson(text, rel));
      filesScanned++;
      if (filesScanned >= MAX_FILES) break;
    }
  }
  return { findings, filesScanned };
}

/** Pure verdict policy. Hard-BLOCK on the unambiguously-malicious shapes
 *  (exfiltration combo, a verified live secret, obfuscated-decode-then-exec);
 *  otherwise a weighted trust score → PROCEED / CAUTION / BLOCK. */
export function scoreMcpPlugin(s: {
  heuristics: HeuristicFinding[];
  sastHigh: number;
  sastCritical: number;
  verifiedSecrets: number;
  unverifiedSecrets: number;
}): { trust_score: number; verdict: McpVerdict; reasons: string[] } {
  const reasons: string[] = [];
  let score = 100;
  let hardBlock = false;

  const by = (c: HeuristicCategory, sev?: HeuristicSeverity) =>
    s.heuristics.filter((h) => h.category === c && (!sev || h.severity === sev));
  const exfil = by("exfiltration", "critical");
  const obfExec = s.heuristics.filter((h) => h.category === "obfuscation" && h.severity === "high");

  if (exfil.length) { hardBlock = true; reasons.push(`Exfiltration pattern in ${exfil.length} file(s): reads secrets/env and sends to the network.`); }
  if (s.verifiedSecrets > 0) { hardBlock = true; reasons.push(`${s.verifiedSecrets} VERIFIED live secret(s) embedded in the source.`); }
  if (obfExec.length) { hardBlock = true; reasons.push(`Obfuscated decode-then-execute (e.g. eval(atob(...))) in ${obfExec.length} place(s).`); }

  const inj = by("prompt_injection");
  const dangerHigh = by("dangerous_capability", "high");
  const dangerMed = by("dangerous_capability", "medium");
  const hooks = by("install_hook");
  const obfOther = s.heuristics.filter((h) => h.category === "obfuscation" && h.severity !== "high");

  // Weighted deductions, tuned against the test corpus. A single signal that is
  // rarely-legit inside an MCP tool (injection sink, install hook, embedded
  // secret, eval/Function) lands in CAUTION ("look before you trust"); an
  // ambiguous-but-sometimes-legit signal (a lone shell-out, one minified file)
  // stays PROCEED-with-a-note. Combos and the hard-block shapes escalate to BLOCK.
  score -= s.sastCritical * 25 + s.sastHigh * 12;
  score -= inj.length * 25;
  score -= dangerHigh.length * 22; // eval / Function / vm
  score -= dangerMed.length * 12;  // shell / child_process / spawn — was unscored before
  score -= hooks.length * 25;
  score -= obfOther.length * 12;
  score -= s.unverifiedSecrets * 25;

  if (s.sastCritical || s.sastHigh) reasons.push(`Static analysis flagged ${s.sastCritical} critical + ${s.sastHigh} high code issue(s).`);
  if (inj.length) reasons.push(`${inj.length} prompt-injection sink(s) (phrases/hidden unicode that could hijack the agent).`);
  if (dangerHigh.length) reasons.push(`${dangerHigh.length} dynamic-execution use(s) (eval / Function / vm).`);
  if (dangerMed.length) reasons.push(`${dangerMed.length} shell/process-execution use(s).`);
  if (hooks.length) reasons.push(`${hooks.length} npm install lifecycle hook(s) — code runs on install.`);
  if (obfOther.length) reasons.push(`${obfOther.length} obfuscation signal(s) (packed/minified or long encoded blob).`);
  if (s.unverifiedSecrets) reasons.push(`${s.unverifiedSecrets} possible embedded secret(s) (unverified).`);
  if (!reasons.length) reasons.push("No exfiltration, injection, dangerous-capability, or secret signals found.");

  score = Math.max(0, Math.min(100, Math.round(score)));
  let verdict: McpVerdict;
  if (hardBlock || score < 50) verdict = "BLOCK";
  else if (score < 80) verdict = "CAUTION";
  else verdict = "PROCEED";
  return { trust_score: score, verdict, reasons };
}

export async function scanMcpPlugin(input: ScanMcpPluginInput) {
  const { source } = input;
  const scanId = uuidv4();
  let tempDir: string | null = null;

  try {
    tempDir = await createTempDir();
    let scanRoot = tempDir;
    let sourceRef = "code_snippet";

    if (source.type === "git_repo") {
      if (!source.url) return { error: "Git repository URL required for git_repo type", scan_id: scanId };
      logScanTarget("scan_mcp_plugin", source.url);
      sourceRef = source.url;
      const repoDir = path.join(tempDir, "repo");
      const clone = await cloneRepo(source.url, repoDir);
      if (!clone.success) return { error: `Failed to clone repository: ${clone.error}`, scan_id: scanId };
      scanRoot = repoDir;
    } else {
      if (!source.code) return { error: "Code content required for code_snippet type", scan_id: scanId };
      if (Buffer.byteLength(source.code, "utf8") > MAX_INPUT_BYTES) {
        return { error: `code_snippet exceeds the ${MAX_INPUT_BYTES / (1024 * 1024)}MB limit`, scan_id: scanId };
      }
      logScanTarget("scan_mcp_plugin", "code_snippet");
      const ext = ({ python: ".py", typescript: ".ts", javascript: ".js" } as Record<string, string>)[source.language?.toLowerCase() || ""] || ".js";
      await fs.writeFile(path.join(tempDir, `server${ext}`), source.code, "utf-8");
    }

    // MCP-specific heuristics + the two static engines, in parallel.
    const [heur, sastFindings, secretFindings] = await Promise.all([
      walkAndScan(scanRoot),
      runSemgrepScan(scanRoot).catch(() => []),
      runSecretScan(scanRoot, false).catch(() => []),
    ]);

    const sastHigh = sastFindings.filter((f) => f.severity === "high").length;
    const sastCritical = sastFindings.filter((f) => f.severity === "critical").length;
    const verifiedSecrets = secretFindings.filter((f) => f.severity === "critical").length;
    const unverifiedSecrets = secretFindings.filter((f) => f.severity === "high").length;

    const { trust_score, verdict, reasons } = scoreMcpPlugin({
      heuristics: heur.findings,
      sastHigh,
      sastCritical,
      verifiedSecrets,
      unverifiedSecrets,
    });

    const byCat = (c: HeuristicCategory) => heur.findings.filter((h) => h.category === c);

    return {
      scan_id: scanId,
      source_type: source.type,
      source_ref: sourceRef,
      verdict,
      trust_score,
      reasons,
      summary: {
        files_scanned: heur.filesScanned,
        exfiltration: byCat("exfiltration").length,
        prompt_injection: byCat("prompt_injection").length,
        dangerous_capabilities: byCat("dangerous_capability").length,
        install_hooks: byCat("install_hook").length,
        obfuscation: byCat("obfuscation").length,
        sast_high: sastHigh,
        sast_critical: sastCritical,
        secrets_verified: verifiedSecrets,
        secrets_unverified: unverifiedSecrets,
      },
      mcp_findings: heur.findings.slice(0, 50),
      static_findings: sastFindings.slice(0, 25),
      secret_findings: secretFindings.slice(0, 25),
      disclaimer: "Heuristic + static analysis — a CAUTION/PROCEED verdict is not a guarantee of safety. Review BLOCK findings before trusting any MCP server or skill with agent credentials.",
    };
  } finally {
    if (tempDir) await cleanupTempDir(tempDir);
  }
}
