#!/usr/bin/env node
//
// Tool-routing eval — does an agent given our tools pick the RIGHT one?
//
// Everything in src/instructions.ts and src/toolCatalog.ts is a bet that better
// copy produces better routing. This measures the bet instead of assuming it.
//
// It runs two arms over the same cases:
//   instructions  — the real server `instructions` as the system prompt
//   control       — no system prompt, tools only
// The difference is the value the instructions actually add. If it is ~0, the
// instructions are costing every conversation ~1.5k tokens for nothing.
//
// NO TOOL IS EVER EXECUTED. We stop at the model's first tool_use block and
// read its name, so this costs Anthropic tokens and zero scan dollars.
//
// Usage:
//   ANTHROPIC_API_KEY=sk-ant-... node evals/tool-routing.mjs
//   node evals/tool-routing.mjs --model claude-sonnet-5 --arm instructions
//   node evals/tool-routing.mjs --case reuse-prior-scan --verbose
//
// The key is read from the environment only; never paste it into a file.
// To load it from Windows Credential Manager the way the rest of this machine
// does:
//   . ~/.claude/mcp-wrappers/cred.ps1
//   $env:ANTHROPIC_API_KEY = Get-Secret 'Claude-MCP:anthropic-api-key'

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildMcpServer } from "../dist/server.js";

const HERE = dirname(fileURLToPath(import.meta.url));

const argv = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? fallback : argv[i + 1];
};
const has = (name) => argv.includes(`--${name}`);

const MODEL = flag("model", "claude-haiku-4-5-20251001");
const ONLY_CASE = flag("case", null);
const ONLY_ARM = flag("arm", null);
const VERBOSE = has("verbose");

const CRED_TARGET = "Claude-MCP:anthropic-api-key";

/** Read the key from Windows Credential Manager via the standard cred.ps1
 *  helper, so a run needs no env setup on this machine. Env still wins, which
 *  keeps the eval portable to CI. Returns null rather than throwing when the
 *  secret is absent — the caller prints the guidance. */
function keyFromCredentialManager() {
  if (process.platform !== "win32") return null;
  const helper = join(process.env.USERPROFILE ?? "", ".claude", "mcp-wrappers", "cred.ps1");
  try {
    const out = execFileSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", `. '${helper}'; Get-Secret '${CRED_TARGET}'`],
      { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] },
    );
    return out.trim() || null;
  } catch {
    return null; // not stored yet, or helper missing
  }
}

const API_KEY = process.env.ANTHROPIC_API_KEY || keyFromCredentialManager();
if (!API_KEY) {
  console.error(`
No Anthropic API key found, so the eval cannot run.

Store it once, in PowerShell (NOT Git Bash):

  . $HOME\\.claude\\mcp-wrappers\\cred.ps1; Set-Secret '${CRED_TARGET}' '<your-key>'

Then "npm run eval:routing" picks it up automatically. Setting
ANTHROPIC_API_KEY in the environment also works and takes precedence.
`);
  process.exit(2);
}

// ---- Load the real tool surface straight from the built server --------------
// Deliberately in-process rather than against prod: the eval should grade the
// code in this working tree, including uncommitted changes.

async function loadSurface() {
  const server = buildMcpServer({ skipPayment: true });
  const client = new Client({ name: "eval", version: "1.0.0" });
  const [c, s] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(s), client.connect(c)]);

  const { tools } = await client.listTools();
  return {
    instructions: client.getInstructions() ?? "",
    tools: tools.map((t) => ({
      name: t.name,
      description: t.description,
      input_schema: t.inputSchema,
    })),
    // Closed before exit: tearing the process down with the transport still
    // open trips a libuv assertion on Windows that reads like a crash.
    close: async () => {
      await client.close().catch(() => {});
      await server.close().catch(() => {});
    },
  };
}

// ---- One model call, returns the tool it reached for (or null) --------------

async function routeOnce({ prompt, tools, system }) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": API_KEY,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 1024,
      ...(system ? { system } : {}),
      tools,
      messages: [{ role: "user", content: prompt }],
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Anthropic API ${res.status}: ${body.slice(0, 300)}`);
  }

  const data = await res.json();
  const toolUse = (data.content ?? []).find((b) => b.type === "tool_use");
  const text = (data.content ?? []).filter((b) => b.type === "text").map((b) => b.text).join(" ");
  return { picked: toolUse?.name ?? null, text, usage: data.usage };
}

// ---- Scoring ----------------------------------------------------------------

function score(testCase, picked) {
  const expected = testCase.expect ?? [];
  const wanted = expected.includes("none") ? [...expected.filter((e) => e !== "none"), null] : expected;

  if (wanted.includes(picked)) return { pass: true, note: "" };
  if (picked && (testCase.avoid ?? []).includes(picked)) {
    return { pass: false, note: `picked an explicitly-wrong tool: ${picked}` };
  }
  return { pass: false, note: `picked ${picked ?? "no tool"}, wanted ${expected.join(" | ")}` };
}

// ---- Run --------------------------------------------------------------------

const { instructions, tools, close } = await loadSurface();
const registered = new Set(tools.map((t) => t.name));

let { cases } = JSON.parse(readFileSync(join(HERE, "cases.json"), "utf-8"));
if (ONLY_CASE) cases = cases.filter((c) => c.id === ONLY_CASE);

// Skip cases that depend on a tool this deployment does not register
// (credential_check only exists when HIBP_API_KEY is set).
const skipped = cases.filter((c) => c.requires && !registered.has(c.requires));
cases = cases.filter((c) => !c.requires || registered.has(c.requires));

const ARMS = { instructions, control: "" };
const armNames = ONLY_ARM ? [ONLY_ARM] : Object.keys(ARMS);

console.log(`model: ${MODEL}`);
console.log(`tools: ${tools.length}   cases: ${cases.length}   arms: ${armNames.join(", ")}`);
if (skipped.length) console.log(`skipped (tool not registered): ${skipped.map((c) => c.id).join(", ")}`);
console.log(`instructions: ${instructions.length} chars\n`);

const results = {};

for (const arm of armNames) {
  const system = ARMS[arm];
  let pass = 0;
  const failures = [];

  for (const testCase of cases) {
    let picked, text;
    try {
      ({ picked, text } = await routeOnce({ prompt: testCase.prompt, tools, system }));
    } catch (err) {
      console.error(`  ${testCase.id}: ERROR ${err.message}`);
      failures.push({ id: testCase.id, note: `error: ${err.message}` });
      continue;
    }

    const { pass: ok, note } = score(testCase, picked);
    if (ok) pass++;
    else failures.push({ id: testCase.id, note });

    if (VERBOSE) {
      console.log(`  [${arm}] ${ok ? "PASS" : "FAIL"} ${testCase.id} -> ${picked ?? "(no tool)"}`);
      if (!ok && text) console.log(`         said: ${text.slice(0, 160)}`);
    }
  }

  results[arm] = { pass, total: cases.length, failures };
  const pct = ((pass / cases.length) * 100).toFixed(0);
  console.log(`${arm.padEnd(14)} ${pass}/${cases.length}  (${pct}%)`);
  for (const f of failures) console.log(`   FAIL ${f.id.padEnd(22)} ${f.note}`);
  console.log("");
}

if (results.instructions && results.control) {
  const lift = results.instructions.pass - results.control.pass;
  const sign = lift > 0 ? "+" : "";
  console.log(`instructions lift: ${sign}${lift} case${Math.abs(lift) === 1 ? "" : "s"} over control`);
  if (lift <= 0) {
    console.log("The instructions are not earning their context cost on this case set.");
  }
}

await close();

// Non-zero exit when the primary arm has any failure, so CI can gate on it.
const primary = results.instructions ?? results[armNames[0]];
process.exitCode = primary && primary.pass === primary.total ? 0 : 1;
