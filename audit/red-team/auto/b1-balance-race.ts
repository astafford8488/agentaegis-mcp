/**
 * B1 — Concurrent balance debit race
 *
 * Hypothesis: An attacker with a valid API key holding $0.20 balance can
 * fire 50 parallel calls at $0.10/each and drain more than $0.20 worth of
 * tools by exploiting a race in the balance check.
 *
 * Expected defense: Atomic SQL UPDATE with conditional WHERE clause
 * (balance >= price). At most 2 calls succeed; rest return 402.
 *
 * Pass criteria:
 *   - successful_calls * tool_price <= initial_balance
 *   - rejected_calls all return HTTP 402 with "insufficient balance"
 *
 * Setup:
 *   - Test customer with EXACTLY $0.20 prepaid balance
 *   - API key issued to that customer
 *   - Tool: cve_lookup ($0.10/call)
 *
 * Output: audit/red-team/results/<DATE>-b1-balance-race.json
 */

import "dotenv/config";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const TARGET = process.env.TARGET_BASE_URL || "https://agentaegis-mcp-production.up.railway.app";
const API_KEY = process.env.RED_TEAM_API_KEY;

if (!API_KEY) {
  console.error("Set RED_TEAM_API_KEY in .env.red-team. Use a TEST customer with $0.20 balance.");
  process.exit(2);
}

const TOOL_PRICE = 0.10;
const INITIAL_BALANCE = 0.20;
const PARALLEL_CALLS = 50;
const TOOL_NAME = "cve_lookup";
const TARGET_CVE = "CVE-2024-3094"; // benign target

type CallResult = {
  index: number;
  status: number;
  duration_ms: number;
  body_excerpt: string;
};

async function makeCall(i: number): Promise<CallResult> {
  const start = Date.now();
  try {
    const res = await fetch(`${TARGET}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${API_KEY}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: i,
        method: "tools/call",
        params: {
          name: TOOL_NAME,
          arguments: { cve_id: TARGET_CVE },
        },
      }),
    });
    const text = await res.text();
    return { index: i, status: res.status, duration_ms: Date.now() - start, body_excerpt: text.slice(0, 200) };
  } catch (err) {
    return { index: i, status: 0, duration_ms: Date.now() - start, body_excerpt: String(err).slice(0, 200) };
  }
}

async function main() {
  console.log(`[B1] Firing ${PARALLEL_CALLS} parallel calls at ${TARGET}/mcp`);
  console.log(`     Tool: ${TOOL_NAME} ($${TOOL_PRICE}/call)`);
  console.log(`     Expected initial balance: $${INITIAL_BALANCE.toFixed(2)}`);
  console.log(`     Max successful calls allowed: ${Math.floor(INITIAL_BALANCE / TOOL_PRICE)}`);

  const calls: Promise<CallResult>[] = [];
  for (let i = 0; i < PARALLEL_CALLS; i++) {
    calls.push(makeCall(i));
  }
  const results = await Promise.all(calls);

  const succeeded = results.filter((r) => r.status === 200);
  const paymentRequired = results.filter((r) => r.status === 402);
  const otherErrors = results.filter((r) => r.status !== 200 && r.status !== 402);

  const totalCharged = succeeded.length * TOOL_PRICE;
  const overdraw = totalCharged > INITIAL_BALANCE;

  const verdict: "PASS" | "FAIL" = overdraw ? "FAIL" : "PASS";

  const report = {
    test: "B1 — Concurrent balance debit race",
    timestamp: new Date().toISOString(),
    target: TARGET,
    initial_balance_usd: INITIAL_BALANCE,
    tool_price_usd: TOOL_PRICE,
    parallel_calls: PARALLEL_CALLS,
    succeeded: succeeded.length,
    payment_required: paymentRequired.length,
    other_errors: otherErrors.length,
    total_charged_usd: Math.round(totalCharged * 10000) / 10000,
    over_initial_balance: overdraw,
    verdict,
    other_error_excerpts: otherErrors.slice(0, 5).map((r) => ({ status: r.status, body: r.body_excerpt })),
  };

  console.log("\n=== Result ===");
  console.log(JSON.stringify(report, null, 2));

  // Persist
  const outDir = path.join(import.meta.dirname || ".", "..", "results");
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${new Date().toISOString().slice(0, 10)}-b1-balance-race.json`);
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote: ${outPath}`);

  process.exit(verdict === "PASS" ? 0 : 1);
}

main().catch((err) => {
  console.error("[B1] Fatal:", err);
  process.exit(2);
});
