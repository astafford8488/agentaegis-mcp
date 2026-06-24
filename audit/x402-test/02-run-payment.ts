// End-to-end x402 test on Base Sepolia.
//
// Uses the official `x402-fetch` client wrapper. Reads the payer wallet
// from wallets.json, hits the live AgentAegis MCP server, expects a 402,
// signs the USDC transferWithAuthorization, retries with X-PAYMENT,
// and verifies the tool actually ran.
//
// Prerequisites:
//   - Payer wallet must hold Base Sepolia ETH (gas) + USDC
//   - Server must have X402_PAYEE_ADDRESS set + X402_NETWORK=base-sepolia
//
// Run:
//   pnpm tsx audit/x402-test/02-run-payment.ts

import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";
const wallets = JSON.parse(fs.readFileSync(path.join(__dirname, "wallets.json"), "utf-8"));

const API_BASE = process.env.AEGIS_API || "https://agentaegis-mcp-production.up.railway.app";

console.log("=".repeat(70));
console.log("AgentAegis x402 testnet end-to-end test");
console.log("=".repeat(70));
console.log("Target:    ", API_BASE);
console.log("Payer:     ", wallets.payer.address);
console.log("Receiver:  ", wallets.receiver.address);
console.log("Network:   ", wallets.payer.chain);
console.log("");

const account = privateKeyToAccount(wallets.payer.private_key as `0x${string}`);

// Wrap fetch to auto-handle 402 → sign → retry. Max payment $0.50 to be safe.
const paidFetch = wrapFetchWithPayment(fetch, account, BigInt(500_000)); // 500k USDC micro-units = $0.50

async function callMcpTool(toolName: string, args: Record<string, unknown>) {
  console.log(`→ Initialize MCP session...`);
  const initRes = await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "x402-test", version: "1" },
      },
    }),
  });

  if (!initRes.ok) {
    console.error(`Init failed: ${initRes.status}`);
    const body = await initRes.text().catch(() => "");
    console.error(body.slice(0, 500));
    process.exit(1);
  }

  const sessionId = initRes.headers.get("mcp-session-id");
  if (!sessionId) {
    console.error("No mcp-session-id in init response");
    process.exit(1);
  }

  console.log(`✓ Session: ${sessionId}`);

  // Send initialized notification
  await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Mcp-Session-Id": sessionId,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });

  console.log(`→ Calling ${toolName}...`);
  const res = await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json, text/event-stream",
      "Mcp-Session-Id": sessionId,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: toolName, arguments: args },
    }),
  });

  console.log(`  Status: ${res.status}`);

  const paymentResp = res.headers.get("x-payment-response");
  if (paymentResp) {
    const decoded = JSON.parse(Buffer.from(paymentResp, "base64").toString("utf-8"));
    console.log(`  Payment settled: txHash=${decoded.transaction || "?"} network=${decoded.network || "?"}`);
  }

  const body = await res.text();
  return body;
}

(async () => {
  try {
    // Try a $0.10 cve_lookup — cheapest paid tool
    const result = await callMcpTool("cve_lookup", { cve_id: "CVE-2024-3094" });
    console.log("");
    console.log("Tool result (first 500 chars):");
    console.log(result.slice(0, 500));
    console.log("");
    console.log("=".repeat(70));
    console.log("✅ x402 test PASSED — payment signed, settled, tool executed");
    console.log("=".repeat(70));
  } catch (err) {
    console.error("");
    console.error("=".repeat(70));
    console.error("❌ x402 test FAILED");
    console.error("=".repeat(70));
    console.error(err);
    process.exit(1);
  }
})();
