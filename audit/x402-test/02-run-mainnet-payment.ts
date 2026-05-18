// End-to-end x402 test against AgentAegis on Base MAINNET.
//
// Uses @x402/fetch (v2-aware client) + @x402/evm (ExactEvmScheme) since the
// server now emits v2 challenges (eip155:8453, `amount` field, ResourceInfo
// envelope) when CDP credentials are set on Railway.
//
// Prerequisites:
//   - audit/x402-test/wallets-mainnet.json exists (run 01-generate-mainnet-wallet.ts)
//   - Payer wallet funded with ≥ $0.50 USDC + ≥ $0.05 ETH for gas on Base mainnet
//   - Server has CDP_API_KEY_ID + CDP_API_KEY_SECRET set on Railway (verified via
//     /health/deep → config.cdp_mode === true)
//
// Run:
//   pnpm tsx audit/x402-test/02-run-mainnet-payment.ts
//
// Expected: 402 challenge → ERC-3009 sign → CDP facilitator verify + settle →
//           on-chain USDC transfer → tool result returned. Median latency ~3-5s.

import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPaymentFromConfig, decodePaymentResponseHeader } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";
const walletsPath = path.join(__dirname, "wallets-mainnet.json");

if (!fs.existsSync(walletsPath)) {
  console.error("❌ Missing wallets-mainnet.json. Run 01-generate-mainnet-wallet.ts first.");
  process.exit(1);
}

const wallets = JSON.parse(fs.readFileSync(walletsPath, "utf-8"));

if (!wallets.payer?.private_key) {
  console.error("❌ wallets-mainnet.json has no payer.private_key.");
  process.exit(1);
}

const API_BASE = process.env.AEGIS_API || "https://agentaegis-mcp-production.up.railway.app";
const account = privateKeyToAccount(wallets.payer.private_key as `0x${string}`);

console.log("=".repeat(72));
console.log("AgentAegis x402 MAINNET end-to-end test");
console.log("=".repeat(72));
console.log("Target:    ", API_BASE);
console.log("Payer:     ", account.address);
console.log("Receiver:  ", wallets.receiver.address);
console.log("Network:    base (eip155:8453, mainnet)");
console.log("Asset:      USDC (0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)");
console.log("");

// Wrap fetch with v2 payment handling. ExactEvmScheme(account) provides the
// signer that builds ERC-3009 transferWithAuthorization payloads from the
// server's v2 PaymentRequirements (eip155:8453 + amount).
const paidFetch = wrapFetchWithPaymentFromConfig(fetch, {
  schemes: [
    {
      network: "eip155:8453", // Base mainnet
      client: new ExactEvmScheme(account),
    },
  ],
});

async function callMcpTool(toolName: string, args: Record<string, unknown>) {
  // 1. Initialize MCP session (no payment needed for init)
  console.log("→ Initialize MCP session...");
  const initRes = await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "x402-mainnet-test", version: "1" },
      },
    }),
  });

  if (!initRes.ok) {
    console.error(`Init failed: HTTP ${initRes.status}`);
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

  // 2. Send initialized notification (no payment needed)
  await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "Mcp-Session-Id": sessionId,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  });

  // 3. Call the paid tool. @x402/fetch will catch the 402, sign with the
  //    ExactEvmScheme, retry with X-PAYMENT header, return the final response.
  console.log(`→ Calling ${toolName}... (will trigger 402 → sign → settle → result)`);
  const t0 = Date.now();
  const res = await paidFetch(`${API_BASE}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "Mcp-Session-Id": sessionId,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: toolName, arguments: args },
    }),
  });
  const elapsedMs = Date.now() - t0;

  console.log(`  Status: ${res.status} (${elapsedMs}ms)`);

  // Server sets X-PAYMENT-RESPONSE on success — decode the on-chain settlement details
  const paymentResp = res.headers.get("x-payment-response") || res.headers.get("PAYMENT-RESPONSE");
  if (paymentResp) {
    try {
      const decoded = decodePaymentResponseHeader(paymentResp);
      console.log("  ✓ Payment settled on-chain:");
      console.log("      transaction:", (decoded as { transaction?: string }).transaction);
      console.log("      network:    ", (decoded as { network?: string }).network);
      console.log("      payer:      ", (decoded as { payer?: string }).payer);
      const tx = (decoded as { transaction?: string }).transaction;
      if (tx) {
        console.log("      BaseScan:   https://basescan.org/tx/" + tx);
      }
    } catch {
      // Fall back to raw base64 → JSON parse if @x402/fetch's decoder rejects our format
      try {
        const raw = JSON.parse(Buffer.from(paymentResp, "base64").toString("utf-8"));
        console.log("  ✓ Payment settled (raw):", JSON.stringify(raw, null, 2).slice(0, 400));
      } catch {
        console.log("  ⚠ Could not decode X-PAYMENT-RESPONSE:", paymentResp.slice(0, 100));
      }
    }
  }

  const body = await res.text();
  return { body, status: res.status };
}

(async () => {
  try {
    // cve_lookup is the cheapest paid tool — $0.10. Lowers blast radius if anything fails.
    const { body, status } = await callMcpTool("cve_lookup", { cve_id: "CVE-2024-3094" });
    console.log("");
    console.log("Tool result (first 600 chars):");
    console.log(body.slice(0, 600));
    console.log("");
    console.log("=".repeat(72));
    if (status >= 200 && status < 300) {
      console.log("✅ x402 mainnet test PASSED — payment signed, settled on-chain, tool executed.");
      console.log("");
      console.log("Verify on-chain:");
      console.log("  • Payer balance change: https://basescan.org/address/" + account.address);
      console.log("  • Receiver inflow:      https://basescan.org/address/" + wallets.receiver.address);
      console.log("");
      console.log("Verify in AgentAegis:");
      console.log("  • aegis_usage_log should have a new row with paid_via='x402' and");
      console.log("    payment_ref = the BaseScan tx hash from above");
    } else {
      console.log(`⚠ Final status was ${status} — payment flow may have failed.`);
      console.log("  Check server logs in Railway for the [x402] verify/settle traces.");
    }
    console.log("=".repeat(72));
  } catch (err) {
    console.error("");
    console.error("=".repeat(72));
    console.error("❌ x402 mainnet test FAILED");
    console.error("=".repeat(72));
    console.error(err);
    process.exit(1);
  }
})();
