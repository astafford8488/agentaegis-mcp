// Pay the HTTP x402 Bazaar resource (POST /x402/vet-endpoint) on Base MAINNET.
//
// The x402-express middleware emits a v1 challenge (x402Version:1), so this uses
// the v1 client (x402-fetch) — NOT the v2 client in 02-run-mainnet-payment.ts.
// On settle, the resource is cataloged in the CDP Bazaar (HTTP-only catalog), which
// is the whole point of this experiment.
//
// Prerequisites:
//   - audit/x402-test/wallets-mainnet.json (payer funded with >= $3 USDC on Base)
//   - Server has CDP creds + X402_PAYEE_ADDRESS set (it does)
//
// Run:
//   npx tsx audit/x402-test/03-run-http-resource.ts
//
// Cost: ~$3.00 USDC (vet_endpoint's real price) — one settlement.

import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";
const wallets = JSON.parse(fs.readFileSync(path.join(__dirname, "wallets-mainnet.json"), "utf-8"));
const account = privateKeyToAccount(wallets.payer.private_key as `0x${string}`);
const API = process.env.AEGIS_API || "https://agentaegis-mcp-production.up.railway.app";

console.log("=".repeat(70));
console.log("AgentAegis HTTP x402 resource — Bazaar discovery test");
console.log("=".repeat(70));
console.log("Endpoint: POST", API + "/x402/vet-endpoint");
console.log("Payer:   ", account.address);
console.log("Max pay:  $5.00 (tool price is $3.00)");
console.log("");

// Cap at $5 (5,000,000 USDC micro-units) — covers the $3.00 price.
const paidFetch = wrapFetchWithPayment(fetch, account, BigInt(5_000_000));

(async () => {
  try {
    console.log("→ Calling vet_endpoint on 'stripe.com' (402 → sign → settle → result)...");
    const t0 = Date.now();
    const res = await paidFetch(`${API}/x402/vet-endpoint`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ endpoint: "stripe.com" }),
    });
    console.log(`  Status: ${res.status} (${Date.now() - t0}ms)`);

    const pr = res.headers.get("x-payment-response");
    if (pr) {
      try {
        const d = JSON.parse(Buffer.from(pr, "base64").toString("utf-8"));
        console.log("  ✓ Settled on-chain:");
        console.log("      transaction:", d.transaction);
        console.log("      BaseScan:   https://basescan.org/tx/" + d.transaction);
      } catch {
        console.log("  payment-response:", pr.slice(0, 100));
      }
    }

    const body = await res.text();
    console.log("");
    console.log("Tool result (first 600 chars):");
    console.log(body.slice(0, 600));
    console.log("");
    console.log("=".repeat(70));
    if (res.status >= 200 && res.status < 300) {
      console.log("✅ PAID + ran. The resource should appear in the CDP Bazaar within ~10 min.");
    } else {
      console.log(`⚠ Final status ${res.status} — check the body above + Railway logs.`);
    }
    console.log("=".repeat(70));
  } catch (err) {
    console.error("❌ FAILED:", err);
    process.exit(1);
  }
})();
