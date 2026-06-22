// Bootstrap the Bazaar listings for the wave-2 HTTP resources by paying each once.
// Each settled payment catalogs that resource in the CDP Bazaar (HTTP-only catalog).
//
// Pays 4 endpoints: cve-lookup ($1), ssl-tls-audit ($1), threat-intel ($2),
// dependency-audit ($2) = ~$6 total. (vet-endpoint is already listed.)
// credential_check is intentionally NOT listed (HIBP resale terms).
//
// Prereq: wallets-mainnet.json payer funded with >= $6 USDC on Base.
// Run:    npx tsx audit/x402-test/04-bootstrap-bazaar.ts

import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";
const wallets = JSON.parse(fs.readFileSync(path.join(__dirname, "wallets-mainnet.json"), "utf-8"));
const account = privateKeyToAccount(wallets.payer.private_key as `0x${string}`);
const API = process.env.AEGIS_API || "https://agentaegis-mcp-production.up.railway.app";

// Cap each payment at $5 (covers the $2 max). Wallet needs >= ~$6 total.
const paidFetch = wrapFetchWithPayment(fetch, account, BigInt(5_000_000));

const calls: { path: string; body: unknown; price: string }[] = [
  { path: "/x402/cve-lookup", price: "$1", body: { cve_id: "CVE-2021-44228" } },
  { path: "/x402/ssl-tls-audit", price: "$1", body: { hostname: "stripe.com" } },
  { path: "/x402/threat-intel", price: "$2", body: { indicator: "1.1.1.1", indicator_type: "ip" } },
  { path: "/x402/dependency-audit", price: "$2", body: { source: { type: "manifest", manifest: "django==2.2.0\nflask==0.12.2\n", manifest_type: "pip" } } },
];

(async () => {
  console.log("Bootstrapping Bazaar listings from", account.address, "→", API, "\n");
  for (const c of calls) {
    process.stdout.write(`→ POST ${c.path} (${c.price}) ... `);
    try {
      const res = await paidFetch(`${API}${c.path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(c.body),
      });
      let tx = "";
      const pr = res.headers.get("x-payment-response");
      if (pr) { try { tx = JSON.parse(Buffer.from(pr, "base64").toString("utf-8")).transaction; } catch { /* ignore */ } }
      console.log(`status ${res.status}${tx ? "  tx " + tx.slice(0, 18) + "…" : ""}`);
    } catch (e) {
      console.log("FAILED:", String(e).slice(0, 160));
    }
  }
  console.log("\nDone. Listings should appear in the Bazaar within ~10 min.");
})();
