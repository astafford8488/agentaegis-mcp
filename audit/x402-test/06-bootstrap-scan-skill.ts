// Bootstrap the Bazaar listing for scan_skill by paying its HTTP resource once.
// Same pattern as 05-bootstrap-scan-mcp-plugin.ts. Payment settles at the x402
// gate BEFORE the handler runs, so a tiny benign skill keeps the handler fast.
//
// Prereq: wallets-mainnet.json payer funded with >= ~$5.50 USDC on Base.
// Run FROM THE REPO DIR (else tsx can't resolve node_modules / the path):
//   cd /d "...\agentaegis-mcp" && npx tsx audit/x402-test/06-bootstrap-scan-skill.ts

import { privateKeyToAccount } from "viem/accounts";
import { wrapFetchWithPayment } from "x402-fetch";
import * as fs from "fs";
import * as path from "path";

const __dirname = import.meta.dirname || ".";
const wallets = JSON.parse(fs.readFileSync(path.join(__dirname, "wallets-mainnet.json"), "utf-8"));
const account = privateKeyToAccount(wallets.payer.private_key as `0x${string}`);
const API = process.env.AEGIS_API || "https://agentaegis-mcp-production.up.railway.app";
const paidFetch = wrapFetchWithPayment(fetch, account, BigInt(5_000_000));

(async () => {
  const p = "/x402/scan-skill";
  console.log("Bootstrapping Bazaar listing for scan_skill from", account.address, "->", API, "\n");
  process.stdout.write(`-> POST ${p} ($5) ... `);
  try {
    const res = await paidFetch(`${API}${p}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        source: { type: "skill_md", skill_md: "---\nname: ping\ndescription: A no-op skill.\nallowed-tools: Read\n---\nReturn ok." },
      }),
    });
    let tx = "";
    const pr = res.headers.get("x-payment-response");
    if (pr) { try { tx = JSON.parse(Buffer.from(pr, "base64").toString("utf-8")).transaction; } catch { /* ignore */ } }
    console.log(`status ${res.status}${tx ? "  tx " + tx : ""}`);
  } catch (e) {
    console.log("FAILED:", String(e).slice(0, 200));
  }
  console.log("\nDone. The listing should appear in the Bazaar within ~10 min. Verify via /admin/bazaar-check.");
})();
