/**
 * H4 — Stripe webhook signature spoof
 *
 * /webhooks/stripe is the endpoint Stripe calls when checkout.session.completed
 * fires. Our handler verifies the Stripe-Signature header (HMAC-SHA256 of the
 * raw body) before crediting the customer balance. If signature verification
 * is missing or weak, an attacker could POST a forged event and credit
 * arbitrary balances.
 *
 * Test cases:
 *   H4-i:   Missing Stripe-Signature header → expect 400
 *   H4-ii:  Empty Stripe-Signature value → expect 400
 *   H4-iii: Stripe-Signature with random bytes → expect 400 (HMAC fail)
 *   H4-iv:  Stripe-Signature with valid format but wrong secret → expect 400
 *   H4-v:   Empty body → expect 400
 *   H4-vi:  Valid-looking event payload, no signature → expect 400
 *
 * No real Stripe data is touched. Tests only the signature verification
 * gate. If any case credits a balance or returns 200, that's a P1 finding.
 *
 * Output: audit/red-team/results/<DATE>-h4-stripe-webhook-spoof.json
 */

import "dotenv/config";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const TARGET = process.env.TARGET_BASE_URL || "https://agentaegis-mcp-production.up.railway.app";
const ENDPOINT = `${TARGET}/webhooks/stripe`;

type Case = {
  case_id: string;
  description: string;
  headers: Record<string, string>;
  body: string;
};

const SAMPLE_EVENT = JSON.stringify({
  id: "evt_test_webhook_spoof",
  object: "event",
  type: "checkout.session.completed",
  data: {
    object: {
      id: "cs_test_attacker_session",
      customer_email: "attacker@example.com",
      amount_total: 1000000, // $10,000 worth — big number to make any false-credit obvious
      payment_status: "paid",
      metadata: {
        agentaegis_customer_id: "00000000-0000-0000-0000-000000000000",
      },
    },
  },
});

const CASES: Case[] = [
  {
    case_id: "H4-i",
    description: "Missing Stripe-Signature header",
    headers: { "Content-Type": "application/json" },
    body: SAMPLE_EVENT,
  },
  {
    case_id: "H4-ii",
    description: "Empty Stripe-Signature value",
    headers: { "Content-Type": "application/json", "Stripe-Signature": "" },
    body: SAMPLE_EVENT,
  },
  {
    case_id: "H4-iii",
    description: "Stripe-Signature with random bytes",
    headers: {
      "Content-Type": "application/json",
      "Stripe-Signature": "t=1700000000,v1=" + "f".repeat(64),
    },
    body: SAMPLE_EVENT,
  },
  {
    case_id: "H4-iv",
    description: "Stripe-Signature with valid format but wrong (random) computed HMAC",
    headers: {
      "Content-Type": "application/json",
      // Realistic Stripe sig format: t=<timestamp>,v1=<hex64>
      "Stripe-Signature":
        "t=" + Math.floor(Date.now() / 1000) + ",v1=" + "9".repeat(64),
    },
    body: SAMPLE_EVENT,
  },
  {
    case_id: "H4-v",
    description: "Empty body, no signature",
    headers: { "Content-Type": "application/json" },
    body: "",
  },
  {
    case_id: "H4-vi",
    description: "Valid-looking event payload, no signature, no Stripe header",
    headers: { "Content-Type": "application/json" },
    body: SAMPLE_EVENT,
  },
];

async function probe(c: Case): Promise<{ status: number; body: string }> {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers: c.headers,
    body: c.body,
  });
  const text = (await res.text().catch(() => "")).slice(0, 300);
  return { status: res.status, body: text };
}

async function main() {
  console.log(`[H4] Probing ${ENDPOINT} for signature-verification gate...\n`);
  const results: Array<{ case: Case; status: number; body: string; verdict: "PASS" | "FAIL" }> = [];

  for (const c of CASES) {
    const { status, body } = await probe(c);
    // PASS: server rejected with 4xx (typically 400). 200/2xx would indicate
    // the spoof was accepted and the event was processed — P1 finding.
    const verdict: "PASS" | "FAIL" = status >= 400 && status < 500 ? "PASS" : "FAIL";
    results.push({ case: c, status, body, verdict });
    console.log(`  ${c.case_id} [${verdict}]: status ${status} — ${body.slice(0, 100)}`);
  }

  const fails = results.filter((r) => r.verdict === "FAIL");
  const overallVerdict: "PASS" | "FAIL" = fails.length === 0 ? "PASS" : "FAIL";

  const report = {
    test: "H4 — Stripe webhook signature spoof",
    timestamp: new Date().toISOString(),
    target: ENDPOINT,
    cases: results.map((r) => ({
      case_id: r.case.case_id,
      description: r.case.description,
      status: r.status,
      body_excerpt: r.body,
      verdict: r.verdict,
    })),
    summary: {
      total: results.length,
      passed: results.filter((r) => r.verdict === "PASS").length,
      failed: fails.length,
    },
    overall_verdict: overallVerdict,
    failed_cases: fails.map((r) => r.case.case_id),
  };

  console.log("\n" + JSON.stringify(report, null, 2));

  const outDir = path.join(import.meta.dirname || ".", "..", "results");
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${new Date().toISOString().slice(0, 10)}-h4-stripe-webhook-spoof.json`);
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote: ${outPath}`);

  process.exit(overallVerdict === "PASS" ? 0 : 1);
}

main().catch((err) => {
  console.error("[H4] Fatal:", err);
  process.exit(2);
});
