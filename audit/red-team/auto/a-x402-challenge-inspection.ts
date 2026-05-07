/**
 * A — x402 challenge inspection (autonomous, no real $ needed)
 *
 * Validates the AgentAegis-side defenses against x402 attacks by inspecting
 * what the server returns at the 402 challenge step + how it handles
 * malformed X-PAYMENT headers. Doesn't require testnet wallets or real USDC.
 *
 * What this test covers:
 *   A2-i: Verify 402 challenge includes the EIP-712 domain {name:"USDC",
 *         version:"2"} in extra (without it, facilitator can't verify
 *         signature → all sigs fail. Spec checkpoint).
 *   A2-ii: Verify resource field is fully-qualified URL (not just /mcp).
 *   A2-iii: Verify network is "base" (mainnet, not "base-sepolia").
 *   A2-iv: Verify asset is the correct USDC contract on Base mainnet.
 *   A2-v: Verify maxAmountRequired matches expected price.
 *   A1: Send malformed X-PAYMENT (random garbage) → expect 402 with
 *        parse-failure error. Confirms the server doesn't crash on bad input.
 *   A1-replay: Send X-PAYMENT with valid base64 of arbitrary JSON →
 *              expect 402 with verification failure (facilitator rejects
 *              an authorization not signed for the requested resource).
 *
 * What this test does NOT cover:
 *   - Real on-chain replay attack (would need a real signed payload from
 *     a previous successful settlement; that's the manual a1-replay-attack.md
 *     procedure)
 *   - Real signature substitution (same — needs a real signed payload)
 *
 * Output: audit/red-team/results/<DATE>-a-x402-challenge-inspection.json
 */

import "dotenv/config";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const TARGET = process.env.TARGET_BASE_URL || "https://agentaegis-mcp-production.up.railway.app";

// Expected values per src/auth/x402Auth.ts
const EXPECTED = {
  network: "base",
  usdcContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  eip712Domain: { name: "USDC", version: "2" },
  // We probe with cve_lookup which is $0.10
  expectedPriceUsd: 0.10,
  expectedMaxAmount: "100000", // $0.10 * 1_000_000 (USDC has 6 decimals)
};

type Finding = {
  case_id: string;
  description: string;
  expected: string;
  actual: string;
  verdict: "PASS" | "FAIL";
};

async function probe402Challenge(): Promise<Record<string, unknown> | null> {
  // First do an MCP initialize to get a session ID, then call cve_lookup
  // without any auth. Server should return 402 with payment requirements.

  // Step 1: initialize to get session ID
  const initRes = await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "x402-challenge-probe", version: "0.1.0" },
      },
    }),
  });

  const sessionId = initRes.headers.get("mcp-session-id");
  if (!sessionId) {
    console.error("[probe] No Mcp-Session-Id returned from initialize. Status:", initRes.status);
    console.error("[probe] Response:", await initRes.text().catch(() => "<no body>"));
    return null;
  }

  // Step 2: send notifications/initialized to complete the handshake
  await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "mcp-session-id": sessionId,
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }),
  });

  // Step 3: call cve_lookup without auth → expect 402
  const callRes = await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "mcp-session-id": sessionId,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "cve_lookup", arguments: { cve_id: "CVE-2024-3094" } },
    }),
  });

  if (callRes.status !== 402) {
    console.error("[probe] Expected 402, got", callRes.status);
    console.error("[probe] Response:", (await callRes.text().catch(() => "")).slice(0, 500));
    return null;
  }

  return (await callRes.json().catch(() => null)) as Record<string, unknown> | null;
}

async function probeMalformedXPayment(garbage: string): Promise<{ status: number; body: string }> {
  // initialize first to get a valid session, then send the malformed payload
  const initRes = await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "probe", version: "0.1.0" } },
    }),
  });
  const sessionId = initRes.headers.get("mcp-session-id") ?? "";
  await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream", "mcp-session-id": sessionId },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized", params: {} }),
  });

  const res = await fetch(`${TARGET}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "mcp-session-id": sessionId,
      "X-PAYMENT": garbage,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "cve_lookup", arguments: { cve_id: "CVE-2024-3094" } },
    }),
  });
  return { status: res.status, body: (await res.text().catch(() => "")).slice(0, 500) };
}

async function main() {
  console.log(`[A] Probing ${TARGET} for x402 challenge correctness...\n`);

  const findings: Finding[] = [];
  const challenge = await probe402Challenge();

  if (!challenge) {
    console.error("Could not obtain 402 challenge. Aborting.");
    process.exit(2);
  }

  // The 402 body is JSON with { x402Version, error, accepts: [...] }
  const accepts = (challenge.accepts as Array<Record<string, unknown>>) || [];
  if (accepts.length === 0) {
    findings.push({
      case_id: "A2-structure",
      description: "402 challenge has at least one accepts[] entry",
      expected: "accepts.length >= 1",
      actual: `accepts.length = ${accepts.length}`,
      verdict: "FAIL",
    });
  } else {
    const req = accepts[0];

    // A2-i: EIP-712 domain present
    const extra = req.extra as Record<string, unknown> | undefined;
    findings.push({
      case_id: "A2-i",
      description: "EIP-712 domain {name:USDC, version:2} present in extra",
      expected: JSON.stringify(EXPECTED.eip712Domain),
      actual: JSON.stringify(extra ?? null),
      verdict:
        extra && extra.name === EXPECTED.eip712Domain.name && extra.version === EXPECTED.eip712Domain.version
          ? "PASS"
          : "FAIL",
    });

    // A2-ii: resource is fully-qualified URL
    const resource = req.resource as string;
    findings.push({
      case_id: "A2-ii",
      description: "resource field is fully-qualified URL (scheme + host + path)",
      expected: "starts with https://",
      actual: resource ?? "<missing>",
      verdict: typeof resource === "string" && /^https:\/\/.+\/mcp/.test(resource) ? "PASS" : "FAIL",
    });

    // A2-iii: network is base mainnet
    findings.push({
      case_id: "A2-iii",
      description: "network is base (mainnet)",
      expected: EXPECTED.network,
      actual: String(req.network),
      verdict: req.network === EXPECTED.network ? "PASS" : "FAIL",
    });

    // A2-iv: asset is correct USDC contract
    findings.push({
      case_id: "A2-iv",
      description: "asset is USDC contract on Base mainnet",
      expected: EXPECTED.usdcContract,
      actual: String(req.asset),
      verdict: req.asset === EXPECTED.usdcContract ? "PASS" : "FAIL",
    });

    // A2-v: maxAmountRequired matches cve_lookup price ($0.10 = 100000 microcents)
    findings.push({
      case_id: "A2-v",
      description: "maxAmountRequired matches expected $0.10 cve_lookup price",
      expected: EXPECTED.expectedMaxAmount,
      actual: String(req.maxAmountRequired),
      verdict: req.maxAmountRequired === EXPECTED.expectedMaxAmount ? "PASS" : "FAIL",
    });

    // A2-vi: payTo address present and looks like an Ethereum address
    const payTo = req.payTo as string;
    findings.push({
      case_id: "A2-vi",
      description: "payTo is set to a valid Ethereum address",
      expected: "0x[40 hex chars]",
      actual: payTo ?? "<missing>",
      verdict: typeof payTo === "string" && /^0x[a-fA-F0-9]{40}$/.test(payTo) ? "PASS" : "FAIL",
    });
  }

  // A1: malformed X-PAYMENT
  console.log("[A1] Probing with malformed X-PAYMENT (random garbage)...");
  const malformed = await probeMalformedXPayment("not-base64-not-anything");
  findings.push({
    case_id: "A1-malformed",
    description: "Malformed X-PAYMENT rejected with 402, server doesn't crash",
    expected: "status 402, body mentions verification or parse failure",
    actual: `status ${malformed.status}, body: ${malformed.body.slice(0, 150)}`,
    verdict: malformed.status === 402 ? "PASS" : "FAIL",
  });

  // A1: valid base64 of arbitrary JSON (looks structurally valid but isn't a real signed authorization)
  console.log("[A1] Probing with valid base64 of fake-but-structured JSON...");
  const fakePayload = Buffer.from(
    JSON.stringify({
      x402Version: 1,
      scheme: "exact",
      network: "base",
      payload: {
        signature: "0x" + "a".repeat(130),
        authorization: {
          from: "0x" + "1".repeat(40),
          to: "0x" + "2".repeat(40),
          value: "100000",
          validAfter: "0",
          validBefore: String(Math.floor(Date.now() / 1000) + 600),
          nonce: "0x" + "f".repeat(64),
        },
      },
    }),
  ).toString("base64");
  const fakeSigRes = await probeMalformedXPayment(fakePayload);
  findings.push({
    case_id: "A1-fake-sig",
    description: "Structurally valid but unsigned X-PAYMENT rejected by facilitator",
    expected: "status 402, body mentions invalid signature or verification failure",
    actual: `status ${fakeSigRes.status}, body: ${fakeSigRes.body.slice(0, 200)}`,
    verdict: fakeSigRes.status === 402 ? "PASS" : "FAIL",
  });

  // Summary
  const fails = findings.filter((f) => f.verdict === "FAIL");
  const overallVerdict: "PASS" | "FAIL" = fails.length === 0 ? "PASS" : "FAIL";

  const report = {
    test: "A — x402 challenge inspection",
    timestamp: new Date().toISOString(),
    target: TARGET,
    challenge_body: challenge,
    findings,
    summary: {
      total: findings.length,
      passed: findings.filter((f) => f.verdict === "PASS").length,
      failed: fails.length,
    },
    overall_verdict: overallVerdict,
    failed_cases: fails.map((f) => f.case_id),
  };

  console.log("\n" + JSON.stringify(report, null, 2));

  const outDir = path.join(import.meta.dirname || ".", "..", "results");
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${new Date().toISOString().slice(0, 10)}-a-x402-challenge-inspection.json`);
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote: ${outPath}`);

  process.exit(overallVerdict === "PASS" ? 0 : 1);
}

main().catch((err) => {
  console.error("[A] Fatal:", err);
  process.exit(2);
});
