/**
 * Deep health check for the AgentAegis MCP server.
 *
 * Returns granular status per upstream dependency, not just "ok". This is
 * what an external uptime monitor (Better Stack, Datadog Synthetics, etc.)
 * should poll — it lets the monitor distinguish "MCP server is up but
 * Supabase is degraded" from "MCP server is down".
 *
 * Checks run in parallel with per-check timeouts so a single slow upstream
 * can't make /health hang.
 */

import { isDbConfigured, getDb } from "../db/client.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isCdpMode } from "../auth/x402Cdp.js";

const CHECK_TIMEOUT_MS = 2000;

export type CheckResult = {
  ok: boolean;
  latency_ms: number | null;
  detail?: string;
};

export type HealthReport = {
  status: "ok" | "degraded" | "fail";
  version: string;
  tools_count: number;
  timestamp: string;
  /**
   * Runtime config visibility — exposes whether the process detected x402
   * facilitator credentials at startup. Diagnostic-only; helps catch the
   * "I set env vars in Railway but the container never restarted" failure
   * mode without needing dashboard access.
   */
  config: {
    /** True iff both CDP_API_KEY_ID and CDP_API_KEY_SECRET are non-empty in process.env. */
    cdp_mode: boolean;
    /** Length of the secret (0 if missing). Helps detect trimmed/truncated paste. */
    cdp_secret_len: number;
    /** Length of the key ID (0 if missing). UUIDs are 36 chars. */
    cdp_key_id_len: number;
    /** Network the server will tell agents to pay on. */
    x402_network: string;
    /** Payee address (truncated for log safety). */
    x402_payee_prefix: string;
  };
  checks: {
    database: CheckResult;
    x402_facilitator: CheckResult;
    stripe: CheckResult;
  };
};

/** Wrap a promise with a timeout. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timeout after ${ms}ms`)), ms),
    ),
  ]);
}

/** Track elapsed time for a check. */
async function timed<T>(fn: () => Promise<T>): Promise<{ result: T | null; latency_ms: number; error: Error | null }> {
  const start = Date.now();
  try {
    const result = await fn();
    return { result, latency_ms: Date.now() - start, error: null };
  } catch (err) {
    return { result: null, latency_ms: Date.now() - start, error: err as Error };
  }
}

async function checkDatabase(): Promise<CheckResult> {
  if (!isDbConfigured()) {
    return { ok: false, latency_ms: null, detail: "DB not configured (SUPABASE_URL not set)" };
  }
  const { result, latency_ms, error } = await timed(async () =>
    withTimeout(
      Promise.resolve().then(() =>
        getDb().from("aegis_customers").select("id", { count: "exact", head: true }).limit(1),
      ),
      CHECK_TIMEOUT_MS,
      "database",
    ),
  );
  if (error) return { ok: false, latency_ms, detail: error.message.slice(0, 200) };
  const queryError = (result as { error?: { message?: string } } | null)?.error;
  if (queryError) return { ok: false, latency_ms, detail: (queryError.message ?? "query error").slice(0, 200) };
  return { ok: true, latency_ms };
}

async function checkX402Facilitator(): Promise<CheckResult> {
  const url = process.env.X402_FACILITATOR_URL || "https://x402.org/facilitator";
  const { result, latency_ms, error } = await timed(() =>
    withTimeout(
      fetch(url, { method: "GET", signal: AbortSignal.timeout(CHECK_TIMEOUT_MS) }),
      CHECK_TIMEOUT_MS + 500, // outer timeout slightly longer than fetch's own
      "x402-facilitator",
    ),
  );
  if (error) return { ok: false, latency_ms, detail: error.message.slice(0, 200) };
  if (!result) return { ok: false, latency_ms, detail: "no response" };
  // 4xx is fine — facilitator is up, just doesn't serve the root URL.
  // We just need a TCP-level reachable response.
  if (result.status >= 500) return { ok: false, latency_ms, detail: `HTTP ${result.status}` };
  return { ok: true, latency_ms };
}

async function checkStripe(): Promise<CheckResult> {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    return { ok: true, latency_ms: null, detail: "Stripe not configured (skipped)" };
  }
  const { result, latency_ms, error } = await timed(() =>
    withTimeout(
      fetch("https://api.stripe.com/v1/charges?limit=1", {
        method: "GET",
        headers: { Authorization: `Bearer ${key}` },
        signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
      }),
      CHECK_TIMEOUT_MS + 500,
      "stripe",
    ),
  );
  if (error) return { ok: false, latency_ms, detail: error.message.slice(0, 200) };
  if (!result) return { ok: false, latency_ms, detail: "no response" };
  if (result.status >= 500) return { ok: false, latency_ms, detail: `Stripe ${result.status}` };
  if (result.status === 401) return { ok: false, latency_ms, detail: "Stripe auth rejected" };
  return { ok: true, latency_ms };
}

/**
 * Run all checks in parallel and return the aggregate report.
 * Overall status is:
 *   - "ok"        if all checks pass
 *   - "degraded"  if at least one upstream is down but DB is up
 *   - "fail"      if database check fails
 */
export async function runHealthCheck(): Promise<HealthReport> {
  const [database, x402_facilitator, stripe] = await Promise.all([
    checkDatabase(),
    checkX402Facilitator(),
    checkStripe(),
  ]);

  let status: HealthReport["status"];
  if (!database.ok) status = "fail";
  else if (!x402_facilitator.ok || !stripe.ok) status = "degraded";
  else status = "ok";

  const payee = process.env.X402_PAYEE_ADDRESS || "";
  return {
    status,
    version: "0.3.0",
    tools_count: Object.keys(TOOL_PRICING).length,
    timestamp: new Date().toISOString(),
    config: {
      cdp_mode: isCdpMode(),
      cdp_secret_len: (process.env.CDP_API_KEY_SECRET || "").length,
      cdp_key_id_len: (process.env.CDP_API_KEY_ID || "").length,
      x402_network: process.env.X402_NETWORK || "(unset)",
      x402_payee_prefix: payee ? `${payee.slice(0, 6)}…${payee.slice(-4)}` : "(unset)",
    },
    checks: { database, x402_facilitator, stripe },
  };
}
