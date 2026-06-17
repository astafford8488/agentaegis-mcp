// Phase 9.0 — agent identity resolution.
//
// Turns a request's auth signal into a persistent Phase 9.0 agent (aegis_agents)
// so scans/usage can be correlated across calls. Resolution is LAZY and
// best-effort: it only touches the DB when a tool actually needs identity, it
// memoizes the result on the request context, and any failure returns null
// rather than blocking the (already-paid) call.
//
// Precedence — strongest cryptographic/account binding first:
//   1. API-key customer_id  (account rail)
//   2. x402 payer wallet     (cryptographically authenticated by the ERC-3009 sig)
//   3. anonymous session     (stable per-day hash of ip+ua — free-tier exploration)

import { createHash } from "crypto";
import type { RequestContext } from "./requestContext.js";
import { isDbConfigured } from "../db/client.js";
import { resolveAgent, type Agent, type AgentIdentity } from "../db/agents.js";

/**
 * Deterministic per-UTC-day anonymous session key from ip + user-agent. Gives
 * unauthenticated free-tier callers a stable identity for the day without any
 * cross-day tracking. Returns null when there's no ip to anchor on.
 */
export function anonSessionKey(ip?: string, ua?: string, now: Date = new Date()): string | null {
  if (!ip) return null;
  const day = now.toISOString().slice(0, 10); // YYYY-MM-DD (UTC)
  const digest = createHash("sha256").update(`${ip}|${ua || ""}|${day}`).digest("hex");
  return `anon_${digest.slice(0, 32)}`;
}

/** Pick the identity anchor for a context, honoring precedence. */
export function identityFor(ctx: RequestContext): AgentIdentity | null {
  if (ctx.apiKey?.customer_id) return { customerId: ctx.apiKey.customer_id };
  if (ctx.payerWallet) return { walletAddress: ctx.payerWallet };
  const anon = anonSessionKey(ctx.ip, ctx.userAgent);
  return anon ? { anonSession: anon } : null;
}

/**
 * Resolve (and memoize on ctx) the agent for this request. Returns null if the
 * DB is unavailable or no identity anchor exists — callers MUST treat identity
 * as optional and never let a null block execution.
 */
export async function getOrResolveAgent(ctx: RequestContext | undefined): Promise<Agent | null> {
  if (!ctx) return null;
  if (ctx.agent) return ctx.agent; // already resolved this request
  if (!isDbConfigured()) return null;

  const identity = identityFor(ctx);
  if (!identity) return null;

  const agent = await resolveAgent(identity);
  if (agent) ctx.agent = agent; // memoize for the remainder of the request
  return agent;
}
