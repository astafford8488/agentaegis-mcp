// Phase 9.0 — agent identity (aegis_agents). First-class identity anchored on
// exactly one of customer_id / wallet_address / anon_session. See migration
// 004_phase9_identity.sql.
import { getDb } from "./client.js";

export interface AgentIdentity {
  customerId?: string;
  walletAddress?: string; // x402 payer; stored lowercased
  anonSession?: string;
}

export interface Agent {
  id: string;
  customer_id: string | null;
  wallet_address: string | null;
  anon_session: string | null;
  call_count: number;
  total_spent_usd: string;
  display_name: string | null;
  created_at: string;
  last_seen_at: string;
}

function anchor(id: AgentIdentity): { col: string; val: string } | null {
  if (id.customerId) return { col: "customer_id", val: id.customerId };
  if (id.walletAddress) return { col: "wallet_address", val: id.walletAddress.toLowerCase() };
  if (id.anonSession) return { col: "anon_session", val: id.anonSession };
  return null;
}

/**
 * Find-or-create the agent for an identity. Exactly one identity field must be
 * set (matches the DB CHECK). Updates last_seen_at on an existing agent.
 * Returns null if the DB is unavailable — callers treat identity as best-effort
 * and must never let it block a paid call.
 */
export async function resolveAgent(id: AgentIdentity): Promise<Agent | null> {
  const a = anchor(id);
  if (!a) return null;
  const db = getDb();
  const { data: existing } = await db.from("aegis_agents").select("*").eq(a.col, a.val).maybeSingle();
  if (existing) {
    await db.from("aegis_agents").update({ last_seen_at: new Date().toISOString() }).eq("id", (existing as Agent).id);
    return existing as Agent;
  }
  // computed-key insert; cast past the typed-client row generic (codebase idiom)
  const { data, error } = await db.from("aegis_agents").insert({ [a.col]: a.val } as any).select().single();
  if (error) return null;
  return data as Agent;
}

/**
 * Increment usage aggregates after a paid call. Best-effort, non-atomic
 * (read+write): these are convenience counters, not billing-of-record (actual
 * billing is atomic on aegis_api_keys / on-chain settlement), so a rare race is
 * acceptable. A SECURITY DEFINER increment RPC can replace this if exactness
 * is ever required.
 */
export async function recordAgentSpend(agentId: string, priceUsd: number): Promise<void> {
  const db = getDb();
  const { data } = await db.from("aegis_agents").select("call_count, total_spent_usd").eq("id", agentId).maybeSingle();
  if (!data) return;
  await db.from("aegis_agents").update({
    call_count: ((data as Agent).call_count ?? 0) + 1,
    total_spent_usd: (Number((data as Agent).total_spent_usd) || 0) + priceUsd,
    last_seen_at: new Date().toISOString(),
  }).eq("id", agentId);
}

export async function getAgent(agentId: string): Promise<Agent | null> {
  const { data } = await getDb().from("aegis_agents").select("*").eq("id", agentId).maybeSingle();
  return (data as Agent) ?? null;
}
