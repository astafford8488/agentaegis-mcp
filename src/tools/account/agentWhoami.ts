// agent_whoami — FREE tool. Returns the calling agent's persistent identity and
// lifetime aggregates (Phase 9.0). Lets an autonomous agent discover the stable
// agent_id it can use to correlate scans across calls and rails.
//
// Identity is resolved from the request: API-key customer, x402 payer wallet, or
// (for unauthenticated free-tier callers) a stable per-day anonymous session.

import { z } from "zod";
import { isDbConfigured } from "../../db/client.js";
import { getRequestContext } from "../../auth/requestContext.js";
import { getOrResolveAgent } from "../../auth/agentIdentity.js";

export const agentWhoamiSchema = z.object({});

export type AgentWhoamiInput = z.infer<typeof agentWhoamiSchema>;

export async function agentWhoami(_input: AgentWhoamiInput) {
  if (!isDbConfigured()) {
    return { identified: false, message: "Identity is unavailable (database not configured)." };
  }

  const ctx = getRequestContext();
  const agent = await getOrResolveAgent(ctx);

  if (!agent) {
    return {
      identified: false,
      message:
        "No identity anchor on this request. Call with an API key, pay via x402, or call from a stable client to receive an anonymous-session identity.",
    };
  }

  const identityType = agent.customer_id ? "api_key" : agent.wallet_address ? "wallet" : "anonymous_session";

  return {
    identified: true,
    agent_id: agent.id,
    identity_type: identityType,
    customer_id: agent.customer_id,
    wallet_address: agent.wallet_address,
    display_name: agent.display_name,
    call_count: agent.call_count,
    total_spent_usd: Number(agent.total_spent_usd),
    first_seen: agent.created_at,
    last_seen: agent.last_seen_at,
    hint: "Pass a prior scan_id as previous_scan_id on a paid tool to chain workflows; use agent_history to list your scans.",
  };
}
