// agent_history — FREE tool. Lists the calling agent's recent scans (summary
// only) so an autonomous agent can find a prior scan_id to retrieve in full
// (agent_scan_get) or chain from (previous_scan_id). Phase 9.0.

import { z } from "zod";
import { isDbConfigured } from "../../db/client.js";
import { getRequestContext } from "../../auth/requestContext.js";
import { getOrResolveAgent } from "../../auth/agentIdentity.js";
import { listAgentScans } from "../../db/scans.js";

export const agentHistorySchema = z.object({
  limit: z.number().int().min(1).max(100).optional().describe("Max scans to return (default 25)."),
  tool: z.string().optional().describe("Filter to a single tool name (e.g. 'cve_lookup')."),
  target: z.string().optional().describe("Filter to scans of a specific target."),
  since: z.string().optional().describe("ISO-8601 timestamp; only scans started at/after this time."),
});

export type AgentHistoryInput = z.infer<typeof agentHistorySchema>;

export async function agentHistory(input: AgentHistoryInput) {
  if (!isDbConfigured()) {
    return { identified: false, scans: [], message: "History is unavailable (database not configured)." };
  }

  const ctx = getRequestContext();
  const agent = await getOrResolveAgent(ctx);

  if (!agent) {
    return {
      identified: false,
      scans: [],
      message: "No identity anchor on this request — cannot list history. See agent_whoami.",
    };
  }

  const scans = await listAgentScans(agent.id, {
    limit: input.limit ?? 25,
    tool: input.tool,
    target: input.target,
    since: input.since,
  });

  return {
    identified: true,
    agent_id: agent.id,
    count: scans.length,
    scans: scans.map((s) => ({
      scan_id: s.id,
      tool_name: s.tool_name,
      target: s.target,
      status: s.status,
      started_at: s.started_at,
      completed_at: s.completed_at,
    })),
    hint: "Retrieve a scan's full output with agent_scan_get(scan_id).",
  };
}
