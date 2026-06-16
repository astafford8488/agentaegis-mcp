// agent_scan_get — FREE tool. Retrieves one of the calling agent's prior scans,
// including the stored full output, so the agent can build on earlier results
// without re-paying. Phase 9.0.
//
// Ownership is enforced in the query (getScanForAgent scopes by agent_id): a
// scan_id belonging to a different agent returns found:false, never another
// agent's data — IDOR-safe by construction.

import { z } from "zod";
import { isDbConfigured } from "../../db/client.js";
import { getRequestContext } from "../../auth/requestContext.js";
import { getOrResolveAgent } from "../../auth/agentIdentity.js";
import { getScanForAgent } from "../../db/scans.js";

export const agentScanGetSchema = z.object({
  scan_id: z.string().uuid().describe("The scan id to retrieve (from agent_history)."),
  include_full_output: z
    .boolean()
    .optional()
    .describe("Include the full stored tool output, not just the summary (default true)."),
});

export type AgentScanGetInput = z.infer<typeof agentScanGetSchema>;

export async function agentScanGet(input: AgentScanGetInput) {
  if (!isDbConfigured()) {
    return { found: false, message: "Scan retrieval is unavailable (database not configured)." };
  }

  const ctx = getRequestContext();
  const agent = await getOrResolveAgent(ctx);

  if (!agent) {
    return { found: false, message: "No identity anchor on this request — cannot scope the lookup. See agent_whoami." };
  }

  const scan = await getScanForAgent(input.scan_id, agent.id);
  if (!scan) {
    // Either the scan doesn't exist or it belongs to a different agent — same
    // response either way, so no cross-agent existence is leaked.
    return { found: false, message: "No such scan for this agent." };
  }

  const includeFull = input.include_full_output !== false;

  return {
    found: true,
    scan_id: scan.id,
    tool_name: scan.tool_name,
    target: scan.target,
    status: scan.status,
    previous_scan_id: scan.previous_scan_id,
    started_at: scan.started_at,
    completed_at: scan.completed_at,
    retention_until: scan.retention_until,
    summary: scan.summary,
    ...(includeFull ? { full_output: scan.full_output } : {}),
  };
}
