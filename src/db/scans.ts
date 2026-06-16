// Phase 9.0 — scan persistence (aegis_scans). Each paid tool call may persist a
// summary (always, small) and full_output (opt-in, large), scoped to the calling
// agent so history/correlation queries can never cross agents. See migration
// 004_phase9_identity.sql.
import { getDb } from "./client.js";

export interface ScanRow {
  id: string;
  agent_id: string;
  tool_name: string;
  target: string | null;
  status: "running" | "complete" | "failed";
  summary: unknown;
  full_output: unknown;
  previous_scan_id: string | null;
  started_at: string;
  completed_at: string | null;
  retention_until: string;
}

/** Open a scan row in `running` state. Returns the scan id, or null on failure
 *  (persistence is best-effort and must never block the paid call). `previousScanId`
 *  records chained-workflow lineage; callers must have already verified it belongs
 *  to the same agent. */
export async function createScan(input: {
  agentId: string;
  toolName: string;
  target?: string;
  previousScanId?: string;
}): Promise<string | null> {
  const { data, error } = await getDb()
    .from("aegis_scans")
    .insert({
      agent_id: input.agentId,
      tool_name: input.toolName,
      target: input.target || null,
      previous_scan_id: input.previousScanId || null,
      status: "running",
    })
    .select("id")
    .single();

  if (error) return null;
  return data.id as string;
}

export async function completeScan(scanId: string, summary: unknown, fullOutput?: unknown): Promise<void> {
  await getDb()
    .from("aegis_scans")
    .update({
      status: "complete",
      summary: summary as any,
      full_output: (fullOutput ?? null) as any,
      completed_at: new Date().toISOString(),
    })
    .eq("id", scanId);
}

export async function failScan(scanId: string): Promise<void> {
  await getDb()
    .from("aegis_scans")
    .update({ status: "failed", completed_at: new Date().toISOString() })
    .eq("id", scanId);
}

/** Recent scans for an agent (summary only — full_output is fetched per-scan via
 *  getScanForAgent). Optional filters narrow by recency, target, or tool. */
export async function listAgentScans(
  agentId: string,
  opts: { limit?: number; since?: string; target?: string; tool?: string } = {},
): Promise<ScanRow[]> {
  let q = getDb()
    .from("aegis_scans")
    .select("id, agent_id, tool_name, target, status, summary, started_at, completed_at, retention_until")
    .eq("agent_id", agentId)
    .order("started_at", { ascending: false })
    .limit(opts.limit ?? 50);

  if (opts.since) q = q.gte("started_at", opts.since);
  if (opts.target) q = q.eq("target", opts.target);
  if (opts.tool) q = q.eq("tool_name", opts.tool);

  const { data, error } = await q;
  if (error) return [];
  return (data as ScanRow[]) || [];
}

/** Fetch one scan INCLUDING full_output, scoped to the owning agent. The
 *  agent_id predicate is the authorization check: a scan id belonging to another
 *  agent returns null, not the row (prevents the IDOR class fixed on /v1/jobs). */
export async function getScanForAgent(scanId: string, agentId: string): Promise<ScanRow | null> {
  const { data, error } = await getDb()
    .from("aegis_scans")
    .select("*")
    .eq("id", scanId)
    .eq("agent_id", agentId)
    .maybeSingle();

  if (error) return null;
  return (data as ScanRow) || null;
}
