import { getDb } from "./client.js";
import type { ScanJob } from "./types.js";

export async function createScanJob(input: {
  customer_id?: string;
  api_key_id?: string;
  tool_name: string;
  target: string;
  input_params: Record<string, unknown>;
}): Promise<ScanJob> {
  const { data, error } = await getDb()
    .from("aegis_scan_jobs")
    .insert({
      customer_id: input.customer_id || null,
      api_key_id: input.api_key_id || null,
      tool_name: input.tool_name,
      target: input.target,
      input_params: input.input_params,
      status: "queued",
    })
    .select()
    .single();

  if (error) throw error;
  return data;
}

export async function markJobRunning(jobId: string): Promise<void> {
  await getDb()
    .from("aegis_scan_jobs")
    .update({ status: "running", started_at: new Date().toISOString() })
    .eq("id", jobId);
}

export async function completeJob(jobId: string, result: unknown, durationMs: number): Promise<void> {
  await getDb()
    .from("aegis_scan_jobs")
    .update({
      status: "completed",
      result: result as any,
      completed_at: new Date().toISOString(),
      duration_ms: durationMs,
    })
    .eq("id", jobId);
}

export async function failJob(jobId: string, errorMessage: string, durationMs?: number): Promise<void> {
  await getDb()
    .from("aegis_scan_jobs")
    .update({
      status: "failed",
      error_message: errorMessage,
      completed_at: new Date().toISOString(),
      duration_ms: durationMs || null,
    })
    .eq("id", jobId);
}

export async function getJob(jobId: string): Promise<ScanJob | null> {
  const { data, error } = await getDb()
    .from("aegis_scan_jobs")
    .select("*")
    .eq("id", jobId)
    .maybeSingle();

  if (error) return null;
  return data;
}

export async function listCustomerJobs(customerId: string, limit: number = 50): Promise<ScanJob[]> {
  const { data, error } = await getDb()
    .from("aegis_scan_jobs")
    .select("*")
    .eq("customer_id", customerId)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error) throw error;
  return data || [];
}
