// Persistent background job queue backed by Supabase scan_jobs table.
//
// Use case: long-running scans (vuln_scan_network, vuln_scan_web_app, sast_scan,
// dependency_audit, secret_scan) routinely take 30+ seconds — sometimes minutes.
// HTTP transports time out at 30s by default. Instead of holding the request,
// we enqueue a job, return a job_id immediately, and run the scan in the
// background. Clients poll GET /v1/jobs/:id or subscribe via webhook.
//
// Architecture:
//  - enqueue() inserts into scan_jobs with status=queued
//  - runJobInBackground() runs the actual handler, updates status as it goes
//  - getJobStatus() reads back. webhook fires on completion.
//
// We don't run a separate worker process — jobs run inline in the Vercel/
// Railway request that enqueued them, just unawaited. This works because
// serverless functions on both platforms allow background tasks to continue
// after the response is sent (waitUntil-style behavior). For Railway it's
// even more permissive since it's a long-running container.

import { v4 as uuidv4 } from "uuid";
import { createScanJob, markJobRunning, completeJob, failJob, getJob } from "../db/scanJobs.js";
import { isDbConfigured } from "../db/client.js";
import { dispatchWebhook } from "../webhooks/dispatcher.js";
import type { ScanJob } from "../db/types.js";

export type BackgroundJobHandler<TInput, TOutput> = (input: TInput) => Promise<TOutput>;

export interface EnqueueOptions {
  customer_id?: string;
  api_key_id?: string;
  /** Wall-clock timeout. Job will be marked failed if it exceeds this. */
  timeout_ms?: number;
  /** If true, fire scan.completed / scan.failed webhooks. */
  emit_webhook?: boolean;
}

export interface EnqueueResult {
  job_id: string;
  status: "queued";
  /** Polling URL for the client. */
  poll_url: string;
  /** When the client should next check. */
  estimated_duration_ms: number;
}

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Enqueue a job for background execution. Returns immediately with a job_id.
 * The handler runs unawaited; the caller can check progress via getJobStatus.
 *
 * Usage:
 *   const job = await enqueue("vuln_scan_network", input, () => runNmapScan(input), {
 *     customer_id, emit_webhook: true, timeout_ms: 300_000
 *   });
 *   return { ...job }; // 202 Accepted
 */
export async function enqueue<TInput extends Record<string, unknown>, TOutput>(
  toolName: string,
  input: TInput,
  handler: () => Promise<TOutput>,
  options: EnqueueOptions = {}
): Promise<EnqueueResult> {
  if (!isDbConfigured()) {
    throw new Error("Background jobs require Supabase. Set SUPABASE_URL and SUPABASE_SERVICE_KEY.");
  }

  const target = (input.target as string) || (input.target_url as string) || (input.hostname as string) || "n/a";

  const job = await createScanJob({
    customer_id: options.customer_id,
    api_key_id: options.api_key_id,
    tool_name: toolName,
    target,
    input_params: input,
  });

  // Run the handler unawaited. Errors are caught and logged on the job record.
  runJobInBackground(job, handler, options);

  return {
    job_id: job.id,
    status: "queued",
    poll_url: `/v1/jobs/${job.id}`,
    estimated_duration_ms: estimateDuration(toolName),
  };
}

function estimateDuration(toolName: string): number {
  switch (toolName) {
    case "vuln_scan_network": return 60_000;
    case "vuln_scan_web_app": return 120_000;
    case "sast_scan": return 90_000;
    case "secret_scan": return 60_000;
    case "dependency_audit": return 30_000;
    default: return 30_000;
  }
}

async function runJobInBackground<TOutput>(
  job: ScanJob,
  handler: () => Promise<TOutput>,
  options: EnqueueOptions
): Promise<void> {
  const startTime = Date.now();
  const timeout = options.timeout_ms || DEFAULT_TIMEOUT_MS;

  try {
    await markJobRunning(job.id);

    // Race the handler against a timeout
    const result = await Promise.race([
      handler(),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`Job ${job.id} timed out after ${timeout}ms`)), timeout)
      ),
    ]);

    const duration = Date.now() - startTime;
    await completeJob(job.id, result, duration);

    if (options.emit_webhook && job.customer_id) {
      await dispatchWebhook(job.customer_id, "scan.completed", {
        job_id: job.id,
        tool_name: job.tool_name,
        target: job.target,
        duration_ms: duration,
        result,
      }).catch((err) => console.error(`[bg-jobs] webhook delivery failed for job ${job.id}:`, err));
    }
  } catch (err) {
    const duration = Date.now() - startTime;
    const errorMessage = err instanceof Error ? err.message : String(err);

    await failJob(job.id, errorMessage, duration);

    if (options.emit_webhook && job.customer_id) {
      await dispatchWebhook(job.customer_id, "scan.failed", {
        job_id: job.id,
        tool_name: job.tool_name,
        target: job.target,
        duration_ms: duration,
        error: errorMessage,
      }).catch(() => { /* best effort */ });
    }
  }
}

/**
 * Decide whether a tool should run synchronously or via the queue.
 * - Synchronous: returns full result inline (current behavior)
 * - Async: returns { job_id, poll_url } — client polls or waits for webhook
 *
 * Tools default to sync if database isn't configured; otherwise long-running
 * tools enqueue when the request explicitly asks for async via input.async = true,
 * OR when an env-var `BG_JOBS_DEFAULT=true` is set (recommended in production).
 */
export function shouldRunAsync(toolName: string, input: Record<string, unknown>): boolean {
  if (!isDbConfigured()) return false;
  if (input.async === true) return true;
  if (input.async === false) return false;

  if (process.env.BG_JOBS_DEFAULT !== "true") return false;

  // These tools commonly exceed 30s
  const longRunning = new Set([
    "vuln_scan_network",
    "vuln_scan_web_app",
    "sast_scan",
    "secret_scan",
    "dependency_audit",
  ]);
  return longRunning.has(toolName);
}

export { getJob as getJobStatus };
