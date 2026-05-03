import { v4 as uuidv4 } from "uuid";

export type JobStatus = "queued" | "running" | "completed" | "failed" | "timeout";

export interface ScanJob {
  id: string;
  tool_name: string;
  target: string;
  status: JobStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  result?: unknown;
  error?: string;
}

const jobs = new Map<string, ScanJob>();

export function createJob(toolName: string, target: string): ScanJob {
  const job: ScanJob = {
    id: uuidv4(),
    tool_name: toolName,
    target,
    status: "queued",
    created_at: new Date().toISOString(),
  };
  jobs.set(job.id, job);
  return job;
}

export function startJob(jobId: string): void {
  const job = jobs.get(jobId);
  if (job) {
    job.status = "running";
    job.started_at = new Date().toISOString();
  }
}

export function completeJob(jobId: string, result: unknown): void {
  const job = jobs.get(jobId);
  if (job) {
    job.status = "completed";
    job.completed_at = new Date().toISOString();
    job.result = result;
  }
}

export function failJob(jobId: string, error: string): void {
  const job = jobs.get(jobId);
  if (job) {
    job.status = "failed";
    job.completed_at = new Date().toISOString();
    job.error = error;
  }
}

export function getJob(jobId: string): ScanJob | undefined {
  return jobs.get(jobId);
}

export function logScanTarget(toolName: string, target: string): void {
  const timestamp = new Date().toISOString();
  console.log(`[SCAN_LOG] ${timestamp} | tool=${toolName} | target=${target}`);
}
