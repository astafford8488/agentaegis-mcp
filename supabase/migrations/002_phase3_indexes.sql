-- Phase 3 — additional indexes to support admin dashboard queries
-- and Stripe webhook idempotency lookups.

-- Idempotency lookup: given a Stripe event id, has it been credited?
CREATE INDEX IF NOT EXISTS idx_usage_log_payment_ref ON usage_log(payment_ref) WHERE payment_ref IS NOT NULL;

-- Admin dashboard "top customers / tools last 30 days" queries
CREATE INDEX IF NOT EXISTS idx_usage_log_success_created ON usage_log(success, created_at DESC) WHERE success = TRUE;
CREATE INDEX IF NOT EXISTS idx_usage_log_paid_via ON usage_log(paid_via, created_at DESC);

-- Admin "recent failures" query
CREATE INDEX IF NOT EXISTS idx_usage_log_failures ON usage_log(created_at DESC) WHERE success = FALSE;
CREATE INDEX IF NOT EXISTS idx_scan_jobs_failed ON scan_jobs(status, created_at DESC) WHERE status = 'failed';

-- Job-status polling
CREATE INDEX IF NOT EXISTS idx_scan_jobs_customer_created ON scan_jobs(customer_id, created_at DESC);
