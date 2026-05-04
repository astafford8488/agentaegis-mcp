-- Phase 3 — additional indexes for admin dashboard and Stripe idempotency
-- (table names prefixed with `aegis_` for co-tenancy)

CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_payment_ref ON aegis_usage_log(payment_ref) WHERE payment_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_success_created ON aegis_usage_log(success, created_at DESC) WHERE success = TRUE;
CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_paid_via ON aegis_usage_log(paid_via, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_failures ON aegis_usage_log(created_at DESC) WHERE success = FALSE;
CREATE INDEX IF NOT EXISTS idx_aegis_scan_jobs_failed ON aegis_scan_jobs(status, created_at DESC) WHERE status = 'failed';
CREATE INDEX IF NOT EXISTS idx_aegis_scan_jobs_customer_created ON aegis_scan_jobs(customer_id, created_at DESC);
