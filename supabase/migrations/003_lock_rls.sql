-- Phase 3 — lock down RLS on all AgentAegis tables.
-- Server uses the service_role key which bypasses RLS by default.
-- No policies are added → anon and authenticated roles get zero access.
-- Required to fix Supabase advisor "RLS Disabled in Public" errors and
-- prevent leakage of sensitive columns (e.g. aegis_webhooks.secret).

ALTER TABLE aegis_customers ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_usage_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_webhooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_webhook_deliveries ENABLE ROW LEVEL SECURITY;

ALTER TABLE aegis_customers FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_scan_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_usage_log FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_webhooks FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_webhook_deliveries FORCE ROW LEVEL SECURITY;

ALTER FUNCTION aegis_update_updated_at_column() SET search_path = public, pg_temp;
ALTER FUNCTION aegis_reset_monthly_api_key_usage() SET search_path = public, pg_temp;
