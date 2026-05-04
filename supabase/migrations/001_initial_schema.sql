-- AgentAegis MCP Server - Initial Schema
-- Tables prefixed with `aegis_` to allow co-tenancy in shared Supabase projects.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============ CUSTOMERS ============
CREATE TABLE IF NOT EXISTS aegis_customers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    company TEXT,
    wallet_address TEXT,
    stripe_customer_id TEXT,
    prepaid_balance_usd NUMERIC(10, 4) DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_aegis_customers_email ON aegis_customers(email);
CREATE INDEX IF NOT EXISTS idx_aegis_customers_wallet ON aegis_customers(wallet_address) WHERE wallet_address IS NOT NULL;

-- ============ API KEYS ============
CREATE TABLE IF NOT EXISTS aegis_api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID NOT NULL REFERENCES aegis_customers(id) ON DELETE CASCADE,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    monthly_limit_usd NUMERIC(10, 2) DEFAULT 100.00,
    current_month_usage_usd NUMERIC(10, 4) DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_aegis_api_keys_hash ON aegis_api_keys(key_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_aegis_api_keys_customer ON aegis_api_keys(customer_id);

-- ============ SCAN JOBS ============
CREATE TABLE IF NOT EXISTS aegis_scan_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID REFERENCES aegis_customers(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES aegis_api_keys(id) ON DELETE SET NULL,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    input_params JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'timeout')),
    result JSONB,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aegis_scan_jobs_customer ON aegis_scan_jobs(customer_id);
CREATE INDEX IF NOT EXISTS idx_aegis_scan_jobs_status ON aegis_scan_jobs(status) WHERE status IN ('queued', 'running');
CREATE INDEX IF NOT EXISTS idx_aegis_scan_jobs_created ON aegis_scan_jobs(created_at DESC);

-- ============ USAGE LOG ============
CREATE TABLE IF NOT EXISTS aegis_usage_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID REFERENCES aegis_customers(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES aegis_api_keys(id) ON DELETE SET NULL,
    tool_name TEXT NOT NULL,
    target TEXT,
    price_usd NUMERIC(10, 4) NOT NULL,
    paid_via TEXT NOT NULL CHECK (paid_via IN ('api_key_balance', 'x402', 'stripe', 'free_tier', 'admin_credit')),
    payment_ref TEXT,
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,
    request_ip TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_customer ON aegis_usage_log(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_api_key ON aegis_usage_log(api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_usage_log_tool ON aegis_usage_log(tool_name, created_at DESC);

-- ============ WEBHOOKS ============
CREATE TABLE IF NOT EXISTS aegis_webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    customer_id UUID NOT NULL REFERENCES aegis_customers(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events_subscribed TEXT[] NOT NULL DEFAULT ARRAY['scan.completed', 'scan.failed'],
    active BOOLEAN DEFAULT TRUE,
    last_delivery_at TIMESTAMPTZ,
    last_delivery_status INTEGER,
    failure_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_aegis_webhooks_customer ON aegis_webhooks(customer_id);

-- ============ WEBHOOK DELIVERIES ============
CREATE TABLE IF NOT EXISTS aegis_webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    webhook_id UUID NOT NULL REFERENCES aegis_webhooks(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    response_status INTEGER,
    response_body TEXT,
    attempts INTEGER DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aegis_webhook_deliveries_webhook ON aegis_webhook_deliveries(webhook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_webhook_deliveries_pending ON aegis_webhook_deliveries(next_retry_at) WHERE delivered_at IS NULL;

-- ============ TRIGGERS ============

CREATE OR REPLACE FUNCTION aegis_update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS aegis_update_customers_updated_at ON aegis_customers;
CREATE TRIGGER aegis_update_customers_updated_at
    BEFORE UPDATE ON aegis_customers
    FOR EACH ROW
    EXECUTE FUNCTION aegis_update_updated_at_column();

CREATE OR REPLACE FUNCTION aegis_reset_monthly_api_key_usage()
RETURNS void AS $$
BEGIN
    UPDATE aegis_api_keys SET current_month_usage_usd = 0;
END;
$$ language 'plpgsql';
