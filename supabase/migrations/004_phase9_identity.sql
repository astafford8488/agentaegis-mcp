-- Phase 9.0 — Agent identity + scan persistence (substrate for the trust layer).
--
-- Turns the per-call atomic model into stateful per-workflow. Adds:
--   aegis_agents  — first-class identity anchored on EXACTLY ONE of customer_id
--                   (API-key rail), wallet_address (x402 rail — cryptographically
--                   authenticated by the ERC-3009 signature), or anon_session
--                   (free-tier exploration).
--   aegis_scans   — per-call output persistence with summary (always) + full_output
--                   (opt-in) and customer-controlled retention.
--
-- RLS is forced with NO policies (deny-all for anon/authenticated), matching
-- migration 003. The server uses the service_role key (bypasses RLS); per-customer
-- isolation is enforced in application code (see app-layer review notes).

-- ── aegis_agents ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis_agents (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_seen_at    timestamptz NOT NULL DEFAULT now(),

  -- exactly one identity source is populated
  customer_id     uuid REFERENCES aegis_customers(id) ON DELETE CASCADE,
  wallet_address  text,                 -- lowercased 0x… (x402 payer)
  anon_session    text,                 -- stable hash of ip+ua+day

  -- aggregates maintained on each call (cheap UPDATE)
  call_count      integer NOT NULL DEFAULT 0,
  total_spent_usd numeric(10,4) NOT NULL DEFAULT 0,

  -- optional self-supplied metadata
  display_name    text,
  notes           text,
  metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,

  CONSTRAINT aegis_agents_one_identity CHECK (
    (customer_id IS NOT NULL)::int +
    (wallet_address IS NOT NULL)::int +
    (anon_session IS NOT NULL)::int = 1
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_wallet   ON aegis_agents (wallet_address) WHERE wallet_address IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_customer ON aegis_agents (customer_id)    WHERE customer_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_anon     ON aegis_agents (anon_session)   WHERE anon_session IS NOT NULL;

-- ── aegis_scans ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aegis_scans (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id        uuid NOT NULL REFERENCES aegis_agents(id) ON DELETE CASCADE,
  tool_name       text NOT NULL,
  target          text,
  started_at      timestamptz NOT NULL DEFAULT now(),
  completed_at    timestamptz,
  status          text NOT NULL DEFAULT 'running'           -- running | complete | failed
    CHECK (status IN ('running','complete','failed')),
  summary         jsonb,                                    -- always populated (small)
  full_output     jsonb,                                    -- opt-in (large)
  retention_until timestamptz NOT NULL DEFAULT (now() + interval '90 days')
);

CREATE INDEX IF NOT EXISTS idx_scans_agent_recent ON aegis_scans (agent_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target       ON aegis_scans (agent_id, target);
CREATE INDEX IF NOT EXISTS idx_scans_retention    ON aegis_scans (retention_until);

-- ── link usage_log to agents (nullable, no backfill required) ────────────────
ALTER TABLE aegis_usage_log ADD COLUMN IF NOT EXISTS agent_id uuid REFERENCES aegis_agents(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_usage_agent ON aegis_usage_log (agent_id) WHERE agent_id IS NOT NULL;

-- ── lock RLS (deny-all for non-service-role, matching migration 003) ─────────
ALTER TABLE aegis_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_scans  ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_agents FORCE ROW LEVEL SECURITY;
ALTER TABLE aegis_scans  FORCE ROW LEVEL SECURITY;
