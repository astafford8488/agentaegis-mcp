# Backup Verification Runbook

Untested backups aren't backups. This runbook verifies that Supabase point-in-time recovery (PITR) actually works against the AgentAegis production data.

**Cadence:** Quarterly. First Wednesday of January, April, July, October.

---

## What backups exist

Supabase project `thtnfctijtpdoplyftaw` retains:

- **Daily backups** at 02:00 UTC, kept for 7 days (Free tier; 30 days on Pro)
- **Point-in-time recovery (PITR)** — only on Pro tier ($25/mo). On Free, you have daily snapshots only

The AgentAegis data lives in tables prefixed `aegis_*`. Critical for revenue continuity:
- `aegis_customers` — credentials, balance
- `aegis_api_keys` — hashes, monthly usage
- `aegis_usage_log` — every charge ever (audit trail)
- `aegis_webhooks` + `aegis_webhook_deliveries`
- `aegis_scan_jobs`

---

## Quarterly verification procedure

This is a **read-only** test against a separate temporary project. **Do not** restore over the production database.

### Step 1 — Create a sibling test project (~5 min)

Through the Supabase dashboard (or `supabase` CLI if you've set it up):

1. Create a new Supabase project named `agentaegis-restore-test-<YYYY-MM-DD>`
2. Choose the same region as production (`us-east-1`)
3. Wait ~3-5 minutes for provisioning
4. Note the project ref — you'll need it as the restore target

### Step 2 — Find the backup to restore

- Go to https://supabase.com/dashboard/project/thtnfctijtpdoplyftaw/database/backups
- Pick the most recent daily backup
- Note its timestamp

### Step 3 — Restore to the sibling project

Free tier:
1. From the production project's Backups page, click "Download backup" on the chosen date
2. In the sibling project, go to SQL Editor and use `psql` via the connection string to import:
   ```bash
   pg_restore -h db.<sibling>.supabase.co -p 5432 -U postgres -d postgres \
     --no-owner --no-privileges --clean --if-exists \
     <backup-file>.dump
   ```

Pro tier:
1. Use Supabase's "Restore to a new project" option — select sibling as target

### Step 4 — Verify integrity

Run these checks against the sibling. Open Supabase SQL Editor on the sibling project:

```sql
-- 1. Table counts roughly match production (within ±a few minutes of the backup time)
SELECT
  (SELECT COUNT(*) FROM aegis_customers) AS customers,
  (SELECT COUNT(*) FROM aegis_api_keys) AS api_keys,
  (SELECT COUNT(*) FROM aegis_usage_log) AS usage_log,
  (SELECT COUNT(*) FROM aegis_webhooks) AS webhooks,
  (SELECT COUNT(*) FROM aegis_webhook_deliveries) AS deliveries;

-- 2. Most recent record timestamp matches the backup time (within seconds)
SELECT MAX(created_at) FROM aegis_usage_log;

-- 3. Foreign-key integrity holds
SELECT COUNT(*) FROM aegis_api_keys k
  LEFT JOIN aegis_customers c ON k.customer_id = c.id
  WHERE c.id IS NULL;
-- Expected: 0 (no orphan API keys)

-- 4. Spot-check a known customer
SELECT id, email, prepaid_balance_usd, created_at
  FROM aegis_customers
  WHERE email = 'andrew@youraigroup.com';

-- 5. Verify RLS policies came along (Supabase backups should preserve them)
SELECT tablename, policyname, cmd, qual
  FROM pg_policies
  WHERE schemaname = 'public' AND tablename LIKE 'aegis_%';
-- Expected: same set of policies as production

-- 6. Verify usage log balances (sum of debits + sum of credits should roughly
--    equal current balance change for each customer)
SELECT customer_id,
  SUM(CASE WHEN price_usd > 0 THEN price_usd ELSE 0 END) AS total_charges,
  SUM(CASE WHEN price_usd < 0 THEN -price_usd ELSE 0 END) AS total_credits
FROM aegis_usage_log
WHERE customer_id IS NOT NULL
GROUP BY customer_id
ORDER BY total_charges DESC
LIMIT 10;
```

### Step 5 — Document the result

Append to `runbooks/BACKUP_VERIFICATION_LOG.md`:

```markdown
## YYYY-MM-DD

- Backup tested: <timestamp from production>
- Sibling project: <ref>
- Restore method: download+pg_restore / Supabase UI
- Wall-clock duration: <restore time>
- Data integrity: pass / fail (with details)
- RLS policies preserved: pass / fail
- Notes: <anything unexpected>
- Tested by: Andrew Stafford
```

### Step 6 — Tear down (CRITICAL)

The sibling project costs money on Pro tier and creates noise on Free. Delete it:

1. Supabase dashboard → sibling project → Settings → Pause project (or delete entirely)
2. Confirm via email "project deleted"

---

## RTO / RPO targets

These are what you commit to in the SOC 2 audit and on the status page:

| Metric | Target | Reality (verified by this runbook) |
|---|---|---|
| **RPO** (recovery point objective) — max acceptable data loss | 24 hours (daily backup cadence) | Validated each quarterly run |
| **RTO** (recovery time objective) — max acceptable downtime | 4 hours | Validated each quarterly run, log the wall-clock time |

If a quarterly verification reveals RTO > 4 hours, the action item is to either:
- Upgrade to Supabase Pro for PITR (faster recovery)
- Document the realistic RTO and update customer commitments accordingly

---

## What's NOT covered by Supabase backups

These need separate backup strategies if they're ever critical to recover:

- **Stripe transactions** — recoverable from Stripe dashboard (they keep the source of truth)
- **x402 on-chain settlements** — already on a public blockchain, recoverable forever via tx hash
- **GitHub repos** — distributed; lose Andrew's local copy + GitHub at the same time = total loss. Mitigation: clone all 4 repos to backup machine quarterly
- **Email-based customer communications (Resend)** — Resend keeps logs; export quarterly via API
- **DNS records** — Cloudflare exports possible; rare to lose unless account compromised
- **Vercel + Railway env vars** — exported via their CLIs; do this quarterly as part of this runbook:
  ```bash
  # MCP server env (Railway)
  railway variables --service agentaegis-mcp > runbooks/env-snapshots/railway-mcp-YYYY-MM-DD.env

  # Portal env (Vercel)
  vercel env pull --environment production runbooks/env-snapshots/vercel-portal-YYYY-MM-DD.env
  ```
  Both files are gitignored. Store on encrypted backup drive.

---

## Disaster scenarios

### Supabase project deleted by accident

- Within 30 days: Supabase support can recover
- Beyond 30 days: data is gone. Restoration depends on your last quarterly backup snapshot

### AWS region outage at us-east-1

- All AgentAegis production runs in us-east-1 (Railway iad1, Vercel iad1, Supabase us-east-1)
- Outage = total downtime
- Mitigation: out of scope for solo operator; multi-region deploy is a Phase 9+ item

### Andrew unavailable (vacation, illness)

- Solo operator failure mode. Mitigations:
  - This runbook documents enough that a contractor could take over
  - Customer-facing status page can be set to "Reduced support" mode
  - Auto-pause incoming Stripe charges if Andrew is unreachable for >7 days (manual setup needed; not yet done)
- Long-term fix: hire / engage a backup operator
