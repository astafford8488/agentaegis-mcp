# Incident Response Runbook

**Operational complement to `audit/policies/incident_response.json`.** The policy doc is the SOC 2 / ISO 27001 evidence artifact; this is what you actually run when something is on fire.

Last updated: 2026-05-06

---

## On-call rotation

| Role | Person | Coverage | Contact |
|---|---|---|---|
| Primary on-call | Andrew Stafford | 24/7 | Phone: [see private contact info] · Email: andrew@youraigroup.com |
| Backup on-call | _none yet — solo operator_ | _N/A_ | _N/A_ |
| Incident Commander | Andrew (same person while solo) | _all severities_ | _same as above_ |
| Communications Lead | Andrew (same person while solo) | _all severities_ | _same as above_ |

**Hand-off rule (when a backup is added):** outgoing on-call writes a 1-line state-of-the-world in the AgentAegis Slack `#oncall-handoff` channel before going off shift.

---

## Severity levels and response times

| Severity | Examples | Initial response time | Notify |
|---|---|---|---|
| **P1 — Critical** | Active data breach · ransomware · production fully down · payment system stealing funds · auth bypass | 15 min | All customers via email + status page · YourAIGroup management |
| **P2 — High** | Partial production outage (>5% error rate) · confirmed unauthorized access attempt · webhook delivery dropping for >50% of customers · Sentry alert flood | 1 hour | Affected customers · status page if user-visible |
| **P3 — Medium** | Single-customer issue · transient errors · failed test webhook · degraded /health/deep | 4 hours | Affected customer |
| **P4 — Low** | Cosmetic UI bug · minor logging issue · documentation gap | 24 hours | None unless customer-reported |

---

## Detection sources (in priority order)

1. **Sentry alerts** (errors above baseline) — `sentry.io/organizations/<your-org>/issues/`
2. **Better Stack uptime monitor** on `https://agentaegis-mcp-production.up.railway.app/health/deep` — pages on hard fail (HTTP 503 = DB down)
3. **Customer report** via email or webhook test failure
4. **Railway deploy alerts** — failed deploys, crash loops
5. **Vercel build/deploy alerts** — failed deploys, function errors
6. **Supabase project alerts** — DB usage spikes, auth issues

---

## P1/P2 response procedure

### Step 1 — Triage (within 15 minutes for P1, 1 hour for P2)

- [ ] Acknowledge the alert in whatever tool surfaced it
- [ ] Open a "war room" — for solo operator, this is a fresh terminal + browser tab dedicated to nothing else
- [ ] Determine severity using the table above. When in doubt, escalate one level
- [ ] Note start time. **Track elapsed time** — every postmortem asks for it

### Step 2 — Investigate (immediately after triage)

- [ ] Pull live data:
  - Sentry: recent errors, group by route/customer
  - Vercel: recent deployments + runtime logs (`mcp__d5cd0892-c677-4d29-a752-eaba6dc86dc6__get_runtime_logs`)
  - Railway: recent deployments + logs (`railway logs --service agentaegis-mcp`)
  - Supabase: project health page, query performance, auth logs
  - `/health/deep` on production
- [ ] Check `aegis_usage_log` for anomalous patterns: spike in failures, unfamiliar IPs, unusual tool mix
- [ ] Form a working hypothesis. Write it down. Update as evidence rolls in

### Step 3 — Contain (P1: minutes, P2: same hour)

Goal: stop the bleeding, even if root cause is unclear.

Actions ranked by impact:
- **Roll back** the most recent deployment if the timing matches the incident (`railway redeploy <previous-deployment-id>` or Vercel "Promote to Production" on a known-good prior deploy)
- **Disable** a specific tool by setting its price to 0 in `TOOL_PRICING` and deploying — keeps server up, blocks the broken path
- **Revoke** a leaked API key via `/admin?token=...&action=revoke_key&key=...`
- **Block** an abusive IP via Cloudflare Firewall if it's a portal-side issue
- **Pause** webhooks for a customer if they're firing a flood (`UPDATE aegis_webhooks SET active=false WHERE customer_id=...`)
- **Take down `/mcp`** by deploying with a feature flag that returns 503. Last resort — only if there's no surgical containment

### Step 4 — Eradicate

Once contained, find and fix the root cause:
- Reproduce in a non-production environment (Vercel preview branch + Railway preview environment)
- Write a regression test before fixing the bug
- Land the fix on `master`, verify the regression test catches the original bug

### Step 5 — Recover

- [ ] Deploy the fix to production
- [ ] Verify `/health/deep` returns `ok`
- [ ] Verify error rate in Sentry returns to baseline (give it 15 minutes minimum)
- [ ] If a roll-back was used in containment, redeploy forward with the fix
- [ ] Re-enable any features disabled during containment
- [ ] Notify customers of resolution (if status page was updated)

### Step 6 — Postmortem (within 5 business days)

Required for every P1 and P2. Template:

```markdown
# Incident YYYY-MM-DD-<short-name>

**Severity:** P1 / P2
**Detected at:** <timestamp + source>
**Resolved at:** <timestamp>
**Duration of impact:** <hh:mm>
**Customers affected:** <count or "all">

## Timeline
- HH:MM — Alert fires
- HH:MM — Triage complete, hypothesis: ...
- HH:MM — Containment action taken: ...
- HH:MM — Root cause identified: ...
- HH:MM — Fix deployed
- HH:MM — All-clear

## Root cause
<technical explanation>

## What went well
<things that helped detect, contain, or fix faster than expected>

## What went poorly
<things that slowed response or made impact worse>

## Action items
- [ ] <owner> — <action> — <due date>
```

Save to `agentaegis-mcp/postmortems/YYYY-MM-DD-<short-name>.md` and reference in the next ROADMAP update.

---

## Customer communication

### Status page (when live at status.agentaegis.org)

- P1 → Update within 15 min of detection. "Investigating" → "Identified" → "Monitoring" → "Resolved"
- P2 affecting >1 customer → Same cadence
- P2 affecting 1 customer → Direct email only, no status page entry

### Email templates

**Initial breach notification (P1):**
> Subject: AgentAegis Service Incident — [date]
>
> We are currently investigating reports of [symptom]. We're working to determine the scope and resolve the issue. Updates will be posted at status.agentaegis.org.
>
> If your application is currently affected, you can [workaround if available].
>
> — AgentAegis Team

**Resolution (P1):**
> Subject: AgentAegis Service Incident — Resolved
>
> The incident reported earlier today has been resolved at [time]. Total customer-facing impact: [duration]. A full postmortem will be available within 5 business days.
>
> If you observe any continued symptoms, please reply to this email.
>
> — AgentAegis Team

---

## Quick reference: where everything is

| Thing | Where |
|---|---|
| Production MCP server logs | Railway dashboard → agentaegis-mcp service → Logs |
| Production portal logs | Vercel dashboard → agentaegis-portal → Logs |
| Database admin | Supabase dashboard → project `thtnfctijtpdoplyftaw` |
| Production env vars (MCP) | Railway → agentaegis-mcp → Variables |
| Production env vars (portal) | Vercel → agentaegis-portal → Settings → Environment Variables |
| Sentry dashboard | sentry.io/organizations/`<your-org>`/projects/ |
| Status page | status.agentaegis.org (Better Stack — Phase 7 setup) |
| Stripe dashboard | dashboard.stripe.com |
| Domain DNS | Cloudflare → agentaegis.org |
| GitHub repos | github.com/astafford8488/agentaegis-mcp + agentaegis-portal + agentaegis-site |
| Wiki | C:/Users/thega/wiki + github.com/astafford8488/llm-wiki |
| API keys + secrets index | wiki/pages/agentaegis-portal.md (architecture) and `~/.claude/projects/.../memory/reference_agentaegis_keys.md` (creds) |

---

## When you genuinely need help

You're solo. Some incidents will exceed what one operator can do. Pre-decide who you call:

- **Database integrity** — Supabase support (Pro plan ticket, ~24h response). For a fast bridge: send `support@supabase.io` with project ref `thtnfctijtpdoplyftaw` and a clear repro
- **Payment fraud / chargeback storm** — Stripe support (live chat from dashboard, ~30 min response)
- **Domain hijack / DNS attack** — Cloudflare support (login → support → urgent ticket)
- **Legal/regulatory** — Patent attorney engagement (Phase 6 prep, but also handles general IP and breach notification advice)
- **Vendor outage you can't fix** — Better Stack monitor confirms it's not just you, then communicate to customers and wait
