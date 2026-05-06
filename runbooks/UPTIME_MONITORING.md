# Uptime Monitoring + Status Page Setup

Phase 7 component. **Setup is a one-time ~15 min task; ongoing maintenance is zero.**

Provider: Better Stack (formerly Better Uptime). Free tier covers our needs:
- 10 monitors at 30-second cadence
- 1 status page with custom domain
- Email + SMS alerts to one operator
- Public + private status pages

Sign up at https://betterstack.com/uptime.

---

## Monitors to configure

| # | Name | URL | Method | Expected | Cadence | Alert delay |
|---|---|---|---|---|---|---|
| 1 | MCP — liveness | `https://agentaegis-mcp-production.up.railway.app/health` | GET | 200 OK · body contains `"status":"ok"` | 30s | 1 min |
| 2 | MCP — deep health | `https://agentaegis-mcp-production.up.railway.app/health/deep` | GET | 200 or 503 (alert on 503) · body `"status"` not equal to `"fail"` | 60s | 2 min |
| 3 | Portal | `https://app.agentaegis.org/login` | GET | 200 OK | 60s | 2 min |
| 4 | Marketing site | `https://www.agentaegis.org` | GET | 200 OK | 5 min | 10 min |
| 5 | x402 facilitator (passive) | `https://x402.org/facilitator` | GET | 200/4xx (alert only on 5xx) | 5 min | 10 min |

**Why two MCP monitors?** Monitor #1 is fast liveness — pages immediately if the container crashes. Monitor #2 is deep health — pages if upstream Supabase or Stripe is degraded but the container itself is fine. Both fire = real outage. Only #2 fires = upstream issue, customer impact unclear.

---

## Setup steps

### 1. Better Stack signup

1. Go to https://betterstack.com/uptime → Sign up with Google (recommended — fewer creds to manage)
2. Skip the "team" prompt (you're solo)
3. Set timezone to your local one (Eastern, presumably)

### 2. Create the 5 monitors

For each row in the table above:

1. Click "Create monitor"
2. URL: paste the URL
3. Type: HTTP(S)
4. Cadence: per the table
5. **Alert** section:
   - Email: andrew@youraigroup.com (default)
   - SMS: enabled, phone from your private contact info
   - Delay: per the table (avoids paging on transient blips)
6. **Recovery** notification: enable (so you know when it's resolved)
7. **Maintenance windows**: skip for now
8. Save

Repeat 5 times.

### 3. Status page at status.agentaegis.org

In Better Stack:

1. Status pages → Create new status page
2. Name: AgentAegis
3. Subdomain: leave blank (we'll use a custom domain)
4. Description: "Real-time status of AgentAegis services"
5. Add monitors:
   - "MCP API" → maps to monitor #1 (liveness)
   - "MCP Health" → maps to monitor #2 (deep)
   - "Customer Portal" → maps to monitor #3
   - "Marketing Site" → maps to monitor #4
   - (skip x402 facilitator on the public status page — that's an upstream we don't own)
6. Save

### 4. Custom domain at status.agentaegis.org

In Better Stack status page settings:
- Custom domain → enter `status.agentaegis.org`
- Better Stack will give you a CNAME target (something like `status.betterstack.com.`)

In Cloudflare:
- DNS → add CNAME record:
  - Type: CNAME
  - Name: `status`
  - Target: (whatever Better Stack provided)
  - Proxy status: **DNS-only** (gray cloud) — Better Stack handles SSL itself

Wait 1-5 minutes for DNS propagation. Better Stack will auto-issue Let's Encrypt cert.

### 5. Test the alerts

To verify SMS/email actually arrive:

1. In Better Stack, find any one monitor → "Test alert" button
2. Confirm you receive both email and SMS within ~30 seconds
3. If SMS doesn't arrive, check the phone number formatting (must be E.164 with `+` prefix)

### 6. Add the status page link to the portal and marketing site

Once `status.agentaegis.org` is live:

- Portal: add a "System status" link in the footer (or skip for now — it's optional)
- Marketing site: add to footer

---

## Alert routing decision tree

When a Better Stack alert fires, follow this:

```
Alert fires
├── Monitor #1 down (liveness)
│   → Container crash. Check Railway logs immediately.
│   → P1 if down >2 min, P2 if recovers within 2 min.
│
├── Monitor #2 fail (deep health 503)
│   → DB down. Check Supabase status page first (https://status.supabase.com)
│   → If Supabase ok, it's our connection. Check env vars + recent migrations.
│   → P1 always.
│
├── Monitor #2 degraded (status === "degraded")
│   → Better Stack treats this as 200, no alert. But it appears on /health/deep
│     response body. Check periodically; investigate during business hours.
│   → P3 typically.
│
├── Monitor #3 down (portal)
│   → Vercel deploy issue, or DNS, or Cloudflare. Try the Vercel URL directly.
│   → P2 (auth issue blocks customer self-service but doesn't block paid /mcp calls).
│
├── Monitor #4 down (marketing site)
│   → Vercel deploy on agentaegis-site, or DNS.
│   → P3 (no customer impact unless they're trying to sign up).
│
└── Monitor #5 5xx (x402 facilitator)
    → Upstream issue. Customers using x402 rail will see 402 challenges fail.
    → P2. Notify customers via status page; can't fix on our end.
```

---

## Monthly hygiene

First Monday of each month, ~5 min:

1. Better Stack → check the past-30-day uptime per monitor
2. Each monitor should be ≥99.9% uptime. If not, investigate why
3. Review Sentry: any high-frequency errors that aren't yet bugs in the tracker?
4. Review the postmortems folder for any P1/P2 from the past month — are action items closed?

---

## Better Stack Pro upgrade triggers

The free tier is fine for now. Move to Pro ($29/mo) when any of these become true:

- We need >10 monitors
- We need 1-second cadence (instead of 30s) for any monitor
- We need PagerDuty integration (sub-1-minute paging beyond just SMS)
- We need on-call schedules with multiple operators
- We need branded SMS sender ID
- The monitor history retention (7 days on free) becomes too short for postmortem evidence
