# AgentAegis Roadmap

Status as of **2026-05-04**. Use this file as the source of truth when picking up dev work after a context switch.

---

## ✅ Shipped (production)

| Phase | Capability | Verified |
|---|---|---|
| 1 | 21 cybersecurity tools across 7 categories | Self-audit ran 12 of them |
| 1 | Engine wrappers: nmap, Nuclei, sslyze, Semgrep, trufflehog, trivy | Live |
| 1 | External APIs: NVD, AbuseIPDB, OTX, abuse.ch, HIBP, Shodan | Live (HIBP not yet purchased) |
| 2 | HTTP Streamable MCP transport | Live |
| 2 | API key auth + monthly budget tracking | Verified — $0.10 deduction confirmed |
| 2 | Stripe credit-card top-ups + webhook signature verification | Verified — $5 real payment landed |
| 2 | Supabase persistence (6 `aegis_*` tables, RLS forced) | Live, sharing Agentbind project |
| 3 | PCI DSS v4.0 framework (full) — total 4 compliance frameworks | Live |
| 3 | Persistent background job queue for long scans | Live |
| 3 | Cloud evidence integrations: GitHub, AWS, Okta | Live |
| 3 | Admin dashboard at `/admin?token=...` | Live |
| 3 | Customer-facing top-up at agentaegis.org/pay | Verified |
| 3 | FAQ at agentaegis.org/faq + `help` MCP tool (single source of truth) | Live |
| 3 | Free `account_balance` MCP tool for agents to self-check budget | Live |
| 4 | Self-audit (Phase 4) — 12 findings, 7 fixed in code | Report at `audit/REPORT.md` |
| 4 | 8 AgentAegis-specific policies generated | At `audit/policies/` |
| 5 | x402 micropayments — testnet end-to-end | Real on-chain settlement on Base Sepolia |
| 5 | x402 micropayments — **mainnet live** | Receiver `0x3347d4E9925cC379a333c017367248e1A11DF7fC` |
| 5 | **US Provisional Patent filed** — App. No. `64/057,021`, Confirmation #8319 | USPTO receipt 2026-05-04 7:33 PM ET, micro entity, $65 |
| 6 | **Customer self-service portal** — `agentaegis-portal` repo, Next.js 15 + Supabase Auth + Vercel | Live at `app.agentaegis.org` 2026-05-06 |
| 6 | `/account` dashboard, `/keys` CRUD, `/usage` + CSV export, `/transactions`, `/webhooks` CRUD + test | All routes verified end-to-end through Google OAuth + magic link |
| 7 | **Sentry SDK** in both repos — `@sentry/node` (MCP) + `@sentry/nextjs` (portal) | Code shipped 2026-05-06; DSN env vars set by Andrew |
| 7 | **Webhook delivery dashboard** in portal at `/account/webhooks/[id]/deliveries` | Live 2026-05-06 |
| 7 | **Better Stack uptime monitoring** — 5 monitors (MCP liveness/deep, portal, marketing, x402 facilitator) | Live 2026-05-07 |
| 7 | **Status page** at `status.agentaegis.org` — Better Stack with custom Cloudflare CNAME | Live 2026-05-07 |
| 7 | **`/health/deep` endpoint** — DB + x402 + Stripe parallel checks with per-check latency | Live on Railway after redeploy 2026-05-07 |
| 7 | **Operational runbooks** — IR, backup verification, uptime monitoring at `agentaegis-mcp/runbooks/` | Committed 2026-05-06 |
| 7 | **AbuseIPDB .org domain verified** — threat intel calls now use the canonical domain | Resolved 2026-05-07 |

**Patent Pending** — provisional discloses dual-rail payment architecture (API-key + x402), MCP-aware body-inspection gating, and unified settlement-to-logging pipeline. 12-month nonprovisional deadline: **2027-05-04**. See `wiki/pages/agentaegis-patent.md` for full filing details.

**Live URLs:**
- MCP server: https://agentaegis-mcp-production.up.railway.app
- Landing site: https://www.agentaegis.org
- **Customer portal: https://app.agentaegis.org**
- **Status page: https://status.agentaegis.org**
- GitHub: github.com/astafford8488/agentaegis-mcp + agentaegis-site + agentaegis-portal

---

## ⏳ Outstanding TODOs (small)

These are small cleanups that don't block anything but should get done.

### DNS hardening (Andrew, ~15 min in Cloudflare)

Findings #2, #3, #11 from the Phase 4 audit. Email auth and CAA records.

#### `agentaegis.org` zone
```
_dmarc      TXT    v=DMARC1; p=quarantine; rua=mailto:dmarc@agentaegis.org; pct=100; sp=quarantine; fo=1
@           CAA    0 issue "letsencrypt.org"
@           CAA    0 issuewild "letsencrypt.org"
@           CAA    0 iodef "mailto:admin@youraigroup.com"
```
(SPF + DKIM already added by Resend — verified.)

#### `youraigroup.com` zone
```
@           TXT    v=spf1 include:_spf.google.com -all
_dmarc      TXT    v=DMARC1; p=quarantine; rua=mailto:dmarc@youraigroup.com; pct=100; sp=quarantine; fo=1
```

After DNS propagates, re-run `dns_security_check` and `email_security_audit` — should flip from F to A.

### x402 mainnet end-to-end verification (optional, ~$1)

Phase 5 was verified end-to-end on testnet but not on mainnet. The protocol is identical, so this is belt-and-suspenders. To do:

1. Use the mainnet test wallet at `0x1baC8AC7Fdd826b0C47C0eba0858d2BFCf8D0086` (already funded with 5 USDC)
2. Update `audit/x402-test/02-run-payment.ts` to point at mainnet (use the test wallet's private key, available via Coinbase Smart Wallet export if Andrew wants to do this)
3. Run a single $0.10 cve_lookup
4. Verify $0.10 USDC moves from `0x1baC...` → `0x3347...`

### HIBP API key (optional, ~$3.50/mo)

`credential_check` tool currently fails without an HIBP API key. If we want it working out of the box:
- Buy at https://haveibeenpwned.com/API/Key ($3.50/month)
- Set `HIBP_API_KEY` on Railway

### Railway auto-deploy from GitHub not firing

GitHub→Railway auto-deploy stopped firing after the 2026-05-04 image (`sha256:faecd9a54a...`). Phase 7 commits (199ab42, b6985e4) are merged on master but Railway is still serving the older container — `/health/deep` returns 404 in production despite the route being present in the committed code. Manual `railway up` also doesn't appear to invalidate Railway's build cache.

To fix:
1. Open Railway dashboard → agentaegis-mcp project → Settings → check Source repo connection
2. Force a manual deploy from Railway UI (Deploy → Deploy from GitHub)
3. After /health/deep returns 200/503 (not 404), Better Stack monitor #2 will auto-recover

Workaround for now: Better Stack monitor #1 (basic /health) covers liveness; monitor #2 can be paused until the deploy issue is resolved.

### Diagnostic Stripe BETA_SIGNUP_FROM check

Earlier env-var debugging revealed `BETA_SIGNUP_FROM` was set on Vercel but pulled empty. We re-set it explicitly. Verify the next real beta signup arrives `from: noreply@agentaegis.org` (not `onboarding@resend.dev`). Last test signup confirmed delivery, but the `from` field wasn't checked.

---

## 🛣 Next phases (un-shipped)

### Phase 8 — Public launch prep (~1–2 days) — **next pick**

- Demo video (3 min, 2 demos + sign-up flow)
- Show HN draft — "I built an MCP server for cybersecurity tools — pay per call via card or USDC"
- X/Twitter thread — "AgentAegis audited itself" (Phase 4 story)
- MCP registry submissions (modelcontextprotocol.io directory)
- Cold outreach list — 50 agent builders, personalized DMs

### Phase 9+ — Post-launch growth

- Cloud integration breadth (Azure, GCP, Datadog, Cloudflare, CloudWatch)
- Container security tools (trivy image scan, kube-bench)
- More compliance frameworks (FedRAMP, GDPR-specific, NIST 800-53)
- White-label / partner program
- Enterprise tier (custom limits, dedicated support)
- Multi-region deployment

---

## 🔐 Credentials index

All operational credentials documented in:
- **API keys**: `~/.claude/projects/.../memory/reference_agentaegis_keys.md`
- **Wallet addresses**: `wiki/pages/agentaegis-x402-wallets.md`
- **Local dev `.env`**: `agentaegis-mcp/.env` (gitignored)
- **Production env vars**: Railway dashboard, project `agentaegis-mcp`
- **Vercel env vars**: Vercel dashboard, project `agentaegis-site`

---

## 🐞 Known issues / accepted risks

- **`/admin` auth is a single shared bearer token** — fine for solo operator, would need to switch to Supabase Auth before adding a second admin
- **No webhook UI yet** — DB schema exists (`aegis_webhooks`) but no endpoints / no customer-facing way to add them
- **No multi-region** — single Railway region (US East). If we get an EU enterprise customer, this becomes a blocker.
- **Customer balance display gap** — `account_balance` returns balance correctly, but our `/admin` and `/v1/customers/:id/usage` views don't auto-refresh. Customers polling get stale views unless they re-fetch.
- **The 8 generated policies are JSON, not markdown** — `audit/policies/*.json` should get rendered into committable markdown for human reading.

---

## When picking this back up

1. Read this file
2. Read `audit/REPORT.md` (Phase 4 self-audit)
3. Read the wiki page [[agentaegis-x402-wallets]]
4. Run `pnpm test` to confirm 50/50 still pass
5. `railway status` to confirm production is healthy
6. Decide: Phase 6 (portal) vs Phase 7 (ops) vs cleanup TODOs vs something new

State of the codebase: clean. 50/50 tests pass. TS compiles without errors. Production has been running with no errors for 24+ hours.
