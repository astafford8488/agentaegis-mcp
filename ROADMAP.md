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
✅ **DONE 2026-06-17** (via Cloudflare API): `_dmarc` TXT (`v=DMARC1; p=quarantine; rua=mailto:dmarc@agentaegis.org; pct=100; sp=quarantine; fo=1`) + apex SPF (`v=spf1 include:amazonses.com ~all`). Safe because Resend DKIM is apex-aligned (mail passes DMARC via DKIM). DKIM + `send.` SPF were already present.

⚠️ **DO NOT add the old CAA records below** — agentaegis.org is Cloudflare-fronted, and Cloudflare issues certs via Google Trust Services / others, so a `letsencrypt.org`-only CAA would **break cert renewal**. If CAA is ever wanted, it must include Cloudflare's full CA set (`pki.goog`, `letsencrypt.org`, `digicert.com`, `sectigo.com`, `ssl.com`, `comodoca.com`) — otherwise leave CAA unset.
~~`@ CAA 0 issue "letsencrypt.org"` / `issuewild` / `iodef`~~ — retired (landmine).

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

## 🧭 Strategic positioning (set 2026-05-21, after investor meetings + June 2026 x402 landscape research)

**AgentAegis is evolving from "MCP cybersecurity tool catalog" → "the security & trust
layer for agentic commerce."** The tool catalog (shipped) is the proof and the revenue
floor. The bigger, more defensible product is the **trust verdict**: when an agent is
about to pay or call an unknown endpoint, AgentAegis answers *"is this safe to transact
with?"* — because we already run the scans AND sit on the payment rail. That's
"Stripe Radar for agentic commerce," and the flagship tool (`vet_endpoint`) gates a
payment, which is exactly what the new provisional patent covers.

Validated by the June 2026 research (full report in the PitchIQ AA workspace wiki:
"x402 & Agentic Commerce Landscape"): x402 is now a Linux Foundation standard backed by
Visa, Mastercard, Stripe, Google, AWS, Microsoft; economic volume is at $1+ (95%);
the MCP-monetization stack (Vercel x402-mcp, Coinbase Bazaar, AWS Bedrock AgentCore) is
production-ready; and **no incumbent yet owns the agent-facing trust/safety verdict.**

Two product layers:
- **L1 — Tools (shipped):** 20 paid cybersecurity tools + dual-rail billing.
- **L2 — Trust layer (the thesis):** `vet_endpoint`, `scan_mcp_plugin`/`scan_skill`,
  `kya_verify`, on-chain agent/wallet reputation. Each consumes L1 tools to produce a
  composite verdict. This is what gets listed in the Bazaar, submitted to ChatGPT, and
  pitched to investors on usage metrics.

Master strategy + site information-architecture + distribution plan:
`wiki/pages/agentaegis-positioning-trust-layer.md`.

## 🛣 Next phases (un-shipped)

### Phase 8 — Public launch prep (~1–2 days) — **UNBLOCKED, next pick**

- ✅ **R-3 mainnet x402 payment test — PASSED.** Full end-to-end on Base mainnet via
  the CDP facilitator: 402 (v2 PAYMENT-REQUIRED header) → ERC-3009 sign → PAYMENT-SIGNATURE
  → CDP verify → on-chain settlement → tool executed (HTTP 200). $1 USDC moved payer
  0x8c82 → receiver 0x3347. Settlement tx: `0xed08f420324458a0146a7ca8bb45c56930f37425b3b7112e0bce5a63446d5b9c`.
  Closes the launch gate AND satisfies x402 Bazaar eligibility (≥1 CDP-settled payment).
  Fixes that got it green: v2 wire protocol (PAYMENT-REQUIRED + PAYMENT-SIGNATURE headers)
  and network-specific EIP-712 domain (Base mainnet USDC = "USD Coin", not "USDC").
- ✅ Repricing to $1+ tiers — DONE 2026-05-21 (commit on master).
- Demo video (3 min, 2 demos + sign-up flow) — now shows real mainnet x402 settlement
- Show HN draft — "per-call billing for MCP servers using HTTP 402 + ERC-3009"
- X/Twitter thread — "AgentAegis audited itself" (Phase 4 story)
- ✅ **MCP registry submission — PUBLISHED 2026-06-16.** Live in the official
  registry as `io.github.astafford8488/agentaegis` v0.3.0 (via `mcp-publisher publish`
  from the repo dir; `server.json` manifest). Re-publish on each version bump.
- Cold outreach list — 50 agent builders, personalized DMs

### Phase 8.5 — Distribution, grants, trust-layer foundation (from June 2026 research + PIQ backlog)

Runs alongside / right after launch. Tasks tracked on the PIQ AA board.

- ✅ **x402 Bazaar listing — SHIPPED + activated.** Discovery extension implemented
  (`src/auth/bazaarCatalog.ts` declares all 20 tools; `buildCdpChallenge` attaches
  `extensions.bazaar`, best-effort). Verified live in the production challenge, and
  activated by a mainnet settlement carrying the metadata (tx `0xf32c01b3…`). Each
  tool indexes the first time it's paid for. Verify the live index via the CDP
  dashboard or an agent's Bazaar `search_resources` (querying needs CDP creds).
- **Confirm CDP Facilitator free tier** (1k free settlements/mo + gas sponsorship) —
  the CDP migration shipped this session; verify we're on the free tier.
- **Submit to ChatGPT via Apps SDK** (PIQ, due 2026-06-28) — distribution surface.
- **Circle USDC Developer Grant** (PIQ, due 2026-07-12) — circle.questbook.app.
- **Base Builder Grants** (PIQ, due 2026-07-12) — retroactive 1–5 ETH + Builder Score.
- 🟡 **File NEW provisional patent** — endpoint-safety verdict gating a per-invocation
  agent payment (PIQ, due 2026-07-15). Captures the L2 trust-layer thesis before a
  competitor does. **DRAFT COMPLETE** — spec + 18 informal claims (method/system/CRM)
  at `~/Downloads/Businesses/AgentAegis/AgentAegis-Provisional-2-Spec.md`, filing-format
  render at `~/Downloads/AgentAegis-Provisional-2-Spec-DRAFT.docx`, cross-references
  US 64/057,021. Repeatable process captured as the `provisional-patent-drafting` skill.
  Remaining: Andrew reviews → export PDF → file at Patent Center (PTO/SB/16 + SB/15A,
  micro-entity ~$65).
- **Brief patent attorney** on the security-verdict claim + de-risk the existing
  provisional (PIQ, due 2026-08-01).
- **Landing-page positioning overhaul** — reframe hero from "22 tools" to the trust
  layer; add per-tool/use-case landing pages with demos (`/vet-endpoint` flagship,
  `/scan-mcp`, `/kya`, `/agent-reputation`). See the positioning wiki page for the IA.

### Phase 9.0 — Agent identity + scan persistence (substrate for Phase 9) — ✅ SHIPPED LIVE 2026-06-17 (migration 004 applied to Agentbind `thtnfctijtpdoplyftaw`; merged to master; `/health/deep` green, tools_count 22→26)

The current per-call atomic model breaks every multi-step workflow. Agents that
pay via x402 have no persistent identity across calls — only a per-call tx hash.
Without an identity primitive, no tool can reference a prior scan, no audit can
compose findings across multiple tools, and the per-tool product ceiling is
fundamentally low. Phase 9.0 ships the substrate that turns per-call into
per-workflow.

**Built (branch `phase-9.0-identity`, commits `8854270`+`0f64e86`; 58/58 tests pass, tsc clean; migration `004` NOT applied, NOT deployed):**
- ✅ `aegis_agents` table — identity anchored on EXACTLY ONE of customer_id,
  wallet address (cryptographically authenticated via x402 signatures), or
  anonymous session. `aegis_scans` table — summary (always) + full_output
  (opt-in) + 90-day retention + `previous_scan_id` self-ref lineage column.
  `usage_log.agent_id` link. Forced RLS deny-all matching migration 003.
- ✅ Data-access layer: `src/db/agents.ts` + `src/db/scans.ts` (`getScanForAgent`
  is **agent_id-scoped → IDOR-safe by construction**, applying the `/v1/jobs` lesson).
- ✅ Identity resolution (`src/auth/agentIdentity.ts`): lazy, memoized
  `getOrResolveAgent` (precedence customer_id > x402 payer wallet > per-day anon
  session). Pure `anonSessionKey` + `identityFor` unit-tested. Wired into the
  `/mcp` x402 gate (resolves payer wallet, stamps `usage_log.agent_id`) and the
  request context.
- ✅ Scan persistence in `wrapTool`: every paid call opens→completes/fails a scan
  linked to the agent, bumps agent aggregates, threads `agent_id` into usage logs.
  Legacy/stdio + budget-exceeded behavior unchanged.
- ✅ `previous_scan_id` injected into every paid tool's schema (`registerPaidTool`),
  recorded as IDOR-safe lineage (validated against the caller's own scans).
- ✅ Three free tools: `agent_whoami`, `agent_history`, `agent_scan_get` (priced 0).

**Remaining (the gated steps + future depth):**
- 🔒 Apply migration `004` to prod Supabase + deploy (Railway watches `master`, so
  merging the branch is the deploy trigger). **GATE: money-path deploy → confirm with Andrew.**
- Per-tool *consumption* of `previous_scan_id` (auto-ingest a parent scan's
  output) → true composite tools: `vuln_prioritize(scan_ids[])`,
  `audit_report_generate(scan_ids[])`, etc. (lineage + retrieval already ship;
  this is the analysis step).
- Optional DX: return the new `_scan_id` in paid-tool responses (currently
  discoverable via `agent_history`) — held back to keep tool outputs unchanged.
- Perf: `getOrResolveAgent` + scan writes add DB round-trips per paid call; fold
  into a SECURITY DEFINER RPC if latency matters at volume.
- Privacy: customer-controlled deletion + export pages (GDPR Art. 15/17 satisfied
  by the schema), default 90-day retention, encrypted full_output.

**Patent angle:** persistent agent identity derived from cryptographic payment
signatures may be a fourth inventive aspect worth filing in the nonprovisional
(US 64/057,021 — hard cutoff 2027-05-04). The 2nd provisional (endpoint-safety
verdict gating a payment) is drafted — see below.

Full design + schema + flow: `wiki/pages/agentaegis-agent-identity.md`

### Phase 9 — The trust layer (L2) + capability expansion (builds on Phase 9.0)

**The L2 trust layer is the product moat.** These compose the existing L1 tools into
agent-facing verdicts. Prioritized from the PIQ AA board:

- ✅ **`vet_endpoint` — SHIPPED LIVE 2026-06-17.** Composite trust verdict for an endpoint
  an agent is about to pay/call: TLS/cert + DNS hygiene + threat intel (domain & resolved
  IP) + RDAP domain age → single PROCEED / CAUTION / BLOCK verdict + trust_score + reasons.
  **Flagship.** Gates a payment → core of the 2nd patent. `src/tools/trustLayer/vetEndpoint.ts`,
  pure unit-tested scorer, $3. NEXT: add on-chain agent/wallet reputation as a 5th sub-score
  (ERC-8004 + GoPlus — PIQ task `ab894469`); breach-exposure sub-score once HIBP key is set.
- **`scan_mcp_plugin`** ✅ SHIPPED 2026-06-23 (live in prod `tools/list`, $5) — supply-chain
  scanner for agent tools: before an agent installs/trusts an MCP server or skill, scan it
  (git repo or code snippet) for exfiltration (secrets/env → network), prompt-injection sinks
  (hijack phrases + hidden/zero-width unicode), dangerous capabilities (eval/shell/dynamic
  exec), npm install lifecycle hooks, and obfuscation — composing Semgrep + secret-scan with
  MCP-specific heuristics into a pure-scored (`scoreMcpPlugin`) PROCEED/CAUTION/BLOCK verdict.
  Hard-blocks on the exfiltration combo / verified secret / decode-then-exec.
  `src/tools/trustLayer/scanMcpPlugin.ts`, in the `/admin/dry-run` QA map. **24-test vitest suite**
  (`tests/scanMcpPlugin.test.ts`: 6 positive + 6 negative behavioral cases + 9 scorer-policy units
  + 3 integration) — the corpus drove a scorer retune (medium dangerous-capabilities were unscored;
  single clear-risk signals now CAUTION). **HTTP Bazaar resource LIVE** at `/x402/scan-mcp-plugin`
  ($5, 402 verified, payTo=Ledger, discoverable) — catalogs on one settled bootstrap payment
  (`audit/x402-test/05-bootstrap-scan-mcp-plugin.ts`). NEXT: run the bootstrap; add a `scan_skill` variant.
- **`kya_verify`** (PIQ, due 2026-08-15) — Know-Your-Agent attestation built on
  Mastercard's Verifiable Intent open spec; pairs with Visa TAP / Web Bot Auth.
- **On-chain agent/wallet reputation scoring** (PIQ, due 2026-08-15) — the "AgentRadar"
  piece; feeds `vet_endpoint` and stands alone as a reputation lookup.
- **Tier-A parity tools** (PIQ, due 2026-07-31) — `ioc_enrich`, `hash_reputation`,
  `kev_lookup`, `cve_risk_score`, etc. — table-stakes coverage that also feeds verdicts.

Secondary capability expansion (lower priority than the trust layer):

- Web3 security (slither, echidna, wallet screen, onchain analyze)
- Container + IaC + cloud posture (trivy image, kube-bench, prowler, scoutsuite, checkov)
- Cloud integration breadth (Azure, GCP, Datadog, Cloudflare, CloudWatch)
- More compliance frameworks (FedRAMP, GDPR-specific, NIST 800-53)
- White-label / partner program · Enterprise tier · Multi-region deployment

### Phase 10 — Managed Security Audit Agent (backlog — evaluate after launch traction)

A new product tier: an autonomous Claude Agent (Agent SDK / Managed Agents) that
connects to the AgentAegis MCP tools, picks and chains them itself, and returns a
complete security audit. Customers pay a flat $49–299 per audit instead of
orchestrating per-tool calls — higher margin, zero customer orchestration effort,
broader market (anyone who needs an assessment, not just agent builders).

- **Status:** backlog proposal. Does NOT disrupt Phase 8 launch or Phase 9 plans.
- **Hard requirement before any build:** target ownership verification (DNS TXT
  record or HTTP meta token) must gate *every* scan. Running scans against
  infrastructure the customer doesn't own is a CFAA exposure, and AgentAegis is
  the party running the scan.
- Test the audit-agent offer only *after* the initial per-tool launch has traction.
- Full proposal + corrected economics: `wiki/pages/agentaegis-audit-agent.md`

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
- ~~**No webhook UI yet**~~ — ✅ RESOLVED 2026-06-23. Portal UI already shipped (`app/account/webhooks/` — create/update/delete/test + deliveries); the real gap was the MCP REST API. Added customer-scoped CRUD at `/v1/customers/:id/webhooks` (+ `/test`) in `src/db/webhooks.ts` + `httpServer.ts` (apiKeyAuth + ownership, https-only URL validation, secret shown once) so agents/API consumers can manage webhooks too. E2E-verified on prod (commit `d687e7e`).
- **No multi-region** — single Railway region (US East). If we get an EU enterprise customer, this becomes a blocker.
- ~~**Customer balance display gap**~~ — ✅ RESOLVED 2026-06-23 (commit `88d1b26`). Data was fresh; the bug was caching. Added `Cache-Control: no-store` to `/v1/customers/:id/balance` + `cache:"no-store"` on the admin dashboard fetch (already polls 60s) → dashboards/portal/agents always see live numbers.
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
