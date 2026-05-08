# Show HN — draft

**Where to post:** https://news.ycombinator.com/submit
**Recommended timing:** Tuesday or Wednesday, 8–10am Eastern. Avoid Mondays (week catch-up) and Fridays (low traffic). Don't post during major HN events (YC Demo Day, Apple keynote) — your post gets buried.

---

## Title (under 80 chars — HN truncates)

```
Show HN: AgentAegis – per-call billing for MCP servers using HTTP 402 + ERC-3009
```

**Why this title:**
- Leads with "Show HN" (mandatory for the category)
- Names the product
- The hyphen-clause is the entire technical pitch in 11 words
- Mentions HTTP 402 (rare, intriguing) and ERC-3009 (specific, technical)
- Doesn't say "AI" anywhere — HN is over-saturated; let the MCP keyword do the agent-related signaling

**Alternative titles (if you want to A/B):**
1. `Show HN: I built an MCP server where agents pay per tool call in USDC`
2. `Show HN: AgentAegis – MCP server with per-invocation billing (x402 + API keys)`
3. `Show HN: HTTP 402 is finally useful — built per-call billing for MCP tools`

I'd go with #1 if you want to lead with "I built" (HN responds well to solo-founder narratives). The default above is more technical-product-focused.

---

## URL field

```
https://www.agentaegis.org
```

---

## Body

```
Hi HN,

I built AgentAegis: an MCP server that lets agents pay per call to run 22
cybersecurity workflows. It wraps battle-tested open-source engines (nmap,
Nuclei, Semgrep, sslyze, trufflehog, trivy) and threat-intel APIs (NVD,
AbuseIPDB, AlienVault OTX, abuse.ch, HIBP) behind a unified per-call billing
layer. Two payment rails on a single endpoint:

1. Pre-funded API key — agent operator tops up via Stripe, server debits
   stored balance per call (atomic UPDATE, no over-draw under concurrency).
2. Per-call USDC micropayment — agent calls /mcp without auth, server
   responds 402 with payment requirements, agent signs an ERC-3009
   transferWithAuthorization (gasless), server forwards to a facilitator,
   on-chain settlement completes within ~3 seconds, then the tool runs.

The body-inspection gating is the part I think is genuinely novel: MCP
multiplexes all tool calls onto one URL (/mcp), so URL-based gateways like
Stripe's metered API or Kong can't tell which tool was called and how much
to charge. The server parses the JSON-RPC body non-destructively to extract
params.name, looks up per-tool pricing, then routes to one of two payment
rails or bypasses if the tool is free. Free tools (help, account_balance,
tools/list) coexist with paid tools on the same endpoint, which is
necessary for autonomous-agent flows that need to discover tools before
committing to a paid call.

Three protocol-level fixes I had to discover the hard way during reduction
to practice:
- The X-PAYMENT header is base64-encoded JSON; the facilitator's /verify
  and /settle expect the DECODED object as paymentPayload (not the base64).
- Payment requirements MUST include the EIP-712 domain {name:"USDC",
  version:"2"} in the "extra" field — the facilitator returns
  invalid_exact_evm_missing_eip712_domain otherwise.
- The "resource" field must be a fully-qualified URL, not a path. The
  reference x402-fetch client zod-validates this before signing.

Also worth mentioning — I ran AgentAegis on AgentAegis itself ("Phase 4
self-audit"). It found 12 findings; 7 got fixed in code. The most
embarrassing was a billing bug in my own tool dispatch wrapper that would
have given paid tools away for free under one code path. The audit caught
it before any real customer hit it. There's an irony I'll take.

What we built vs. what we wrap:
- Built: dual-rail billing engine, body-inspection gating, MCP integration,
  the customer portal, the orchestration that runs each engine in a
  sandboxed subprocess and normalizes its output to JSON. Patent provisional
  filed (US 64/057,021) on the architecture.
- Wrapped: the actual scanning is done by nmap, Nuclei, Semgrep, sslyze,
  trufflehog, trivy. Threat intel from NVD (free, public), AbuseIPDB,
  AlienVault OTX, abuse.ch, HIBP. Full attribution at
  github.com/astafford8488/agentaegis-mcp/blob/master/NOTICE.md.

Stack:
- Node 22 + Express on Railway, Streamable HTTP MCP transport
- Postgres on Supabase with row-level security + service-role separation
  for SOC 2 / ISO 27001 audit posture
- Customer portal at app.agentaegis.org built on Next.js 15 + Vercel
  (separate repo, decoupled deploy lifecycle so a portal deploy can't
  crater the paid /mcp endpoint)
- viem + x402-fetch for cryptographic settlement on Base mainnet

Try it:
- Marketing: https://www.agentaegis.org
- Live MCP server: https://agentaegis-mcp-production.up.railway.app/mcp
- Customer portal: https://app.agentaegis.org
- Status page: https://status.agentaegis.org
- Pricing: https://agentaegis-mcp-production.up.railway.app/pricing
- FAQ (same content as the in-MCP help tool):
  https://agentaegis-mcp-production.up.railway.app/faq

Provisional patent filed under 35 USC 111(b) covering the dual-rail +
body-inspection gating + unified rail-discriminator logging pipeline.
Mostly mentioning that because some HN readers ask about IP posture for
agent-native infra plays.

What I'd love feedback on:

1. The free/paid coexistence pattern — is the "tools/list returns prices
   alongside schemas" approach right, or does it belong in a separate
   discovery endpoint?

2. The deep-health endpoint (/health/deep) returns
   degraded/ok/fail per upstream. Better Stack monitors fail-closed on
   "fail" only, treat "degraded" as informational. Does that match your
   ops mental model, or should monitor authors expect tri-state?

3. Anyone tried building an x402 facilitator? The reference one at
   x402.org has been reliable for me but I'd love to hear about
   alternatives or self-hosted setups.

Happy to answer questions about MCP body inspection, the x402 reduction-
to-practice gotchas, or the Supabase row-level security setup. Code is
not yet open source (I'm still figuring out the right OSS posture for
the dual-rail billing engine specifically), but the marketing site,
landing pages, and FAQ docs are public.

— Andrew
```

---

## Pre-launch sanity checks

Before clicking submit:

- [ ] **agentaegis.org is up** (curl `https://www.agentaegis.org` → 200)
- [ ] **/mcp returns a 402 challenge** (curl POST with no auth → 402 with payment requirements)
- [ ] **/health/deep is healthy** (after the Railway deploy issue is fixed)
- [ ] **Status page shows green** (https://status.agentaegis.org)
- [ ] **The FAQ is current** — re-read /faq, fix anything that says "coming soon"
- [ ] **Customer portal lets a fresh signup work** (test in incognito, log in via Google, verify /account loads)
- [ ] **You have ~3 hours of free time after submission** to engage with comments. HN posts that get answered within the first hour climb; ones that ghost their commenters die. Be on it.
- [ ] **You haven't been linkbaited into a flame war** elsewhere in the past 24 hours (HN moderators sometimes shadow-bury accounts in active drama)

## After-submit playbook

- Watch for the post to climb. Top of "new" → top 30 of "front page" within 30 min if it's going to take off
- Respond to every comment within 60 minutes for the first 4 hours
- When someone challenges a technical claim, link to source code or a deployed endpoint, not a marketing page
- If you hit the front page, *expect Stripe traffic*. Make sure the customer portal can handle a small spike (50-100 simultaneous signups, not 5000)
- Keep `/health/deep` open in a tab and refresh periodically. If anything goes degraded, fix it visibly — HN respects operators who debug in public
- Save the permalink to the post and pin it in your X/Twitter thread (next file)
