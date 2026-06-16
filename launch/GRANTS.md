# Grant Applications — Circle USDC + Base Builder

Application-ready drafts for the two grants AgentAegis qualifies for. **Canonical
source** (repo); the PitchIQ "Grant Applications" page mirrors this for review.

> **Truthfulness rules (read first).** Every claim here must be verifiable. Where a
> number depends on launch traction we don't have yet, the draft uses a
> `[FILL: …]` placeholder — do not submit with placeholders, and do not invent
> metrics. AgentAegis is **infrastructure-shipped and live on Base mainnet**, but
> pre-public-launch on usage volume; frame it that way. Both programs change their
> portals/mechanics often — **verify the current URL, form, and ask amounts before
> submitting** (links below were correct as of the last research pass, June 2026).

---

## Shared facts & boilerplate (reuse across both)

**One-liner:** AgentAegis is a pay-per-call cybersecurity API for AI agents — 20
security tools (vuln scans, threat intel, compliance, code security) behind a
single MCP endpoint, billed per call in USDC on Base via the x402 protocol (or a
Stripe-funded API key).

**Why it matters:** Autonomous agents increasingly need to *pay for services* mid-task
without a human in the loop. AgentAegis is a live, production example of agent-native
commerce: an agent hits the endpoint, gets an HTTP 402, signs an ERC-3009
`transferWithAuthorization` (gasless), and a USDC micropayment settles on Base
mainnet before the tool runs — no account, no subscription, no human approval.

**What's shipped & verifiable (June 2026):**
- 20 paid cybersecurity tools + free discovery tier, live at the MCP endpoint
  `https://agentaegis-mcp-production.up.railway.app/mcp`.
- **Real x402 settlements on Base mainnet** via Coinbase's CDP facilitator —
  e.g. tx `0xed08f420324458a0146a7ca8bb45c56930f37425b3b7112e0bce5a63446d5b9c`
  (USDC payer → receiver `0x3347d4E9925cC379a333c017367248e1A11DF7fC`).
- Listed in the **official MCP registry** as `io.github.astafford8488/agentaegis`.
- Discoverable in the **x402 Bazaar** (Coinbase's agentic-commerce index) — each
  tool indexes on its first CDP-settled payment.
- **US provisional patent** filed on the dual-rail per-invocation payment
  architecture (App. No. 64/057,021); a second provisional (endpoint-safety
  verdict gating an agent payment) is drafted.
- Customer portal (`app.agentaegis.org`), public status page, FAQ, pricing API.

**Team:** Andrew Stafford, founder (Your AI Group). Solo founder + AI-assisted
build. Contact: admin@youraigroup.com.

**Links:** site `https://www.agentaegis.org` · MCP endpoint (above) · GitHub
`https://github.com/astafford8488/agentaegis-mcp` · registry
`io.github.astafford8488/agentaegis` · status `https://status.agentaegis.org`.

**Tech:** Node 22 + Express on Railway (Streamable-HTTP MCP transport); Supabase
Postgres with forced row-level security; viem + `@coinbase/x402` for settlement on
Base mainnet; Next.js portal on Vercel.

---

## Application 1 — Circle USDC Developer Grant

**Program:** Circle's developer grant for projects that drive real USDC utility,
with an explicit interest in the agentic / stablecoin-payments economy.
**Where (verify):** `https://www.circle.com/grants` (or the Questbook portal
`circle.questbook.app`). **Ask:** the program has historically ranged ~$5K–$100K;
request a **specific** figure tied to use-of-funds (draft below asks **$25,000**).
**Track:** agentic economy / payments infrastructure.

### Project name
AgentAegis — pay-per-call cybersecurity for AI agents, settled in USDC.

### Short description (≤ ~300 chars)
AgentAegis lets AI agents buy cybersecurity tools one call at a time, paying in
USDC on Base via x402 (HTTP 402 + ERC-3009). No account, no subscription — the
agent signs a gasless USDC authorization and the tool runs. Live on Base mainnet
and listed in the official MCP registry.

### Problem
Autonomous agents can now *do* work, but they can't easily *pay* for third-party
services mid-task. Subscriptions and API keys assume a human signs up and manages
billing in advance. That breaks the moment an agent needs a capability its operator
never pre-provisioned. The missing primitive is **per-call settlement an agent can
perform itself** — and a stable unit of account it can hold and spend. USDC is that
unit; x402 is the rail; but there are few live, non-trivial services actually
demonstrating it end-to-end.

### Solution & how it uses USDC
AgentAegis exposes 20 cybersecurity tools through one MCP endpoint with two billing
rails. The USDC-native rail: an agent calls a paid tool with no API key, receives an
HTTP 402 with payment requirements, signs an ERC-3009 `transferWithAuthorization`
(gasless for the agent), and the server settles the USDC micropayment on **Base
mainnet** through Coinbase's CDP facilitator before returning results. Every paid
call is real USDC volume from a genuine service — not a faucet demo. Pricing is
$1–$5 per call. This is a working reference implementation of USDC-settled,
agent-initiated commerce.

### Traction
- Infrastructure live in production on Base mainnet; verifiable on-chain
  settlements (tx hashes above).
- Listed in the official MCP registry + indexed in the x402 Bazaar.
- `[FILL: paid-call count / unique paying agents / USDC settled — as of submission]`
- Public launch (Show HN, directories, demo) in progress; submit with launch
  metrics attached.

### Use of funds (requesting $25,000)
- **CDP facilitator + settlement at scale** (~$8K): move beyond the free tier,
  add settlement retries/idempotency hardening, and a USDC treasury buffer.
- **Open-source x402 client package** (~$7K): ship `@agentaegis/mcp-client` (MIT)
  — a typed client + x402 payment helper so any agent framework can transact in
  USDC against the endpoint in minutes. Grows the USDC-paying agent ecosystem.
- **Trust-layer tool `vet_endpoint`** (~$10K): a pre-transaction safety verdict an
  agent calls *before* it pays an unknown counterparty in USDC — directly reduces
  fraud/loss in agentic USDC payments (the subject of our 2nd patent).

### Why Circle should fund this
AgentAegis turns USDC into the working currency of an agent's security budget. It's
already live, already settling on Base, and the grant directly expands the volume
and the developer surface of USDC-settled agent commerce — plus the trust-layer work
makes those USDC payments *safer*, which is squarely in Circle's interest as the
issuer.

---

## Application 2 — Base Builder Grants (retroactive)

**Program:** Base Builder Grants — retroactive rewards for builders shipping real
usage on Base. **Mechanism (verify — this changes):** historically nominated /
applied via Gitcoin and the Base builder program; awards ~1–5 ETH. Qualify by
**shipping on Base**, which AgentAegis has (live mainnet x402 settlements).
**Where (verify):** the current Base Builder Grants / Gitcoin round; also register a
**Builder Score** (Talent Protocol) and ensure the receiving wallet is the project's
Base address.

### What we built on Base
AgentAegis is a cybersecurity API for AI agents where **payment happens on Base**.
Agents pay per tool call in USDC via x402 (HTTP 402 + ERC-3009), settled on Base
mainnet through Coinbase's CDP facilitator. Base is the settlement layer for the
entire product — not an add-on. We also list in the x402 Bazaar, Coinbase's
Base-native agentic-commerce discovery index.

### Why it advances the Base / agentic-commerce ecosystem
- **Novel primitive on Base:** agent-initiated, per-invocation USDC micropayments
  for a real service — a concrete answer to "what do agents actually buy on Base?"
- **Drives Base transaction volume** from a non-speculative, utility source
  (security tooling), and demonstrates x402 + ERC-3009 + the CDP facilitator working
  together in production.
- **Reference implementation** other Base builders can learn from; we plan to
  open-source the x402 client package so more agents transact on Base.
- **Distribution:** listed in the official MCP registry and the x402 Bazaar, with a
  public launch underway — bringing MCP/agent developers onto Base rails.

### Proof of shipping on Base
- Mainnet settlement txs (above), receiver `0x3347d4E9925cC379a333c017367248e1A11DF7fC`.
- USDC contract on Base: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.
- `[FILL: settlement count / volume on Base as of submission]`

### Ask & use
Retroactive grant (whatever the round awards). Funds go to scaling settlement,
the open-source Base/x402 client package, and the `vet_endpoint` trust tool that
makes agent payments on Base safer.

---

## Submission checklist & sequencing

- [ ] **Launch first, then submit** — both applications are materially stronger with
  post-launch metrics. Fill every `[FILL: …]` with a real number.
- [ ] Confirm the **current portal + form + ask range** for each (these programs
  change; don't trust a stale URL).
- [ ] Circle: tie the ask to the use-of-funds breakdown; attach the on-chain tx
  links and the registry listing as proof.
- [ ] Base: register/refresh a **Builder Score**; ensure the **Base receiving
  wallet** is correct; submit in the active round.
- [ ] Have ready as attachments: the demo video, the Show HN permalink, the
  one-pager / investor deck outline, and the on-chain settlement links.
- [ ] Do **not** mention unreleased tools (the agent identity tools) as shipped.
- [ ] Log submission dates + statuses on the PitchIQ Launch board.
