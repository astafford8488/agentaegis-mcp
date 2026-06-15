# Investor Deck Outline (5 slides + appendix)

For the VVP / VIPC follow-ups. Capitalizes on the now-live mainnet payment proof. Position as
**trust-verdict infrastructure for agentic commerce**, raising on usage metrics — not a scan vendor.
Full strategy: wiki `agentaegis-positioning-trust-layer.md`.

Keep it to 5 slides for the conversation; the appendix is backup for the questions.

---

## Slide 1 — The problem

**Headline:** AI agents are starting to transact autonomously. They have no way to know who's safe.

- Agents now pay for APIs, call unknown MCP servers, hit endpoints with no human in the loop.
- The rails exist (x402 = Linux Foundation standard, backed by Visa/Mastercard/Stripe/Google/AWS).
- Missing: the **trust verdict** — "should my agent pay/call this counterparty?" No incumbent owns it.

**Speaker note:** This is the "before Stripe Radar, card fraud was everyone's problem" moment.

## Slide 2 — The thesis

**Headline:** AgentAegis is the security & trust layer for agentic commerce.

- **L1 (shipped):** 20 pay-per-call cybersecurity tools over MCP — vuln scans, threat intel,
  compliance, code security. Dual-rail billing (Stripe API key + x402 USDC). $1–$5/call.
- **L2 (the moat):** the trust verdict — `vet_endpoint`, `scan_mcp_plugin`, `kya_verify`,
  on-chain reputation. Each composes L1 tools into a single PROCEED/CAUTION/BLOCK answer.
- "Stripe Radar for agentic commerce" — and the verdict gates a payment, which is the patent.

## Slide 3 — Proof (this is the slide that lands)

**Headline:** It's live, in production, and money moves on mainnet.

- Live MCP server, marketing site (SEO 94/100), customer portal, status page — all in production.
- **Real mainnet x402 settlement:** agent → $1 USDC → our wallet → tool ran, ~2s. BaseScan link.
- Dual-rail verified end-to-end: Stripe top-up ($5 real payment landed) + x402 (on-chain tx).
- We audited ourselves with our own tools (12 findings, 7 fixed) — including a pre-launch billing bug.

**Speaker note:** Open BaseScan live in the meeting. "This isn't a mockup — here's the transaction."

## Slide 4 — Moat & defensibility

**Headline:** Patent-pending architecture + first-mover on an unowned layer.

- US provisional 64/057,021 (dual-rail billing + MCP body-inspection gating + settlement-logging).
- Second provisional in progress: endpoint-safety verdict gating a per-invocation payment (the L2 moat).
- Integration depth: every engine sandboxed + output-normalized — months to replicate.
- Wrapper, not competitor: we *enable* nmap/Nuclei/Semgrep; the OSS community pulls us along.
- Timing: MCP ~18 months old, x402 ~12. We're early with a working product + filed IP.

## Slide 5 — The ask

**Headline:** Raising [pre-seed $500K–$1.5M] to compress time-to-cofounder and time-to-EU.

Use of funds:
- Cybersecurity ops cofounder + 1 eng (the bandwidth ceiling today is one person).
- L2 trust layer build-out (vet_endpoint → the high-margin product).
- EU multi-region + SOC 2 (opens enterprise + European buyers).
- Patent nonprovisional (hard deadline 2027-05-04).

**Honest framing:** "I don't need funding to keep operating — costs scale with revenue. I'd take
it to move faster on the cofounder and the trust layer, while the category is still unowned."

---

## Appendix — backup for Q&A

**Unit economics:** $1–$5/call, ~95% gross margin (open-source engines; cost is external API +
compute). No subscription gating — fully usage-priced. Audit-tier (Phase 10): $49–299/audit.

**Traction metrics to gather BEFORE the meeting** (fill these in — "pre-revenue" is weaker than
"$X/week organic"): calls/day, unique paying agents, repeat rate, revenue/day, Bazaar rank,
HN/Reddit reach, signup count. Even small real numbers beat projections.

**Why us:** Andrew Stafford — 25 yrs (Amazon, NASA, NetApp, Veradigm), two exits, filed the patent
solo, shipped production solo. Recruiting a cybersecurity ops cofounder.

**Market sizing logic:** every autonomous agent that transacts is a potential caller; the trust
verdict is a per-transaction tax the whole ecosystem needs. TAM grows with agent adoption, not
with our sales team.

**Biggest risk (say it before they do):** MCP adoption timing. Hedge: protocol-agnostic engines +
billing; we'd refit to whatever wins. The bet is that agent-native paid infrastructure is real —
and Visa/Mastercard/Stripe standardizing x402 says it is.

**Readiness gaps (be honest):** need to incorporate (DE C-Corp), assign IP to the entity, set up
founder vesting + 83(b), business banking, bookkeeping. None are blockers to a SAFE; all are
table-stakes before a priced round. (Tracked in the funding-readiness PIQ task.)
