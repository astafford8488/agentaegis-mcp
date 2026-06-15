# HN / Reddit Comment Prep — hard questions, pre-answered

Quick-reference for launch day. Keep this open. Answers are honest, specific, and link to
deployed proof where possible. Tone: builder talking to builders, concede real limits.

---

## Open source / trust

**"Is it open source?"**
> The marketing site, FAQ, and the full tool catalog + attribution (NOTICE.md) are public on
> GitHub. The MCP server itself is closed for now — the dual-rail billing engine is the part
> I'm still deciding the right OSS posture for. Considering a thin open-source companion client.

**"Why should I trust a closed security tool?"**
> Fair. Three things: (1) the actual scanning is done by tools you already trust — nmap, Nuclei,
> Semgrep, sslyze, trufflehog, trivy — we're the integration + billing layer, not a new engine;
> (2) we ran AgentAegis on AgentAegis (Phase 4 self-audit, 12 findings, 7 fixed in code); (3) full
> open-source attribution at NOTICE.md. We're a wrapper, and we're upfront about it.

## Why MCP / why this shape

**"Why MCP instead of a REST API?"**
> Because the customer is an AI agent, and MCP is the protocol agents already speak. An agent in
> Claude Desktop / Cursor / Cline can discover and call these tools mid-conversation with zero
> bespoke integration. A REST API would need the agent author to write a client.

**"Why per-call instead of a subscription?"**
> Agents don't have procurement cycles. An autonomous agent that needs one SSL audit shouldn't
> require its operator to sign up for a monthly plan. Per-call (card or USDC) matches how agents
> actually consume tools — bursty, unpredictable, often one-shot.

## Payments / x402

**"Why USDC / x402 at all? Why not just Stripe?"**
> Both — same endpoint. Stripe-funded API keys for human-mediated signups. x402 USDC for
> autonomous agents that can't do a signup flow (no email, no card). The agent signs an ERC-3009
> authorization, the facilitator settles on Base, ~3 sec. The agent never holds gas. That last
> property is the point: agents can't manage ETH.

**"Isn't x402 a Coinbase thing you're locked into?"**
> The protocol is open (now a Linux Foundation standard). We use Coinbase's CDP facilitator today
> because it's the production-grade one supporting Base mainnet. The facilitator is swappable —
> we isolated it behind one module and could self-host or switch providers.

**"What about atomicity — you take payment then could withhold the result?"**
> Real critique. Our ordering is verify → settle → run; payment settles before the tool runs, so
> in principle a provider could take payment and fail to deliver. In practice we run the tool
> immediately after settlement in the same request, and Base Flashblocks make settlement ~sub-second.
> A reputation/escrow layer is the longer-term answer for the ecosystem. Not hand-waving it.

**"Live mainnet proof?"**
> Yes — here's a real settlement: basescan.org/tx/0xed08f420324458a0146a7ca8bb45c56930f37425b3b7112e0bce5a63446d5b9c
> $1 USDC, agent → our wallet, tool executed. Not testnet.

## Competition / moat

**"How is this different from Lakera / Pillar / [prompt-security tool]?"**
> Different layer. Those defend the prompt ("is this input malicious?"). AgentAegis lets the agent
> *do security work* as part of its job ("scan this domain before you submit a form on it"). We're
> not prompt defense; we're agent-callable security operations.

**"Couldn't Cloudflare / Palo Alto / AWS just do this?"**
> They could bolt on tools, but they're not MCP-native and their pricing is subscription-shaped,
> which breaks for autonomous per-call agents. The defensible piece is the dual-rail billing +
> MCP body-inspection gating (patent pending) and the trust-verdict layer we're building on top.

**"What stops me from just running nmap myself?"**
> Nothing — and for the cost-sensitive that's the right call. We sell to operators who'd rather
> pay $1 than provision and maintain the scanner + wrap its output + handle the billing. Same
> reason teams use Datadog instead of self-hosting Prometheus.

## Security / abuse

**"What stops someone scanning infrastructure they don't own?"**
> Input validation rejects RFC1918 / loopback / link-local / cloud-metadata IPs and non-HTTPS
> targets before any engine runs. For the upcoming managed-audit tier, target-ownership
> verification (DNS TXT / HTTP meta token) is a hard gate. Every scan is logged to a customer ID.

**"Has it been pen-tested?"**
> Self-audit + an automated red-team suite (open-redirect, MCP-bypass, Stripe-webhook spoof, SSRF,
> x402 challenge inspection) run clean on the major surfaces. External pen test is on the backlog
> once revenue justifies it. Honest: it's early, solo-built, and I'd welcome findings.

**"What's your biggest risk?"**
> MCP adoption timing. If MCP plateaus, our distribution shrinks. Hedge: the engines and billing
> layer are protocol-agnostic; we'd refit. But the early-mover thesis assumes MCP wins.

## Product / roadmap

**"What's next?"**
> The trust layer: `vet_endpoint` — an agent about to pay an unknown endpoint asks "is this safe
> to transact with?" and gets a composite verdict (SSL, domain age, threat intel, breach exposure,
> on-chain reputation). "Stripe Radar for agentic commerce."

**"Pricing seems high / low."**
> $1–$5/call. We floored at $1 because the on-chain data shows ~95% of x402 volume is $1+ and
> sub-$1 micropayments are a dead segment. Open to feedback — what would you expect to pay?

---

## Rules of engagement (don't break these)

- Never argue with a downvote. Answer the substance, move on.
- Never claim something works that you haven't verified. "Not yet — on the roadmap" is fine.
- Credit anyone who finds a bug. Fix fast, say you fixed it.
- No marketing-speak ("revolutionary", "game-changing", "AI-powered") — instant death on HN/r/LocalLLaMA.
- If you don't know, say "good question, I don't know yet" — it reads as honest, not weak.
