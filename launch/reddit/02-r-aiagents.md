# r/AI_Agents post

**Sub:** https://www.reddit.com/r/AI_Agents/
**Day:** Wednesday week 1
**Best time:** 8–10 am Eastern
**Flair:** "Resource" or "Tool" (whichever current convention)

## Title

```
Per-call billing on a single MCP endpoint (API key + per-call USDC) — three things that broke during integration
```

**Why this title:**
- Names the architecture pattern (specific, not vague)
- Promises war stories ("three things that broke")
- This sub responds well to "I built X, here's what I learned" vs "go buy my product"

## Body

```
Built an MCP server where agents pay per tool call. Two rails on one
endpoint:

  1. Pre-funded API key (Stripe-backed) — agent operator tops up, server
     debits balance per call.
  2. Per-call USDC micropayment — agent calls /mcp with no auth, server
     responds 402 with payment requirements, agent signs ERC-3009
     transferWithAuthorization (gasless), server forwards to a facilitator
     for verification + on-chain settlement on Base mainnet.

Same endpoint, same dispatch handler. Body inspection routes between the
two rails based on what headers are present. Free tools (tools/list, help,
account_balance) bypass both, which lets autonomous agents discover what's
available before committing money.

Three things that broke during the x402 + MCP integration that aren't in
either spec:

1. The X-PAYMENT header is base64-encoded JSON, but the facilitator's
   /verify and /settle endpoints want the DECODED object as the
   paymentPayload field. Sending the base64 string directly returns a
   confusing "invalid_*" error.

2. Payment requirements have to include the EIP-712 domain
   {name:"USDC", version:"2"} in the "extra" field. Without it, the
   facilitator returns invalid_exact_evm_missing_eip712_domain — because
   it can't reconstruct the typed-data domain to verify the signature.
   Different stablecoins have different domains (USDT = "Tether USD",
   DAI = "Dai Stablecoin"), so you can't hardcode one and call it done.

3. The "resource" field has to be a fully-qualified URL, not just a path.
   The reference x402-fetch client zod-validates this and rejects
   path-only values before signing.

The body-inspection gating itself is the part nobody else has solved yet
that I've seen. URL-based gateways (Stripe Metered, Kong, Cloudflare API
Shield) gate by URL path. MCP multiplexes everything onto /mcp, so the
URL-based approach charges a flat rate or breaks. I parse the JSON-RPC
body non-destructively (preserving for downstream MCP handlers), look up
params.name in a pricing map, then route.

Architecture diagrams, patent provisional, and the actual 22 tools (cybersec
focused — CVE lookup, vuln scans, threat intel, compliance, code security,
identity audits) are at agentaegis.org if anyone wants to look or use it.

Mostly posting because I haven't seen the body-inspection gating pattern
written up anywhere and figured this sub would have opinions. Curious if
anyone has shipped something similar — what'd you do differently?
```

## Pinned reply

```
Forgot to mention — free tier is meaningful enough to integrate without
spending: tools/list returns full schemas + per-tool prices, so an agent
can plan the cost of a workflow before committing. Found this matters
more than I expected for autonomous-agent flows where the human can't
pre-approve.

Status page: status.agentaegis.org
FAQ (mirrors the help tool): agentaegis-mcp-production.up.railway.app/faq
```

## Anti-patterns to avoid in this sub

- Don't lead with the product — lead with the technical insight (the three protocol gotchas)
- Don't position as "agent infra you must use." Position as "I shipped this, here's what I learned"
- This sub is small enough that the same usernames recur. Engaging with thoughtful comments builds reputation that compounds for future posts
