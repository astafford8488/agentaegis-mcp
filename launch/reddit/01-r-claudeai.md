# r/ClaudeAI post

**Sub:** https://www.reddit.com/r/ClaudeAI/
**Day:** Tuesday week 1 (after red-team complete)
**Best time:** 8–10 am Eastern
**Flair:** "Built with Claude" or "MCP" (whichever current convention)

## Title

```
Built an MCP server with 22 cybersecurity tools for Claude Desktop — free tier for discovery
```

**Why this title:**
- Says exactly what it is in 12 words
- "Free tier for discovery" tells readers they can try before they pay (lowers click-resistance)
- No marketing language, no "AI-powered" / "revolutionary"

## Body

```
Hi r/ClaudeAI,

Just shipped AgentAegis — an MCP server exposing 22 cybersecurity tools that
Claude can call as part of any conversation. Vulnerability scans, CVE
lookups, port scanning, SSL audits, secret scanning, threat intel, dependency
audits, identity reviews, and compliance checks for SOC 2 / ISO 27001 / HIPAA
/ PCI DSS.

To use it in Claude Desktop, add this to your config:

    {
      "mcpServers": {
        "agentaegis": {
          "url": "https://agentaegis-mcp-production.up.railway.app/mcp",
          "headers": {
            "Authorization": "Bearer your_aegis_key_here"
          }
        }
      }
    }

Restart Claude Desktop and the tools show up in the slash menu.

Free tier covers tools/list, help, and account_balance so you can browse
what's available and check pricing without spending anything. Paid tools
start at $0.10/call. No subscription, no monthly minimum.

A few things worth mentioning:

- The body-inspection gating layer was the hardest part. URL-based gateways
  like Stripe Metered or Kong can't see params.name in a JSON-RPC body, so
  we parse it server-side before routing to free / API-key / x402 rails.

- Atomic SQL UPDATEs prevent over-draw under concurrent calls (50 parallel
  $0.10 calls against a $0.20 balance correctly stop after 2).

- We ran AgentAegis on AgentAegis itself for a self-audit phase. Found 12
  issues; 7 fixed in code. Most embarrassing: a billing bug in our own
  dispatch wrapper that would have given paid tools away free under one
  code path. Caught it pre-launch.

It's hosted (not self-hostable) because the billing engine isn't trivial to
operate. Patent pending on the dual-rail pattern. Marketing site, FAQ, and
status page are public.

Happy to answer questions about MCP integration or how Claude tends to use
these tools mid-conversation. Good and bad takes welcome.
```

## Pinned reply (as OP, immediately after posting)

```
For anyone curious where to actually try it: https://www.agentaegis.org

Pricing is at /pricing on the same domain. The MCP /faq endpoint mirrors
all the help text the in-tool 'help' command returns, so you can read
through it without setting up the integration first.
```

(Putting the link in a comment, not the body, is the Reddit norm — looks less promotional and survives subs that auto-filter promotional posts.)

## Comments to expect + how to reply

| Q | A |
|---|---|
| "Is the source open?" | "Marketing site + FAQ are open. Server itself is closed because the billing engine is the moat. Considering a thin open-source companion SDK at @agentaegis/mcp-client (Phase 9)." |
| "Why USDC and not just Stripe?" | "Both. Stripe-funded API keys for human-mediated signups. USDC via x402 for autonomous agents that can't do a signup flow. Same endpoint, body inspection routes to whichever the agent presents." |
| "How is this different from [Lakera / Pillar / etc]?" | "Different layer of the stack. Those defend the prompt. AgentAegis lets the agent run cybersec ops AS PART OF its work — 'scan this domain before submitting a form on it' rather than 'is the prompt malicious'." |
| "Has this passed a real pen test?" | "Self-audit + automated red-team suite ran clean on the major attack surfaces (open-redirect, body-inspection bypass, DoS resistance, SSRF in webhook URLs). External pen test is on the Phase 9 backlog when there's customer revenue to justify." |
| "What stops me from cancelling/disputing the Stripe charge?" | "Standard Stripe dispute mechanics — if you charge back, balance goes to zero, future calls 402 until you top up. Honest answer." |
