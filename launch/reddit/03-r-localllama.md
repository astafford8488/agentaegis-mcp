# r/LocalLLaMA post

**Sub:** https://www.reddit.com/r/LocalLLaMA/
**Day:** Thursday week 1
**Best time:** 9–11 am Eastern
**Flair:** "Discussion" or "Resources" (whichever fits — check current sub norms)

⚠️ **Hardest sub to land on.** r/LocalLLaMA is sharply technical and allergic to AI-marketing language. Lead with technical substance, not the product. If the post smells like marketing, downvotes within minutes.

## Title

```
MCP server with body-inspection gating — how to charge per tool call when JSON-RPC multiplexes everything onto one URL
```

**Why this title:**
- Specific architectural problem, not a product pitch
- Names "body-inspection gating" — distinctive enough to spark "wait, what?" curiosity
- No "AI", no "agent", no "revolutionary"

## Body

```
Building an MCP server where each tool call has a different price means
the gating layer needs to know WHICH tool was called BEFORE deciding
whether to allow the request through. URL-based gateways can't help
here — MCP's Streamable HTTP transport multiplexes everything onto
POST /mcp, with the actual tool name buried in the JSON-RPC body's
params.name field.

The naive options are bad:

  a) Charge a flat rate for any /mcp access: kills per-tool pricing,
     leaves money on the table for cheap tools and undercharges expensive ones.
  b) Deploy distinct URL paths per tool: breaks MCP discoverability and
     spec conformance. Clients won't find your tools without bespoke
     configuration per server.
  c) Push gating to the application layer: works but loses the security
     and performance benefits of dedicated gateway middleware.

What I ended up with: a non-destructive body-inspection layer between the
HTTP server and the MCP handler. Pseudocode:

    app.use("/mcp", (req, res, next) => {
      const body = JSON.parse(rawBody);  // buffered parse, kept separate
      if (body.method === "tools/call") {
        const tool = body.params?.name;
        const price = TOOL_PRICING[tool] ?? 0;

        if (price === 0) return next();  // free, route to dispatch
        if (req.headers["authorization"]) return apiKeyRail(req, res, next);
        if (req.headers["x-payment"]) return x402Rail(req, res, next);
        return send402Challenge(res, tool, price);
      }
      // tools/list, initialize, etc — let through unmodified
      next();
    });

Two non-obvious things that mattered:

1. The body parse has to be non-destructive. Express's default body parser
   consumes the stream, so the downstream MCP handler gets nothing. Solution
   is buffering raw bytes alongside the parsed object so both the gating
   layer and the MCP handler can each access their own copy.

2. The pricing map has to be read-only at the gating layer. Tools register
   themselves at server startup but the gating layer can't trust any
   per-request mutation — that opens a race where one request can drop
   the price of a tool another request is paying for. The map is frozen
   after registration; pricing changes require a server restart.

Two payment rails terminate at the same dispatch handler:
- API key: atomic SQL UPDATE on customer balance with conditional WHERE
- x402 (USDC on Base): HTTP 402 challenge → ERC-3009 transferWithAuthorization
  → facilitator /verify + /settle → on-chain settlement → dispatch

The unified rail-discriminator log table lets a single SQL query produce
revenue reports across both rails — eliminates the rail-reconciliation pain
in mixed payment systems.

I shipped this as AgentAegis (cybersec tools for AI agents). Patent provisional
filed on the body-inspection + dual-rail pattern. Marketing site is
agentaegis.org if you want to see what the actual tools look like.

The body-inspection-gating pattern is what I haven't seen elsewhere. If
anyone has done something similar with a different RPC protocol (Jsonnet,
gRPC reflective handlers, JSON-RPC variants), I'd be curious what
constraints you hit.
```

## Pinned reply

```
TOOL_PRICING is a TypeScript const-frozen map at server startup. Looks like:

    {
      "cve_lookup": 0.10,
      "port_scan": 0.50,
      "compliance_check": 1.00,
      "help": 0,           // free
      "account_balance": 0,// free
      ...
    }

Currency is USD. Conversion to USDC microcents (10^6) happens at
challenge construction time. About 22 tools currently.

Paying customer balance is a separate aegis_customers row; debit is a
single atomic UPDATE with `WHERE balance_usd >= price` clause to prevent
over-draw under concurrency.
```

## Anti-patterns specific to this sub

- DO NOT use words like "revolutionary", "game-changing", "AI-powered". Instant downvote
- DO NOT bury the technical substance under product pitch. Substance first.
- DO show actual code, even if pseudocode. r/LocalLLaMA respects code
- DO acknowledge limitations and trade-offs honestly
- DO NOT respond to every comment with "let me DM you" — use public threads
