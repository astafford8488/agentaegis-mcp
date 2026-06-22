// HTTP x402 resource — Bazaar discovery experiment (one flagship tool).
//
// The CDP Bazaar catalogs HTTP resources ONLY (type:"http"); it does not list
// MCP servers/tools, so our /mcp tools can't appear there no matter what we send
// on settle (confirmed: the live index is 100% type:"http", and our type:"mcp"
// declaration sits in "processing" forever). To get a foothold we expose ONE tool
// — vet_endpoint, the trust-layer flagship — as a dedicated HTTP endpoint and let
// the official x402-express middleware handle the 402 gate + the Bazaar discovery
// declaration (config.discoverable=true) + enrichment + on-settle cataloging.
//
// This rides the Coinbase mainnet stack (x402-express + @coinbase/x402 facilitator),
// separate from our custom /mcp CDP gate (x402Cdp.ts) — the custom gate exists
// because /mcp is JSON-RPC and doesn't fit per-route middleware; a plain HTTP route
// fits the middleware perfectly. Scoped as an experiment: if this draws agent
// traffic from the Bazaar, expand to the rest of the catalog.

import type { Express, Request, Response } from "express";
import { paymentMiddleware, type RoutesConfig } from "x402-express";
import { facilitator } from "@coinbase/x402";
import { vetEndpoint, vetEndpointSchema } from "../tools/trustLayer/vetEndpoint.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isCdpMode } from "../auth/x402Cdp.js";
import { logUsage } from "../db/usageLog.js";
import { isDbConfigured } from "../db/client.js";

const VET_PATH = "/x402/vet-endpoint";

/**
 * Mount the HTTP x402 resource(s). No-op unless a payee + CDP mode are configured
 * (so the endpoint never 402s without a working facilitator behind it). Must be
 * called after express.json() so the handler can read the body.
 */
export function mountHttpResources(app: Express): void {
  const payTo = process.env.X402_PAYEE_ADDRESS;
  if (!payTo || !isCdpMode()) return;

  const price = TOOL_PRICING["vet_endpoint"] ?? 3;
  const network = process.env.X402_NETWORK || "base";
  // Force the public https URL. Behind Railway's edge, req.protocol is "http"
  // (TLS terminated upstream), so x402-express would otherwise advertise + catalog
  // an http:// resource. The client signs whatever the challenge says, so this must
  // match on both sides — pin it explicitly to the https public URL.
  const baseUrl = process.env.PUBLIC_BASE_URL || "https://agentaegis-mcp-production.up.railway.app";

  const routes: RoutesConfig = {
    [`POST ${VET_PATH}`]: {
      price: `$${price.toFixed(2)}`,
      network: network as never,
      config: {
        description:
          "AgentAegis vet_endpoint — composite PROCEED/CAUTION/BLOCK safety verdict for an endpoint an AI agent is about to call or pay. Runs live TLS/cert, DNS hygiene, threat-intel (domain + resolved IP), and domain-age signals → one trust score with reasons.",
        mimeType: "application/json",
        maxTimeoutSeconds: 60,
        discoverable: true,
        resource: `${baseUrl}${VET_PATH}` as never,
        // Discovery metadata (best-effort shape; informs Bazaar consumers).
        inputSchema: { bodyType: "json", body: { endpoint: "example.com or https://api.example.com/pay" } } as never,
        outputSchema: {
          example: { endpoint: "stripe.com", verdict: "PROCEED", trust_score: 95, reasons: ["valid TLS", "clean threat intel"] },
        },
      },
    },
  };

  // Gate + discovery + on-settle cataloging are all handled by the middleware.
  // It only intercepts the configured route; everything else falls through.
  app.use(paymentMiddleware(payTo as `0x${string}`, routes, facilitator as never));

  app.post(VET_PATH, async (req: Request, res: Response) => {
    // Payment was already verified + settled by the middleware above.
    const parsed = vetEndpointSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid body. Expected { "endpoint": "<domain or URL>" }.' });
    }
    try {
      const result = await vetEndpoint(parsed.data);
      if (isDbConfigured()) {
        // Best-effort usage log (the HTTP rail doesn't resolve a Phase 9.0 agent yet).
        logUsage({
          tool_name: "vet_endpoint",
          paid_via: "x402",
          price_usd: price,
          success: true,
          request_ip: req.ip,
          user_agent: req.headers["user-agent"],
        }).catch(() => { /* best-effort */ });
      }
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });
}
