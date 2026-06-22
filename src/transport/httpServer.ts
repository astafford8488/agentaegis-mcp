import express, { type Express, type Request, type Response } from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { v4 as uuidv4 } from "uuid";
import { apiKeyAuth, type AuthenticatedRequest } from "../auth/apiKeyAuth.js";
import { authorizeToolCall } from "../auth/gate.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isDbConfigured, getDb } from "../db/client.js";
import { createCustomer, findCustomerByEmail, addBalance } from "../db/customers.js";
import { createApiKey } from "../db/apiKeys.js";
import { getCustomerUsage, logUsage } from "../db/usageLog.js";
import { getJob } from "../db/scanJobs.js";
import { resolveAgent } from "../db/agents.js";
import {
  createCheckoutSession,
  verifyWebhookSignature,
  parseCheckoutCompleted,
} from "../payments/stripe.js";
import { buildAdminRouter } from "./adminRoutes.js";
import { mountHttpResources } from "./httpResource.js";
import { runWithContext } from "../auth/requestContext.js";
import { runHealthCheck } from "./healthCheck.js";
import { Sentry } from "../observability/sentry.js";

export function buildHttpApp(buildServer: () => McpServer): Express {
  const app = express();
  app.use(cors({ origin: "*", exposedHeaders: ["Mcp-Session-Id", "X-PAYMENT-RESPONSE", "PAYMENT-REQUIRED", "PAYMENT-RESPONSE"] }));

  // === Stripe webhook (raw body required for signature verification) ===
  // This route MUST be registered before express.json() so the body stays raw.
  app.post("/webhooks/stripe", express.raw({ type: "application/json" }), async (req: Request, res: Response) => {
    const sigHeader = req.headers["stripe-signature"] as string | undefined;
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret) return res.status(503).json({ error: "Stripe webhook not configured (missing STRIPE_WEBHOOK_SECRET)" });
    if (!sigHeader) return res.status(400).json({ error: "Missing Stripe-Signature header" });

    const rawBody = (req.body as Buffer).toString("utf8");

    if (!verifyWebhookSignature(rawBody, sigHeader, secret)) {
      return res.status(400).json({ error: "Invalid signature" });
    }

    let event: any;
    try {
      event = JSON.parse(rawBody);
    } catch {
      return res.status(400).json({ error: "Invalid JSON" });
    }

    // Idempotency: skip if we've already credited this session
    if (isDbConfigured() && event.type === "checkout.session.completed") {
      const eventId = event.id;
      const { data: existing } = await getDb()
        .from("aegis_usage_log")
        .select("id")
        .eq("payment_ref", eventId)
        .maybeSingle();
      if (existing) {
        return res.status(200).json({ ok: true, idempotent: true });
      }
    }

    if (event.type === "checkout.session.completed") {
      const parsed = parseCheckoutCompleted(event);
      if (parsed) {
        try {
          await addBalance(parsed.customer_id, parsed.amount_usd);
          // Log a "credit" entry in usage_log so it shows up in customer history.
          // We use price_usd = -amount (negative spend = credit).
          await logUsage({
            customer_id: parsed.customer_id,
            tool_name: "_topup",
            target: parsed.session_id,
            price_usd: -parsed.amount_usd,
            paid_via: "stripe",
            payment_ref: event.id,
            success: true,
          });
        } catch (err) {
          console.error("[stripe] credit failed for session", parsed.session_id, err);
          return res.status(500).json({ error: "Internal credit error" });
        }
      }
    }

    return res.status(200).json({ received: true, type: event.type });
  });

  // === All other routes use JSON body parser ===
  app.use(express.json({ limit: "5mb" }));

  // Liveness — fast, no upstream calls. For container orchestration probes.
  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      version: "0.3.0",
      tools_count: Object.keys(TOOL_PRICING).length,
      db_configured: isDbConfigured(),
      timestamp: new Date().toISOString(),
    });
  });

  // Deep health — calls each upstream dependency in parallel. For external
  // uptime monitors that need to detect partial outages.
  // Returns 200 when status==="ok" or "degraded", 503 when "fail" so monitors
  // can alert on hard failure (DB down) but treat upstream-only outages as
  // informational.
  app.get("/health/deep", async (_req, res) => {
    const report = await runHealthCheck();
    res.status(report.status === "fail" ? 503 : 200).json(report);
  });

  // FAQ — public endpoint, same content the help tool returns.
  // Optional ?topic=getting_started filter.
  app.get("/faq", async (req, res) => {
    const { FAQ } = await import("../tools/account/help.js");
    const topic = (req.query.topic as string | undefined) || "all";
    const entries = topic === "all" ? FAQ : FAQ.filter((e) => e.topic === topic);
    res.set("Cache-Control", "public, max-age=300");
    res.json({
      topic,
      topics_available: Array.from(new Set(FAQ.map((e) => e.topic))),
      entry_count: entries.length,
      entries,
    });
  });

  // Pricing
  app.get("/pricing", (_req, res) => {
    res.json({
      tools: Object.entries(TOOL_PRICING).map(([name, price]) => ({
        name,
        price_usd: price,
      })),
      payment_methods: ["api_key", "x402"],
      x402_network: process.env.X402_NETWORK || "base-sepolia",
      x402_payee: process.env.X402_PAYEE_ADDRESS || null,
    });
  });

  // Customer signup
  app.post("/v1/customers", async (req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    const { email, name, company, wallet_address } = req.body;
    if (!email) return res.status(400).json({ error: "email required" });

    try {
      const existing = await findCustomerByEmail(email);
      if (existing) return res.status(409).json({ error: "Customer with this email already exists" });

      const customer = await createCustomer({ email, name, company, wallet_address });
      res.status(201).json({ customer });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // API key creation
  app.post("/v1/customers/:customerId/api-keys", async (req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    const customerId = req.params.customerId as string;
    const { name, monthly_limit_usd } = req.body;

    if (!name) return res.status(400).json({ error: "name required" });

    try {
      const result = await createApiKey({ customer_id: customerId, name, monthly_limit_usd });
      res.status(201).json({
        id: result.apiKey.id,
        name: result.apiKey.name,
        key: result.rawKey,
        prefix: result.apiKey.key_prefix,
        monthly_limit_usd: result.apiKey.monthly_limit_usd,
        warning: "Store this key securely — it cannot be retrieved again.",
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // Account snapshot — balance, monthly usage, key info.
  // Auth: API key belonging to that customer. Designed to be the one call
  // an agent (or human dashboard) makes to know "where do I stand?"
  app.get("/v1/customers/:customerId/balance", apiKeyAuth, async (req: AuthenticatedRequest, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    const customerId = req.params.customerId as string;
    if (req.apiKey?.customer_id !== customerId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    try {
      const { data: customer, error } = await getDb()
        .from("aegis_customers")
        .select("id, email, prepaid_balance_usd, created_at")
        .eq("id", customerId)
        .maybeSingle();

      if (error || !customer) return res.status(404).json({ error: "Customer not found" });

      const monthStart = new Date();
      monthStart.setUTCDate(1);
      monthStart.setUTCHours(0, 0, 0, 0);
      const monthUsage = await getCustomerUsage(customerId, monthStart.toISOString());

      const balance = parseFloat(customer.prepaid_balance_usd as any);
      const monthlyLimit = parseFloat(req.apiKey.monthly_limit_usd as any);
      const monthlyUsage = parseFloat(req.apiKey.current_month_usage_usd as any);

      // Affordability hint: how many of each tool the customer can still afford
      const TOOL_PRICING = (await import("../types/mcp.js")).TOOL_PRICING;
      const paidPrices = Object.values(TOOL_PRICING).filter((p) => p > 0);
      const cheapestTool = paidPrices.length > 0 ? Math.min(...paidPrices) : 0;
      const callsRemaining = balance > 0 && cheapestTool > 0 ? Math.floor(balance / cheapestTool) : 0;

      res.json({
        customer_id: customer.id,
        email: customer.email,
        prepaid_balance_usd: balance,
        api_key: {
          id: req.apiKey.id,
          name: req.apiKey.name,
          monthly_limit_usd: monthlyLimit,
          current_month_usage_usd: monthlyUsage,
          monthly_remaining_usd: Math.max(0, monthlyLimit - monthlyUsage),
        },
        usage_this_month: monthUsage,
        affordability: {
          cheapest_tool_price_usd: cheapestTool,
          remaining_cheapest_tool_calls: callsRemaining,
          balance_low_warning: balance < 1.0,
        },
        topup_url_template: `/v1/customers/${customer.id}/checkout-session`,
      });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // Customer usage stats
  app.get("/v1/customers/:customerId/usage", apiKeyAuth, async (req: AuthenticatedRequest, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    const customerId = req.params.customerId as string;
    const fromDate = req.query.from as string | undefined;

    if (req.apiKey?.customer_id !== customerId) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const fromDateStr = typeof fromDate === "string" ? fromDate : undefined;

    try {
      const usage = await getCustomerUsage(customerId, fromDateStr);
      res.json(usage);
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // === Stripe checkout session ===
  // Returns a Stripe Checkout URL the customer can use to top up their balance.
  // No auth required — the customer_id in the URL is the only "auth" needed.
  // (Anyone could create a session that credits an existing customer's account
  // with their own money — that's fine, it's their money.)
  app.post("/v1/customers/:customerId/checkout-session", async (req: Request, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });
    if (!process.env.STRIPE_SECRET_KEY) return res.status(503).json({ error: "Stripe not configured" });

    const customerId = req.params.customerId as string;
    const { amount_usd, success_url, cancel_url } = req.body || {};

    if (typeof amount_usd !== "number" || amount_usd < 5 || amount_usd > 5000) {
      return res.status(400).json({ error: "amount_usd must be a number between 5 and 5000" });
    }

    // Look up the customer to get their email
    const { data: customer, error } = await getDb()
      .from("aegis_customers")
      .select("email")
      .eq("id", customerId)
      .maybeSingle();

    if (error || !customer) return res.status(404).json({ error: "Customer not found" });

    try {
      const session = await createCheckoutSession({
        customer_id: customerId,
        customer_email: customer.email,
        amount_usd,
        success_url: success_url || `https://agentaegis.org/billing/success`,
        cancel_url: cancel_url || `https://agentaegis.org/billing/cancel`,
      });
      res.json({ checkout_url: session.url, session_id: session.id, expires_at: session.expires_at });
    } catch (err) {
      res.status(500).json({ error: String(err) });
    }
  });

  // === Admin routes ===
  app.use("/admin", buildAdminRouter());

  // === HTTP x402 resource(s) — Bazaar discovery experiment (vet_endpoint) ===
  // No-op unless payee + CDP mode are set. Uses x402-express middleware so the
  // route is gated AND declared discoverable to the Bazaar (HTTP-only catalog).
  mountHttpResources(app);

  // Scan job status (for async scans) — requires API-key auth + ownership check.
  app.get("/v1/jobs/:jobId", apiKeyAuth, async (req: AuthenticatedRequest, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    // Require authentication. apiKeyAuth is OPTIONAL middleware (a request with no
    // Authorization header passes through with req.apiKey undefined). Without this
    // guard, the ownership check below — previously `if (req.apiKey && ...)` — was
    // skipped for unauthenticated callers, so anyone who knew a job UUID could read
    // another customer's scan results (IDOR). Require a valid key first.
    if (!req.apiKey) return res.status(401).json({ error: "Authentication required" });

    const jobId = req.params.jobId as string;
    const job = await getJob(jobId);
    if (!job) return res.status(404).json({ error: "Job not found" });

    // Ownership: only the customer that created the job may read it. Jobs with a
    // null customer_id (e.g. anonymous/x402) are not readable via this endpoint.
    if (job.customer_id !== req.apiKey.customer_id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    res.json({ job });
  });

  // MCP Streamable HTTP endpoint
  // Each session gets its own transport instance
  const transports = new Map<string, StreamableHTTPServerTransport>();
  const servers = new Map<string, McpServer>();

  app.post("/mcp", apiKeyAuth, async (req: AuthenticatedRequest, res: Response) => {
    try {
      // ===== x402 gate (only for paid tool calls without an API key) =====
      // If the request is a JSON-RPC tools/call for a priced tool AND the
      // caller hasn't authenticated with an API key, require x402 payment.
      // - No X-PAYMENT header → 402 with payment requirements
      // - X-PAYMENT present → verify + settle, then proceed
      const body = req.body;
      const isToolCall = body?.method === "tools/call";
      const toolName = isToolCall ? body?.params?.name : undefined;
      const toolPrice = toolName ? (TOOL_PRICING[toolName] ?? 0) : 0;
      const requiresPayment = isToolCall && toolPrice > 0 && !req.apiKey;

      if (requiresPayment && process.env.X402_PAYEE_ADDRESS) {
        // The v2 x402 client (@x402/fetch) sends the signed payment in the
        // PAYMENT-SIGNATURE header; the legacy v1 client uses X-PAYMENT. Accept
        // either so both rails work on the same endpoint.
        const paymentHeader = (req.headers["payment-signature"] || req.headers["x-payment"]) as string | undefined;
        // Railway / Vercel terminate TLS at the edge, so req.protocol comes
        // through as "http" even when the user reached us over HTTPS. The
        // resource URL is bound into the EIP-712 signed payload — if we
        // mis-state the scheme, the agent's signature won't match what the
        // facilitator computes, and verification fails. Trust X-Forwarded-Proto
        // (set by Railway / Vercel / Cloudflare) and force HTTPS in production.
        const forwardedProto = req.headers["x-forwarded-proto"] as string | undefined;
        const protocol =
          forwardedProto === "https" || req.protocol === "https" || process.env.NODE_ENV === "production"
            ? "https"
            : req.protocol;
        const fullResourceUrl = `${protocol}://${req.get("host")}${req.originalUrl}`;

        // CDP-mode branch (R-3): when both CDP_API_KEY_ID and CDP_API_KEY_SECRET
        // env vars are set, route to the @coinbase/x402 SDK with v2 wire format
        // (chain-id network names like "eip155:8453", `amount` field, ResourceInfo
        // envelope, x402Version:2). Otherwise fall through to the legacy v1
        // raw-fetch path against X402_FACILITATOR_URL. The legacy path remains
        // the default for testnet, self-hosted facilitators, or any non-CDP
        // provider — switching modes is purely env-var-driven, no code redeploy.
        const x402Cdp = await import("../auth/x402Cdp.js");
        if (x402Cdp.isCdpMode()) {
          const cdpReqs = x402Cdp.buildCdpPaymentRequirements(toolName!);

          if (!paymentHeader) {
            // v2 client reads the challenge from the PAYMENT-REQUIRED header, not the body.
            res.setHeader("PAYMENT-REQUIRED", x402Cdp.encodeCdpChallengeHeader(toolName!, fullResourceUrl));
            return res.status(402).json(x402Cdp.buildCdpChallenge(toolName!, fullResourceUrl));
          }

          // Decode X-PAYMENT (base64 JSON envelope used by all x402 clients)
          let paymentPayload: unknown;
          try { paymentPayload = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf-8")); }
          catch { try { paymentPayload = JSON.parse(paymentHeader); } catch { paymentPayload = paymentHeader; } }

          const verified = await x402Cdp.cdpVerify(paymentPayload, cdpReqs);
          if (!verified.isValid) {
            res.setHeader("PAYMENT-REQUIRED", x402Cdp.encodeCdpChallengeHeader(toolName!, fullResourceUrl));
            return res.status(402).json({
              ...x402Cdp.buildCdpChallenge(toolName!, fullResourceUrl),
              error: `Payment invalid: ${verified.invalidReason || "unknown"}`,
            });
          }

          const settlement = await x402Cdp.cdpSettle(paymentPayload, cdpReqs);
          if (!settlement.success) {
            res.setHeader("PAYMENT-REQUIRED", x402Cdp.encodeCdpChallengeHeader(toolName!, fullResourceUrl));
            return res.status(402).json({
              ...x402Cdp.buildCdpChallenge(toolName!, fullResourceUrl),
              error: `Settlement failed: ${settlement.error || "unknown"}`,
            });
          }

          res.setHeader(
            "X-PAYMENT-RESPONSE",
            Buffer.from(JSON.stringify({
              success: true,
              transaction: settlement.txHash,
              network: settlement.network || cdpReqs.network,
              payer: verified.payerAddress,
            })).toString("base64")
          );
          (req as any).x402Settled = true;
          (req as any).payerWallet = verified.payerAddress;
          if (isDbConfigured()) {
            // Resolve the x402 payer wallet to a persistent agent (best-effort) so
            // the usage log + downstream scan persistence link to a stable identity.
            // Stashed on req → carried into the request context → reused by wrapTool
            // (no second resolve).
            const x402Agent = verified.payerAddress
              ? await resolveAgent({ walletAddress: verified.payerAddress }).catch(() => null)
              : null;
            (req as any).agent = x402Agent;
            // Capture the row id so wrapTool can flip success→false if the tool throws
            // (settlement already happened; this only corrects the logged outcome).
            (req as any).x402UsageLogId = await logUsage({
              agent_id: x402Agent?.id,
              tool_name: toolName!,
              target: undefined,
              price_usd: toolPrice,
              paid_via: "x402",
              payment_ref: settlement.txHash,
              success: true,
              request_ip: req.ip,
              user_agent: req.headers["user-agent"],
            }).catch(() => null);
          }
        } else {
          // === Legacy v1 path (unchanged behavior — raw fetch to X402_FACILITATOR_URL) ===
          const requirements = (await import("../auth/x402Auth.js")).buildPaymentRequirements(toolName!, fullResourceUrl);

          if (!paymentHeader) {
            // RFC: send 402 with x402 payment requirements
            return res.status(402).json({
              x402Version: 1,
              error: "X-PAYMENT header required",
              accepts: [requirements],
            });
          }

          // Verify + settle the payment
          const x402Auth = await import("../auth/x402Auth.js");
          const verified = await x402Auth.verifyX402Payment(paymentHeader, requirements);
          if (!verified.isValid) {
            return res.status(402).json({
              x402Version: 1,
              error: `Payment invalid: ${verified.invalidReason || "unknown"}`,
              accepts: [requirements],
            });
          }
          const settlement = await x402Auth.settleX402Payment(paymentHeader, requirements);
          if (!settlement.success) {
            return res.status(402).json({
              x402Version: 1,
              error: `Settlement failed: ${settlement.error || "unknown"}`,
              accepts: [requirements],
            });
          }
          // Tell the client the payment was settled
          res.setHeader(
            "X-PAYMENT-RESPONSE",
            Buffer.from(JSON.stringify({
              success: true,
              transaction: settlement.txHash,
              network: process.env.X402_NETWORK || "base-sepolia",
              payer: verified.payerAddress,
            })).toString("base64")
          );
          // Mark request as x402-paid so wrapTool skips its own payment check
          (req as any).x402Settled = true;
          (req as any).payerWallet = verified.payerAddress;
          // Log the x402-paid call
          if (isDbConfigured()) {
            const x402Agent = verified.payerAddress
              ? await resolveAgent({ walletAddress: verified.payerAddress }).catch(() => null)
              : null;
            (req as any).agent = x402Agent;
            // Capture the row id so wrapTool can flip success→false if the tool throws
            // (settlement already happened; this only corrects the logged outcome).
            (req as any).x402UsageLogId = await logUsage({
              agent_id: x402Agent?.id,
              tool_name: toolName!,
              target: undefined,
              price_usd: toolPrice,
              paid_via: "x402",
              payment_ref: settlement.txHash,
              success: true,
              request_ip: req.ip,
              user_agent: req.headers["user-agent"],
            }).catch(() => null);
          }
        }
      }

      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      let transport: StreamableHTTPServerTransport;

      if (sessionId && transports.has(sessionId)) {
        transport = transports.get(sessionId)!;
      } else if (!sessionId && isInitializeRequest(req.body)) {
        const newSessionId = uuidv4();
        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => newSessionId,
          onsessioninitialized: (sid: string) => {
            transports.set(sid, transport);
          },
        });

        transport.onclose = () => {
          if (transport.sessionId) {
            transports.delete(transport.sessionId);
            servers.delete(transport.sessionId);
          }
        };

        const server = buildServer();
        servers.set(newSessionId, server);
        await server.connect(transport);
      } else {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "No valid session ID" },
          id: null,
        });
        return;
      }

      // Attach payment context to request for tool handlers
      (req as any).authContext = {
        apiKey: req.apiKey,
        authorize: (toolName: string, target?: string) =>
          authorizeToolCall(req, res, toolName, target),
      };

      // Run the entire request inside an AsyncLocalStorage context so tool
      // handlers can read the api key/customer without explicit threading.
      const x402Settled = (req as any).x402Settled === true;
      await runWithContext(
        {
          apiKey: req.apiKey,
          authMethod: x402Settled ? "x402" : req.authMethod,
          x402Settled,
          payerWallet: (req as any).payerWallet,
          agent: (req as any).agent,
          x402UsageLogId: (req as any).x402UsageLogId,
          ip: req.ip,
          userAgent: req.headers["user-agent"],
        },
        () => transport.handleRequest(req, res, req.body)
      );
    } catch (err) {
      console.error("MCP request error:", err);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal error" },
          id: null,
        });
      }
    }
  });

  app.get("/mcp", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports.has(sessionId)) {
      return res.status(400).json({ error: "Invalid or missing session ID" });
    }
    await transports.get(sessionId)!.handleRequest(req, res);
  });

  app.delete("/mcp", async (req: Request, res: Response) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports.has(sessionId)) {
      return res.status(400).json({ error: "Invalid or missing session ID" });
    }
    await transports.get(sessionId)!.handleRequest(req, res);
  });

  // Sentry Express error handler — must be the LAST middleware registered.
  // Captures any unhandled errors thrown from the route handlers above and
  // forwards them to Sentry with request context attached. No-op if Sentry
  // wasn't initialized (SENTRY_DSN unset).
  Sentry.setupExpressErrorHandler(app);

  // Final fallback error handler — keeps the server from leaking stack traces
  // to clients while still surfacing a useful response. Runs AFTER Sentry
  // has captured the error.
  app.use((err: any, _req: Request, res: Response, _next: any) => {
    if (res.headersSent) return;
    console.error("[http] unhandled:", err);
    res.status(500).json({ error: "Internal server error" });
  });

  return app;
}
