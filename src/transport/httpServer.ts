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
import {
  createCheckoutSession,
  verifyWebhookSignature,
  parseCheckoutCompleted,
} from "../payments/stripe.js";
import { buildAdminRouter } from "./adminRoutes.js";
import { runWithContext } from "../auth/requestContext.js";

export function buildHttpApp(buildServer: () => McpServer): Express {
  const app = express();
  app.use(cors({ origin: "*", exposedHeaders: ["Mcp-Session-Id", "X-PAYMENT-RESPONSE"] }));

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

  // Health check
  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      version: "0.3.0",
      tools_count: Object.keys(TOOL_PRICING).length,
      db_configured: isDbConfigured(),
      timestamp: new Date().toISOString(),
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

  // Scan job status (for async scans)
  app.get("/v1/jobs/:jobId", apiKeyAuth, async (req: AuthenticatedRequest, res: Response) => {
    if (!isDbConfigured()) return res.status(503).json({ error: "Database not configured" });

    const jobId = req.params.jobId as string;
    const job = await getJob(jobId);
    if (!job) return res.status(404).json({ error: "Job not found" });

    if (req.apiKey && job.customer_id !== req.apiKey.customer_id) {
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
      await runWithContext(
        {
          apiKey: req.apiKey,
          authMethod: req.authMethod,
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

  return app;
}
