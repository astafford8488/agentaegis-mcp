import express, { type Express, type Request, type Response } from "express";
import cors from "cors";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { v4 as uuidv4 } from "uuid";
import { apiKeyAuth, type AuthenticatedRequest } from "../auth/apiKeyAuth.js";
import { authorizeToolCall } from "../auth/gate.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isDbConfigured } from "../db/client.js";
import { createCustomer, findCustomerByEmail } from "../db/customers.js";
import { createApiKey } from "../db/apiKeys.js";
import { getCustomerUsage } from "../db/usageLog.js";
import { getJob } from "../db/scanJobs.js";

export function buildHttpApp(buildServer: () => McpServer): Express {
  const app = express();
  app.use(cors({ origin: "*", exposedHeaders: ["Mcp-Session-Id", "X-PAYMENT-RESPONSE"] }));
  app.use(express.json({ limit: "5mb" }));

  // Health check
  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      version: "0.2.0",
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

      await transport.handleRequest(req, res, req.body);
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
