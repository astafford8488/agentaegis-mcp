import "dotenv/config";
import { buildHttpApp } from "./transport/httpServer.js";
import { buildMcpServer } from "./server.js";
import type { Request, Response } from "express";
import type { AuthenticatedRequest } from "./auth/apiKeyAuth.js";

const PORT = parseInt(process.env.PORT || "3000");

const app = buildHttpApp(() => {
  // Each MCP session gets its own server. We pass a payment-checker that
  // reads the per-request auth context attached by the HTTP middleware.
  return buildMcpServer({
    preAuthorized: async () => {
      // The HTTP middleware sets req.authContext.authorize per request.
      // For Streamable HTTP, the request lifecycle is per tool-call so
      // we need to consult the active context here. Currently the SDK
      // doesn't pass per-request context to tool handlers, so we rely
      // on top-level middleware having already authorized the session.
      // Future: use AsyncLocalStorage to thread context through.
      return { authorized: true };
    },
  });
});

app.listen(PORT, () => {
  const dbStatus = process.env.SUPABASE_URL ? "configured" : "not configured";
  const x402Status = process.env.X402_PAYEE_ADDRESS ? "configured" : "not configured (set X402_PAYEE_ADDRESS)";
  console.log(`AgentAegis MCP server running on http://localhost:${PORT}`);
  console.log(`  - HTTP transport: POST /mcp`);
  console.log(`  - Health: GET /health`);
  console.log(`  - Pricing: GET /pricing`);
  console.log(`  - DB: ${dbStatus}`);
  console.log(`  - x402: ${x402Status}`);
});
