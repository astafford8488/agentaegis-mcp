import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import "dotenv/config";
import { buildMcpServer } from "./server.js";

async function main() {
  // Stdio transport: typically run locally for Claude Desktop. Skip payment by default
  // since it's local; set REQUIRE_PAYMENT=true to enforce x402 even on stdio.
  const skipPayment = process.env.REQUIRE_PAYMENT !== "true";

  const server = buildMcpServer({ skipPayment });
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error(
    `AgentAegis MCP server running (stdio) — 20 tools available, payment ${skipPayment ? "disabled" : "required"}`
  );
}

main().catch((err) => {
  console.error("Failed to start AgentAegis MCP server:", err);
  process.exit(1);
});
