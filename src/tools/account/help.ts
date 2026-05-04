// help — agent-facing FAQ. Free to call. Mirrors the human FAQ at
// https://agentaegis.org/faq exactly. Agents call this tool to discover
// integration patterns, payment flows, error semantics, and tool catalog
// without needing to scrape the website.
//
// To keep the human and agent surfaces in sync we export the same FAQ
// constant and just render it differently in each surface.

import { z } from "zod";
import { TOOL_PRICING } from "../../types/mcp.js";

export const helpSchema = z.object({
  topic: z.enum([
    "all",
    "getting_started",
    "authentication",
    "balance_and_billing",
    "tools",
    "async_jobs",
    "integration",
    "errors",
    "x402",
    "rate_limits",
    "security",
  ]).optional(),
});

export type HelpInput = z.infer<typeof helpSchema>;

export interface FAQEntry {
  topic: string;
  question: string;
  answer: string;
  example?: string;
}

export const FAQ: FAQEntry[] = [
  // === Getting started ===
  {
    topic: "getting_started",
    question: "What is AgentAegis?",
    answer: "An MCP server that exposes 21 cybersecurity tools — compliance assessments, vulnerability scans, code security, threat intel, incident triage, identity audits — to AI agents. Pay per call: API key with monthly budget OR x402 micropayment (USDC on Base). No subscription.",
  },
  {
    topic: "getting_started",
    question: "What is the base URL?",
    answer: "Production: https://agentaegis-mcp-production.up.railway.app — eventually api.agentaegis.org once DNS is wired.",
  },
  {
    topic: "getting_started",
    question: "How do I get started in 30 seconds?",
    answer: "POST /v1/customers with your email → POST /v1/customers/:id/api-keys with a name → use the returned aegis_... key as Bearer auth on /mcp.",
    example: `curl -X POST https://agentaegis-mcp-production.up.railway.app/v1/customers \\
  -H "Content-Type: application/json" \\
  -d '{"email":"you@company.com","name":"You"}'

curl -X POST https://agentaegis-mcp-production.up.railway.app/v1/customers/<id>/api-keys \\
  -H "Content-Type: application/json" \\
  -d '{"name":"production","monthly_limit_usd":100}'`,
  },

  // === Authentication ===
  {
    topic: "authentication",
    question: "How do I authenticate API calls?",
    answer: "Send the API key as a Bearer token in the Authorization header. Keys start with aegis_ and are issued by POST /v1/customers/:id/api-keys.",
    example: `Authorization: Bearer aegis_z9J5w5_medG2zzrhYD2WD-q0v9wSgD5OsGlq3-AUrmg`,
  },
  {
    topic: "authentication",
    question: "What auth methods are supported?",
    answer: "Two: (1) API key with prepaid balance and monthly budget, (2) x402 micropayment per call (USDC on Base, no signup). The /mcp endpoint accepts either — same per-call prices, you choose.",
  },
  {
    topic: "authentication",
    question: "Are API keys retrievable?",
    answer: "No. The full key is returned exactly once at creation. We store only a SHA-256 hash. Lost a key? Issue a new one and revoke the old.",
  },

  // === Balance and billing ===
  {
    topic: "balance_and_billing",
    question: "How do I check my balance?",
    answer: "Three ways: (1) call the account_balance MCP tool — free. (2) GET /v1/customers/:id/balance with your API key. (3) operator dashboard at /admin (requires admin token).",
    example: `# As an MCP tool call:
{"method":"tools/call","params":{"name":"account_balance","arguments":{}}}

# As an HTTP call:
curl -H "Authorization: Bearer aegis_..." \\
  https://agentaegis-mcp-production.up.railway.app/v1/customers/<id>/balance`,
  },
  {
    topic: "balance_and_billing",
    question: "How do I top up?",
    answer: "POST /v1/customers/:id/checkout-session with amount_usd (5–5000). Returns a Stripe Checkout URL. After the customer pays, the webhook credits prepaid_balance_usd within seconds.",
    example: `curl -X POST https://agentaegis-mcp-production.up.railway.app/v1/customers/<id>/checkout-session \\
  -H "Content-Type: application/json" \\
  -d '{"amount_usd": 50}'
# → {"checkout_url": "https://checkout.stripe.com/...", "session_id": "cs_live_..."}`,
  },
  {
    topic: "balance_and_billing",
    question: "What happens when balance hits zero?",
    answer: "Tool calls return 402 Payment Required with a top-up URL. Other paths (account_balance, /pricing, /health, job polling) keep working — only paid tool execution is blocked.",
  },
  {
    topic: "balance_and_billing",
    question: "What's the monthly limit for?",
    answer: "Per-API-key spending cap. Even with prepaid balance available, a key won't spend more than monthly_limit_usd in a calendar month. Set it to whatever ceiling makes you comfortable. Resets on the 1st UTC.",
  },
  {
    topic: "balance_and_billing",
    question: "Are tool calls billed if they fail?",
    answer: "No. Failed calls (engine errors, target-validation rejections, timeouts) are logged in usage_log with success=false and don't deduct from balance.",
  },

  // === Tools and pricing ===
  {
    topic: "tools",
    question: "What tools are available?",
    answer: "21 tools across 7 categories: compliance (5), vuln management (5), code security (3), blue team (4), identity (2), offensive (1), account (1). Get the full priced catalog at GET /pricing.",
  },
  {
    topic: "tools",
    question: "What does each tool cost?",
    answer: `Cheapest: cve_lookup ($0.10). Most expensive: vuln_scan_web_app ($1.50). Free: account_balance, help. Full table available at GET /pricing or by calling the help tool with topic=tools.`,
    example: JSON.stringify(
      Object.entries(TOOL_PRICING)
        .sort((a, b) => a[1] - b[1])
        .reduce((acc, [name, price]) => ({ ...acc, [name]: `$${price.toFixed(2)}` }), {} as Record<string, string>),
      null,
      2
    ),
  },
  {
    topic: "tools",
    question: "Are scan targets validated?",
    answer: "Yes. Targets must be public IPs (no RFC 1918, link-local, loopback) or registered domains. URLs must be HTTPS. CIDR ranges max /24. Local domains (.local, .internal) blocked. Command-injection patterns rejected. Any violation returns 400 before the engine starts.",
  },

  // === Async jobs ===
  {
    topic: "async_jobs",
    question: "Some scans take minutes — does the request stay open?",
    answer: "Long-running tools (vuln_scan_network, vuln_scan_web_app, sast_scan, secret_scan, dependency_audit) auto-route to a background queue when BG_JOBS_DEFAULT=true. They return immediately with a job_id. Or pass async:true on any tool call to force enqueue.",
  },
  {
    topic: "async_jobs",
    question: "How do I get the result of an async job?",
    answer: "Two options: poll GET /v1/jobs/:job_id, or subscribe to webhooks (scan.completed / scan.failed). Webhook payloads are HMAC-SHA256-signed in X-AgentAegis-Signature.",
    example: `curl -H "Authorization: Bearer aegis_..." \\
  https://agentaegis-mcp-production.up.railway.app/v1/jobs/<job_id>`,
  },
  {
    topic: "async_jobs",
    question: "How long do jobs persist?",
    answer: "Job records (input, status, result) persist indefinitely in aegis_scan_jobs. Customer can list their own jobs via the API. We may add 90-day retention later for storage hygiene.",
  },

  // === Integration ===
  {
    topic: "integration",
    question: "How do I connect from Claude Desktop?",
    answer: "Add to claude_desktop_config.json. The local stdio transport doesn't require payment by default (REQUIRE_PAYMENT=false).",
    example: `{
  "mcpServers": {
    "agentaegis": {
      "command": "node",
      "args": ["/path/to/agentaegis-mcp/dist/index.js"],
      "env": {
        "OTX_API_KEY": "...",
        "ABUSEIPDB_API_KEY": "...",
        "NVD_API_KEY": "..."
      }
    }
  }
}`,
  },
  {
    topic: "integration",
    question: "How do I connect from a custom agent over HTTP?",
    answer: "POST /mcp using the Streamable HTTP MCP transport. Initialize with no session ID; the response Mcp-Session-Id header is used for subsequent calls. All requests carry your Bearer aegis_... key.",
  },
  {
    topic: "integration",
    question: "Does the Streamable HTTP transport support streaming?",
    answer: "Yes. The MCP SDK opens an SSE channel on POST /mcp for tools that emit progress. Long scans stream log lines as they complete; the final response is JSON.",
  },

  // === Errors ===
  {
    topic: "errors",
    question: "What HTTP status codes does the API return?",
    answer: "200 success, 201 created, 202 accepted (async job), 400 input validation, 401 missing API key, 402 payment required, 403 forbidden (cross-customer), 404 not found, 429 rate limited, 500 server error, 503 dependency unavailable (DB or Stripe not configured).",
  },
  {
    topic: "errors",
    question: "I got 'Cannot find database' / 503 — what's wrong?",
    answer: "The server hasn't been configured with SUPABASE_URL and SUPABASE_SERVICE_KEY. Customer/key/job/usage features all require it. Health endpoint at /health reports db_configured.",
  },
  {
    topic: "errors",
    question: "I got 'Target is a private/reserved IP address'",
    answer: "Your scan target is in RFC 1918 / loopback / link-local space. AgentAegis intentionally refuses to scan internal networks from a public service to prevent SSRF abuse. Use a target with a public IP or registered domain.",
  },

  // === x402 ===
  {
    topic: "x402",
    question: "What is x402 micropayment?",
    answer: "An HTTP 402-based protocol where the server returns payment requirements, the client signs a USDC transferWithAuthorization on Base, retries with X-PAYMENT header, and the server settles via a facilitator. No customer/account needed — agents pay per call.",
  },
  {
    topic: "x402",
    question: "Which network does AgentAegis use for x402?",
    answer: "Base mainnet for production. Base Sepolia for testing. Default network is set via X402_NETWORK env var.",
  },

  // === Rate limits ===
  {
    topic: "rate_limits",
    question: "What are the rate limits?",
    answer: "Per API key + per target: max 10 scans/hour against the same target. Per server: max 5 concurrent scans. Hitting either returns 429 with a reset_at timestamp. Limits apply only to scan tools, not to lookups (cve_lookup, threat_intel, etc.) or compliance/policy generation.",
  },

  // === Security ===
  {
    topic: "security",
    question: "How is customer data protected?",
    answer: "Postgres Row-Level Security forced on all aegis_* tables — only the service_role key (server-side) can read. API keys hashed (SHA-256), never stored plaintext. Webhook secrets HMAC-verified. Stripe events idempotent on event ID.",
  },
  {
    topic: "security",
    question: "What's logged?",
    answer: "Every tool call: customer_id, api_key_id, tool_name, target, price_usd, paid_via, success, error_message, request_ip, user_agent, timestamp. Retained indefinitely; queryable via the admin dashboard.",
  },
  {
    topic: "security",
    question: "Are scans sandboxed?",
    answer: "Yes. Each scan runs in an isolated subprocess. Code repos clone shallow (depth=1) into temp dirs that are wiped after. Max repo size 500MB, max scan duration 5 minutes. No shared state between scans.",
  },
];

export async function help(input: HelpInput) {
  const topic = input.topic ?? "all";
  const entries = topic === "all" ? FAQ : FAQ.filter((e) => e.topic === topic);

  const topicsAvailable = Array.from(new Set(FAQ.map((e) => e.topic)));

  return {
    topic_requested: topic,
    topics_available: topicsAvailable,
    entry_count: entries.length,
    entries,
    quickstart: {
      step_1: "POST /v1/customers — create a customer with your email",
      step_2: "POST /v1/customers/:id/api-keys — issue an API key (returned once)",
      step_3: "POST /v1/customers/:id/checkout-session — top up via Stripe ($5 minimum)",
      step_4: "POST /mcp with Authorization: Bearer aegis_... — call any tool",
    },
    related: {
      pricing: "/pricing — full tool catalog with prices",
      balance: "/v1/customers/:id/balance OR account_balance MCP tool",
      health: "/health — service status",
      website: "https://agentaegis.org/faq — same FAQ rendered for humans",
    },
  };
}
