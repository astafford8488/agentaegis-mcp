// HTTP x402 resources — Bazaar discovery.
//
// The CDP Bazaar catalogs HTTP resources ONLY (type:"http"); it does not list MCP
// servers/tools (confirmed 2026-06-22 — the live index is 100% http, and our
// type:"mcp" declaration sits in "processing" forever). So we expose select tools
// as dedicated HTTP endpoints and let the official x402-express middleware handle
// the 402 gate + the Bazaar discovery declaration (config.discoverable=true) +
// enrichment + on-settle cataloging.
//
// Rides the Coinbase mainnet stack (x402-express + @coinbase/x402 facilitator),
// separate from the custom /mcp CDP gate (x402Cdp.ts) — the custom gate exists
// because /mcp is JSON-RPC and doesn't fit per-route middleware; plain HTTP routes
// fit it perfectly. Config-driven: add a tool to RESOURCES to list it.
//
// NOTE: credential_check is deliberately NOT here — it's HIBP-backed, and HIBP's
// terms prohibit reselling lookups via a paid public API. It stays an MCP tool for
// our own customers only.

import type { Express, Request, Response } from "express";
import type { ZodTypeAny } from "zod";
import { paymentMiddleware, type RoutesConfig } from "x402-express";
import { facilitator } from "@coinbase/x402";
import { vetEndpoint, vetEndpointSchema } from "../tools/trustLayer/vetEndpoint.js";
import { cveLookup, cveLookupSchema } from "../tools/vulnManagement/cveLookup.js";
import { sslTlsAudit, sslTlsAuditSchema } from "../tools/vulnManagement/sslTlsAudit.js";
import { threatIntelLookup, threatIntelLookupSchema } from "../tools/blueTeam/threatIntelLookup.js";
import { dependencyAudit, dependencyAuditSchema } from "../tools/codeSecurity/dependencyAudit.js";
import { scanMcpPlugin, scanMcpPluginSchema } from "../tools/trustLayer/scanMcpPlugin.js";
import { scanSkill, scanSkillSchema } from "../tools/trustLayer/scanSkill.js";
import { TOOL_PRICING } from "../types/mcp.js";
import { isCdpMode } from "../auth/x402Cdp.js";
import { logUsage } from "../db/usageLog.js";
import { resolveAgent } from "../db/agents.js";
import { isDbConfigured } from "../db/client.js";

interface HttpResource {
  path: string;
  toolName: string;
  schema: ZodTypeAny;
  handler: (input: unknown) => Promise<unknown>;
  description: string;
  inputBody: Record<string, unknown>;   // example body → Bazaar discovery inputSchema
  outputExample: Record<string, unknown>;
}

const RESOURCES: HttpResource[] = [
  {
    path: "/x402/vet-endpoint",
    toolName: "vet_endpoint",
    schema: vetEndpointSchema,
    handler: vetEndpoint as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis vet_endpoint — composite PROCEED/CAUTION/BLOCK safety verdict for an endpoint an AI agent is about to call or pay. Live TLS/cert, DNS hygiene, threat-intel (domain + resolved IP), and domain-age signals → one trust score with reasons.",
    inputBody: { endpoint: "example.com or https://api.example.com/pay" },
    outputExample: { endpoint: "stripe.com", verdict: "PROCEED", trust_score: 95, reasons: ["valid TLS", "clean threat intel"] },
  },
  {
    path: "/x402/cve-lookup",
    toolName: "cve_lookup",
    schema: cveLookupSchema,
    handler: cveLookup as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis cve_lookup — CVSS score, severity, CWE classifications, CISA KEV (known-exploited) status, affected products and references for a CVE id. NVD with CIRCL + OSV fallback for reliability.",
    inputBody: { cve_id: "CVE-2024-3094" },
    outputExample: { cve_id: "CVE-2021-44228", severity: "CRITICAL", cvss_v3: { score: 10 }, known_exploited: true },
  },
  {
    path: "/x402/ssl-tls-audit",
    toolName: "ssl_tls_audit",
    schema: sslTlsAuditSchema,
    handler: sslTlsAudit as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis ssl_tls_audit — TLS/certificate health grade for a host: supported protocols, cipher strength, certificate validity + days-to-expiry, and known TLS vulnerabilities.",
    inputBody: { hostname: "example.com" },
    outputExample: { hostname: "stripe.com", grade: { grade: "A+", score: 100 } },
  },
  {
    path: "/x402/threat-intel",
    toolName: "threat_intel_lookup",
    schema: threatIntelLookupSchema,
    handler: threatIntelLookup as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis threat_intel_lookup — reputation + threat verdict for an IOC (IP, domain, URL, or file hash) aggregated across AbuseIPDB, AlienVault OTX, and abuse.ch.",
    inputBody: { indicator: "45.155.205.233", indicator_type: "ip" },
    outputExample: { indicator: "45.155.205.233", malicious: true, threat_score: 80 },
  },
  {
    path: "/x402/dependency-audit",
    toolName: "dependency_audit",
    schema: dependencyAuditSchema,
    handler: dependencyAudit as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis dependency_audit — scan a git repository or a dependency manifest (npm/pip/go/ruby/java/cargo) for known-CVE packages, with severities and upgrade fixes (Trivy).",
    inputBody: { source: { type: "git_repo", url: "https://github.com/owner/repo" } },
    outputExample: { summary: { total_vulnerabilities: 12, critical: 2, high: 5 } },
  },
  {
    path: "/x402/scan-mcp-plugin",
    toolName: "scan_mcp_plugin",
    schema: scanMcpPluginSchema,
    handler: scanMcpPlugin as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis scan_mcp_plugin — supply-chain trust scan of an MCP server or agent skill BEFORE you install/trust it. Clones a git repo (or takes a code snippet) and flags exfiltration (secrets/env to the network), prompt-injection sinks (hijack phrases + hidden unicode), dangerous capabilities (eval/shell/dynamic exec), npm install hooks, and obfuscation → one PROCEED/CAUTION/BLOCK verdict with findings.",
    inputBody: { source: { type: "git_repo", url: "https://github.com/owner/mcp-server" } },
    outputExample: { verdict: "BLOCK", trust_score: 35, summary: { exfiltration: 1, prompt_injection: 2, dangerous_capabilities: 1 }, reasons: ["Exfiltration pattern: reads secrets/env and sends to the network."] },
  },
  {
    path: "/x402/scan-skill",
    toolName: "scan_skill",
    schema: scanSkillSchema,
    handler: scanSkill as (i: unknown) => Promise<unknown>,
    description:
      "AgentAegis scan_skill — supply-chain trust scan of an AGENT SKILL (a SKILL.md + bundled scripts) BEFORE you install/trust it. Flags prompt-injection / hidden-unicode in the instructions the agent will follow (hard block), over-broad allowed-tools grants, plus exfiltration, dangerous capabilities, secrets and obfuscation in bundled code → one PROCEED/CAUTION/BLOCK verdict.",
    inputBody: { source: { type: "git_repo", url: "https://github.com/owner/skill-repo" } },
    outputExample: { verdict: "BLOCK", trust_score: 0, summary: { instruction_injection: true, overbroad_tools: ["Bash"] }, reasons: ["SKILL.md instructions contain prompt-injection directives."] },
  },
];

/**
 * Mount the HTTP x402 resources. No-op unless payee + CDP mode are set. Must be
 * called after express.json() so handlers can read the body.
 */
export function mountHttpResources(app: Express): void {
  const payTo = process.env.X402_PAYEE_ADDRESS;
  if (!payTo || !isCdpMode()) return;

  const network = process.env.X402_NETWORK || "base";
  // Behind Railway's edge req.protocol is "http" (TLS terminated upstream), so pin
  // the public https URL — the client signs whatever the challenge says, so the
  // advertised + cataloged resource must be the real https one.
  const baseUrl = process.env.PUBLIC_BASE_URL || "https://agentaegis-mcp-production.up.railway.app";

  const routes: RoutesConfig = {};
  for (const r of RESOURCES) {
    const price = TOOL_PRICING[r.toolName] ?? 1;
    routes[`POST ${r.path}`] = {
      price: `$${price.toFixed(2)}`,
      network: network as never,
      config: {
        description: r.description,
        mimeType: "application/json",
        maxTimeoutSeconds: 60,
        discoverable: true,
        resource: `${baseUrl}${r.path}` as never,
        inputSchema: { bodyType: "json", body: r.inputBody } as never,
        outputSchema: { example: r.outputExample },
      },
    };
  }

  // Gate + discovery + on-settle cataloging handled by the middleware; it only
  // intercepts the configured routes and falls through for everything else.
  app.use(paymentMiddleware(payTo as `0x${string}`, routes, facilitator as never));

  for (const r of RESOURCES) {
    app.post(r.path, async (req: Request, res: Response) => {
      // Payment already verified + settled by the middleware above.
      const parsed = r.schema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: "Invalid request body", tool: r.toolName });
      }

      // Best-effort identity + payment ref from the x402 headers, so the HTTP rail
      // logs the same agent_id + payment_ref as the /mcp rail — and so we can tell
      // organic Bazaar traffic from our own test wallet in aegis_usage_log.
      let agentId: string | undefined;
      let paymentRef: string | undefined;
      try {
        const xp = (req.headers["x-payment"] || req.headers["payment-signature"]) as string | undefined;
        if (xp && isDbConfigured()) {
          const d = JSON.parse(Buffer.from(xp, "base64").toString("utf-8")) as {
            payload?: { authorization?: { from?: string }; from?: string };
            from?: string;
          };
          const payer = d?.payload?.authorization?.from || d?.payload?.from || d?.from;
          if (payer) {
            const agent = await resolveAgent({ walletAddress: payer.toLowerCase() }).catch(() => null);
            agentId = agent?.id;
          }
        }
        const xpr = res.getHeader("X-PAYMENT-RESPONSE");
        if (typeof xpr === "string") {
          paymentRef = (JSON.parse(Buffer.from(xpr, "base64").toString("utf-8")) as { transaction?: string })?.transaction;
        }
      } catch { /* best-effort identity — never block a paid call */ }

      const data = parsed.data as Record<string, unknown>;
      const target = (data.endpoint || data.cve_id || data.hostname || data.indicator || data.target || (data.source as { url?: string } | undefined)?.url) as string | undefined;
      const price = TOOL_PRICING[r.toolName] ?? 1;
      const logIt = (success: boolean, error?: string) => {
        if (!isDbConfigured()) return;
        logUsage({
          tool_name: r.toolName,
          paid_via: "x402",
          price_usd: price,
          agent_id: agentId,
          payment_ref: paymentRef,
          target,
          success,
          error_message: error,
          request_ip: req.ip,
          user_agent: req.headers["user-agent"],
        }).catch(() => { /* best-effort */ });
      };

      try {
        const result = await r.handler(parsed.data);
        logIt(true);
        res.json(result);
      } catch (err) {
        logIt(false, String(err).slice(0, 500));
        res.status(500).json({ error: String(err) });
      }
    });
  }
}
