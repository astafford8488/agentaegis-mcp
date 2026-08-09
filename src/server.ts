import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z, type ZodRawShape } from "zod";

// Compliance tools
import { complianceFrameworkCheck, complianceFrameworkCheckSchema } from "./tools/compliance/complianceFrameworkCheck.js";
import { evidenceCollect, evidenceCollectSchema } from "./tools/compliance/evidenceCollect.js";
import { controlGapAnalysis, controlGapAnalysisSchema } from "./tools/compliance/controlGapAnalysis.js";
import { auditReportGenerate, auditReportGenerateSchema } from "./tools/compliance/auditReportGenerate.js";
import { policyGenerate, policyGenerateSchema } from "./tools/compliance/policyGenerate.js";

// Vulnerability Management tools
import { vulnScanNetwork, vulnScanNetworkSchema } from "./tools/vulnManagement/vulnScanNetwork.js";
import { vulnScanWebApp, vulnScanWebAppSchema } from "./tools/vulnManagement/vulnScanWebApp.js";
import { vulnPrioritize, vulnPrioritizeSchema } from "./tools/vulnManagement/vulnPrioritize.js";
import { cveLookup, cveLookupSchema } from "./tools/vulnManagement/cveLookup.js";
import { sslTlsAudit, sslTlsAuditSchema } from "./tools/vulnManagement/sslTlsAudit.js";

// Code Security tools
import { sastScan, sastScanSchema } from "./tools/codeSecurity/sastScan.js";
import { secretScan, secretScanSchema } from "./tools/codeSecurity/secretScan.js";
import { dependencyAudit, dependencyAuditSchema } from "./tools/codeSecurity/dependencyAudit.js";

// Blue Team tools
import { incidentTriage, incidentTriageSchema } from "./tools/blueTeam/incidentTriage.js";
import { threatIntelLookup, threatIntelLookupSchema } from "./tools/blueTeam/threatIntelLookup.js";
import { dnsSecurityCheck, dnsSecurityCheckSchema } from "./tools/blueTeam/dnsSecurityCheck.js";
import { emailSecurityAudit, emailSecurityAuditSchema } from "./tools/blueTeam/emailSecurityAudit.js";

// Identity tools
import { accessReview, accessReviewSchema } from "./tools/identity/accessReview.js";
import { mfaAudit, mfaAuditSchema } from "./tools/identity/mfaAudit.js";

// Offensive tools
import { credentialCheck, credentialCheckSchema } from "./tools/offensive/credentialCheck.js";

// Trust Layer (L2) — composite agent-facing verdicts
import { vetEndpoint, vetEndpointSchema } from "./tools/trustLayer/vetEndpoint.js";
import { scanMcpPlugin, scanMcpPluginSchema } from "./tools/trustLayer/scanMcpPlugin.js";
import { scanSkill, scanSkillSchema } from "./tools/trustLayer/scanSkill.js";

// Account tools (free for the agent — needed to manage budget)
import { accountBalance, accountBalanceSchema } from "./tools/account/accountBalance.js";
import { help, helpSchema } from "./tools/account/help.js";

// Phase 9.0 identity tools (free — agent self-knowledge + scan history)
import { agentWhoami, agentWhoamiSchema } from "./tools/account/agentWhoami.js";
import { agentHistory, agentHistorySchema } from "./tools/account/agentHistory.js";
import { agentScanGet, agentScanGetSchema } from "./tools/account/agentScanGet.js";

// Middleware
import { verifyPayment } from "./middleware/x402.js";
import { TOOL_PRICING, formatUsd } from "./types/mcp.js";
import { buildServerInstructions } from "./instructions.js";
import { registerPrompts } from "./prompts.js";
import { toolMeta } from "./toolCatalog.js";
import { getRequestContext } from "./auth/requestContext.js";
import { chargeApiKey } from "./auth/apiKeyAuth.js";
import { isDbConfigured } from "./db/client.js";
import { logUsage, updateUsageOutcome } from "./db/usageLog.js";

// Phase 9.0 — agent identity + scan persistence
import { getOrResolveAgent } from "./auth/agentIdentity.js";
import { createScan, completeScan, failScan, getScanForAgent } from "./db/scans.js";
import { recordAgentSpend } from "./db/agents.js";

export interface ServerOptions {
  /** When true, skip payment verification (used by stdio transport in dev mode). */
  skipPayment?: boolean;
  /** Optional pre-authorized payment from HTTP transport.
   *  Note: legacy hook; the standard path now reads request context via AsyncLocalStorage. */
  preAuthorized?: () => Promise<{ authorized: boolean; reason?: string }>;
}

// Phase 9.0 — the chained-workflow lineage param. registerPaidTool injects it
// into every PAID tool's input schema; wrapTool strips it before the handler
// runs, so the underlying tools never see it.
const CHAIN_PARAM: ZodRawShape = {
  previous_scan_id: z
    .string()
    .uuid()
    .optional()
    .describe(
      "Optional. A prior scan_id (from agent_history) to record as this call's parent — builds a traversable chained-workflow lineage retrievable via agent_scan_get. Must be one of your own scans; ignored otherwise. Does not change this tool's analysis."
    ),
};

const asText = (result: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] });
const asError = (result: unknown) => ({ content: [{ type: "text" as const, text: JSON.stringify(result) }], isError: true });

function wrapTool(toolName: string, handler: (args: any) => Promise<any>, options: ServerOptions) {
  return async (rawArgs: any) => {
    const price = TOOL_PRICING[toolName] ?? 0;

    // Free tools (account_balance, help, agent_*) bypass billing + persistence.
    if (price === 0) {
      try { return asText(await handler(rawArgs)); }
      catch (err) { return asError({ error: String(err) }); }
    }

    // Separate the injected lineage param from the handler's real args.
    let args = rawArgs;
    let previousScanId: string | undefined;
    if (rawArgs && typeof rawArgs === "object" && "previous_scan_id" in rawArgs) {
      previousScanId = (rawArgs as any).previous_scan_id || undefined;
      const { previous_scan_id: _omit, ...rest } = rawArgs as any;
      args = rest;
    }

    const ctx = getRequestContext();
    const target = (args && (args.target || args.target_url || args.hostname || args.domain)) || undefined;

    const isX402Paid = !!ctx?.x402Settled;
    const isApiKeyPaid = !isX402Paid && !!(ctx?.apiKey && isDbConfigured());

    // ===== Paid HTTP paths (x402-settled at the gate, or API-key budget) =====
    if (isX402Paid || isApiKeyPaid) {
      // Resolve identity once (best-effort) → links the scan + spend to the agent.
      const agent = await getOrResolveAgent(ctx).catch(() => null);

      // Lineage is honored only for the agent's OWN prior scans (IDOR-safe).
      let parentScanId: string | undefined;
      if (previousScanId && agent) {
        const parent = await getScanForAgent(previousScanId, agent.id).catch(() => null);
        if (parent) parentScanId = parent.id;
      }

      // Open a scan row around the handler (best-effort; never blocks the call).
      let scanId: string | null = null;
      if (agent) {
        scanId = await createScan({ agentId: agent.id, toolName, target, previousScanId: parentScanId }).catch(() => null);
      }

      let result: any;
      try {
        result = await handler(args);
      } catch (err) {
        if (scanId) await failScan(scanId).catch(() => { /* best-effort */ });
        // API-key path logs the failed call (no charge). x402 was settled + logged
        // success=true at the gate (before the handler ran) — correct that row to a
        // failure now that the tool threw, so billing/analytics aren't inflated.
        if (isApiKeyPaid) {
          await logUsage({
            customer_id: ctx!.apiKey!.customer_id,
            api_key_id: ctx!.apiKey!.id,
            agent_id: agent?.id,
            tool_name: toolName,
            target,
            price_usd: price,
            paid_via: "api_key_balance",
            success: false,
            error_message: String(err).slice(0, 500),
            request_ip: ctx!.ip,
            user_agent: ctx!.userAgent,
          }).catch(() => { /* best-effort */ });
        } else if (isX402Paid && ctx?.x402UsageLogId) {
          await updateUsageOutcome(ctx.x402UsageLogId, false, String(err)).catch(() => { /* best-effort */ });
        }
        return asError({ error: String(err) });
      }

      // Success: persist output + bump agent aggregates (both best-effort).
      if (scanId) {
        await completeScan(scanId, { tool_name: toolName, target, completed: true }, result).catch(() => { /* best-effort */ });
      }
      if (agent) await recordAgentSpend(agent.id, price).catch(() => { /* best-effort */ });

      // x402 already paid at the gate — just return.
      if (isX402Paid) return asText(result);

      // API-key — charge the monthly budget (only on success).
      const charge = await chargeApiKey(ctx!.apiKey!, toolName, price, {
        target,
        success: true,
        ip: ctx!.ip,
        ua: ctx!.userAgent,
        agentId: agent?.id,
      });
      if (!charge.ok) {
        // Budget exceeded after the call ran — surface the warning but still
        // return the result. Better UX than silently failing post-hoc.
        return asText({ warning: charge.reason, monthly_limit_exceeded: true, result });
      }
      return asText(result);
    }

    // ===== Legacy / stdio paths (unchanged behavior) =====
    if (options.preAuthorized) {
      const r = await options.preAuthorized();
      if (!r.authorized) return asError({ error: r.reason || "Payment required" });
    } else if (!options.skipPayment) {
      const payment = await verifyPayment(toolName);
      if (!payment.valid) return asError({ error: payment.error, price: payment.price_usd });
    }
    try { return asText(await handler(args)); }
    catch (err) { return asError({ error: String(err) }); }
  };
}

/** Look up a tool's description + annotations, failing loudly if absent.
 *  A tool with no catalog entry would otherwise register with no description
 *  and no risk hints, which is worse than not registering at all. */
function meta(name: string) {
  const entry = toolMeta(name);
  if (!entry) throw new Error(`Tool "${name}" has no entry in TOOL_CATALOG (src/toolCatalog.ts)`);
  return entry;
}

/** Register a PAID tool: injects the previous_scan_id lineage param into its
 *  schema and wraps the handler with billing + scan persistence.
 *
 *  Description and annotations come from TOOL_CATALOG; the price is appended
 *  from TOOL_PRICING. An agent deciding whether to spend the user's money needs
 *  the cost in front of it, and a repricing must never leave 22 descriptions
 *  quoting the old number. */
function registerPaidTool(
  server: McpServer,
  name: string,
  shape: ZodRawShape,
  handler: (args: any) => Promise<any>,
  options: ServerOptions,
) {
  const { description, annotations } = meta(name);
  const price = TOOL_PRICING[name] ?? 0;
  server.registerTool(
    name,
    {
      description: price > 0 ? `${description} Costs ${formatUsd(price)} per call.` : description,
      inputSchema: { ...shape, ...CHAIN_PARAM },
      annotations,
    },
    wrapTool(name, handler, options) as never,
  );
}

/** Register a FREE tool: no billing, no scan persistence, no lineage param. */
function registerFreeTool(
  server: McpServer,
  name: string,
  shape: ZodRawShape,
  handler: (args: any) => Promise<any>,
) {
  const { description, annotations } = meta(name);
  server.registerTool(
    name,
    { description, inputSchema: shape, annotations },
    wrapTool(name, handler, { skipPayment: true }) as never,
  );
}

export function buildMcpServer(options: ServerOptions = {}): McpServer {
  const server = new McpServer(
    {
      name: "agentaegis",
      version: "0.2.0",
    },
    {
      // Surfaced on `initialize` and injected into the host's system prompt by
      // most MCP clients — the only tool-routing guidance that reaches an agent
      // with nothing installed on the caller's side. See src/instructions.ts.
      instructions: buildServerInstructions({
        includeCredentialCheck: !!process.env.HIBP_API_KEY,
      }),
    }
  );

  // Guided workflows (prompts/list + prompts/get). Free: the x402 gate only
  // charges `tools/call`, and rendering a prompt executes no tool. See src/prompts.ts.
  registerPrompts(server);

  // Registration is name + schema + handler only; the description and the
  // annotations come from TOOL_CATALOG (src/toolCatalog.ts) and the price from
  // TOOL_PRICING, so all agent-facing copy has exactly one home.

  // Compliance & Audit
  registerPaidTool(server, "compliance_framework_check", complianceFrameworkCheckSchema.shape, complianceFrameworkCheck, options);
  registerPaidTool(server, "evidence_collect", evidenceCollectSchema.shape, evidenceCollect, options);
  registerPaidTool(server, "control_gap_analysis", controlGapAnalysisSchema.shape, controlGapAnalysis, options);
  registerPaidTool(server, "audit_report_generate", auditReportGenerateSchema.shape, auditReportGenerate, options);
  registerPaidTool(server, "policy_generate", policyGenerateSchema.shape, policyGenerate, options);

  // Vuln Mgmt — vuln_scan_* are the only tools annotated as non-read-only:
  // they send probe traffic that can trip IDS or destabilise a fragile service.
  registerPaidTool(server, "vuln_scan_network", vulnScanNetworkSchema.shape, vulnScanNetwork, options);
  registerPaidTool(server, "vuln_scan_web_app", vulnScanWebAppSchema.shape, vulnScanWebApp, options);
  registerPaidTool(server, "vuln_prioritize", vulnPrioritizeSchema.shape, vulnPrioritize, options);
  registerPaidTool(server, "cve_lookup", cveLookupSchema.shape, cveLookup, options);
  registerPaidTool(server, "ssl_tls_audit", sslTlsAuditSchema.shape, sslTlsAudit, options);

  // Code Security
  registerPaidTool(server, "sast_scan", sastScanSchema.shape, sastScan, options);
  registerPaidTool(server, "secret_scan", secretScanSchema.shape, secretScan, options);
  registerPaidTool(server, "dependency_audit", dependencyAuditSchema.shape, dependencyAudit, options);

  // Blue Team
  registerPaidTool(server, "incident_triage", incidentTriageSchema.shape, incidentTriage, options);
  registerPaidTool(server, "threat_intel_lookup", threatIntelLookupSchema.shape, threatIntelLookup, options);
  registerPaidTool(server, "dns_security_check", dnsSecurityCheckSchema.shape, dnsSecurityCheck, options);
  registerPaidTool(server, "email_security_audit", emailSecurityAuditSchema.shape, emailSecurityAudit, options);

  // Identity
  registerPaidTool(server, "access_review", accessReviewSchema.shape, accessReview, options);
  registerPaidTool(server, "mfa_audit", mfaAuditSchema.shape, mfaAudit, options);

  // Offensive — credential_check's only data source is HIBP, which has no
  // fallback. x402 settles payment BEFORE the tool runs, so exposing it without
  // a key means a caller pays and just gets "HIBP_API_KEY not configured". Only
  // register it when the key is set (it auto-enables once HIBP_API_KEY is added).
  if (process.env.HIBP_API_KEY) {
    registerPaidTool(server, "credential_check", credentialCheckSchema.shape, credentialCheck, options);
  }

  // Trust Layer (L2) — the flagship. Composite verdicts an agent uses to decide
  // whether to call, pay, install or trust something, BEFORE it does so.
  registerPaidTool(server, "vet_endpoint", vetEndpointSchema.shape, vetEndpoint, options);
  registerPaidTool(server, "scan_mcp_plugin", scanMcpPluginSchema.shape, scanMcpPlugin, options);
  registerPaidTool(server, "scan_skill", scanSkillSchema.shape, scanSkill, options);

  // Free tools — budget self-check, FAQ, and Phase 9.0 identity/history, which
  // lets an agent retrieve a prior scan instead of paying for it twice.
  registerFreeTool(server, "account_balance", accountBalanceSchema.shape, accountBalance);
  registerFreeTool(server, "help", helpSchema.shape, help);
  registerFreeTool(server, "agent_whoami", agentWhoamiSchema.shape, agentWhoami);
  registerFreeTool(server, "agent_history", agentHistorySchema.shape, agentHistory);
  registerFreeTool(server, "agent_scan_get", agentScanGetSchema.shape, agentScanGet);

  return server;
}
