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

// Account tools (free for the agent — needed to manage budget)
import { accountBalance, accountBalanceSchema } from "./tools/account/accountBalance.js";
import { help, helpSchema } from "./tools/account/help.js";

// Phase 9.0 identity tools (free — agent self-knowledge + scan history)
import { agentWhoami, agentWhoamiSchema } from "./tools/account/agentWhoami.js";
import { agentHistory, agentHistorySchema } from "./tools/account/agentHistory.js";
import { agentScanGet, agentScanGetSchema } from "./tools/account/agentScanGet.js";

// Middleware
import { verifyPayment } from "./middleware/x402.js";
import { TOOL_PRICING } from "./types/mcp.js";
import { getRequestContext } from "./auth/requestContext.js";
import { chargeApiKey } from "./auth/apiKeyAuth.js";
import { isDbConfigured } from "./db/client.js";
import { logUsage } from "./db/usageLog.js";

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
        // API-key path logs the failed call (no charge). x402 was already settled
        // + logged at the gate, so don't double-log it here.
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

/** Register a PAID tool: injects the previous_scan_id lineage param into its
 *  schema and wraps the handler with billing + scan persistence. */
function registerPaidTool(
  server: McpServer,
  name: string,
  description: string,
  shape: ZodRawShape,
  handler: (args: any) => Promise<any>,
  options: ServerOptions,
) {
  server.tool(name, description, { ...shape, ...CHAIN_PARAM }, wrapTool(name, handler, options));
}

export function buildMcpServer(options: ServerOptions = {}): McpServer {
  const server = new McpServer({
    name: "agentaegis",
    version: "0.2.0",
  });

  // Compliance & Audit
  registerPaidTool(server, "compliance_framework_check", "Assess an organization's security posture against a compliance framework (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF).", complianceFrameworkCheckSchema.shape, complianceFrameworkCheck, options);
  registerPaidTool(server, "evidence_collect", "Generate evidence collection plans for compliance controls.", evidenceCollectSchema.shape, evidenceCollect, options);
  registerPaidTool(server, "control_gap_analysis", "Deep-dive analysis of compliance control gaps with remediation roadmap.", controlGapAnalysisSchema.shape, controlGapAnalysis, options);
  registerPaidTool(server, "audit_report_generate", "Generate audit-ready compliance reports.", auditReportGenerateSchema.shape, auditReportGenerate, options);
  registerPaidTool(server, "policy_generate", "Generate tailored security policy documents.", policyGenerateSchema.shape, policyGenerate, options);

  // Vuln Mgmt
  registerPaidTool(server, "vuln_scan_network", "Scan an IP/domain for open ports, services, and vulnerabilities.", vulnScanNetworkSchema.shape, vulnScanNetwork, options);
  registerPaidTool(server, "vuln_scan_web_app", "Scan a web app for OWASP Top 10 vulnerabilities.", vulnScanWebAppSchema.shape, vulnScanWebApp, options);
  registerPaidTool(server, "vuln_prioritize", "Prioritize vulnerabilities by exploitability and business impact.", vulnPrioritizeSchema.shape, vulnPrioritize, options);
  registerPaidTool(server, "cve_lookup", "Look up CVE details, CVSS scores, and patches.", cveLookupSchema.shape, cveLookup, options);
  registerPaidTool(server, "ssl_tls_audit", "Audit SSL/TLS configuration for a domain.", sslTlsAuditSchema.shape, sslTlsAudit, options);

  // Code Security
  registerPaidTool(server, "sast_scan", "Static analysis for security vulnerabilities. Supports Python, JS/TS, Java, Go, Ruby, PHP, C/C++.", sastScanSchema.shape, sastScan, options);
  registerPaidTool(server, "secret_scan", "Detect hardcoded secrets in source code.", secretScanSchema.shape, secretScan, options);
  registerPaidTool(server, "dependency_audit", "Audit dependencies for known vulnerabilities (npm, pip, Go, Ruby, Java, Cargo).", dependencyAuditSchema.shape, dependencyAudit, options);

  // Blue Team
  registerPaidTool(server, "incident_triage", "Classify and respond to security incidents.", incidentTriageSchema.shape, incidentTriage, options);
  registerPaidTool(server, "threat_intel_lookup", "IOC lookup against threat intel feeds.", threatIntelLookupSchema.shape, threatIntelLookup, options);
  registerPaidTool(server, "dns_security_check", "Check DNS security (SPF, DKIM, DMARC, DNSSEC).", dnsSecurityCheckSchema.shape, dnsSecurityCheck, options);
  registerPaidTool(server, "email_security_audit", "Comprehensive email security audit.", emailSecurityAuditSchema.shape, emailSecurityAudit, options);

  // Identity
  registerPaidTool(server, "access_review", "Audit user access against least-privilege.", accessReviewSchema.shape, accessReview, options);
  registerPaidTool(server, "mfa_audit", "Assess MFA coverage and strength.", mfaAuditSchema.shape, mfaAudit, options);

  // Offensive
  registerPaidTool(server, "credential_check", "Check email/domain in breach databases (HIBP).", credentialCheckSchema.shape, credentialCheck, options);

  // Trust Layer (L2) — the flagship. Composite PROCEED/CAUTION/BLOCK verdict for
  // an endpoint an agent is about to call or pay: TLS + DNS hygiene + threat
  // intel + domain age → one decision. Designed to gate a per-invocation payment.
  registerPaidTool(server, "vet_endpoint", "Composite trust verdict (PROCEED/CAUTION/BLOCK) for an endpoint an agent is about to call or pay — combines TLS/cert health, DNS hygiene, threat-intel reputation, and domain age into one decision with reasons.", vetEndpointSchema.shape, vetEndpoint, options);

  // Account — free tool so agents can self-check budget before paid calls.
  // Bypasses payment gating entirely (skipPayment for this one regardless of options).
  server.tool(
    "account_balance",
    "Returns the calling API key's prepaid balance, monthly limit, current month usage, and a breakdown of how many of each tool the customer can still afford. Free to call.",
    accountBalanceSchema.shape,
    wrapTool("account_balance", accountBalance, { skipPayment: true })
  );

  // Help — free FAQ tool so agents can discover authentication, billing,
  // tool catalog, error semantics, integration patterns. Mirrors agentaegis.org/faq.
  server.tool(
    "help",
    "Returns AgentAegis FAQ — authentication, balance/billing, tool catalog, async jobs, error codes, x402, rate limits, security. Optional topic filter. Free to call.",
    helpSchema.shape,
    wrapTool("help", help, { skipPayment: true })
  );

  // Phase 9.0 — identity & history (free). Let an agent discover its persistent
  // identity, list prior scans, and retrieve a past scan's full output to chain
  // workflows without re-paying.
  server.tool(
    "agent_whoami",
    "Returns your persistent AgentAegis agent identity (agent_id), how you're identified (API key / wallet / anonymous session), and lifetime call count + spend. Free to call.",
    agentWhoamiSchema.shape,
    wrapTool("agent_whoami", agentWhoami, { skipPayment: true })
  );
  server.tool(
    "agent_history",
    "Lists your recent scans (scan_id, tool, target, status, time) so you can retrieve or chain from a prior result. Optional limit/tool/target/since filters. Free to call.",
    agentHistorySchema.shape,
    wrapTool("agent_history", agentHistory, { skipPayment: true })
  );
  server.tool(
    "agent_scan_get",
    "Retrieves one of your prior scans by scan_id, including the stored full output, so you can build on earlier results without re-paying. Free to call.",
    agentScanGetSchema.shape,
    wrapTool("agent_scan_get", agentScanGet, { skipPayment: true })
  );

  return server;
}
