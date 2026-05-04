import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

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

// Account tools (free for the agent — needed to manage budget)
import { accountBalance, accountBalanceSchema } from "./tools/account/accountBalance.js";
import { help, helpSchema } from "./tools/account/help.js";

// Middleware
import { verifyPayment } from "./middleware/x402.js";
import { TOOL_PRICING } from "./types/mcp.js";
import { getRequestContext } from "./auth/requestContext.js";
import { chargeApiKey } from "./auth/apiKeyAuth.js";
import { isDbConfigured } from "./db/client.js";
import { logUsage } from "./db/usageLog.js";

export interface ServerOptions {
  /** When true, skip payment verification (used by stdio transport in dev mode). */
  skipPayment?: boolean;
  /** Optional pre-authorized payment from HTTP transport.
   *  Note: legacy hook; the standard path now reads request context via AsyncLocalStorage. */
  preAuthorized?: () => Promise<{ authorized: boolean; reason?: string }>;
}

function wrapTool(toolName: string, handler: (args: any) => Promise<any>, options: ServerOptions) {
  return async (args: any) => {
    const price = TOOL_PRICING[toolName] ?? 0;

    // Free tools (account_balance, help) bypass billing entirely.
    if (price === 0) {
      try {
        const result = await handler(args);
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: String(err) }) }], isError: true };
      }
    }

    // Paid tools: prefer to read the request context (HTTP transport).
    // Fall back to the legacy preAuthorized callback or skipPayment for stdio dev mode.
    const ctx = getRequestContext();

    // x402-settled requests already paid at the /mcp gate — just run the tool.
    if (ctx?.x402Settled) {
      try {
        const result = await handler(args);
        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: String(err) }) }], isError: true };
      }
    }

    if (ctx?.apiKey && isDbConfigured()) {
      // HTTP path with valid API key — charge the customer's monthly budget.
      const apiKey = ctx.apiKey;

      // Run the tool; only charge on success.
      try {
        const result = await handler(args);
        const target = (args && (args.target || args.target_url || args.hostname || args.domain)) || undefined;

        const charge = await chargeApiKey(apiKey, toolName, price, {
          target,
          success: true,
          ip: ctx.ip,
          ua: ctx.userAgent,
        });

        if (!charge.ok) {
          // Budget exceeded after the call ran — surface the error but still
          // return the result. Better UX than silently failing post-hoc.
          return {
            content: [{ type: "text" as const, text: JSON.stringify({
              warning: charge.reason,
              monthly_limit_exceeded: true,
              result,
            }, null, 2) }],
          };
        }

        return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
      } catch (err) {
        // Failed call — log usage with success=false but don't deduct.
        await logUsage({
          customer_id: apiKey.customer_id,
          api_key_id: apiKey.id,
          tool_name: toolName,
          target: undefined,
          price_usd: price,
          paid_via: "api_key_balance",
          success: false,
          error_message: String(err).slice(0, 500),
          request_ip: ctx.ip,
          user_agent: ctx.userAgent,
        }).catch(() => { /* best-effort */ });

        return { content: [{ type: "text" as const, text: JSON.stringify({ error: String(err) }) }], isError: true };
      }
    }

    // Legacy / stdio paths.
    if (options.preAuthorized) {
      const result = await options.preAuthorized();
      if (!result.authorized) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: result.reason || "Payment required" }) }], isError: true };
      }
    } else if (!options.skipPayment) {
      const payment = await verifyPayment(toolName);
      if (!payment.valid) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ error: payment.error, price: payment.price_usd }) }], isError: true };
      }
    }

    try {
      const result = await handler(args);
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    } catch (err) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: String(err) }) }], isError: true };
    }
  };
}

export function buildMcpServer(options: ServerOptions = {}): McpServer {
  const server = new McpServer({
    name: "agentaegis",
    version: "0.2.0",
  });

  // Compliance & Audit
  server.tool("compliance_framework_check", "Assess an organization's security posture against a compliance framework (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF).", complianceFrameworkCheckSchema.shape, wrapTool("compliance_framework_check", complianceFrameworkCheck, options));
  server.tool("evidence_collect", "Generate evidence collection plans for compliance controls.", evidenceCollectSchema.shape, wrapTool("evidence_collect", evidenceCollect, options));
  server.tool("control_gap_analysis", "Deep-dive analysis of compliance control gaps with remediation roadmap.", controlGapAnalysisSchema.shape, wrapTool("control_gap_analysis", controlGapAnalysis, options));
  server.tool("audit_report_generate", "Generate audit-ready compliance reports.", auditReportGenerateSchema.shape, wrapTool("audit_report_generate", auditReportGenerate, options));
  server.tool("policy_generate", "Generate tailored security policy documents.", policyGenerateSchema.shape, wrapTool("policy_generate", policyGenerate, options));

  // Vuln Mgmt
  server.tool("vuln_scan_network", "Scan an IP/domain for open ports, services, and vulnerabilities.", vulnScanNetworkSchema.shape, wrapTool("vuln_scan_network", vulnScanNetwork, options));
  server.tool("vuln_scan_web_app", "Scan a web app for OWASP Top 10 vulnerabilities.", vulnScanWebAppSchema.shape, wrapTool("vuln_scan_web_app", vulnScanWebApp, options));
  server.tool("vuln_prioritize", "Prioritize vulnerabilities by exploitability and business impact.", vulnPrioritizeSchema.shape, wrapTool("vuln_prioritize", vulnPrioritize, options));
  server.tool("cve_lookup", "Look up CVE details, CVSS scores, and patches.", cveLookupSchema.shape, wrapTool("cve_lookup", cveLookup, options));
  server.tool("ssl_tls_audit", "Audit SSL/TLS configuration for a domain.", sslTlsAuditSchema.shape, wrapTool("ssl_tls_audit", sslTlsAudit, options));

  // Code Security
  server.tool("sast_scan", "Static analysis for security vulnerabilities. Supports Python, JS/TS, Java, Go, Ruby, PHP, C/C++.", sastScanSchema.shape, wrapTool("sast_scan", sastScan, options));
  server.tool("secret_scan", "Detect hardcoded secrets in source code.", secretScanSchema.shape, wrapTool("secret_scan", secretScan, options));
  server.tool("dependency_audit", "Audit dependencies for known vulnerabilities (npm, pip, Go, Ruby, Java, Cargo).", dependencyAuditSchema.shape, wrapTool("dependency_audit", dependencyAudit, options));

  // Blue Team
  server.tool("incident_triage", "Classify and respond to security incidents.", incidentTriageSchema.shape, wrapTool("incident_triage", incidentTriage, options));
  server.tool("threat_intel_lookup", "IOC lookup against threat intel feeds.", threatIntelLookupSchema.shape, wrapTool("threat_intel_lookup", threatIntelLookup, options));
  server.tool("dns_security_check", "Check DNS security (SPF, DKIM, DMARC, DNSSEC).", dnsSecurityCheckSchema.shape, wrapTool("dns_security_check", dnsSecurityCheck, options));
  server.tool("email_security_audit", "Comprehensive email security audit.", emailSecurityAuditSchema.shape, wrapTool("email_security_audit", emailSecurityAudit, options));

  // Identity
  server.tool("access_review", "Audit user access against least-privilege.", accessReviewSchema.shape, wrapTool("access_review", accessReview, options));
  server.tool("mfa_audit", "Assess MFA coverage and strength.", mfaAuditSchema.shape, wrapTool("mfa_audit", mfaAudit, options));

  // Offensive
  server.tool("credential_check", "Check email/domain in breach databases (HIBP).", credentialCheckSchema.shape, wrapTool("credential_check", credentialCheck, options));

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

  return server;
}
