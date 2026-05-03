import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import "dotenv/config";

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

// Middleware
import { verifyPayment, generatePriceList } from "./middleware/x402.js";

const server = new McpServer({
  name: "agentaegis",
  version: "0.1.0",
});

// Helper to wrap tool handlers with payment verification
function wrapWithPayment(toolName: string, handler: (args: any) => Promise<any>) {
  return async (args: any) => {
    const payment = await verifyPayment(toolName);
    if (!payment.valid) {
      return { content: [{ type: "text" as const, text: JSON.stringify({ error: payment.error, price: payment.price_usd }) }] };
    }
    const result = await handler(args);
    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  };
}

// === COMPLIANCE & AUDIT ===

server.tool(
  "compliance_framework_check",
  "Assess an organization's security posture against a compliance framework. Supported frameworks: SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF.",
  complianceFrameworkCheckSchema.shape,
  wrapWithPayment("compliance_framework_check", complianceFrameworkCheck),
);

server.tool(
  "evidence_collect",
  "Collect evidence artifacts for specific compliance controls. Identifies what evidence is needed and returns a collection plan.",
  evidenceCollectSchema.shape,
  wrapWithPayment("evidence_collect", evidenceCollect),
);

server.tool(
  "control_gap_analysis",
  "Deep-dive analysis of compliance control gaps with detailed remediation steps, effort estimates, and tool recommendations.",
  controlGapAnalysisSchema.shape,
  wrapWithPayment("control_gap_analysis", controlGapAnalysis),
);

server.tool(
  "audit_report_generate",
  "Generate an audit-ready compliance report including executive summary, control assessments, and remediation roadmap.",
  auditReportGenerateSchema.shape,
  wrapWithPayment("audit_report_generate", auditReportGenerate),
);

server.tool(
  "policy_generate",
  "Generate a security policy document tailored to the organization's size, industry, and compliance requirements.",
  policyGenerateSchema.shape,
  wrapWithPayment("policy_generate", policyGenerate),
);

// === VULNERABILITY MANAGEMENT ===

server.tool(
  "vuln_scan_network",
  "Scan an IP address, IP range, or domain for open ports, running services, and known vulnerabilities.",
  vulnScanNetworkSchema.shape,
  wrapWithPayment("vuln_scan_network", vulnScanNetwork),
);

server.tool(
  "vuln_scan_web_app",
  "Scan a web application URL for OWASP Top 10 vulnerabilities including XSS, SQL injection, and security misconfigurations.",
  vulnScanWebAppSchema.shape,
  wrapWithPayment("vuln_scan_web_app", vulnScanWebApp),
);

server.tool(
  "vuln_prioritize",
  "Prioritize vulnerabilities by exploitability, business impact, and EPSS score. Transforms findings into an actionable remediation plan.",
  vulnPrioritizeSchema.shape,
  wrapWithPayment("vuln_prioritize", vulnPrioritize),
);

server.tool(
  "cve_lookup",
  "Look up detailed information about a specific CVE including CVSS scores, affected products, exploitability metrics, and available patches.",
  cveLookupSchema.shape,
  wrapWithPayment("cve_lookup", cveLookup),
);

server.tool(
  "ssl_tls_audit",
  "Audit SSL/TLS configuration for a domain. Checks certificate validity, protocol versions, cipher suites, and vulnerabilities.",
  sslTlsAuditSchema.shape,
  wrapWithPayment("ssl_tls_audit", sslTlsAudit),
);

// === CODE SECURITY ===

server.tool(
  "sast_scan",
  "Static Application Security Testing — scan source code for security vulnerabilities and insecure patterns. Supports Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C/C++.",
  sastScanSchema.shape,
  wrapWithPayment("sast_scan", sastScan),
);

server.tool(
  "secret_scan",
  "Scan source code for hardcoded secrets including API keys, tokens, passwords, and private keys.",
  secretScanSchema.shape,
  wrapWithPayment("secret_scan", secretScan),
);

server.tool(
  "dependency_audit",
  "Audit project dependencies for known vulnerabilities. Supports npm, pip, Go, Ruby, Java, and Cargo.",
  dependencyAuditSchema.shape,
  wrapWithPayment("dependency_audit", dependencyAudit),
);

// === BLUE TEAM / DEFENSIVE ===

server.tool(
  "incident_triage",
  "Triage a security incident — classify severity, identify attack type, recommend containment, and generate an incident response plan.",
  incidentTriageSchema.shape,
  wrapWithPayment("incident_triage", incidentTriage),
);

server.tool(
  "threat_intel_lookup",
  "Look up indicators of compromise (IOCs) against multiple threat intelligence feeds. Supports IPs, domains, URLs, and file hashes.",
  threatIntelLookupSchema.shape,
  wrapWithPayment("threat_intel_lookup", threatIntelLookup),
);

server.tool(
  "dns_security_check",
  "Check DNS configuration for security issues including SPF, DKIM, DMARC, DNSSEC, and dangling records.",
  dnsSecurityCheckSchema.shape,
  wrapWithPayment("dns_security_check", dnsSecurityCheck),
);

server.tool(
  "email_security_audit",
  "Comprehensive email security audit — evaluates SPF, DKIM, DMARC configuration with actionable hardening recommendations.",
  emailSecurityAuditSchema.shape,
  wrapWithPayment("email_security_audit", emailSecurityAudit),
);

// === IDENTITY & ACCESS ===

server.tool(
  "access_review",
  "Audit user access lists against least-privilege principles. Identifies excessive permissions, orphaned accounts, and separation of duties violations.",
  accessReviewSchema.shape,
  wrapWithPayment("access_review", accessReview),
);

server.tool(
  "mfa_audit",
  "Assess multi-factor authentication coverage. Identifies accounts without MFA, weak MFA methods, and MFA bypass risks.",
  mfaAuditSchema.shape,
  wrapWithPayment("mfa_audit", mfaAudit),
);

// === OFFENSIVE ===

server.tool(
  "credential_check",
  "Check if email addresses or a domain appear in known data breaches using Have I Been Pwned.",
  credentialCheckSchema.shape,
  wrapWithPayment("credential_check", credentialCheck),
);

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`AgentAegis MCP server running (${Object.keys(generatePriceList()).length} tools available)`);
}

main().catch((err) => {
  console.error("Failed to start AgentAegis MCP server:", err);
  process.exit(1);
});
