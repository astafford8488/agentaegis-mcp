/**
 * x402 Bazaar discovery catalog.
 *
 * The Coinbase Bazaar is the discovery layer for agentic commerce — a searchable
 * index where AI agents find x402-payable services. Listing is automatic: the CDP
 * facilitator catalogs a resource the first time it SETTLES a payment whose
 * `paymentPayload.extensions.bazaar` carries a valid discovery declaration.
 *
 * We don't use the SDK's resource-server middleware (we have a custom CDP gate),
 * so we wire discovery the lightweight way: put the declaration in the 402
 * challenge's `extensions` field. The v2 client copies a challenge's `extensions`
 * into the signed `paymentPayload.extensions`, which we then forward to the
 * facilitator on settle (see @x402/core extractDiscoveryInfo). Net effect: each
 * tool is indexed in the Bazaar the first time an agent pays for it.
 *
 * This is purely additive metadata — `buildBazaarExtension` is best-effort and
 * never throws, so a bad declaration can never break a payment challenge.
 */

import { declareDiscoveryExtension } from "@x402/extensions/bazaar";

interface ToolMeta {
  description: string;
  inputSchema: Record<string, unknown>;
}

const obj = (properties: Record<string, unknown>, required: string[]) => ({
  type: "object",
  properties,
  required,
});
const str = (description: string) => ({ type: "string", description });

/** Curated, agent-facing discovery metadata for each paid tool. */
const TOOL_DISCOVERY: Record<string, ToolMeta> = {
  // Vulnerability management
  cve_lookup: { description: "Look up a CVE: CVSS score, KEV status, affected packages, references (via NVD).", inputSchema: obj({ cve_id: str("CVE identifier, e.g. CVE-2024-3094") }, ["cve_id"]) },
  vuln_scan_network: { description: "Scan an IP or domain for open ports, services, and known vulnerabilities (nmap).", inputSchema: obj({ target: str("IP address or domain to scan") }, ["target"]) },
  vuln_scan_web_app: { description: "OWASP Top 10 web-application vulnerability scan (Nuclei).", inputSchema: obj({ target_url: str("HTTPS URL to scan"), scan_depth: str("surface | standard | thorough") }, ["target_url", "scan_depth"]) },
  vuln_prioritize: { description: "Risk-rank vulnerability findings using EPSS plus business context.", inputSchema: obj({ findings: { type: "array", description: "Vulnerability findings to prioritize" } }, ["findings"]) },
  ssl_tls_audit: { description: "Audit SSL/TLS: certificate validity, protocols, ciphers, known vulns (sslyze).", inputSchema: obj({ target: str("Hostname or domain") }, ["target"]) },

  // Blue team / threat intel
  threat_intel_lookup: { description: "Look up an IOC (IP, domain, or hash) across AbuseIPDB, AlienVault OTX, abuse.ch.", inputSchema: obj({ indicator: str("IP address, domain, or file hash") }, ["indicator"]) },
  dns_security_check: { description: "Check DNS security posture: SPF, DKIM, DMARC, DNSSEC, dangling records.", inputSchema: obj({ domain: str("Domain to check") }, ["domain"]) },
  email_security_audit: { description: "Audit email security (DMARC/SPF/DKIM) with hardening recommendations.", inputSchema: obj({ domain: str("Email domain to audit") }, ["domain"]) },
  incident_triage: { description: "Triage a security incident: classify, prioritize, and suggest containment steps.", inputSchema: obj({ description: str("Incident description and indicators") }, ["description"]) },

  // Code security
  sast_scan: { description: "Static code analysis for security vulnerabilities across 8+ languages (Semgrep).", inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]) },
  secret_scan: { description: "Detect hardcoded secrets, API keys, and tokens in a repository (trufflehog).", inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]) },
  dependency_audit: { description: "Audit dependencies for known CVEs across npm/pip/Go/Ruby/Java/Cargo (trivy).", inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]) },

  // Identity & offensive
  access_review: { description: "Review user access against least-privilege principles.", inputSchema: obj({ access_data: { type: "object", description: "Access/role data to review" } }, ["access_data"]) },
  mfa_audit: { description: "Audit MFA coverage and method strength.", inputSchema: obj({ config: { type: "object", description: "MFA/identity configuration" } }, ["config"]) },
  credential_check: { description: "Check an email or domain against known breach databases (HIBP).", inputSchema: obj({ target: str("Email address or domain") }, ["target"]) },

  // Compliance & GRC
  compliance_framework_check: { description: "Assess security posture against SOC 2, ISO 27001, HIPAA, PCI DSS, or NIST CSF.", inputSchema: obj({ framework: str("soc2 | iso27001 | hipaa | pci_dss | nist_csf") }, ["framework"]) },
  control_gap_analysis: { description: "Prioritized remediation roadmap with effort estimates for a framework.", inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]) },
  evidence_collect: { description: "Generate an evidence-collection plan for audit controls.", inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]) },
  audit_report_generate: { description: "Generate an audit-ready compliance report.", inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]) },
  policy_generate: { description: "Generate a tailored security policy (incident response, access control, etc.).", inputSchema: obj({ policy_type: str("Policy type to generate") }, ["policy_type"]) },
};

/**
 * Build the `{ bazaar: <discovery extension> }` object for a tool, suitable for
 * the 402 challenge's `extensions` field. Best-effort: returns undefined (never
 * throws) so discovery can never break a payment challenge.
 */
export function buildBazaarExtension(toolName: string): Record<string, unknown> | undefined {
  const meta = TOOL_DISCOVERY[toolName];
  if (!meta) return undefined;
  try {
    return declareDiscoveryExtension({
      toolName,
      description: meta.description,
      inputSchema: meta.inputSchema,
    });
  } catch {
    return undefined;
  }
}

/** Agent-facing one-line description for a tool, used as the resource description. */
export function toolDiscoveryDescription(toolName: string): string | undefined {
  return TOOL_DISCOVERY[toolName]?.description;
}
