// The single source of truth for how each tool DESCRIBES itself.
//
// Tool copy used to live in four places that drifted independently: the MCP
// registrations in server.ts, the Bazaar discovery map in auth/bazaarCatalog.ts,
// the HTTP x402 resource list in transport/httpResource.ts, and the site's
// llms.txt. The Bazaar map was missing the entire trust layer, so a 402 for
// vet_endpoint — the flagship — advertised itself as "single tool invocation".
//
// Everything an agent reads about a tool now comes from here. Price still lives
// in TOOL_PRICING (types/mcp.ts) because the payment gate reads it directly;
// this module deliberately does not duplicate it.
//
// Adding a tool means adding one entry here plus a TOOL_PRICING line;
// tests/toolCatalog.test.ts fails if the two ever disagree.

import type { ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";

export interface ToolCatalogEntry {
  /** Rich agent-facing description for MCP tools/list. The price is appended
   *  centrally by registerPaidTool, so never write a dollar amount here. */
  description: string;
  /** Machine-readable risk hints. Clients use these to decide what may be
   *  auto-approved, so they must be honest rather than flattering. */
  annotations: ToolAnnotations;
  /** One-line description for the x402 402-challenge and Bazaar discovery.
   *  Kept short: it is catalog copy, not documentation. Paid tools only. */
  discovery?: string;
  /** JSON Schema for Bazaar discovery. Paid tools only. */
  inputSchema?: Record<string, unknown>;
  /** Long, branded copy for the standalone HTTP x402 rail. Only the tools
   *  mounted in httpResource.ts have one, and these strings are ALREADY
   *  INDEXED in the CDP Bazaar — changing one changes a live listing. */
  resource?: string;
}

// ---- Annotation presets ----------------------------------------------------
//
// readOnlyHint is about the TARGET's state, not ours. Everything here is
// read-only in that sense except the two active scanners: nmap and Nuclei send
// probe traffic that can create log entries, trip intrusion detection, lock
// accounts, or destabilise a fragile service. Marking those read-only would
// invite clients to auto-approve them, so they are deliberately not.
//
// None of these hints can express "this costs money" — the MCP spec has no such
// field — which is why cost lives in the description and server instructions.

/** Processes data the caller supplied. Touches nothing outside this server. */
const ANALYSIS: ToolAnnotations = { readOnlyHint: true, idempotentHint: true, openWorldHint: false };

/** Reads from third-party services or clones a repo. Changes nothing. */
const LOOKUP: ToolAnnotations = { readOnlyHint: true, idempotentHint: true, openWorldHint: true };

/** Sends probe traffic to a target the caller must be authorized to test. */
const ACTIVE_SCAN: ToolAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
};

/** Free account/identity utilities. Read our own database only. */
const ACCOUNT: ToolAnnotations = { readOnlyHint: true, idempotentHint: true, openWorldHint: false };

// ---- Bazaar input-schema helpers -------------------------------------------

const obj = (properties: Record<string, unknown>, required: string[]) => ({
  type: "object",
  properties,
  required,
});
const str = (description: string) => ({ type: "string", description });
const gitSource = str("Git repository URL (https), or an inline code snippet");

export const TOOL_CATALOG: Record<string, ToolCatalogEntry> = {
  // ===== Trust layer (L2) — the flagship =====
  vet_endpoint: {
    description:
      "Composite trust verdict (PROCEED/CAUTION/BLOCK) for an endpoint an agent is about to call or pay — combines TLS/cert health, DNS hygiene, threat-intel reputation, and domain age into one decision with reasons. Prefer this over running ssl_tls_audit + dns_security_check + threat_intel_lookup separately: it costs less than the sum and returns a decision rather than three reports to reconcile.",
    annotations: LOOKUP,
    discovery:
      "Composite PROCEED/CAUTION/BLOCK trust verdict for an endpoint an agent is about to call or pay.",
    inputSchema: obj({ endpoint: str("Endpoint URL or domain to vet") }, ["endpoint"]),
    resource:
      "AgentAegis vet_endpoint — composite PROCEED/CAUTION/BLOCK safety verdict for an endpoint an AI agent is about to call or pay. Live TLS/cert, DNS hygiene, threat-intel (domain + resolved IP), and domain-age signals → one trust score with reasons.",
  },
  scan_mcp_plugin: {
    description:
      "Scan an MCP server (git repo or code) for supply-chain risk BEFORE trusting it — exfiltration (secrets/env to the network), prompt-injection sinks, dangerous capabilities, npm install hooks, obfuscation, plus Semgrep + secret scanning → a PROCEED/CAUTION/BLOCK verdict with findings.",
    annotations: LOOKUP,
    discovery:
      "Supply-chain trust scan of an MCP server or plugin before you install it → PROCEED/CAUTION/BLOCK.",
    inputSchema: obj({ source: gitSource }, ["source"]),
    resource:
      "AgentAegis scan_mcp_plugin — supply-chain trust scan of an MCP server or agent skill BEFORE you install/trust it. Clones a git repo (or takes a code snippet) and flags exfiltration (secrets/env to the network), prompt-injection sinks (hijack phrases + hidden unicode), dangerous capabilities (eval/shell/dynamic exec), npm install hooks, and obfuscation → one PROCEED/CAUTION/BLOCK verdict with findings.",
  },
  scan_skill: {
    description:
      "Scan an agent SKILL (git repo or SKILL.md) for supply-chain risk BEFORE trusting it — prompt-injection / hidden-unicode in the instructions (hard block), over-broad allowed-tools grants, plus exfiltration, dangerous capabilities, secrets and obfuscation in bundled scripts → a PROCEED/CAUTION/BLOCK verdict.",
    annotations: LOOKUP,
    discovery:
      "Supply-chain trust scan of an agent skill (SKILL.md + scripts) before you load it → PROCEED/CAUTION/BLOCK.",
    inputSchema: obj({ source: gitSource }, ["source"]),
    resource:
      "AgentAegis scan_skill — supply-chain trust scan of an AGENT SKILL (a SKILL.md + bundled scripts) BEFORE you install/trust it. Flags prompt-injection / hidden-unicode in the instructions the agent will follow (hard block), over-broad allowed-tools grants, plus exfiltration, dangerous capabilities, secrets and obfuscation in bundled code → one PROCEED/CAUTION/BLOCK verdict.",
  },

  // ===== Vulnerability management =====
  vuln_scan_network: {
    description:
      "Discover open ports, running services and known vulnerabilities on an IP or domain (nmap). SENDS REAL TRAFFIC to the target and may trigger intrusion detection — only run against hosts the caller owns or is explicitly authorized to test, and confirm that first. Pass async:true to get a job_id to poll instead of blocking.",
    annotations: ACTIVE_SCAN,
    discovery: "Scan an IP or domain for open ports, services, and known vulnerabilities (nmap).",
    inputSchema: obj({ target: str("IP address or domain to scan") }, ["target"]),
  },
  vuln_scan_web_app: {
    description:
      "Scan a web application for OWASP Top 10 issues and known CVEs (Nuclei). SENDS REAL TRAFFIC to the target — authorized targets only, confirm before calling. Pass async:true to get a job_id to poll instead of blocking.",
    annotations: ACTIVE_SCAN,
    discovery: "OWASP Top 10 web-application vulnerability scan (Nuclei).",
    inputSchema: obj(
      { target_url: str("HTTPS URL to scan"), scan_depth: str("surface | standard | thorough") },
      ["target_url", "scan_depth"]
    ),
  },
  vuln_prioritize: {
    description:
      "Rank vulnerabilities you already have by exploitability and business impact, and group them into remediation actions. Analyzes findings you supply; it discovers nothing on its own.",
    annotations: ANALYSIS,
    discovery: "Risk-rank vulnerability findings using EPSS plus business context.",
    inputSchema: obj(
      { findings: { type: "array", description: "Vulnerability findings to prioritize" } },
      ["findings"]
    ),
  },
  cve_lookup: {
    description:
      "Look up one CVE by identifier: CVSS score and vector, affected products, patch availability and references. Use when a specific CVE ID is already known.",
    annotations: LOOKUP,
    discovery: "Look up a CVE: CVSS score, KEV status, affected packages, references (via NVD).",
    inputSchema: obj({ cve_id: str("CVE identifier, e.g. CVE-2024-3094") }, ["cve_id"]),
    resource:
      "AgentAegis cve_lookup — CVSS score, severity, CWE classifications, CISA KEV (known-exploited) status, affected products and references for a CVE id. NVD with CIRCL + OSV fallback for reliability.",
  },
  ssl_tls_audit: {
    description:
      "Audit a domain's TLS configuration (sslyze): certificate validity and expiry, protocol versions, cipher suites, and known TLS weaknesses. Passive — safe against any host.",
    annotations: LOOKUP,
    discovery: "Audit SSL/TLS: certificate validity, protocols, ciphers, known vulns (sslyze).",
    inputSchema: obj({ target: str("Hostname or domain") }, ["target"]),
    resource:
      "AgentAegis ssl_tls_audit — TLS/certificate health grade for a host: supported protocols, cipher strength, certificate validity + days-to-expiry, and known TLS vulnerabilities.",
  },

  // ===== Code security =====
  sast_scan: {
    description:
      "Static analysis of source code or an https git repo for security flaws (Semgrep): injection, unsafe deserialization, path traversal, crypto misuse. Python, JS/TS, Java, Go, Ruby, PHP, C/C++. For code LOGIC flaws — use secret_scan for hardcoded credentials and dependency_audit for vulnerable packages.",
    annotations: LOOKUP,
    discovery: "Static code analysis for security vulnerabilities across 8+ languages (Semgrep).",
    inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]),
  },
  secret_scan: {
    description:
      "Detect hardcoded credentials, API keys and tokens in source code or an https git repo (trufflehog), verified against the issuing provider where supported. Use when the question is 'did we commit a secret'.",
    annotations: LOOKUP,
    discovery: "Detect hardcoded secrets, API keys, and tokens in a repository (trufflehog).",
    inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]),
  },
  dependency_audit: {
    description:
      "Audit a dependency manifest or https git repo for known-vulnerable packages (trivy): npm, pip, Go, Ruby, Java, Cargo. The cheapest, highest-signal first step when assessing an unfamiliar repository.",
    annotations: LOOKUP,
    discovery: "Audit dependencies for known CVEs across npm/pip/Go/Ruby/Java/Cargo (trivy).",
    inputSchema: obj({ repo_url: str("Git repository URL") }, ["repo_url"]),
    resource:
      "AgentAegis dependency_audit — scan a git repository or a dependency manifest (npm/pip/go/ruby/java/cargo) for known-CVE packages, with severities and upgrade fixes (Trivy).",
  },

  // ===== Blue team / threat intel =====
  incident_triage: {
    description:
      "Classify a security incident and produce severity, likely category, containment steps and a response plan. Use when something has already happened. If all you have is a suspicious IP or domain, run threat_intel_lookup first — it is cheaper and may settle the question.",
    annotations: ANALYSIS,
    discovery: "Triage a security incident: classify, prioritize, and suggest containment steps.",
    inputSchema: obj({ description: str("Incident description and indicators") }, ["description"]),
  },
  threat_intel_lookup: {
    description:
      "Reputation and indicator lookup for an IP or domain across AbuseIPDB, AlienVault OTX and abuse.ch. The cheapest way to check whether an indicator is known-bad. Interpret with care: large CDN, cloud and payment infrastructure routinely returns reputation hits, so only a curated active-malware hit is strong evidence on its own.",
    annotations: LOOKUP,
    discovery: "Look up an IOC (IP, domain, or hash) across AbuseIPDB, AlienVault OTX, abuse.ch.",
    inputSchema: obj({ indicator: str("IP address, domain, or file hash") }, ["indicator"]),
    resource:
      "AgentAegis threat_intel_lookup — reputation + threat verdict for an IOC (IP, domain, URL, or file hash) aggregated across AbuseIPDB, AlienVault OTX, and abuse.ch.",
  },
  dns_security_check: {
    description:
      "Check a domain's DNS security records — SPF, DKIM, DMARC, DNSSEC — and grade the configuration. Passive. Covers the records themselves; for full spoofability posture use email_security_audit.",
    annotations: LOOKUP,
    discovery: "Check DNS security posture: SPF, DKIM, DMARC, DNSSEC, dangling records.",
    inputSchema: obj({ domain: str("Domain to check") }, ["domain"]),
  },
  email_security_audit: {
    description:
      "Full email-security posture for a domain: whether mail from it can be spoofed, with DMARC/SPF/DKIM alignment and policy strength. A superset of dns_security_check for the email question specifically.",
    annotations: LOOKUP,
    discovery: "Audit email security (DMARC/SPF/DKIM) with hardening recommendations.",
    inputSchema: obj({ domain: str("Email domain to audit") }, ["domain"]),
  },

  // ===== Identity & offensive =====
  access_review: {
    description:
      "Review user and role assignments you supply against least-privilege, flagging excessive, stale or orphaned access. Analyzes data the caller provides; it does not connect to an identity provider.",
    annotations: ANALYSIS,
    discovery: "Review user access against least-privilege principles.",
    inputSchema: obj(
      { access_data: { type: "object", description: "Access/role data to review" } },
      ["access_data"]
    ),
  },
  mfa_audit: {
    description:
      "Assess MFA coverage and factor strength across a user or configuration set you supply, flagging unenrolled accounts and weak factors such as SMS. Analyzes data the caller provides; it does not connect to an identity provider.",
    annotations: ANALYSIS,
    discovery: "Audit MFA coverage and method strength.",
    inputSchema: obj({ config: { type: "object", description: "MFA/identity configuration" } }, ["config"]),
  },
  credential_check: {
    description:
      "Check whether an email address or domain appears in known credential-breach corpora (Have I Been Pwned), with the breaches and data classes exposed. Use when assessing account-takeover exposure.",
    annotations: LOOKUP,
    discovery: "Check an email or domain against known breach databases (HIBP).",
    inputSchema: obj({ target: str("Email address or domain") }, ["target"]),
  },

  // ===== Compliance & GRC =====
  compliance_framework_check: {
    description:
      "Assess an organization's security posture against a compliance framework (SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF) and report per-control status. Use this FIRST when asked whether the org is audit-ready; control_gap_analysis builds on its output.",
    annotations: ANALYSIS,
    discovery: "Assess security posture against SOC 2, ISO 27001, HIPAA, PCI DSS, or NIST CSF.",
    inputSchema: obj({ framework: str("soc2 | iso27001 | hipaa | pci_dss | nist_csf") }, ["framework"]),
  },
  control_gap_analysis: {
    description:
      "Turn unmet compliance controls into a prioritized remediation roadmap with effort estimates. Use after compliance_framework_check to answer 'what do we fix first'.",
    annotations: ANALYSIS,
    discovery: "Prioritized remediation roadmap with effort estimates for a framework.",
    inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]),
  },
  evidence_collect: {
    description:
      "Build an evidence-collection plan for specific compliance controls: what artifact each control needs, where it comes from, and what makes it sufficient. Use when preparing for a real audit, after the gaps are known. Plans the collection; does not gather evidence for you.",
    annotations: ANALYSIS,
    discovery: "Generate an evidence-collection plan for audit controls.",
    inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]),
  },
  audit_report_generate: {
    description:
      "Synthesize findings into an audit-ready compliance report. Use at the END of an engagement, once gaps are closed. If the user only wants to know where they currently stand, run compliance_framework_check instead — it costs less and answers that question directly.",
    annotations: ANALYSIS,
    discovery: "Generate an audit-ready compliance report.",
    inputSchema: obj({ framework: str("Compliance framework") }, ["framework"]),
  },
  policy_generate: {
    description:
      "Generate a tailored written security policy (incident response, access control, encryption, vendor management, remote work, and similar). Use when a control gap specifically calls for documented policy.",
    annotations: ANALYSIS,
    discovery: "Generate a tailored security policy (incident response, access control, etc.).",
    inputSchema: obj({ policy_type: str("Policy type to generate") }, ["policy_type"]),
  },

  // ===== Free account & identity tools =====
  // No discovery/inputSchema: they are never payable, so they are never listed.
  account_balance: {
    description:
      "Returns the calling API key's prepaid balance, monthly limit, current month usage, and a breakdown of how many of each tool the customer can still afford. Free to call.",
    annotations: ACCOUNT,
  },
  help: {
    description:
      "Returns AgentAegis FAQ — authentication, balance/billing, tool catalog, async jobs, error codes, x402, rate limits, security. Optional topic filter. Free to call.",
    annotations: ACCOUNT,
  },
  agent_whoami: {
    description:
      "Returns your persistent AgentAegis agent identity (agent_id), how you're identified (API key / wallet / anonymous session), and lifetime call count + spend. Free to call.",
    annotations: ACCOUNT,
  },
  agent_history: {
    description:
      "Lists your recent scans (scan_id, tool, target, status, time) so you can retrieve or chain from a prior result. Optional limit/tool/target/since filters. Free to call.",
    annotations: ACCOUNT,
  },
  agent_scan_get: {
    description:
      "Retrieves one of your prior scans by scan_id, including the stored full output, so you can build on earlier results without re-paying. Free to call.",
    annotations: ACCOUNT,
  },
};

/** Catalog entry for a tool, or undefined if it has none. */
export function toolMeta(name: string): ToolCatalogEntry | undefined {
  return TOOL_CATALOG[name];
}
