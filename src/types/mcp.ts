export interface ToolPricing {
  tool_name: string;
  price_usd: number;
}

// Pricing floor is $1.00 per paid call. Rationale: as of mid-2026, x402
// economic volume sits decisively at $1+ (95% of on-chain volume per
// Chainalysis); sub-$1 micropayments collapsed to ~4%. Pricing below $1
// targets a dead segment. Tiers below scale by compute + data cost:
//   $1 — single-source lookups (one API / one fast engine pass)
//   $2 — multi-source aggregation or real compute (Semgrep, trufflehog, etc.)
//   $3 — deeper active scans
//   $5 — heaviest scans / full report synthesis
export const TOOL_PRICING: Record<string, number> = {
  // $1 — single-source lookups
  cve_lookup: 1.00,
  vuln_prioritize: 1.00,
  ssl_tls_audit: 1.00,
  dns_security_check: 1.00,
  mfa_audit: 1.00,
  evidence_collect: 1.00,
  access_review: 1.00,

  // $2 — multi-source aggregation / real compute
  compliance_framework_check: 2.00,
  control_gap_analysis: 2.00,
  policy_generate: 2.00,
  secret_scan: 2.00,
  dependency_audit: 2.00,
  email_security_audit: 2.00,
  credential_check: 2.00,
  threat_intel_lookup: 2.00,

  // $3 — deeper active scans
  incident_triage: 3.00,
  vuln_scan_network: 3.00,
  vet_endpoint: 3.00, // L2 trust layer — composite verdict from multiple sub-checks

  // $5 — heaviest scans / full report synthesis
  vuln_scan_web_app: 5.00,
  sast_scan: 5.00,
  audit_report_generate: 5.00,
  scan_mcp_plugin: 5.00, // L2 trust — clone + Semgrep + secret scan + MCP heuristics
  scan_skill: 5.00, // L2 trust — same core, scoped to agent skills (SKILL.md + scripts)

  // Free utility tools (always 0)
  account_balance: 0,
  help: 0,

  // Free Phase 9.0 identity tools (always 0)
  agent_whoami: 0,
  agent_history: 0,
  agent_scan_get: 0,
};
