export interface ToolPricing {
  tool_name: string;
  price_usd: number;
}

export const TOOL_PRICING: Record<string, number> = {
  compliance_framework_check: 0.50,
  evidence_collect: 0.25,
  control_gap_analysis: 0.50,
  audit_report_generate: 1.00,
  policy_generate: 0.50,
  vuln_scan_network: 1.00,
  vuln_scan_web_app: 1.50,
  vuln_prioritize: 0.25,
  cve_lookup: 0.10,
  ssl_tls_audit: 0.25,
  sast_scan: 1.00,
  secret_scan: 0.50,
  dependency_audit: 0.50,
  incident_triage: 0.75,
  threat_intel_lookup: 0.25,
  dns_security_check: 0.25,
  email_security_audit: 0.50,
  access_review: 0.50,
  mfa_audit: 0.25,
  credential_check: 0.50,
};
