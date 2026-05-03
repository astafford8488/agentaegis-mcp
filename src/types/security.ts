export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type ComplianceFramework = "soc2" | "iso27001" | "hipaa" | "pci_dss" | "nist_csf";

export type ControlStatus = "met" | "partial" | "not_met" | "not_applicable";

export interface ComplianceControl {
  id: string;
  category: string;
  subcategory: string;
  title: string;
  description: string;
  evidence_types: string[];
  common_tools: string[];
  evaluation_criteria: string;
  weight: "critical" | "high" | "medium" | "low";
}

export interface ControlAssessment {
  control_id: string;
  status: ControlStatus;
  evidence_ref?: string;
  notes?: string;
  remediation?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score?: number;
  cve_id?: string;
  cwe_id?: string;
  affected_system: string;
  affected_component?: string;
  evidence?: string;
  remediation: string;
  references?: string[];
}

export interface ScanResult {
  scan_id: string;
  scan_type: string;
  target: string;
  started_at: string;
  completed_at: string;
  status: "completed" | "failed" | "timeout";
  findings: Finding[];
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface OrganizationProfile {
  industry: string;
  employee_count: number;
  handles_pii: boolean;
  handles_phi: boolean;
  handles_payment_cards: boolean;
  cloud_providers: string[];
  has_soc_report: boolean;
  has_pentest: boolean;
  has_security_team: boolean;
  tools_in_use: string[];
}

export interface ThreatIntelResult {
  indicator: string;
  indicator_type: string;
  reputation_score: number;
  is_malicious: boolean;
  sources: {
    source: string;
    result: Record<string, unknown>;
  }[];
  first_seen?: string;
  last_seen?: string;
  associated_malware?: string[];
  geographic_data?: Record<string, unknown>;
  recommendations: string[];
}

export interface IncidentClassification {
  type: "phishing" | "malware" | "ransomware" | "credential_stuffing" | "insider_threat" | "data_exfil" | "ddos" | "unknown";
  severity: "P1" | "P2" | "P3" | "P4";
  confidence: number;
  containment_actions: string[];
  investigation_steps: string[];
  evidence_checklist: string[];
  communication_templates: Record<string, string>;
  escalation_criteria: string[];
}

export interface AccessReviewFinding {
  type: "orphaned_account" | "dormant_account" | "excessive_admin" | "sod_violation" | "shared_account" | "missing_mfa";
  severity: Severity;
  affected_users: string[];
  description: string;
  remediation: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  days_until_expiry: number;
  san: string[];
  chain_valid: boolean;
  key_size: number;
  signature_algorithm: string;
}

export interface SSLGrade {
  grade: string;
  score: number;
  issues: string[];
}
