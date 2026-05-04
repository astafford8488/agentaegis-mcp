import { z } from "zod";
import type { ComplianceFramework, ControlStatus, OrganizationProfile } from "../../types/security.js";
import { calculateComplianceScore } from "../../utils/scoring.js";

export const complianceFrameworkCheckSchema = z.object({
  framework: z.enum(["soc2", "iso27001", "hipaa", "pci_dss", "nist_csf"]),
  organization_profile: z.object({
    industry: z.string(),
    employee_count: z.number(),
    handles_pii: z.boolean(),
    handles_phi: z.boolean(),
    handles_payment_cards: z.boolean(),
    cloud_providers: z.array(z.string()),
    has_soc_report: z.boolean(),
    has_pentest: z.boolean(),
    has_security_team: z.boolean(),
    tools_in_use: z.array(z.string()),
  }),
});

export type ComplianceFrameworkCheckInput = z.infer<typeof complianceFrameworkCheckSchema>;

interface ControlEvaluation {
  control_id: string;
  title: string;
  category: string;
  status: ControlStatus;
  evidence_needed: string[];
  remediation?: string;
  priority: "critical" | "high" | "medium" | "low";
}

const IDENTITY_PROVIDERS = ["okta", "azure_ad", "azure ad", "auth0", "onelogin", "ping", "duo", "jumpcloud"];
const MONITORING_TOOLS = ["datadog", "splunk", "elastic", "new relic", "cloudwatch", "pagerduty", "grafana", "prometheus"];
const CI_CD_TOOLS = ["github", "gitlab", "jenkins", "circleci", "github actions", "bitbucket"];
const EDR_TOOLS = ["crowdstrike", "sentinelone", "carbon black", "defender", "cylance"];
const BACKUP_TOOLS = ["veeam", "aws backup", "azure backup", "backblaze", "acronis"];

function hasToolCategory(tools: string[], category: string[]): boolean {
  return tools.some((t) => category.some((c) => t.toLowerCase().includes(c.toLowerCase())));
}

function evaluateSOC2Controls(profile: OrganizationProfile): ControlEvaluation[] {
  const evaluations: ControlEvaluation[] = [];
  const tools = profile.tools_in_use;

  // CC1 - Control Environment
  evaluations.push({
    control_id: "CC1.1",
    title: "Integrity and Ethical Values",
    category: "Control Environment",
    status: profile.has_security_team ? "partial" : "not_met",
    evidence_needed: ["code_of_conduct", "ethics_policy", "training_records"],
    remediation: !profile.has_security_team ? "Establish a security team or designate a security-responsible individual" : undefined,
    priority: "high",
  });

  // CC6.1 - Logical Access
  const hasIdp = hasToolCategory(tools, IDENTITY_PROVIDERS);
  evaluations.push({
    control_id: "CC6.1",
    title: "Logical Access Security",
    category: "Logical and Physical Access",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["iam_config", "access_control_policy", "user_access_review", "mfa_config"],
    remediation: !hasIdp ? "Implement a centralized identity provider (Okta, Azure AD, etc.)" : "Ensure MFA is enforced and access reviews are conducted quarterly",
    priority: "critical",
  });

  // CC6.2 - User Registration/Deprovisioning
  evaluations.push({
    control_id: "CC6.2",
    title: "User Registration and Authorization",
    category: "Logical and Physical Access",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["onboarding_process", "offboarding_checklist", "access_review_records"],
    remediation: "Document and automate user provisioning/deprovisioning processes",
    priority: "high",
  });

  // CC6.3 - Role-based Access
  evaluations.push({
    control_id: "CC6.3",
    title: "Role-Based Access Control",
    category: "Logical and Physical Access",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["rbac_matrix", "role_definitions", "least_privilege_policy"],
    remediation: "Define roles and implement least-privilege access model",
    priority: "high",
  });

  // CC7.1 - Monitoring
  const hasMonitoring = hasToolCategory(tools, MONITORING_TOOLS);
  evaluations.push({
    control_id: "CC7.1",
    title: "Detection of Anomalies and Security Events",
    category: "System Operations",
    status: hasMonitoring ? "partial" : "not_met",
    evidence_needed: ["monitoring_config", "alert_policies", "incident_response_plan"],
    remediation: !hasMonitoring ? "Implement security monitoring (SIEM, log aggregation)" : "Document alerting thresholds and response procedures",
    priority: "critical",
  });

  // CC7.2 - Incident Response
  evaluations.push({
    control_id: "CC7.2",
    title: "Incident Response",
    category: "System Operations",
    status: profile.has_security_team ? "partial" : "not_met",
    evidence_needed: ["incident_response_plan", "incident_records", "postmortem_reports"],
    remediation: "Create and test an incident response plan",
    priority: "critical",
  });

  // CC8.1 - Change Management
  const hasCICD = hasToolCategory(tools, CI_CD_TOOLS);
  evaluations.push({
    control_id: "CC8.1",
    title: "Change Management Process",
    category: "Change Management",
    status: hasCICD ? "partial" : "not_met",
    evidence_needed: ["change_management_policy", "code_review_records", "deployment_logs"],
    remediation: !hasCICD ? "Implement version control and CI/CD pipeline" : "Document change management procedures and approval workflows",
    priority: "high",
  });

  // CC3.1 - Risk Assessment
  evaluations.push({
    control_id: "CC3.1",
    title: "Risk Assessment Process",
    category: "Risk Assessment",
    status: profile.has_pentest ? "partial" : "not_met",
    evidence_needed: ["risk_assessment_report", "risk_register", "pentest_report"],
    remediation: "Conduct annual risk assessment and maintain a risk register",
    priority: "high",
  });

  // CC9.1 - Risk Mitigation
  const hasEDR = hasToolCategory(tools, EDR_TOOLS);
  evaluations.push({
    control_id: "CC9.1",
    title: "Risk Mitigation",
    category: "Risk Mitigation",
    status: hasEDR && hasMonitoring ? "partial" : "not_met",
    evidence_needed: ["security_controls_inventory", "edr_config", "vulnerability_management_policy"],
    remediation: "Implement endpoint detection and vulnerability management program",
    priority: "high",
  });

  // A1.1 - Availability
  const hasBackups = hasToolCategory(tools, BACKUP_TOOLS);
  evaluations.push({
    control_id: "A1.1",
    title: "System Availability",
    category: "Availability",
    status: hasBackups ? "partial" : "not_met",
    evidence_needed: ["backup_policy", "disaster_recovery_plan", "uptime_sla", "backup_test_records"],
    remediation: "Implement backup solution and document disaster recovery plan",
    priority: "high",
  });

  return evaluations;
}

function evaluatePCIDSSControls(profile: OrganizationProfile): ControlEvaluation[] {
  const evaluations: ControlEvaluation[] = [];
  const tools = profile.tools_in_use;
  const handlesCards = profile.handles_payment_cards;
  const hasIdp = hasToolCategory(tools, IDENTITY_PROVIDERS);
  const hasMonitoring = hasToolCategory(tools, MONITORING_TOOLS);
  const hasEDR = hasToolCategory(tools, EDR_TOOLS);
  const hasCICD = hasToolCategory(tools, CI_CD_TOOLS);
  const isCloudOnly = profile.cloud_providers.length > 0;
  const TOKENIZATION_TOOLS = ["stripe", "braintree", "spreedly", "tokenex", "very good security", "vgs", "basis theory"];
  const hasTokenization = hasToolCategory(tools, TOKENIZATION_TOOLS);

  // If org doesn't handle cards, mark everything not_applicable
  if (!handlesCards) {
    evaluations.push({
      control_id: "PCI-NA",
      title: "PCI DSS not applicable",
      category: "scope",
      status: "not_applicable",
      evidence_needed: [],
      priority: "low",
    });
    return evaluations;
  }

  // Requirement 1 — Network Security Controls
  evaluations.push({
    control_id: "1.3.1",
    title: "Inbound traffic to CDE restricted",
    category: "Network Security",
    status: isCloudOnly ? "partial" : "not_met",
    evidence_needed: ["firewall_rules", "ingress_policy", "vpc_diagram"],
    remediation: isCloudOnly
      ? "Document VPC security group rules and confirm CDE is in dedicated subnets with explicit ingress restrictions"
      : "Implement network firewall with documented ingress rules between CDE and other networks",
    priority: "critical",
  });
  evaluations.push({
    control_id: "1.4.1",
    title: "Network segmentation between CDE and untrusted networks",
    category: "Network Security",
    status: isCloudOnly ? "partial" : "not_met",
    evidence_needed: ["network_diagram", "segmentation_evidence", "pentest_segmentation_validation"],
    remediation: "Document network segmentation architecture and validate via penetration test annually",
    priority: "critical",
  });

  // Requirement 2 — Configurations
  evaluations.push({
    control_id: "2.2.1",
    title: "Configuration standards developed",
    category: "Secure Configuration",
    status: hasCICD ? "partial" : "not_met",
    evidence_needed: ["hardening_standards", "iac_repos", "cis_benchmark_evidence"],
    remediation: "Adopt CIS Benchmarks or AWS Foundational Security Best Practices; codify in IaC",
    priority: "high",
  });

  // Requirement 3 — Stored data protection (CRITICAL for fintechs)
  evaluations.push({
    control_id: "3.3.1",
    title: "Sensitive authentication data not stored after authorization",
    category: "Data Protection",
    status: hasTokenization ? "partial" : "not_met",
    evidence_needed: ["data_inventory", "tokenization_implementation", "card_data_flow_diagram"],
    remediation: hasTokenization
      ? "Confirm CVV/CAV2 never stored anywhere, even temporarily. Audit logs and DB schemas."
      : "Implement tokenization (Stripe, VGS, Basis Theory) — never store raw PAN or CVV",
    priority: "critical",
  });
  evaluations.push({
    control_id: "3.4.1",
    title: "PAN masked when displayed",
    category: "Data Protection",
    status: hasTokenization ? "met" : "not_met",
    evidence_needed: ["display_implementation", "ui_masking_examples"],
    remediation: "Display only first 6 and last 4 digits in dashboards, emails, logs, exports",
    priority: "critical",
  });
  evaluations.push({
    control_id: "3.5.1",
    title: "PAN rendered unreadable wherever stored",
    category: "Data Protection",
    status: hasTokenization ? "partial" : "not_met",
    evidence_needed: ["encryption_implementation", "kms_config", "tokenization_setup"],
    remediation: "Tokenize PAN at the entry point. If stored encrypted, use envelope encryption with KMS.",
    priority: "critical",
  });
  evaluations.push({
    control_id: "3.6.1",
    title: "Cryptographic keys protected",
    category: "Data Protection",
    status: isCloudOnly ? "partial" : "not_met",
    evidence_needed: ["key_management_policy", "kms_config", "key_rotation_records"],
    remediation: "Use AWS KMS / GCP KMS / HashiCorp Vault with annual rotation and access audit",
    priority: "critical",
  });

  // Requirement 4 — Crypto in transit
  evaluations.push({
    control_id: "4.2.1",
    title: "Strong cryptography in transit (TLS 1.2+)",
    category: "Transmission",
    status: isCloudOnly ? "partial" : "not_met",
    evidence_needed: ["tls_config", "cipher_suite_inventory", "ssl_labs_score"],
    remediation: "Disable TLS 1.0/1.1. Run AgentAegis ssl_tls_audit on all public endpoints.",
    priority: "critical",
  });

  // Requirement 5 — Anti-malware
  evaluations.push({
    control_id: "5.2.1",
    title: "Anti-malware deployed on all relevant systems",
    category: "Malware Protection",
    status: hasEDR ? "partial" : "not_met",
    evidence_needed: ["edr_config", "deployment_records", "endpoint_inventory"],
    remediation: hasEDR
      ? "Confirm EDR coverage on 100% of CDE-adjacent endpoints; document exceptions"
      : "Deploy EDR (CrowdStrike, SentinelOne, Defender) — required by PCI 4.0 for all in-scope systems",
    priority: "critical",
  });

  // Requirement 6 — Secure development
  evaluations.push({
    control_id: "6.3.1",
    title: "Vulnerability management program",
    category: "Secure Development",
    status: profile.has_pentest ? "partial" : "not_met",
    evidence_needed: ["vuln_management_program", "scan_results", "patch_records"],
    remediation: "Implement regular vulnerability scanning (run AgentAegis vuln_scan_* tools weekly) with documented patch SLAs",
    priority: "critical",
  });
  evaluations.push({
    control_id: "6.3.3",
    title: "Critical patches installed within one month",
    category: "Secure Development",
    status: hasCICD ? "partial" : "not_met",
    evidence_needed: ["patch_management_policy", "patching_metrics"],
    remediation: "Enable automated dependency updates (Dependabot/Renovate) and document patch SLA",
    priority: "high",
  });
  evaluations.push({
    control_id: "6.4.1",
    title: "Public-facing web apps protected",
    category: "Secure Development",
    status: profile.has_pentest ? "partial" : "not_met",
    evidence_needed: ["pentest_records", "waf_config", "automated_scan_evidence"],
    remediation: "Deploy WAF (Cloudflare, AWS WAF) with managed rule sets, and run quarterly pentests",
    priority: "critical",
  });

  // Requirement 7 — Need-to-know
  evaluations.push({
    control_id: "7.2.1",
    title: "Least-privilege access policy",
    category: "Access Control",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["access_control_policy", "rbac_matrix", "iam_config"],
    remediation: hasIdp
      ? "Document role definitions and ensure CDE access is restricted by job function"
      : "Deploy centralized IdP (Okta, Azure AD) with RBAC before applying for PCI",
    priority: "critical",
  });
  evaluations.push({
    control_id: "7.2.4",
    title: "Access reviews every 6 months",
    category: "Access Control",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["access_review_records", "review_evidence"],
    remediation: "Conduct semi-annual access review; reviewer signs off on every account",
    priority: "high",
  });

  // Requirement 8 — Authentication & MFA
  evaluations.push({
    control_id: "8.4.2",
    title: "MFA for all CDE access",
    category: "Authentication",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["mfa_config", "mfa_enforcement_screenshots"],
    remediation: "Enforce MFA on every account that can reach the CDE. Run AgentAegis mfa_audit to find gaps.",
    priority: "critical",
  });
  evaluations.push({
    control_id: "8.4.3",
    title: "MFA for all remote access into corporate network",
    category: "Authentication",
    status: hasIdp ? "partial" : "not_met",
    evidence_needed: ["vpn_mfa_config", "remote_access_policy"],
    remediation: "Enforce MFA on VPN and any remote access tooling",
    priority: "critical",
  });

  // Requirement 9 — Physical (mostly inherited from cloud provider)
  evaluations.push({
    control_id: "9.2.1",
    title: "Physical access controls",
    category: "Physical Security",
    status: isCloudOnly ? "met" : "partial",
    evidence_needed: isCloudOnly
      ? ["cloud_provider_aoc", "aws_pci_attestation"]
      : ["physical_security_assessment", "badge_logs"],
    remediation: isCloudOnly
      ? "Maintain copies of cloud provider's PCI Attestation of Compliance (AoC) on file"
      : "Document physical security for any office where CDE assets reside",
    priority: "medium",
  });

  // Requirement 10 — Logging & monitoring
  evaluations.push({
    control_id: "10.2.1",
    title: "Audit logs for all system components",
    category: "Logging",
    status: hasMonitoring ? "partial" : "not_met",
    evidence_needed: ["log_config", "siem_inventory", "log_sources_list"],
    remediation: hasMonitoring
      ? "Confirm 100% of CDE components log to central SIEM with required fields"
      : "Deploy SIEM (Datadog, Splunk, Elastic) and forward logs from all CDE components",
    priority: "critical",
  });
  evaluations.push({
    control_id: "10.4.1",
    title: "Daily log review",
    category: "Logging",
    status: hasMonitoring ? "partial" : "not_met",
    evidence_needed: ["log_review_procedures", "review_records", "alert_runbooks"],
    remediation: "Implement automated alerting on security events and document daily review process",
    priority: "critical",
  });
  evaluations.push({
    control_id: "10.5.1",
    title: "12 months of audit log retention",
    category: "Logging",
    status: hasMonitoring ? "partial" : "not_met",
    evidence_needed: ["retention_config", "retention_policy"],
    remediation: "Configure log aggregator for 12-month retention with last 3 months hot",
    priority: "high",
  });

  // Requirement 11 — Testing
  evaluations.push({
    control_id: "11.3.1",
    title: "Internal vulnerability scans quarterly",
    category: "Security Testing",
    status: profile.has_pentest ? "partial" : "not_met",
    evidence_needed: ["scan_records", "remediation_records"],
    remediation: "Run AgentAegis vuln_scan_network internally on quarterly cadence; document findings and fixes",
    priority: "critical",
  });
  evaluations.push({
    control_id: "11.3.2",
    title: "External vulnerability scans quarterly (ASV)",
    category: "Security Testing",
    status: "not_met",
    evidence_needed: ["asv_scan_records", "asv_invoice"],
    remediation: "Engage an Approved Scanning Vendor (Trustwave, Qualys, Tenable) for quarterly ASV scans — required by PCI",
    priority: "critical",
  });
  evaluations.push({
    control_id: "11.4.1",
    title: "Penetration testing annually",
    category: "Security Testing",
    status: profile.has_pentest ? "met" : "not_met",
    evidence_needed: ["pentest_reports", "remediation_records"],
    remediation: "Schedule annual external pentest, plus after any significant change to the CDE",
    priority: "critical",
  });

  // Requirement 12 — Policies and program
  evaluations.push({
    control_id: "12.1.1",
    title: "Information security policy",
    category: "Program",
    status: profile.has_security_team ? "partial" : "not_met",
    evidence_needed: ["security_policy", "review_records", "approval_signatures"],
    remediation: "Generate via AgentAegis policy_generate, get exec approval, review annually",
    priority: "critical",
  });
  evaluations.push({
    control_id: "12.3.1",
    title: "Risk assessment process",
    category: "Program",
    status: profile.has_security_team ? "partial" : "not_met",
    evidence_needed: ["risk_assessment_process", "assessment_records", "risk_register"],
    remediation: "Document risk methodology and conduct annual risk assessment",
    priority: "critical",
  });
  evaluations.push({
    control_id: "12.10.1",
    title: "Incident response plan tested annually",
    category: "Program",
    status: profile.has_security_team ? "partial" : "not_met",
    evidence_needed: ["incident_response_plan", "tabletop_test_records"],
    remediation: "Generate IRP via AgentAegis policy_generate; conduct annual tabletop exercise",
    priority: "critical",
  });

  return evaluations;
}

export async function complianceFrameworkCheck(input: ComplianceFrameworkCheckInput) {
  const { framework, organization_profile } = input;

  let evaluations: ControlEvaluation[];

  switch (framework) {
    case "soc2":
      evaluations = evaluateSOC2Controls(organization_profile);
      break;
    case "pci_dss":
      evaluations = evaluatePCIDSSControls(organization_profile);
      break;
    default:
      // For other frameworks in Phase 1, use a simplified evaluation
      evaluations = evaluateSOC2Controls(organization_profile).map((e) => ({
        ...e,
        control_id: `${framework.toUpperCase()}-${e.control_id}`,
      }));
  }

  const met = evaluations.filter((e) => e.status === "met").length;
  const partial = evaluations.filter((e) => e.status === "partial").length;
  const notMet = evaluations.filter((e) => e.status === "not_met").length;
  const readinessScore = calculateComplianceScore(evaluations.length, met, partial);

  return {
    framework,
    organization: organization_profile,
    readiness_score: readinessScore,
    summary: {
      total_controls: evaluations.length,
      met,
      partial,
      not_met: notMet,
      not_applicable: evaluations.filter((e) => e.status === "not_applicable").length,
    },
    critical_gaps: evaluations
      .filter((e) => e.status === "not_met" && e.priority === "critical")
      .map((e) => ({
        control_id: e.control_id,
        title: e.title,
        remediation: e.remediation,
      })),
    evaluations,
    recommendations: [
      readinessScore < 50 ? "Significant gaps exist. Recommend engaging a compliance consultant." : null,
      !hasToolCategory(organization_profile.tools_in_use, IDENTITY_PROVIDERS)
        ? "Implement a centralized identity provider as a foundational control."
        : null,
      !organization_profile.has_security_team
        ? "Designate a security-responsible individual or hire a security engineer."
        : null,
    ].filter(Boolean),
  };
}
