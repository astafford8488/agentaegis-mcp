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

export async function complianceFrameworkCheck(input: ComplianceFrameworkCheckInput) {
  const { framework, organization_profile } = input;

  let evaluations: ControlEvaluation[];

  switch (framework) {
    case "soc2":
      evaluations = evaluateSOC2Controls(organization_profile);
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
