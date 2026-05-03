import { z } from "zod";

export const evidenceCollectSchema = z.object({
  framework: z.enum(["soc2", "iso27001", "hipaa", "pci_dss", "nist_csf"]),
  control_ids: z.array(z.string()),
  integrations: z.object({
    aws_account_id: z.string().optional(),
    github_org: z.string().optional(),
    okta_domain: z.string().optional(),
  }).optional(),
});

export type EvidenceCollectInput = z.infer<typeof evidenceCollectSchema>;

interface EvidencePlan {
  control_id: string;
  evidence_items: {
    type: string;
    description: string;
    collection_method: "manual" | "automated" | "api_pull";
    format: string;
    sufficiency_criteria: string[];
    instructions: string;
  }[];
}

const EVIDENCE_CATALOG: Record<string, { type: string; description: string; format: string; collection_method: "manual" | "automated" | "api_pull"; sufficiency_criteria: string[]; instructions: string }[]> = {
  "CC6.1": [
    {
      type: "iam_config",
      description: "Identity provider configuration showing access controls",
      format: "Screenshot or config export (JSON/YAML)",
      collection_method: "manual",
      sufficiency_criteria: [
        "Shows centralized identity management is in place",
        "Demonstrates role-based access control configuration",
        "Shows MFA enforcement settings",
      ],
      instructions: "Export your IdP configuration showing: user directory, role assignments, MFA policy, and conditional access rules. For Okta: Admin > Security > General. For Azure AD: Portal > Azure Active Directory > Security.",
    },
    {
      type: "access_control_policy",
      description: "Documented access control policy",
      format: "PDF or Word document",
      collection_method: "manual",
      sufficiency_criteria: [
        "Defines access request/approval process",
        "Specifies principle of least privilege",
        "Includes periodic review requirements",
      ],
      instructions: "Provide your access control policy document. It should cover: who can request access, approval workflows, role definitions, and review frequency.",
    },
    {
      type: "user_access_review",
      description: "Evidence of periodic user access reviews",
      format: "Spreadsheet or tool export showing review completion",
      collection_method: "manual",
      sufficiency_criteria: [
        "Shows reviews conducted at least quarterly",
        "Includes reviewer sign-off",
        "Documents any access removed/modified",
      ],
      instructions: "Provide records of your most recent user access review. Should include: list of users reviewed, reviewer name, date, and any changes made.",
    },
  ],
  "CC7.1": [
    {
      type: "monitoring_config",
      description: "Security monitoring and alerting configuration",
      format: "Screenshots or config export",
      collection_method: "manual",
      sufficiency_criteria: [
        "Shows active security monitoring is in place",
        "Demonstrates alert rules for security events",
        "Shows log retention configuration",
      ],
      instructions: "Export your SIEM/monitoring configuration showing: active alert rules, log sources configured, retention period, and escalation paths.",
    },
    {
      type: "alert_policies",
      description: "Documented alerting policies and thresholds",
      format: "Document or tool export",
      collection_method: "manual",
      sufficiency_criteria: [
        "Defines what constitutes a security event",
        "Specifies response SLAs",
        "Includes escalation procedures",
      ],
      instructions: "Provide documentation of your alerting policies including: alert categories, severity levels, response timeframes, and on-call procedures.",
    },
  ],
  "CC7.2": [
    {
      type: "incident_response_plan",
      description: "Documented incident response plan",
      format: "PDF or Word document",
      collection_method: "manual",
      sufficiency_criteria: [
        "Defines incident classification levels",
        "Specifies roles and responsibilities",
        "Includes communication procedures",
        "Covers containment, eradication, recovery steps",
      ],
      instructions: "Provide your incident response plan. Should include: incident classifications (P1-P4), response team roles, communication templates, containment procedures, and post-incident review process.",
    },
    {
      type: "incident_records",
      description: "Records of past security incidents and responses",
      format: "Incident tracker export or postmortem documents",
      collection_method: "manual",
      sufficiency_criteria: [
        "Shows incidents are tracked and documented",
        "Demonstrates response procedures were followed",
        "Includes root cause analysis",
      ],
      instructions: "Provide records of security incidents from the past 12 months (or confirmation of no incidents). Include: date, classification, response actions, resolution, and lessons learned.",
    },
  ],
  "CC8.1": [
    {
      type: "change_management_policy",
      description: "Change management process documentation",
      format: "PDF or Word document",
      collection_method: "manual",
      sufficiency_criteria: [
        "Defines change request process",
        "Specifies approval requirements",
        "Includes testing/rollback procedures",
      ],
      instructions: "Provide your change management policy covering: change classification, approval matrix, testing requirements, rollback procedures, and emergency change process.",
    },
    {
      type: "code_review_records",
      description: "Evidence of code review and approval before deployment",
      format: "Screenshots of PR reviews or CI/CD logs",
      collection_method: "automated",
      sufficiency_criteria: [
        "Shows peer review is required",
        "Demonstrates approval before merge/deploy",
        "Shows automated testing in pipeline",
      ],
      instructions: "Export from GitHub/GitLab showing: branch protection rules requiring reviews, sample merged PRs with reviewer approval, and CI/CD pipeline configuration.",
    },
  ],
  "CC3.1": [
    {
      type: "risk_assessment_report",
      description: "Annual risk assessment results",
      format: "PDF report",
      collection_method: "manual",
      sufficiency_criteria: [
        "Conducted within last 12 months",
        "Covers key risk areas (technical, operational, compliance)",
        "Includes risk ratings and treatment plans",
      ],
      instructions: "Provide your most recent risk assessment. Should include: methodology used, risks identified, likelihood/impact ratings, current controls, and remediation plans.",
    },
  ],
};

export async function evidenceCollect(input: EvidenceCollectInput) {
  const plans: EvidencePlan[] = [];

  for (const controlId of input.control_ids) {
    const evidenceItems = EVIDENCE_CATALOG[controlId];

    if (evidenceItems) {
      plans.push({
        control_id: controlId,
        evidence_items: evidenceItems,
      });
    } else {
      plans.push({
        control_id: controlId,
        evidence_items: [{
          type: "general_evidence",
          description: `Evidence demonstrating compliance with ${controlId}`,
          format: "Document, screenshot, or configuration export",
          collection_method: "manual",
          sufficiency_criteria: [
            "Demonstrates the control is implemented",
            "Shows the control is operating effectively",
            "Covers the audit period",
          ],
          instructions: `Provide documentation showing how your organization meets the requirements of ${controlId}. This may include policies, configurations, logs, or third-party attestations.`,
        }],
      });
    }
  }

  const integrationStatus = input.integrations ? {
    aws: input.integrations.aws_account_id ? "configured" : "not_configured",
    github: input.integrations.github_org ? "configured" : "not_configured",
    okta: input.integrations.okta_domain ? "configured" : "not_configured",
    note: "Phase 1: Evidence collection plans are provided. Automated collection via integrations available in Phase 2.",
  } : { note: "No integrations configured. All evidence collection will be manual." };

  return {
    framework: input.framework,
    evidence_plans: plans,
    total_evidence_items: plans.reduce((sum, p) => sum + p.evidence_items.length, 0),
    collection_summary: {
      manual: plans.flatMap((p) => p.evidence_items).filter((e) => e.collection_method === "manual").length,
      automated: plans.flatMap((p) => p.evidence_items).filter((e) => e.collection_method === "automated").length,
      api_pull: plans.flatMap((p) => p.evidence_items).filter((e) => e.collection_method === "api_pull").length,
    },
    integration_status: integrationStatus,
  };
}
