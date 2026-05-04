import { z } from "zod";
import { collectGitHubEvidence } from "../../integrations/github.js";
import { collectAWSEvidence, type AWSCredentials } from "../../integrations/aws.js";
import { collectOktaEvidence } from "../../integrations/okta.js";

export const evidenceCollectSchema = z.object({
  framework: z.enum(["soc2", "iso27001", "hipaa", "pci_dss", "nist_csf"]),
  control_ids: z.array(z.string()),
  integrations: z.object({
    // GitHub
    github_org: z.string().optional(),
    github_token: z.string().optional(),

    // AWS — caller can either pass credentials directly OR list an account_id
    // and rely on the server's IAM role (if configured)
    aws_account_id: z.string().optional(),
    aws_access_key_id: z.string().optional(),
    aws_secret_access_key: z.string().optional(),
    aws_session_token: z.string().optional(),
    aws_region: z.string().optional(),

    // Okta
    okta_domain: z.string().optional(),
    okta_token: z.string().optional(),
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

  // Phase 3: actually pull evidence from configured integrations
  const collectedEvidence: Record<string, unknown> = {};
  const integrationStatus: Record<string, string> = {};
  const integrationErrors: string[] = [];

  if (input.integrations) {
    const i = input.integrations;

    // GitHub
    if (i.github_org && i.github_token) {
      try {
        collectedEvidence.github = await collectGitHubEvidence(i.github_org, i.github_token);
        integrationStatus.github = "collected";
      } catch (err) {
        integrationStatus.github = "error";
        integrationErrors.push(`github: ${String(err).slice(0, 200)}`);
      }
    } else if (i.github_org) {
      integrationStatus.github = "needs_token (provide github_token with read:org scope)";
    } else {
      integrationStatus.github = "not_configured";
    }

    // AWS
    if (i.aws_access_key_id && i.aws_secret_access_key) {
      const creds: AWSCredentials = {
        access_key_id: i.aws_access_key_id,
        secret_access_key: i.aws_secret_access_key,
        session_token: i.aws_session_token,
        region: i.aws_region,
      };
      try {
        collectedEvidence.aws = await collectAWSEvidence(creds);
        integrationStatus.aws = "collected";
      } catch (err) {
        integrationStatus.aws = "error";
        integrationErrors.push(`aws: ${String(err).slice(0, 200)}`);
      }
    } else if (i.aws_account_id) {
      integrationStatus.aws = "needs_credentials (provide aws_access_key_id + aws_secret_access_key)";
    } else {
      integrationStatus.aws = "not_configured";
    }

    // Okta
    if (i.okta_domain && i.okta_token) {
      try {
        collectedEvidence.okta = await collectOktaEvidence(i.okta_domain, i.okta_token);
        integrationStatus.okta = "collected";
      } catch (err) {
        integrationStatus.okta = "error";
        integrationErrors.push(`okta: ${String(err).slice(0, 200)}`);
      }
    } else if (i.okta_domain) {
      integrationStatus.okta = "needs_token (provide okta_token with read scopes)";
    } else {
      integrationStatus.okta = "not_configured";
    }
  }

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
    integration_errors: integrationErrors.length > 0 ? integrationErrors : undefined,
    collected_evidence: Object.keys(collectedEvidence).length > 0 ? collectedEvidence : undefined,
  };
}
