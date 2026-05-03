import { z } from "zod";
import type { ControlStatus } from "../../types/security.js";
import { calculateComplianceScore } from "../../utils/scoring.js";

export const auditReportGenerateSchema = z.object({
  framework: z.enum(["soc2", "iso27001", "hipaa", "pci_dss", "nist_csf"]),
  assessment_results: z.array(z.object({
    control_id: z.string(),
    status: z.enum(["met", "partial", "not_met", "not_applicable"]),
    evidence_ref: z.string().optional(),
    notes: z.string().optional(),
  })),
  organization_name: z.string(),
  report_date: z.string(),
  report_type: z.enum(["internal", "board", "auditor", "regulator"]),
});

export type AuditReportGenerateInput = z.infer<typeof auditReportGenerateSchema>;

export async function auditReportGenerate(input: AuditReportGenerateInput) {
  const { framework, assessment_results, organization_name, report_date, report_type } = input;

  const total = assessment_results.length;
  const met = assessment_results.filter((r) => r.status === "met").length;
  const partial = assessment_results.filter((r) => r.status === "partial").length;
  const notMet = assessment_results.filter((r) => r.status === "not_met").length;
  const na = assessment_results.filter((r) => r.status === "not_applicable").length;
  const score = calculateComplianceScore(total - na, met, partial);

  const criticalFindings = assessment_results.filter((r) => r.status === "not_met");
  const partialFindings = assessment_results.filter((r) => r.status === "partial");

  const frameworkNames: Record<string, string> = {
    soc2: "SOC 2 Type II",
    iso27001: "ISO 27001:2022",
    hipaa: "HIPAA Security Rule",
    pci_dss: "PCI DSS v4.0",
    nist_csf: "NIST Cybersecurity Framework 2.0",
  };

  const executiveSummary = generateExecutiveSummary(report_type, {
    frameworkName: frameworkNames[framework],
    organization_name,
    score,
    total,
    met,
    partial,
    notMet,
    criticalCount: criticalFindings.length,
  });

  const findingsTable = assessment_results
    .filter((r) => r.status !== "met" && r.status !== "not_applicable")
    .sort((a, b) => {
      const order: Record<ControlStatus, number> = { not_met: 0, partial: 1, met: 2, not_applicable: 3 };
      return order[a.status] - order[b.status];
    })
    .map((r) => ({
      control_id: r.control_id,
      status: r.status,
      severity: r.status === "not_met" ? "HIGH" : "MEDIUM",
      notes: r.notes || "No additional details provided",
      evidence_ref: r.evidence_ref || "No evidence referenced",
    }));

  return {
    report_metadata: {
      title: `${frameworkNames[framework]} Compliance Assessment Report`,
      organization: organization_name,
      date: report_date,
      report_type,
      generated_by: "AgentAegis",
      framework,
    },
    executive_summary: executiveSummary,
    readiness_score: {
      percentage: score,
      rating: score >= 80 ? "Strong" : score >= 60 ? "Moderate" : score >= 40 ? "Weak" : "Critical",
      trend: "baseline",
    },
    control_summary: {
      total_controls: total,
      met,
      partial,
      not_met: notMet,
      not_applicable: na,
    },
    findings_table: findingsTable,
    detailed_assessments: assessment_results.map((r) => ({
      control_id: r.control_id,
      status: r.status,
      evidence: r.evidence_ref || null,
      notes: r.notes || null,
      action_required: r.status === "not_met" ? "Immediate remediation required"
        : r.status === "partial" ? "Additional controls or evidence needed"
        : null,
    })),
    remediation_timeline: {
      immediate: criticalFindings.slice(0, 5).map((f) => f.control_id),
      short_term_30_days: criticalFindings.slice(5).map((f) => f.control_id),
      medium_term_90_days: partialFindings.map((f) => f.control_id),
    },
    appendices: {
      methodology: `Assessment conducted against ${frameworkNames[framework]} controls. Each control evaluated as Met (fully implemented with evidence), Partial (partially implemented or evidence gaps), Not Met (not implemented), or Not Applicable.`,
      scope: `This assessment covers ${organization_name}'s information security controls as of ${report_date}.`,
      limitations: "This assessment is based on information provided and does not constitute a formal audit or certification.",
    },
  };
}

function generateExecutiveSummary(
  reportType: string,
  data: {
    frameworkName: string;
    organization_name: string;
    score: number;
    total: number;
    met: number;
    partial: number;
    notMet: number;
    criticalCount: number;
  }
) {
  const { frameworkName, organization_name, score, total, met, notMet, criticalCount } = data;

  const baseContent = {
    overview: `${organization_name} was assessed against ${frameworkName} encompassing ${total} controls. The overall readiness score is ${score}%.`,
    key_metrics: `${met} controls fully met, ${criticalCount} critical gaps identified requiring immediate attention.`,
    risk_rating: score >= 80 ? "LOW" : score >= 60 ? "MEDIUM" : score >= 40 ? "HIGH" : "CRITICAL",
  };

  switch (reportType) {
    case "board":
      return {
        ...baseContent,
        recommendation: score >= 80
          ? "The organization demonstrates strong security posture. Continue current program with focus on continuous improvement."
          : `${criticalCount} critical gaps must be addressed before audit readiness. Recommend allocating additional resources to security program.`,
      };
    case "auditor":
      return {
        ...baseContent,
        scope_statement: `Assessment of ${total} controls within the ${frameworkName} framework.`,
        opinion: score >= 80
          ? "Based on the assessment, the entity's controls are suitably designed and operating effectively."
          : "Exceptions noted in the findings section require remediation before formal audit engagement.",
      };
    case "regulator":
      return {
        ...baseContent,
        compliance_status: notMet === 0 ? "COMPLIANT" : "NON-COMPLIANT",
        corrective_actions: notMet > 0 ? `${notMet} controls require corrective action. Remediation plan included.` : "No corrective actions required.",
      };
    default:
      return baseContent;
  }
}
