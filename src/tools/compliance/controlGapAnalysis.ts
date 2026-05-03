import { z } from "zod";

export const controlGapAnalysisSchema = z.object({
  framework: z.enum(["soc2", "iso27001", "hipaa", "pci_dss", "nist_csf"]),
  failing_controls: z.array(z.object({
    control_id: z.string(),
    current_state: z.string(),
  })),
  budget_constraint: z.enum(["low", "medium", "high"]).optional(),
  timeline_constraint: z.enum(["30_days", "90_days", "6_months", "12_months"]).optional(),
});

export type ControlGapAnalysisInput = z.infer<typeof controlGapAnalysisSchema>;

interface RemediationItem {
  control_id: string;
  severity_rank: number;
  effort_hours: number;
  cost_estimate: { low: number; high: number };
  tool_recommendations: { name: string; cost: string; open_source_alt?: string }[];
  implementation_steps: string[];
  dependencies: string[];
  quick_win: boolean;
}

const REMEDIATION_PLAYBOOK: Record<string, Omit<RemediationItem, "control_id" | "severity_rank">> = {
  "CC6.1": {
    effort_hours: 40,
    cost_estimate: { low: 500, high: 5000 },
    tool_recommendations: [
      { name: "Okta", cost: "$6/user/month", open_source_alt: "Keycloak" },
      { name: "Azure AD", cost: "$6/user/month", open_source_alt: "FreeIPA" },
      { name: "Duo MFA", cost: "$3/user/month", open_source_alt: "Google Authenticator (free)" },
    ],
    implementation_steps: [
      "Select and provision identity provider",
      "Configure SSO for all critical applications",
      "Define role hierarchy and role-based access policies",
      "Enable MFA for all users (hardware keys for admins)",
      "Configure conditional access policies",
      "Document access request/approval workflow",
      "Conduct initial access review",
    ],
    dependencies: [],
    quick_win: false,
  },
  "CC7.1": {
    effort_hours: 60,
    cost_estimate: { low: 1000, high: 10000 },
    tool_recommendations: [
      { name: "Datadog", cost: "$15/host/month", open_source_alt: "ELK Stack" },
      { name: "Splunk", cost: "$150/GB/day", open_source_alt: "Graylog" },
      { name: "CrowdStrike Falcon", cost: "$8/endpoint/month", open_source_alt: "OSSEC/Wazuh" },
    ],
    implementation_steps: [
      "Deploy log aggregation solution",
      "Configure log shipping from all critical systems",
      "Define security alert rules (failed logins, privilege escalation, etc.)",
      "Set up on-call rotation and escalation paths",
      "Configure log retention (minimum 90 days, recommended 365)",
      "Test alerting with simulated security events",
      "Document monitoring procedures and response playbooks",
    ],
    dependencies: [],
    quick_win: false,
  },
  "CC7.2": {
    effort_hours: 20,
    cost_estimate: { low: 0, high: 2000 },
    tool_recommendations: [
      { name: "PagerDuty", cost: "$21/user/month", open_source_alt: "Grafana OnCall" },
      { name: "Jira (incident tracking)", cost: "$7.75/user/month" },
    ],
    implementation_steps: [
      "Draft incident response plan (use template from AgentAegis policy_generate tool)",
      "Define incident severity levels (P1-P4)",
      "Assign incident response roles",
      "Create communication templates (internal, customer, regulatory)",
      "Conduct tabletop exercise",
      "Set up incident tracking system",
    ],
    dependencies: ["CC7.1"],
    quick_win: true,
  },
  "CC8.1": {
    effort_hours: 30,
    cost_estimate: { low: 0, high: 1000 },
    tool_recommendations: [
      { name: "GitHub (branch protection)", cost: "$4/user/month for Teams" },
      { name: "GitLab", cost: "$29/user/month for Premium", open_source_alt: "Gitea" },
    ],
    implementation_steps: [
      "Enable branch protection on main/production branches",
      "Require code review approval before merge",
      "Configure CI pipeline with automated tests",
      "Document change management process",
      "Define emergency change procedure",
      "Implement deployment approval gates for production",
    ],
    dependencies: [],
    quick_win: true,
  },
  "CC3.1": {
    effort_hours: 24,
    cost_estimate: { low: 0, high: 5000 },
    tool_recommendations: [
      { name: "Risk assessment template", cost: "Free" },
      { name: "Penetration testing (external)", cost: "$5,000-$25,000/engagement" },
    ],
    implementation_steps: [
      "Define risk assessment methodology",
      "Identify assets and data flows",
      "Assess threats and vulnerabilities",
      "Rate risks by likelihood and impact",
      "Document risk treatment decisions (accept, mitigate, transfer, avoid)",
      "Create risk register and assign owners",
      "Schedule annual reassessment",
    ],
    dependencies: [],
    quick_win: false,
  },
};

export async function controlGapAnalysis(input: ControlGapAnalysisInput) {
  const budgetMultiplier = { low: 0.5, medium: 1.0, high: 2.0 }[input.budget_constraint || "medium"];
  const timelineDays = { "30_days": 30, "90_days": 90, "6_months": 180, "12_months": 365 }[input.timeline_constraint || "6_months"];

  const remediationPlan: RemediationItem[] = input.failing_controls.map((fc, index) => {
    const playbook = REMEDIATION_PLAYBOOK[fc.control_id];

    if (playbook) {
      return {
        control_id: fc.control_id,
        severity_rank: index + 1,
        ...playbook,
      };
    }

    return {
      control_id: fc.control_id,
      severity_rank: index + 1,
      effort_hours: 20,
      cost_estimate: { low: 500, high: 5000 },
      tool_recommendations: [],
      implementation_steps: [
        `Assess current state: "${fc.current_state}"`,
        "Identify specific gaps against control requirements",
        "Select appropriate tools or processes to fill gaps",
        "Implement controls",
        "Document evidence of implementation",
        "Test control effectiveness",
      ],
      dependencies: [],
      quick_win: false,
    };
  });

  // Sort by severity rank and filter by budget/timeline
  remediationPlan.sort((a, b) => a.severity_rank - b.severity_rank);

  const totalEffort = remediationPlan.reduce((sum, r) => sum + r.effort_hours, 0);
  const totalCostLow = remediationPlan.reduce((sum, r) => sum + r.cost_estimate.low, 0);
  const totalCostHigh = remediationPlan.reduce((sum, r) => sum + r.cost_estimate.high, 0);

  const quickWins = remediationPlan.filter((r) => r.quick_win);
  const feasibleInTimeline = remediationPlan.filter((r) => {
    const daysNeeded = (r.effort_hours / 8) * 2; // Assume 50% allocation
    return daysNeeded <= timelineDays;
  });

  return {
    framework: input.framework,
    total_gaps: input.failing_controls.length,
    remediation_roadmap: remediationPlan,
    summary: {
      total_effort_hours: totalEffort,
      estimated_cost: { low: totalCostLow, high: totalCostHigh },
      quick_wins: quickWins.length,
      feasible_in_timeline: feasibleInTimeline.length,
    },
    recommended_sequence: [
      ...quickWins.map((q) => `[QUICK WIN] ${q.control_id}`),
      ...remediationPlan.filter((r) => !r.quick_win).map((r) => r.control_id),
    ],
    budget_fit: totalCostHigh * budgetMultiplier <= totalCostHigh
      ? "within_budget"
      : "may_exceed_budget",
    timeline_fit: totalEffort / 8 <= timelineDays * 0.5
      ? "achievable"
      : "aggressive_timeline",
  };
}
