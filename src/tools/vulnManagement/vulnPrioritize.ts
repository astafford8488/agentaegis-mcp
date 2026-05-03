import { z } from "zod";
import { calculateRiskScore } from "../../utils/scoring.js";

export const vulnPrioritizeSchema = z.object({
  findings: z.array(z.object({
    cve_id: z.string().optional(),
    description: z.string(),
    cvss_score: z.number().optional(),
    affected_system: z.string(),
    service_version: z.string().optional(),
  })),
  business_context: z.object({
    internet_facing: z.boolean(),
    handles_sensitive_data: z.boolean(),
    business_criticality: z.enum(["low", "medium", "high", "critical"]),
  }).optional(),
});

export type VulnPrioritizeInput = z.infer<typeof vulnPrioritizeSchema>;

async function getEPSSScore(cveId: string): Promise<number> {
  try {
    const response = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`);
    if (!response.ok) return 0;
    const data = await response.json();
    return parseFloat(data.data?.[0]?.epss || "0");
  } catch {
    return 0;
  }
}

export async function vulnPrioritize(input: VulnPrioritizeInput) {
  const { findings, business_context } = input;
  const context = business_context || { internet_facing: true, handles_sensitive_data: true, business_criticality: "high" as const };

  const prioritized = await Promise.all(
    findings.map(async (finding) => {
      const epss = finding.cve_id ? await getEPSSScore(finding.cve_id) : 0;
      const cvss = finding.cvss_score || 5.0;
      const riskScore = calculateRiskScore(cvss, epss, context);

      return {
        ...finding,
        epss_score: epss,
        epss_percentile: Math.round(epss * 100),
        adjusted_risk_score: riskScore,
        exploitation_likelihood: epss > 0.5 ? "very_high" : epss > 0.1 ? "high" : epss > 0.01 ? "medium" : "low",
        remediation_effort: cvss >= 9 ? "immediate" : cvss >= 7 ? "high_priority" : cvss >= 4 ? "scheduled" : "backlog",
        fix_recommendation: generateFixRecommendation(finding),
      };
    })
  );

  // Sort by adjusted risk score descending
  prioritized.sort((a, b) => b.adjusted_risk_score - a.adjusted_risk_score);

  // Group by remediation action
  const remediationGroups = groupByRemediation(prioritized);

  return {
    prioritized_findings: prioritized,
    total_findings: prioritized.length,
    risk_distribution: {
      critical: prioritized.filter((f) => f.adjusted_risk_score >= 9).length,
      high: prioritized.filter((f) => f.adjusted_risk_score >= 7 && f.adjusted_risk_score < 9).length,
      medium: prioritized.filter((f) => f.adjusted_risk_score >= 4 && f.adjusted_risk_score < 7).length,
      low: prioritized.filter((f) => f.adjusted_risk_score < 4).length,
    },
    top_actions: remediationGroups.slice(0, 5),
    recommendation: prioritized.length > 0
      ? `Focus on the top ${Math.min(3, prioritized.length)} findings first. ${prioritized.filter((f) => f.exploitation_likelihood === "very_high" || f.exploitation_likelihood === "high").length} findings have active exploitation in the wild.`
      : "No findings to prioritize.",
  };
}

function generateFixRecommendation(finding: { cve_id?: string; description: string; service_version?: string; affected_system: string }): string {
  if (finding.cve_id && finding.service_version) {
    return `Patch ${finding.affected_system} — upgrade the service from ${finding.service_version} to the latest patched version that addresses ${finding.cve_id}`;
  }
  if (finding.cve_id) {
    return `Apply vendor patch for ${finding.cve_id} on ${finding.affected_system}`;
  }
  return `Review and remediate: ${finding.description.slice(0, 100)}`;
}

function groupByRemediation(findings: any[]): { action: string; affected_systems: string[]; finding_count: number; max_risk: number }[] {
  const groups = new Map<string, { systems: Set<string>; count: number; maxRisk: number }>();

  for (const f of findings) {
    const key = f.fix_recommendation;
    const existing = groups.get(key) || { systems: new Set(), count: 0, maxRisk: 0 };
    existing.systems.add(f.affected_system);
    existing.count++;
    existing.maxRisk = Math.max(existing.maxRisk, f.adjusted_risk_score);
    groups.set(key, existing);
  }

  return Array.from(groups.entries())
    .map(([action, data]) => ({
      action,
      affected_systems: Array.from(data.systems),
      finding_count: data.count,
      max_risk: data.maxRisk,
    }))
    .sort((a, b) => b.max_risk - a.max_risk);
}
