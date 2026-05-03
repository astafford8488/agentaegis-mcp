import type { Severity } from "../types/security.js";

export function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score >= 0.1) return "low";
  return "info";
}

export function severityToScore(severity: Severity): number {
  switch (severity) {
    case "critical": return 10;
    case "high": return 8;
    case "medium": return 5;
    case "low": return 2;
    case "info": return 0;
  }
}

export function calculateRiskScore(
  cvss: number,
  epss: number,
  businessContext: {
    internet_facing: boolean;
    handles_sensitive_data: boolean;
    business_criticality: "low" | "medium" | "high" | "critical";
  }
): number {
  const criticalityMultiplier = {
    low: 0.5,
    medium: 1.0,
    high: 1.5,
    critical: 2.0,
  };

  let score = cvss * 0.4 + epss * 10 * 0.3;

  if (businessContext.internet_facing) score *= 1.3;
  if (businessContext.handles_sensitive_data) score *= 1.2;
  score *= criticalityMultiplier[businessContext.business_criticality];

  return Math.min(10, Math.round(score * 10) / 10);
}

export function calculateComplianceScore(
  totalControls: number,
  metControls: number,
  partialControls: number
): number {
  const score = ((metControls + partialControls * 0.5) / totalControls) * 100;
  return Math.round(score);
}
