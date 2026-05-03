import { describe, it, expect } from "vitest";
import { vulnPrioritize } from "../../src/tools/vulnManagement/vulnPrioritize.js";

describe("vulnPrioritize", () => {
  it("ranks high CVSS findings above low ones", async () => {
    const result = await vulnPrioritize({
      findings: [
        { description: "Low severity issue", cvss_score: 3.0, affected_system: "web1" },
        { description: "Critical RCE", cvss_score: 9.8, affected_system: "web2" },
        { description: "Medium issue", cvss_score: 5.5, affected_system: "web3" },
      ],
      business_context: {
        internet_facing: true,
        handles_sensitive_data: true,
        business_criticality: "high",
      },
    });

    expect(result.prioritized_findings[0].cvss_score).toBe(9.8);
    expect(result.prioritized_findings[2].cvss_score).toBe(3.0);
  });

  it("provides risk distribution", async () => {
    const result = await vulnPrioritize({
      findings: [
        { description: "Critical", cvss_score: 9.5, affected_system: "s1" },
        { description: "High", cvss_score: 7.5, affected_system: "s2" },
        { description: "Medium", cvss_score: 5.0, affected_system: "s3" },
        { description: "Low", cvss_score: 2.0, affected_system: "s4" },
      ],
      business_context: {
        internet_facing: true,
        handles_sensitive_data: true,
        business_criticality: "critical",
      },
    });

    expect(result.risk_distribution).toBeDefined();
    expect(result.total_findings).toBe(4);
  });

  it("groups remediation actions", async () => {
    const result = await vulnPrioritize({
      findings: [
        { description: "Issue 1", cvss_score: 7.0, affected_system: "web1", cve_id: "CVE-2024-001", service_version: "nginx 1.18" },
        { description: "Issue 2", cvss_score: 7.0, affected_system: "web2", cve_id: "CVE-2024-001", service_version: "nginx 1.18" },
      ],
      business_context: {
        internet_facing: true,
        handles_sensitive_data: false,
        business_criticality: "medium",
      },
    });

    expect(result.top_actions).toBeDefined();
    expect(result.top_actions.length).toBeGreaterThan(0);
  });
});
