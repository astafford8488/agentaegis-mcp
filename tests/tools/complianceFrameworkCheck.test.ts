import { describe, it, expect } from "vitest";
import { complianceFrameworkCheck } from "../../src/tools/compliance/complianceFrameworkCheck.js";

describe("complianceFrameworkCheck", () => {
  it("scores well-tooled SaaS company higher than greenfield", async () => {
    const wellEquipped = await complianceFrameworkCheck({
      framework: "soc2",
      organization_profile: {
        industry: "saas",
        employee_count: 50,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: false,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: true,
        has_security_team: true,
        tools_in_use: ["okta", "datadog", "github", "crowdstrike", "aws backup"],
      },
    });

    const greenfield = await complianceFrameworkCheck({
      framework: "soc2",
      organization_profile: {
        industry: "saas",
        employee_count: 5,
        handles_pii: false,
        handles_phi: false,
        handles_payment_cards: false,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: false,
        has_security_team: false,
        tools_in_use: [],
      },
    });

    expect(wellEquipped.readiness_score).toBeGreaterThan(greenfield.readiness_score);
  });

  it("identifies critical gaps", async () => {
    const result = await complianceFrameworkCheck({
      framework: "soc2",
      organization_profile: {
        industry: "saas",
        employee_count: 10,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: false,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: false,
        has_security_team: false,
        tools_in_use: [],
      },
    });

    expect(result.critical_gaps.length).toBeGreaterThan(0);
    expect(result.summary.not_met).toBeGreaterThan(0);
  });

  it("returns evaluations for every input control", async () => {
    const result = await complianceFrameworkCheck({
      framework: "soc2",
      organization_profile: {
        industry: "saas",
        employee_count: 50,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: false,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: true,
        has_security_team: true,
        tools_in_use: ["okta", "datadog"],
      },
    });

    expect(result.evaluations.length).toBeGreaterThan(0);
    for (const evalItem of result.evaluations) {
      expect(evalItem.control_id).toBeDefined();
      expect(evalItem.status).toMatch(/^(met|partial|not_met|not_applicable)$/);
    }
  });
});
