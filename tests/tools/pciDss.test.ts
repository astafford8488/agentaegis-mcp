import { describe, it, expect } from "vitest";
import { complianceFrameworkCheck } from "../../src/tools/compliance/complianceFrameworkCheck.js";

describe("complianceFrameworkCheck — PCI DSS", () => {
  it("returns N/A for orgs that don't handle payment cards", async () => {
    const result = await complianceFrameworkCheck({
      framework: "pci_dss",
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

    expect(result.summary.not_applicable).toBeGreaterThan(0);
  });

  it("identifies critical gaps for a fintech without tokenization", async () => {
    const result = await complianceFrameworkCheck({
      framework: "pci_dss",
      organization_profile: {
        industry: "fintech",
        employee_count: 50,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: true,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: false,
        has_security_team: true,
        tools_in_use: ["okta", "github", "datadog"],
      },
    });

    expect(result.critical_gaps.length).toBeGreaterThan(0);
    expect(result.evaluations.some((e) => e.control_id.startsWith("3."))).toBe(true);
    expect(result.evaluations.some((e) => e.control_id.startsWith("11."))).toBe(true);
  });

  it("scores well-tooled fintech higher than greenfield", async () => {
    const wellEquipped = await complianceFrameworkCheck({
      framework: "pci_dss",
      organization_profile: {
        industry: "fintech",
        employee_count: 50,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: true,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: true,
        has_security_team: true,
        tools_in_use: ["okta", "github", "datadog", "crowdstrike", "stripe"],
      },
    });

    const greenfield = await complianceFrameworkCheck({
      framework: "pci_dss",
      organization_profile: {
        industry: "fintech",
        employee_count: 5,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: true,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: false,
        has_security_team: false,
        tools_in_use: [],
      },
    });

    expect(wellEquipped.readiness_score).toBeGreaterThan(greenfield.readiness_score);
  });

  it("includes ASV scan requirement (11.3.2) as critical not_met", async () => {
    const result = await complianceFrameworkCheck({
      framework: "pci_dss",
      organization_profile: {
        industry: "fintech",
        employee_count: 50,
        handles_pii: true,
        handles_phi: false,
        handles_payment_cards: true,
        cloud_providers: ["aws"],
        has_soc_report: false,
        has_pentest: true,
        has_security_team: true,
        tools_in_use: ["okta", "github", "datadog", "stripe"],
      },
    });

    const asvControl = result.evaluations.find((e) => e.control_id === "11.3.2");
    expect(asvControl?.status).toBe("not_met");
    expect(asvControl?.priority).toBe("critical");
  });
});
