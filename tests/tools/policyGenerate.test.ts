import { describe, it, expect } from "vitest";
import { policyGenerate } from "../../src/tools/compliance/policyGenerate.js";

describe("policyGenerate", () => {
  it("generates incident response policy with required sections", async () => {
    const result = await policyGenerate({
      policy_type: "incident_response",
      organization_name: "Acme Corp",
      industry: "saas",
      employee_count: 50,
      frameworks: ["soc2"],
    });

    expect(result.title).toContain("Acme Corp");
    expect(result.title).toContain("Incident Response");
    expect(result.sections).toBeDefined();
    expect(result.sections.length).toBeGreaterThan(5);
    expect(result.metadata.policy_type).toBe("incident_response");
  });

  it("tailors content based on industry (healthcare → HIPAA notification)", async () => {
    const result = await policyGenerate({
      policy_type: "incident_response",
      organization_name: "MedCare",
      industry: "healthcare",
      employee_count: 100,
      frameworks: ["hipaa"],
    });

    const allText = JSON.stringify(result.sections);
    expect(allText).toContain("HIPAA");
  });

  it("generates remote work policy for distributed orgs", async () => {
    const result = await policyGenerate({
      policy_type: "remote_work",
      organization_name: "DistributedCo",
      industry: "tech",
      employee_count: 200,
      frameworks: ["soc2"],
      customizations: { remote_workforce: true },
    });

    expect(result.title).toContain("Remote Work");
    expect(result.sections.length).toBeGreaterThan(3);
  });
});
