import { describe, it, expect } from "vitest";
import { cvssToSeverity, severityToScore, calculateRiskScore, calculateComplianceScore } from "../../src/utils/scoring.js";

describe("cvssToSeverity", () => {
  it("maps to critical for 9.0+", () => {
    expect(cvssToSeverity(9.0)).toBe("critical");
    expect(cvssToSeverity(10.0)).toBe("critical");
    expect(cvssToSeverity(9.5)).toBe("critical");
  });

  it("maps to high for 7.0-8.9", () => {
    expect(cvssToSeverity(7.0)).toBe("high");
    expect(cvssToSeverity(8.9)).toBe("high");
  });

  it("maps to medium for 4.0-6.9", () => {
    expect(cvssToSeverity(4.0)).toBe("medium");
    expect(cvssToSeverity(6.9)).toBe("medium");
  });

  it("maps to low for 0.1-3.9", () => {
    expect(cvssToSeverity(0.1)).toBe("low");
    expect(cvssToSeverity(3.9)).toBe("low");
  });

  it("maps to info for 0", () => {
    expect(cvssToSeverity(0)).toBe("info");
  });
});

describe("calculateRiskScore", () => {
  it("amplifies risk for internet-facing critical systems", () => {
    const score = calculateRiskScore(7.5, 0.8, {
      internet_facing: true,
      handles_sensitive_data: true,
      business_criticality: "critical",
    });
    expect(score).toBeGreaterThan(7.5);
  });

  it("reduces risk for internal low-criticality systems", () => {
    const score = calculateRiskScore(7.5, 0.1, {
      internet_facing: false,
      handles_sensitive_data: false,
      business_criticality: "low",
    });
    expect(score).toBeLessThan(7.5);
  });

  it("caps at 10", () => {
    const score = calculateRiskScore(10.0, 1.0, {
      internet_facing: true,
      handles_sensitive_data: true,
      business_criticality: "critical",
    });
    expect(score).toBeLessThanOrEqual(10);
  });
});

describe("calculateComplianceScore", () => {
  it("returns 100 for all met", () => {
    expect(calculateComplianceScore(10, 10, 0)).toBe(100);
  });

  it("returns 0 for none met", () => {
    expect(calculateComplianceScore(10, 0, 0)).toBe(0);
  });

  it("counts partial as half", () => {
    expect(calculateComplianceScore(10, 0, 10)).toBe(50);
  });

  it("blends met and partial", () => {
    expect(calculateComplianceScore(10, 5, 4)).toBe(70);
  });
});
