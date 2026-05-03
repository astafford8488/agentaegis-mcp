import { describe, it, expect } from "vitest";
import { mfaAudit } from "../../src/tools/identity/mfaAudit.js";

describe("mfaAudit", () => {
  it("flags admin without MFA as critical", async () => {
    const result = await mfaAudit({
      users: [
        { username: "admin1", email: "a@co.com", mfa_enabled: false, is_admin: true, is_service_account: false },
        { username: "user1", email: "u@co.com", mfa_enabled: true, mfa_method: "totp", is_admin: false, is_service_account: false },
      ],
    });

    expect(result.risk_level).toBe("CRITICAL");
    expect(result.summary.admins_without_mfa).toBe(1);
  });

  it("calculates accurate coverage percentage", async () => {
    const result = await mfaAudit({
      users: [
        { username: "u1", email: "u1@co.com", mfa_enabled: true, mfa_method: "totp", is_admin: false, is_service_account: false },
        { username: "u2", email: "u2@co.com", mfa_enabled: true, mfa_method: "totp", is_admin: false, is_service_account: false },
        { username: "u3", email: "u3@co.com", mfa_enabled: false, is_admin: false, is_service_account: false },
        { username: "u4", email: "u4@co.com", mfa_enabled: false, is_admin: false, is_service_account: false },
      ],
    });

    expect(result.summary.mfa_coverage_percent).toBe(50);
  });

  it("flags weak SMS-based MFA", async () => {
    const result = await mfaAudit({
      users: [
        { username: "u1", email: "u1@co.com", mfa_enabled: true, mfa_method: "sms", is_admin: false, is_service_account: false },
      ],
    });

    const weakFinding = result.findings.find((f) => f.description.toLowerCase().includes("weak"));
    expect(weakFinding).toBeDefined();
  });

  it("excludes service accounts from coverage calculation", async () => {
    const result = await mfaAudit({
      users: [
        { username: "human", email: "h@co.com", mfa_enabled: true, mfa_method: "totp", is_admin: false, is_service_account: false },
        { username: "service", email: "s@co.com", mfa_enabled: false, is_admin: false, is_service_account: true },
      ],
    });

    expect(result.summary.human_users).toBe(1);
    expect(result.summary.service_accounts).toBe(1);
    expect(result.summary.mfa_coverage_percent).toBe(100);
  });
});
