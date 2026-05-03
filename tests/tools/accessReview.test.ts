import { describe, it, expect } from "vitest";
import { accessReview } from "../../src/tools/identity/accessReview.js";

describe("accessReview", () => {
  it("flags terminated users with active access", async () => {
    const result = await accessReview({
      users: [
        { username: "alice", email: "alice@co.com", roles: ["user"], permissions: ["read"], employment_status: "active", last_login: new Date().toISOString() },
        { username: "bob", email: "bob@co.com", roles: ["admin"], permissions: ["all"], employment_status: "terminated" },
      ],
    });

    const orphan = result.findings.find((f) => f.type === "orphaned_account");
    expect(orphan).toBeDefined();
    expect(orphan?.affected_users).toContain("bob");
  });

  it("flags dormant accounts", async () => {
    const sixMonthsAgo = new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString();
    const result = await accessReview({
      users: [
        { username: "active_user", email: "a@co.com", roles: ["user"], permissions: ["read"], employment_status: "active", last_login: new Date().toISOString() },
        { username: "dormant_user", email: "d@co.com", roles: ["user"], permissions: ["read"], employment_status: "active", last_login: sixMonthsAgo },
      ],
    });

    const dormant = result.findings.find((f) => f.type === "dormant_account");
    expect(dormant).toBeDefined();
    expect(dormant?.affected_users).toContain("dormant_user");
  });

  it("flags excessive admin concentration", async () => {
    const users = Array.from({ length: 10 }, (_, i) => ({
      username: `user${i}`,
      email: `u${i}@co.com`,
      roles: i < 5 ? ["admin"] : ["user"],
      permissions: i < 5 ? ["all"] : ["read"],
      employment_status: "active" as const,
      last_login: new Date().toISOString(),
    }));

    const result = await accessReview({ users });
    const excessive = result.findings.find((f) => f.type === "excessive_admin");
    expect(excessive).toBeDefined();
  });

  it("returns LOW risk for well-configured tenant", async () => {
    // 19 users with 1 admin (~5%) — under the 10% threshold
    const users = Array.from({ length: 19 }, (_, i) => ({
      username: `user${i}`,
      email: `u${i}@co.com`,
      roles: ["user"],
      permissions: ["read"],
      employment_status: "active" as const,
      last_login: new Date().toISOString(),
    }));
    users.push({
      username: "admin1",
      email: "admin@co.com",
      roles: ["admin"],
      permissions: ["admin"],
      employment_status: "active" as const,
      last_login: new Date().toISOString(),
    });

    const result = await accessReview({ users });
    expect(result.risk_level).toBe("LOW");
  });
});
