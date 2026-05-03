import { z } from "zod";
import type { AccessReviewFinding, Severity } from "../../types/security.js";

export const accessReviewSchema = z.object({
  users: z.array(z.object({
    username: z.string(),
    email: z.string(),
    roles: z.array(z.string()),
    permissions: z.array(z.string()),
    last_login: z.string().optional(),
    department: z.string().optional(),
    employment_status: z.enum(["active", "terminated", "contractor", "leave"]).optional(),
    created_date: z.string().optional(),
  })),
  admin_roles: z.array(z.string()).optional(),
  sensitive_permissions: z.array(z.string()).optional(),
});

export type AccessReviewInput = z.infer<typeof accessReviewSchema>;

export async function accessReview(input: AccessReviewInput) {
  const { users, admin_roles = ["admin", "administrator", "superadmin", "root", "owner"], sensitive_permissions = ["delete", "admin", "write_all", "manage_users", "billing"] } = input;

  const findings: AccessReviewFinding[] = [];

  // Check for orphaned accounts (terminated users with access)
  const terminated = users.filter((u) => u.employment_status === "terminated");
  if (terminated.length > 0) {
    findings.push({
      type: "orphaned_account",
      severity: "critical",
      affected_users: terminated.map((u) => u.username),
      description: `${terminated.length} terminated user(s) still have active access`,
      remediation: "Immediately revoke all access for terminated users. Implement automated offboarding workflow.",
    });
  }

  // Check for dormant accounts (no login in 90+ days)
  const now = Date.now();
  const dormantThreshold = 90 * 24 * 60 * 60 * 1000;
  const dormant = users.filter((u) => {
    if (!u.last_login || u.employment_status === "terminated") return false;
    return now - new Date(u.last_login).getTime() > dormantThreshold;
  });
  if (dormant.length > 0) {
    findings.push({
      type: "dormant_account",
      severity: "medium",
      affected_users: dormant.map((u) => u.username),
      description: `${dormant.length} account(s) with no login in 90+ days`,
      remediation: "Disable dormant accounts. Contact users to verify if access is still needed.",
    });
  }

  // Check for excessive admin access
  const activeUsers = users.filter((u) => u.employment_status !== "terminated");
  const admins = activeUsers.filter((u) =>
    u.roles.some((r) => admin_roles.some((ar) => r.toLowerCase().includes(ar.toLowerCase())))
  );
  const adminPercentage = activeUsers.length > 0 ? (admins.length / activeUsers.length) * 100 : 0;

  if (adminPercentage > 10) {
    findings.push({
      type: "excessive_admin",
      severity: "high",
      affected_users: admins.map((u) => u.username),
      description: `${Math.round(adminPercentage)}% of users have admin roles (${admins.length}/${activeUsers.length}). Best practice: <10%`,
      remediation: "Review admin role assignments. Implement least-privilege model with role-based access.",
    });
  }

  // Check for separation of duties violations
  const sodPairs: [string, string][] = [
    ["approve", "submit"],
    ["create", "approve"],
    ["admin", "audit"],
    ["deploy", "approve_deploy"],
  ];

  for (const [perm1, perm2] of sodPairs) {
    const violators = activeUsers.filter((u) => {
      const perms = u.permissions.map((p) => p.toLowerCase());
      return perms.some((p) => p.includes(perm1)) && perms.some((p) => p.includes(perm2));
    });

    if (violators.length > 0) {
      findings.push({
        type: "sod_violation",
        severity: "high",
        affected_users: violators.map((u) => u.username),
        description: `${violators.length} user(s) have both "${perm1}" and "${perm2}" permissions (separation of duties violation)`,
        remediation: `Remove one of the conflicting permissions or implement compensating controls (dual approval, audit trail).`,
      });
    }
  }

  // Check for users with too many sensitive permissions
  const overPrivileged = activeUsers.filter((u) => {
    const sensitiveCount = u.permissions.filter((p) =>
      sensitive_permissions.some((sp) => p.toLowerCase().includes(sp.toLowerCase()))
    ).length;
    return sensitiveCount > 3;
  });

  if (overPrivileged.length > 0) {
    findings.push({
      type: "excessive_admin",
      severity: "medium",
      affected_users: overPrivileged.map((u) => u.username),
      description: `${overPrivileged.length} user(s) have more than 3 sensitive permissions`,
      remediation: "Review and reduce sensitive permission assignments. Apply least-privilege principle.",
    });
  }

  // Summary stats
  const summary = {
    total_users: users.length,
    active_users: activeUsers.length,
    terminated_with_access: terminated.length,
    dormant_accounts: dormant.length,
    admin_users: admins.length,
    admin_percentage: Math.round(adminPercentage),
    total_findings: findings.length,
    critical_findings: findings.filter((f) => f.severity === "critical").length,
    high_findings: findings.filter((f) => f.severity === "high").length,
  };

  return {
    summary,
    findings,
    risk_level: findings.some((f) => f.severity === "critical") ? "CRITICAL"
      : findings.some((f) => f.severity === "high") ? "HIGH"
      : findings.length > 0 ? "MEDIUM" : "LOW",
    immediate_actions: findings
      .filter((f) => f.severity === "critical")
      .map((f) => f.remediation),
  };
}
