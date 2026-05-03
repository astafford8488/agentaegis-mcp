import { z } from "zod";

export const mfaAuditSchema = z.object({
  users: z.array(z.object({
    username: z.string(),
    email: z.string(),
    mfa_enabled: z.boolean(),
    mfa_method: z.enum(["totp", "sms", "push", "hardware_key", "email", "none"]).optional(),
    is_admin: z.boolean(),
    is_service_account: z.boolean(),
    last_mfa_verification: z.string().optional(),
  })),
});

export type MFAAuditInput = z.infer<typeof mfaAuditSchema>;

export async function mfaAudit(input: MFAAuditInput) {
  const { users } = input;

  const totalUsers = users.length;
  const humanUsers = users.filter((u) => !u.is_service_account);
  const serviceAccounts = users.filter((u) => u.is_service_account);
  const admins = users.filter((u) => u.is_admin);

  const mfaEnabled = humanUsers.filter((u) => u.mfa_enabled);
  const mfaDisabled = humanUsers.filter((u) => !u.mfa_enabled);
  const adminNoMFA = admins.filter((u) => !u.mfa_enabled);
  const coveragePercent = humanUsers.length > 0 ? Math.round((mfaEnabled.length / humanUsers.length) * 100) : 0;

  // Method breakdown
  const methodBreakdown = {
    hardware_key: mfaEnabled.filter((u) => u.mfa_method === "hardware_key").length,
    totp: mfaEnabled.filter((u) => u.mfa_method === "totp").length,
    push: mfaEnabled.filter((u) => u.mfa_method === "push").length,
    sms: mfaEnabled.filter((u) => u.mfa_method === "sms").length,
    email: mfaEnabled.filter((u) => u.mfa_method === "email").length,
  };

  // Weak MFA methods
  const weakMFA = mfaEnabled.filter((u) => u.mfa_method === "sms" || u.mfa_method === "email");

  // Findings
  const findings: { severity: string; description: string; affected_users: string[]; recommendation: string }[] = [];

  if (adminNoMFA.length > 0) {
    findings.push({
      severity: "CRITICAL",
      description: `${adminNoMFA.length} admin account(s) without MFA`,
      affected_users: adminNoMFA.map((u) => u.username),
      recommendation: "Enable MFA immediately for all admin accounts. Use hardware security keys for highest protection.",
    });
  }

  if (mfaDisabled.length > 0 && coveragePercent < 100) {
    findings.push({
      severity: "HIGH",
      description: `${mfaDisabled.length} user account(s) without MFA (${100 - coveragePercent}% uncovered)`,
      affected_users: mfaDisabled.map((u) => u.username),
      recommendation: "Enforce MFA for all user accounts. Set a deadline and provide setup support.",
    });
  }

  if (weakMFA.length > 0) {
    findings.push({
      severity: "MEDIUM",
      description: `${weakMFA.length} user(s) using weak MFA method (SMS or email)`,
      affected_users: weakMFA.map((u) => u.username),
      recommendation: "Migrate from SMS/email MFA to TOTP, push notifications, or hardware keys. SMS is vulnerable to SIM swapping.",
    });
  }

  if (serviceAccounts.length > 0) {
    const saWithMFA = serviceAccounts.filter((u) => u.mfa_enabled);
    findings.push({
      severity: "INFO",
      description: `${serviceAccounts.length} service account(s) detected. ${saWithMFA.length} have MFA.`,
      affected_users: serviceAccounts.map((u) => u.username),
      recommendation: "Service accounts should use API keys or certificates rather than password + MFA. Review authentication method.",
    });
  }

  return {
    summary: {
      total_accounts: totalUsers,
      human_users: humanUsers.length,
      service_accounts: serviceAccounts.length,
      mfa_coverage_percent: coveragePercent,
      admin_accounts: admins.length,
      admins_without_mfa: adminNoMFA.length,
    },
    method_breakdown: methodBreakdown,
    method_strength_ranking: [
      { method: "hardware_key", strength: "Strongest", count: methodBreakdown.hardware_key },
      { method: "totp", strength: "Strong", count: methodBreakdown.totp },
      { method: "push", strength: "Strong", count: methodBreakdown.push },
      { method: "sms", strength: "Weak (SIM swapping risk)", count: methodBreakdown.sms },
      { method: "email", strength: "Weak (account takeover risk)", count: methodBreakdown.email },
    ],
    findings,
    risk_level: adminNoMFA.length > 0 ? "CRITICAL"
      : coveragePercent < 50 ? "HIGH"
      : coveragePercent < 90 ? "MEDIUM"
      : "LOW",
    recommendations: [
      coveragePercent < 100 ? `Achieve 100% MFA coverage (currently ${coveragePercent}%)` : null,
      adminNoMFA.length > 0 ? "URGENT: Enable MFA for all admin accounts" : null,
      weakMFA.length > 0 ? "Migrate SMS/email MFA users to TOTP or hardware keys" : null,
      methodBreakdown.hardware_key === 0 && admins.length > 0 ? "Consider hardware security keys for admin accounts" : null,
    ].filter(Boolean),
  };
}
