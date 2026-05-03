import { z } from "zod";
import { checkEmail, checkDomain } from "../../apis/hibp.js";

export const credentialCheckSchema = z.object({
  check_type: z.enum(["email", "domain"]),
  target: z.string().min(1),
});

export type CredentialCheckInput = z.infer<typeof credentialCheckSchema>;

export async function credentialCheck(input: CredentialCheckInput) {
  const { check_type, target } = input;

  if (check_type === "email") {
    const breaches = await checkEmail(target);

    const totalExposed = breaches.reduce((sum, b) => sum + b.pwn_count, 0);
    const dataTypesExposed = [...new Set(breaches.flatMap((b) => b.data_classes))];

    return {
      check_type: "email",
      target,
      breached: breaches.length > 0,
      breach_count: breaches.length,
      breaches: breaches.map((b) => ({
        name: b.title,
        date: b.breach_date,
        data_exposed: b.data_classes,
        records_in_breach: b.pwn_count,
        verified: b.is_verified,
      })),
      summary: {
        total_breaches: breaches.length,
        earliest_breach: breaches.length > 0
          ? breaches.sort((a, b) => a.breach_date.localeCompare(b.breach_date))[0].breach_date
          : null,
        latest_breach: breaches.length > 0
          ? breaches.sort((a, b) => b.breach_date.localeCompare(a.breach_date))[0].breach_date
          : null,
        data_types_exposed: dataTypesExposed,
        passwords_exposed: dataTypesExposed.includes("Passwords"),
      },
      recommendations: breaches.length > 0 ? [
        "Change password immediately if reused across services",
        "Enable MFA on all accounts associated with this email",
        dataTypesExposed.includes("Passwords") ? "CRITICAL: Passwords were exposed — rotate all passwords using this email" : null,
        dataTypesExposed.includes("Phone numbers") ? "Be alert for SIM swapping and phishing attempts" : null,
        "Consider using a password manager with unique passwords per service",
      ].filter(Boolean) : ["No breaches found — continue practicing good security hygiene"],
    };
  } else {
    const domainResult = await checkDomain(target);

    return {
      check_type: "domain",
      target,
      breached: domainResult.breaches.length > 0,
      summary: {
        total_breached_accounts: domainResult.total_breached_accounts,
        breach_count: domainResult.breaches.length,
        most_impactful_breaches: domainResult.breaches
          .sort((a, b) => b.pwn_count - a.pwn_count)
          .slice(0, 5)
          .map((b) => ({
            name: b.name,
            date: b.breach_date,
            records: b.pwn_count,
            data_types: b.data_classes,
          })),
      },
      risk_assessment: domainResult.total_breached_accounts > 100
        ? "HIGH: Significant number of corporate accounts found in breaches. Credential stuffing attacks likely."
        : domainResult.total_breached_accounts > 10
        ? "MEDIUM: Multiple accounts exposed. Review and rotate affected credentials."
        : domainResult.total_breached_accounts > 0
        ? "LOW: Limited exposure detected."
        : "NONE: No accounts from this domain found in known breaches.",
      recommendations: domainResult.breaches.length > 0 ? [
        "Enforce password reset for users in recent breaches",
        "Enable MFA for all accounts (blocks 99.9% of credential stuffing)",
        "Monitor for credential stuffing attacks (failed login spikes)",
        "Implement breached password detection in authentication flow",
        "Consider a dark web monitoring service for ongoing alerts",
      ] : ["No breaches found for this domain — maintain vigilance"],
    };
  }
}
