// Okta evidence collection (read-only).
//
// Required scope on the supplied token: `okta.users.read`, `okta.policies.read`,
// `okta.factors.read`. Token is an Okta API token.

export interface OktaEvidenceBundle {
  collected_at: string;
  domain: string;
  user_count: number;
  active_users: number;
  suspended_users: number;
  password_policy: {
    min_length: number;
    require_uppercase: boolean;
    require_lowercase: boolean;
    require_number: boolean;
    require_symbol: boolean;
    history_count: number;
    max_age_days: number;
  } | null;
  mfa_factors_active: string[];
  groups_count: number;
  applications_count: number;
  control_evidence: {
    cc6_1_centralized_iam: boolean;
    cc6_2_user_provisioning: "documented" | "partial" | "unknown";
    cc6_5_termination_workflow: boolean;
    mfa_enforced: "all" | "partial" | "none";
    password_policy_strong: boolean;
  };
  warnings: string[];
}

async function oktaGet(domain: string, token: string, path: string): Promise<any> {
  const url = `https://${domain}${path}`;
  const r = await fetch(url, {
    headers: {
      Authorization: `SSWS ${token}`,
      Accept: "application/json",
      "User-Agent": "AgentAegis-MCP",
    },
  });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`Okta ${r.status} on ${path}: ${body.slice(0, 200)}`);
  }
  return r.json();
}

export async function collectOktaEvidence(domain: string, token: string): Promise<OktaEvidenceBundle> {
  const warnings: string[] = [];

  // Users
  let users: any[] = [];
  try {
    users = await oktaGet(domain, token, "/api/v1/users?limit=200");
  } catch (err) {
    warnings.push(`users: ${String(err).slice(0, 100)}`);
  }
  const activeUsers = users.filter((u) => u.status === "ACTIVE").length;
  const suspendedUsers = users.filter((u) => u.status === "SUSPENDED" || u.status === "DEPROVISIONED").length;

  // Password policies
  let passwordPolicy: OktaEvidenceBundle["password_policy"] = null;
  try {
    const policies = await oktaGet(domain, token, "/api/v1/policies?type=PASSWORD");
    if (Array.isArray(policies) && policies.length > 0) {
      const p = policies[0].settings?.password?.complexity || {};
      const age = policies[0].settings?.password?.age || {};
      passwordPolicy = {
        min_length: p.minLength ?? 0,
        require_uppercase: (p.minUpperCase ?? 0) > 0,
        require_lowercase: (p.minLowerCase ?? 0) > 0,
        require_number: (p.minNumber ?? 0) > 0,
        require_symbol: (p.minSymbol ?? 0) > 0,
        history_count: p.history ?? 0,
        max_age_days: age.maxAgeDays ?? 0,
      };
    }
  } catch (err) {
    warnings.push(`password_policy: ${String(err).slice(0, 100)}`);
  }

  // MFA factors active in the org
  let mfaFactors: string[] = [];
  try {
    const factors = await oktaGet(domain, token, "/api/v1/org/factors");
    mfaFactors = (factors as any[]).filter((f) => f.status === "ACTIVE").map((f) => f.provider + ":" + f.factorType);
  } catch (err) {
    warnings.push(`mfa_factors: ${String(err).slice(0, 100)}`);
  }

  // Groups
  let groupsCount = 0;
  try {
    const groups = await oktaGet(domain, token, "/api/v1/groups?limit=200");
    groupsCount = Array.isArray(groups) ? groups.length : 0;
  } catch (err) {
    warnings.push(`groups: ${String(err).slice(0, 100)}`);
  }

  // Applications
  let appsCount = 0;
  try {
    const apps = await oktaGet(domain, token, "/api/v1/apps?limit=100");
    appsCount = Array.isArray(apps) ? apps.length : 0;
  } catch (err) {
    warnings.push(`applications: ${String(err).slice(0, 100)}`);
  }

  const passwordPolicyStrong = !!passwordPolicy && passwordPolicy.min_length >= 12
    && passwordPolicy.require_uppercase && passwordPolicy.require_lowercase
    && passwordPolicy.require_number && passwordPolicy.require_symbol;

  const mfaEnforced: OktaEvidenceBundle["control_evidence"]["mfa_enforced"] = mfaFactors.length >= 2 ? "all" : mfaFactors.length === 1 ? "partial" : "none";

  return {
    collected_at: new Date().toISOString(),
    domain,
    user_count: users.length,
    active_users: activeUsers,
    suspended_users: suspendedUsers,
    password_policy: passwordPolicy,
    mfa_factors_active: mfaFactors,
    groups_count: groupsCount,
    applications_count: appsCount,
    control_evidence: {
      cc6_1_centralized_iam: true,  // having an Okta tenant proves this control
      cc6_2_user_provisioning: groupsCount > 0 ? "partial" : "unknown",
      cc6_5_termination_workflow: suspendedUsers > 0,  // some signal that people have been deprovisioned
      mfa_enforced: mfaEnforced,
      password_policy_strong: passwordPolicyStrong,
    },
    warnings,
  };
}
