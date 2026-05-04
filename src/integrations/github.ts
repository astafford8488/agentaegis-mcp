// GitHub integration for evidence collection.
// Pulls observable security configuration from a GitHub org so the
// evidence_collect tool can return actual artifacts instead of just a plan.
//
// Required scope on the supplied token (PAT or GitHub App): `read:org`,
// `repo` (read), `admin:org` (read for branch protection details).
//
// We only call read endpoints — never mutate state.

export interface GitHubOrg {
  login: string;
  members: number;
  two_factor_required: boolean | null;
  default_repo_permission: string | null;
  members_can_create_repositories: boolean | null;
}

export interface GitHubRepoSecurity {
  name: string;
  visibility: "public" | "private" | "internal";
  default_branch: string;
  branch_protection: {
    enabled: boolean;
    required_reviews: number;
    dismiss_stale_reviews: boolean;
    require_code_owner_reviews: boolean;
    required_status_checks: string[];
    enforce_admins: boolean;
  } | null;
  vulnerability_alerts_enabled: boolean | null;
  secret_scanning_enabled: boolean | null;
  push_protection_enabled: boolean | null;
  has_dependabot_config: boolean;
}

export interface GitHubEvidenceBundle {
  collected_at: string;
  organization: GitHubOrg;
  repos_sampled: GitHubRepoSecurity[];
  member_count: number;
  external_collaborator_count: number;
  pending_invitations: number;
  control_evidence: {
    cc6_1_centralized_access: boolean;
    cc6_3_least_privilege: "documented" | "partial" | "unknown";
    cc8_1_change_management: "branch_protection_enforced" | "partial" | "missing";
    cc7_1_monitoring: "secret_scanning_on" | "partial" | "off";
    cc9_1_vuln_management: "dependabot_active" | "partial" | "missing";
  };
  warnings: string[];
}

const GITHUB_API = "https://api.github.com";

function authHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "AgentAegis-MCP",
  };
}

async function ghGet(token: string, path: string): Promise<any> {
  const r = await fetch(`${GITHUB_API}${path}`, { headers: authHeaders(token) });
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error(`GitHub API ${r.status} on ${path}: ${body.slice(0, 200)}`);
  }
  return r.json();
}

export async function collectGitHubEvidence(
  org: string,
  token: string,
  options: { sample_repo_count?: number } = {}
): Promise<GitHubEvidenceBundle> {
  const sampleSize = options.sample_repo_count ?? 5;
  const warnings: string[] = [];

  // Org-level config
  const orgData = await ghGet(token, `/orgs/${encodeURIComponent(org)}`);

  const organization: GitHubOrg = {
    login: orgData.login,
    members: orgData.public_members ?? 0,
    two_factor_required: orgData.two_factor_requirement_enabled ?? null,
    default_repo_permission: orgData.default_repository_permission ?? null,
    members_can_create_repositories: orgData.members_can_create_repositories ?? null,
  };

  if (organization.two_factor_required !== true) {
    warnings.push("Org-wide MFA is NOT enforced. SOC 2 CC6.1 weak.");
  }

  // Member count
  let memberCount = 0;
  try {
    const members = await ghGet(token, `/orgs/${encodeURIComponent(org)}/members?per_page=100`);
    memberCount = Array.isArray(members) ? members.length : 0;
  } catch {
    warnings.push("Could not list members (token may lack read:org scope)");
  }

  // External collaborators
  let externalCount = 0;
  try {
    const ext = await ghGet(token, `/orgs/${encodeURIComponent(org)}/outside_collaborators?per_page=100`);
    externalCount = Array.isArray(ext) ? ext.length : 0;
  } catch {
    // requires admin:org
  }

  // Pending invitations
  let pendingInvites = 0;
  try {
    const inv = await ghGet(token, `/orgs/${encodeURIComponent(org)}/invitations`);
    pendingInvites = Array.isArray(inv) ? inv.length : 0;
  } catch {
    // best effort
  }

  // Sample repos
  const repos = await ghGet(token, `/orgs/${encodeURIComponent(org)}/repos?per_page=${sampleSize}&sort=pushed`);
  const reposSampled: GitHubRepoSecurity[] = [];

  for (const repo of (repos as any[]).slice(0, sampleSize)) {
    const repoSec: GitHubRepoSecurity = {
      name: repo.name,
      visibility: repo.private ? "private" : (repo.visibility === "internal" ? "internal" : "public"),
      default_branch: repo.default_branch,
      branch_protection: null,
      vulnerability_alerts_enabled: null,
      secret_scanning_enabled: null,
      push_protection_enabled: null,
      has_dependabot_config: false,
    };

    // Branch protection
    try {
      const bp = await ghGet(token, `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(repo.default_branch)}/protection`);
      repoSec.branch_protection = {
        enabled: true,
        required_reviews: bp.required_pull_request_reviews?.required_approving_review_count ?? 0,
        dismiss_stale_reviews: bp.required_pull_request_reviews?.dismiss_stale_reviews ?? false,
        require_code_owner_reviews: bp.required_pull_request_reviews?.require_code_owner_reviews ?? false,
        required_status_checks: bp.required_status_checks?.contexts ?? [],
        enforce_admins: bp.enforce_admins?.enabled ?? false,
      };
    } catch {
      repoSec.branch_protection = { enabled: false, required_reviews: 0, dismiss_stale_reviews: false, require_code_owner_reviews: false, required_status_checks: [], enforce_admins: false };
    }

    // Security features (vulnerability alerts, secret scanning, push protection)
    try {
      const repoDetail = await ghGet(token, `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}`);
      repoSec.vulnerability_alerts_enabled = repoDetail.security_and_analysis?.dependabot_security_updates?.status === "enabled";
      repoSec.secret_scanning_enabled = repoDetail.security_and_analysis?.secret_scanning?.status === "enabled";
      repoSec.push_protection_enabled = repoDetail.security_and_analysis?.secret_scanning_push_protection?.status === "enabled";
    } catch {
      // older API, leave as null
    }

    // Dependabot config presence
    try {
      await ghGet(token, `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/contents/.github/dependabot.yml`);
      repoSec.has_dependabot_config = true;
    } catch {
      try {
        await ghGet(token, `/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/contents/.github/dependabot.yaml`);
        repoSec.has_dependabot_config = true;
      } catch {
        repoSec.has_dependabot_config = false;
      }
    }

    reposSampled.push(repoSec);
  }

  // Aggregate control evidence
  const branchProtectedCount = reposSampled.filter((r) => r.branch_protection?.enabled).length;
  const protectedRatio = reposSampled.length > 0 ? branchProtectedCount / reposSampled.length : 0;
  const secretScanningCount = reposSampled.filter((r) => r.secret_scanning_enabled === true).length;
  const dependabotCount = reposSampled.filter((r) => r.has_dependabot_config || r.vulnerability_alerts_enabled).length;

  const controlEvidence: GitHubEvidenceBundle["control_evidence"] = {
    cc6_1_centralized_access: organization.two_factor_required === true,
    cc6_3_least_privilege: organization.default_repo_permission === "read" ? "documented"
      : organization.default_repo_permission ? "partial" : "unknown",
    cc8_1_change_management: protectedRatio === 1 ? "branch_protection_enforced"
      : protectedRatio > 0 ? "partial" : "missing",
    cc7_1_monitoring: secretScanningCount === reposSampled.length && reposSampled.length > 0 ? "secret_scanning_on"
      : secretScanningCount > 0 ? "partial" : "off",
    cc9_1_vuln_management: dependabotCount === reposSampled.length && reposSampled.length > 0 ? "dependabot_active"
      : dependabotCount > 0 ? "partial" : "missing",
  };

  return {
    collected_at: new Date().toISOString(),
    organization,
    repos_sampled: reposSampled,
    member_count: memberCount,
    external_collaborator_count: externalCount,
    pending_invitations: pendingInvites,
    control_evidence: controlEvidence,
    warnings,
  };
}
