import { execInSandbox } from "../utils/sandbox.js";
import { sanitizeShellArg } from "../utils/sanitize.js";
import type { CertificateInfo, SSLGrade } from "../types/security.js";

export interface SSLAuditResult {
  hostname: string;
  certificate: CertificateInfo;
  protocols: {
    tls_1_0: boolean;
    tls_1_1: boolean;
    tls_1_2: boolean;
    tls_1_3: boolean;
    ssl_3_0: boolean;
  };
  cipher_suites: {
    strong: string[];
    acceptable: string[];
    weak: string[];
  };
  vulnerabilities: {
    heartbleed: boolean;
    robot: boolean;
    beast: boolean;
    poodle: boolean;
    crime: boolean;
  };
  hsts: {
    enabled: boolean;
    max_age?: number;
    include_subdomains?: boolean;
    preload?: boolean;
  };
  ocsp_stapling: boolean;
  grade: SSLGrade;
}

export async function runSSLAudit(hostname: string, port: number = 443): Promise<SSLAuditResult> {
  const target = `${sanitizeShellArg(hostname)}:${port}`;

  const result = await execInSandbox(
    process.env.SSLYZE_PATH || "sslyze",
    ["--json_out=-", target],
    { timeout: 120_000 }
  );

  if (result.exitCode !== 0 && !result.stdout) {
    throw new Error(`sslyze scan failed: ${result.stderr}`);
  }

  try {
    const parsed = JSON.parse(result.stdout);
    return parseSSLyzeOutput(hostname, parsed);
  } catch {
    return buildFallbackResult(hostname, result.stdout);
  }
}

function parseSSLyzeOutput(hostname: string, data: Record<string, unknown>): SSLAuditResult {
  const serverResults = (data as any).server_scan_results?.[0];
  const certInfo = serverResults?.scan_commands_results?.certificate_info;
  const certDeployment = certInfo?.certificate_deployments?.[0];
  const leafCert = certDeployment?.received_certificate_chain?.[0];

  const certificate: CertificateInfo = {
    subject: leafCert?.subject?.rfc4514_string || hostname,
    issuer: leafCert?.issuer?.rfc4514_string || "Unknown",
    valid_from: leafCert?.not_valid_before || "",
    valid_to: leafCert?.not_valid_after || "",
    days_until_expiry: leafCert ? Math.floor((new Date(leafCert.not_valid_after).getTime() - Date.now()) / 86400000) : 0,
    san: leafCert?.subject_alternative_name?.dns || [],
    chain_valid: certDeployment?.verified_certificate_chain !== null,
    key_size: leafCert?.public_key?.key_size || 0,
    signature_algorithm: leafCert?.signature_algorithm_oid || "",
  };

  const tls10 = serverResults?.scan_commands_results?.tls_1_0_cipher_suites;
  const tls11 = serverResults?.scan_commands_results?.tls_1_1_cipher_suites;
  const tls12 = serverResults?.scan_commands_results?.tls_1_2_cipher_suites;
  const tls13 = serverResults?.scan_commands_results?.tls_1_3_cipher_suites;

  const protocols = {
    ssl_3_0: false,
    tls_1_0: tls10?.accepted_cipher_suites?.length > 0,
    tls_1_1: tls11?.accepted_cipher_suites?.length > 0,
    tls_1_2: tls12?.accepted_cipher_suites?.length > 0,
    tls_1_3: tls13?.accepted_cipher_suites?.length > 0,
  };

  const heartbleed = serverResults?.scan_commands_results?.heartbleed;
  const robot = serverResults?.scan_commands_results?.robot;

  const vulnerabilities = {
    heartbleed: heartbleed?.is_vulnerable_to_heartbleed || false,
    robot: robot?.robot_result !== "NOT_VULNERABLE_NO_ORACLE",
    beast: protocols.tls_1_0,
    poodle: protocols.ssl_3_0,
    crime: false,
  };

  const grade = calculateSSLGrade(protocols, vulnerabilities, certificate);

  return {
    hostname,
    certificate,
    protocols,
    cipher_suites: { strong: [], acceptable: [], weak: [] },
    vulnerabilities,
    hsts: { enabled: false },
    ocsp_stapling: false,
    grade,
  };
}

function buildFallbackResult(hostname: string, _rawOutput: string): SSLAuditResult {
  return {
    hostname,
    certificate: {
      subject: hostname,
      issuer: "Unable to determine",
      valid_from: "",
      valid_to: "",
      days_until_expiry: 0,
      san: [],
      chain_valid: false,
      key_size: 0,
      signature_algorithm: "",
    },
    protocols: { ssl_3_0: false, tls_1_0: false, tls_1_1: false, tls_1_2: false, tls_1_3: false },
    cipher_suites: { strong: [], acceptable: [], weak: [] },
    vulnerabilities: { heartbleed: false, robot: false, beast: false, poodle: false, crime: false },
    hsts: { enabled: false },
    ocsp_stapling: false,
    grade: { grade: "U", score: 0, issues: ["Unable to complete SSL scan"] },
  };
}

function calculateSSLGrade(
  protocols: SSLAuditResult["protocols"],
  vulnerabilities: SSLAuditResult["vulnerabilities"],
  certificate: CertificateInfo
): SSLGrade {
  let score = 100;
  const issues: string[] = [];

  if (vulnerabilities.heartbleed) { score -= 50; issues.push("Vulnerable to Heartbleed"); }
  if (vulnerabilities.robot) { score -= 30; issues.push("Vulnerable to ROBOT attack"); }
  if (vulnerabilities.poodle) { score -= 30; issues.push("SSL 3.0 enabled (POODLE)"); }
  if (protocols.tls_1_0) { score -= 15; issues.push("TLS 1.0 enabled (deprecated)"); }
  if (protocols.tls_1_1) { score -= 10; issues.push("TLS 1.1 enabled (deprecated)"); }
  if (!protocols.tls_1_3) { score -= 5; issues.push("TLS 1.3 not supported"); }
  if (!certificate.chain_valid) { score -= 30; issues.push("Certificate chain invalid"); }
  if (certificate.days_until_expiry < 0) { score -= 40; issues.push("Certificate expired"); }
  else if (certificate.days_until_expiry < 30) { score -= 10; issues.push("Certificate expires within 30 days"); }

  let grade: string;
  if (score >= 95) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { grade, score: Math.max(0, score), issues };
}
