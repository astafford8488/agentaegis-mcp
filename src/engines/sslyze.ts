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
    { timeout: 60_000 } // bounded — a scanner-blocking host (e.g. badssl) used to hang the full 120s
  );

  // Timed out or failed with no output → return a graceful "could not complete"
  // result instead of throwing. The 120s hang on a scanner-blocking host used to
  // surface as a 500 on the standalone ssl_tls_audit path; now the caller gets a
  // "U" grade that explains why. (vet_endpoint bounds this separately via withTimeout.)
  if (!result.stdout) {
    const reason = result.exitCode === 124
      ? "scan timed out — the host may be blocking or tarpitting scanners"
      : `scanner error: ${(result.stderr || "unknown").slice(0, 200)}`;
    return buildFallbackResult(hostname, reason);
  }

  try {
    const parsed = JSON.parse(result.stdout);
    return parseSSLyzeOutput(hostname, parsed);
  } catch {
    return buildFallbackResult(hostname, "scanner returned unparseable output");
  }
}

function parseSSLyzeOutput(hostname: string, data: Record<string, unknown>): SSLAuditResult & { data_quality?: { partial: boolean; missing_fields: string[] } } {
  const serverResults = (data as any).server_scan_results?.[0];
  const scan = serverResults?.scan_commands_results || serverResults?.scan_result;
  const certInfo = scan?.certificate_info?.result || scan?.certificate_info;
  const certDeployment = certInfo?.certificate_deployments?.[0];
  const leafCert = certDeployment?.received_certificate_chain?.[0];

  const missingFields: string[] = [];

  // Certificate fields. If anything is missing we report it explicitly rather
  // than fabricating a "valid_to: 0 → expires today" false positive.
  const validTo = leafCert?.not_valid_after;
  let daysUntilExpiry: number | null = null;
  if (validTo) {
    daysUntilExpiry = Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000);
  } else {
    missingFields.push("certificate.not_valid_after");
  }

  const verifiedChain = certDeployment?.verified_certificate_chain;
  const chainValid = Array.isArray(verifiedChain) && verifiedChain.length > 0;
  if (verifiedChain === undefined) missingFields.push("certificate.verified_certificate_chain");

  const certificate: CertificateInfo = {
    subject: leafCert?.subject?.rfc4514_string || hostname,
    issuer: leafCert?.issuer?.rfc4514_string || "Unknown",
    valid_from: leafCert?.not_valid_before || "",
    valid_to: validTo || "",
    days_until_expiry: daysUntilExpiry ?? 0,
    san: leafCert?.subject_alternative_name?.dns || [],
    chain_valid: chainValid,
    key_size: leafCert?.public_key?.key_size || 0,
    signature_algorithm: leafCert?.signature_algorithm_oid || "",
  };
  if (!leafCert) missingFields.push("certificate.received_certificate_chain[0]");

  const tls10 = scan?.tls_1_0_cipher_suites?.result || scan?.tls_1_0_cipher_suites;
  const tls11 = scan?.tls_1_1_cipher_suites?.result || scan?.tls_1_1_cipher_suites;
  const tls12 = scan?.tls_1_2_cipher_suites?.result || scan?.tls_1_2_cipher_suites;
  const tls13 = scan?.tls_1_3_cipher_suites?.result || scan?.tls_1_3_cipher_suites;
  const ssl30 = scan?.ssl_3_0_cipher_suites?.result || scan?.ssl_3_0_cipher_suites;

  const protocols = {
    ssl_3_0: (ssl30?.accepted_cipher_suites?.length ?? 0) > 0,
    tls_1_0: (tls10?.accepted_cipher_suites?.length ?? 0) > 0,
    tls_1_1: (tls11?.accepted_cipher_suites?.length ?? 0) > 0,
    tls_1_2: (tls12?.accepted_cipher_suites?.length ?? 0) > 0,
    tls_1_3: (tls13?.accepted_cipher_suites?.length ?? 0) > 0,
  };
  if (!tls12 && !tls13) missingFields.push("scan.tls_1_2_cipher_suites & tls_1_3_cipher_suites");

  // Cipher suite extraction
  const allAccepted: string[] = [];
  const collectCiphers = (group: any) => {
    for (const cs of group?.accepted_cipher_suites || []) {
      const name = cs?.cipher_suite?.name || cs?.name;
      if (name) allAccepted.push(name);
    }
  };
  collectCiphers(tls12);
  collectCiphers(tls13);
  collectCiphers(tls11);
  collectCiphers(tls10);

  const weak = allAccepted.filter((c) => /RC4|MD5|NULL|EXPORT|DES|3DES|anon/i.test(c));
  const strong = allAccepted.filter((c) => /ECDHE|GCM|CHACHA20|TLS_AES/i.test(c) && !/RC4|MD5|NULL/i.test(c));
  const acceptable = allAccepted.filter((c) => !weak.includes(c) && !strong.includes(c));

  // Vulnerabilities. Default to FALSE when we can't confirm — never assume vulnerable
  // just because a field is missing. (This was the audit-found bug.)
  const heartbleed = scan?.heartbleed?.result || scan?.heartbleed;
  const robot = scan?.robot?.result || scan?.robot;

  const vulnerabilities = {
    heartbleed: heartbleed?.is_vulnerable_to_heartbleed === true,
    robot: typeof robot?.robot_result === "string" &&
           robot.robot_result !== "NOT_VULNERABLE_NO_ORACLE" &&
           robot.robot_result !== "NOT_VULNERABLE_RSA_NOT_SUPPORTED",
    beast: protocols.tls_1_0,
    poodle: protocols.ssl_3_0,
    crime: false,
  };

  // HSTS — sslyze doesn't usually return this in the headers; we leave as default.
  const grade = calculateSSLGrade(protocols, vulnerabilities, certificate, missingFields.length > 0);

  const out: SSLAuditResult & { data_quality?: { partial: boolean; missing_fields: string[] } } = {
    hostname,
    certificate,
    protocols,
    cipher_suites: { strong, acceptable, weak },
    vulnerabilities,
    hsts: { enabled: false },
    ocsp_stapling: false,
    grade,
  };
  if (missingFields.length > 0) {
    out.data_quality = { partial: true, missing_fields: missingFields };
  }
  return out;
}

function buildFallbackResult(hostname: string, reason: string): SSLAuditResult {
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
    grade: { grade: "U", score: 0, issues: [`Unable to complete SSL scan: ${reason}`] },
  };
}

function calculateSSLGrade(
  protocols: SSLAuditResult["protocols"],
  vulnerabilities: SSLAuditResult["vulnerabilities"],
  certificate: CertificateInfo,
  partialData: boolean = false
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
  if (certificate.valid_to && certificate.days_until_expiry < 0) {
    score -= 40; issues.push("Certificate expired");
  } else if (certificate.valid_to && certificate.days_until_expiry < 30) {
    score -= 10; issues.push("Certificate expires within 30 days");
  }

  // If sslyze gave us partial data, return Unknown rather than a fabricated grade.
  if (partialData) {
    issues.unshift("Partial data from scanner — grade may not be reliable; check data_quality field");
    return { grade: "U", score: Math.max(0, score), issues };
  }

  let grade: string;
  if (score >= 95) grade = "A+";
  else if (score >= 85) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 60) grade = "C";
  else if (score >= 40) grade = "D";
  else grade = "F";

  return { grade, score: Math.max(0, score), issues };
}
