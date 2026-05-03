import { z } from "zod";
import { validateTarget } from "../../utils/sanitize.js";
import { logScanTarget } from "../../queue/scanQueue.js";
import { runSSLAudit } from "../../engines/sslyze.js";

export const sslTlsAuditSchema = z.object({
  hostname: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
});

export type SSLTlsAuditInput = z.infer<typeof sslTlsAuditSchema>;

export async function sslTlsAudit(input: SSLTlsAuditInput) {
  const { hostname, port = 443 } = input;

  const validation = validateTarget(hostname);
  if (!validation.valid) {
    return { error: validation.reason };
  }

  logScanTarget("ssl_tls_audit", `${hostname}:${port}`);

  const result = await runSSLAudit(hostname, port);

  const recommendations: string[] = [];

  if (result.protocols.tls_1_0) recommendations.push("Disable TLS 1.0 — deprecated since 2020");
  if (result.protocols.tls_1_1) recommendations.push("Disable TLS 1.1 — deprecated since 2020");
  if (!result.protocols.tls_1_3) recommendations.push("Enable TLS 1.3 for improved security and performance");
  if (result.vulnerabilities.heartbleed) recommendations.push("CRITICAL: Patch Heartbleed (CVE-2014-0160) immediately");
  if (result.vulnerabilities.robot) recommendations.push("Mitigate ROBOT attack vulnerability");
  if (!result.hsts.enabled) recommendations.push("Enable HTTP Strict Transport Security (HSTS)");
  if (result.certificate.days_until_expiry < 30 && result.certificate.days_until_expiry > 0) {
    recommendations.push(`Certificate expires in ${result.certificate.days_until_expiry} days — renew soon`);
  }
  if (result.certificate.days_until_expiry <= 0) {
    recommendations.push("CRITICAL: Certificate has expired — renew immediately");
  }
  if (!result.ocsp_stapling) recommendations.push("Enable OCSP stapling for faster certificate validation");
  if (result.cipher_suites.weak.length > 0) {
    recommendations.push(`Remove ${result.cipher_suites.weak.length} weak cipher suites`);
  }

  return {
    hostname,
    port,
    grade: result.grade,
    certificate: result.certificate,
    protocol_support: result.protocols,
    cipher_suites: {
      strong_count: result.cipher_suites.strong.length,
      acceptable_count: result.cipher_suites.acceptable.length,
      weak_count: result.cipher_suites.weak.length,
      weak_ciphers: result.cipher_suites.weak,
    },
    vulnerabilities: result.vulnerabilities,
    hsts: result.hsts,
    ocsp_stapling: result.ocsp_stapling,
    recommendations,
  };
}
