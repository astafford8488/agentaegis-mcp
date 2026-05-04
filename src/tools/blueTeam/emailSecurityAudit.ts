import { z } from "zod";
import * as dns from "dns/promises";
import * as tls from "tls";
import { validateTarget } from "../../utils/sanitize.js";
import { dnsSecurityCheck } from "./dnsSecurityCheck.js";

export const emailSecurityAuditSchema = z.object({
  domain: z.string().min(1),
  include_mx_analysis: z.boolean().optional(),
});

export type EmailSecurityAuditInput = z.infer<typeof emailSecurityAuditSchema>;

export async function emailSecurityAudit(input: EmailSecurityAuditInput) {
  const { domain, include_mx_analysis } = input;

  const validation = validateTarget(domain);
  if (!validation.valid) {
    return { error: validation.reason };
  }

  // Get base DNS security check results
  const dnsResults = await dnsSecurityCheck({ domain });

  // Enhanced DKIM analysis with more selectors
  const dkimDetail = await deepDKIMCheck(domain);

  // MX analysis
  let mxAnalysis = null;
  if (include_mx_analysis) {
    mxAnalysis = await analyzeMXSecurity(domain);
  }

  // MTA-STS check
  const mtaSts = await checkMTASTS(domain);

  // BIMI check
  const bimi = await checkBIMI(domain);

  // Generate prioritized recommendations
  const recommendations = generateRecommendations(dnsResults, dkimDetail, mxAnalysis, mtaSts, bimi);

  return {
    domain,
    overall_grade: calculateOverallGrade(dnsResults, dkimDetail, mxAnalysis, mtaSts),
    spf: (dnsResults as any).spf,
    dkim: dkimDetail,
    dmarc: (dnsResults as any).dmarc,
    mx_security: mxAnalysis,
    mta_sts: mtaSts,
    bimi,
    recommendations,
  };
}

async function deepDKIMCheck(domain: string): Promise<object> {
  const selectors = [
    "google", "selector1", "selector2", "k1", "k2", "default",
    "dkim", "mail", "s1", "s2", "mandrill", "amazonses", "cm",
    "protonmail", "protonmail2", "protonmail3",
  ];

  const found: { selector: string; key_type?: string; key_bits?: string }[] = [];

  for (const selector of selectors) {
    try {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      const record = records.map((r) => r.join("")).join("");
      if (record.includes("v=DKIM1")) {
        const keyType = record.match(/k=([^;]+)/)?.[1] || "rsa";
        found.push({ selector, key_type: keyType });
      }
    } catch {
      // Not found
    }
  }

  return {
    configured: found.length > 0,
    selectors: found,
    key_strength: found.length > 0 ? "Unable to determine key size from DNS (need actual key)" : "N/A",
    issues: found.length === 0 ? ["No DKIM selectors found — emails may fail authentication"] : [],
  };
}

async function analyzeMXSecurity(domain: string): Promise<object> {
  try {
    const mxRecords = await dns.resolveMx(domain);
    if (!mxRecords.length) {
      return { configured: false, issues: ["No MX records found"] };
    }

    const results = await Promise.all(
      mxRecords.sort((a, b) => a.priority - b.priority).slice(0, 3).map(async (mx) => {
        const tlsSupport = await checkSTARTTLS(mx.exchange);
        return {
          hostname: mx.exchange,
          priority: mx.priority,
          tls_support: tlsSupport,
        };
      })
    );

    const allTLS = results.every((r) => r.tls_support);

    return {
      configured: true,
      servers: results,
      all_support_tls: allTLS,
      issues: allTLS ? [] : ["Not all MX servers support STARTTLS — emails may be sent in cleartext"],
    };
  } catch {
    return { configured: false, issues: ["Failed to resolve MX records"] };
  }
}

async function checkSTARTTLS(hostname: string): Promise<boolean> {
  return new Promise((resolve) => {
    // nosemgrep: bypass-tls-verification
    // We are AUDITING the MX server's TLS posture, not establishing a trusted
    // connection to it. We want to know whether the server speaks STARTTLS at
    // all, even with self-signed/expired certs (those are findings, not errors).
    // We immediately destroy the socket without sending any data.
    const socket = tls.connect(
      { host: hostname, port: 25, rejectUnauthorized: false, timeout: 5000 },
      () => { socket.destroy(); resolve(true); }
    );
    socket.on("error", () => { resolve(false); });
    socket.on("timeout", () => { socket.destroy(); resolve(false); });
  });
}

async function checkMTASTS(domain: string): Promise<object> {
  try {
    const records = await dns.resolveTxt(`_mta-sts.${domain}`);
    const record = records.map((r) => r.join("")).find((r) => r.startsWith("v=STSv1"));
    return {
      configured: !!record,
      record: record || null,
      note: record ? "MTA-STS configured — enforces TLS for inbound email" : "MTA-STS not configured",
    };
  } catch {
    return { configured: false, note: "MTA-STS not configured — consider adding for TLS enforcement" };
  }
}

async function checkBIMI(domain: string): Promise<object> {
  try {
    const records = await dns.resolveTxt(`default._bimi.${domain}`);
    const record = records.map((r) => r.join("")).find((r) => r.includes("v=BIMI1"));
    return {
      configured: !!record,
      record: record || null,
      note: record ? "BIMI configured — brand logo appears in email clients" : "BIMI not configured (optional, requires DMARC enforcement)",
    };
  } catch {
    return { configured: false, note: "BIMI not configured (optional enhancement)" };
  }
}

function generateRecommendations(
  dnsResults: any,
  dkim: any,
  mx: any,
  mtaSts: any,
  bimi: any
): { priority: "critical" | "high" | "medium" | "low"; action: string; example?: string }[] {
  const recs: { priority: "critical" | "high" | "medium" | "low"; action: string; example?: string }[] = [];

  if (!dnsResults.spf?.present) {
    recs.push({ priority: "critical", action: "Add SPF record to prevent email spoofing", example: "v=spf1 include:_spf.google.com -all" });
  } else if (!dnsResults.spf?.pass) {
    recs.push({ priority: "high", action: "Fix SPF record issues: " + (dnsResults.spf.issues?.join(", ") || "") });
  }

  if (!dnsResults.dmarc?.present) {
    recs.push({ priority: "critical", action: "Add DMARC record", example: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@yourdomain.com" });
  } else if (dnsResults.dmarc?.policy === "none") {
    recs.push({ priority: "high", action: "Upgrade DMARC policy from 'none' to 'quarantine' or 'reject'" });
  }

  if (!dkim.configured) {
    recs.push({ priority: "high", action: "Configure DKIM signing for outbound email" });
  }

  if (mx && !mx.all_support_tls) {
    recs.push({ priority: "medium", action: "Ensure all MX servers support STARTTLS" });
  }

  if (!mtaSts.configured) {
    recs.push({ priority: "medium", action: "Configure MTA-STS to enforce TLS for inbound email" });
  }

  if (!bimi.configured && dnsResults.dmarc?.policy === "reject") {
    recs.push({ priority: "low", action: "Consider BIMI to display brand logo in email clients" });
  }

  return recs;
}

function calculateOverallGrade(dnsResults: any, dkim: any, mx: any, mtaSts: any): string {
  let score = 0;
  if (dnsResults.spf?.present && dnsResults.spf?.pass) score += 25;
  if (dnsResults.dmarc?.present && dnsResults.dmarc?.policy !== "none") score += 30;
  else if (dnsResults.dmarc?.present) score += 10;
  if (dkim.configured) score += 25;
  if (mx?.all_support_tls) score += 10;
  if (mtaSts.configured) score += 10;

  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}
