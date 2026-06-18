import { z } from "zod";
import * as dns from "dns/promises";
import { validateTarget } from "../../utils/sanitize.js";

export const dnsSecurityCheckSchema = z.object({
  domain: z.string().min(1),
});

export type DNSSecurityCheckInput = z.infer<typeof dnsSecurityCheckSchema>;

export async function dnsSecurityCheck(input: DNSSecurityCheckInput) {
  const { domain } = input;

  const validation = validateTarget(domain);
  if (!validation.valid) {
    return { error: validation.reason };
  }

  const results: Record<string, unknown> = {
    domain,
    records: {},
    spf: null,
    dkim: null,
    dmarc: null,
    dnssec: null,
    caa: null,
    email_security_grade: "F",
  };

  // Fetch all record types in parallel
  const [mx, txt, ns, caa] = await Promise.allSettled([
    dns.resolveMx(domain),
    dns.resolveTxt(domain),
    dns.resolveNs(domain),
    dns.resolveCaa(domain).catch(() => []),
  ]);

  results.records = {
    mx: mx.status === "fulfilled" ? mx.value : [],
    ns: ns.status === "fulfilled" ? ns.value : [],
    caa: caa.status === "fulfilled" ? caa.value : [],
  };

  // SPF Analysis
  const txtRecords = txt.status === "fulfilled" ? txt.value.map((r) => r.join("")) : [];
  const spfRecord = txtRecords.find((r) => r.startsWith("v=spf1"));
  results.spf = analyzeSPF(spfRecord);

  // DMARC Analysis
  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = dmarcRecords.map((r) => r.join("")).find((r) => r.startsWith("v=DMARC1"));
    results.dmarc = analyzeDMARC(dmarcRecord);
  } catch {
    results.dmarc = { present: false, issues: ["No DMARC record found"] };
  }

  // DKIM Check (common selectors)
  results.dkim = await checkDKIM(domain);

  // CAA Records
  results.caa = {
    present: (caa.status === "fulfilled" && (caa.value as any[]).length > 0),
    records: caa.status === "fulfilled" ? caa.value : [],
    recommendation: (caa.status === "fulfilled" && (caa.value as any[]).length > 0)
      ? "CAA records configured — limits which CAs can issue certificates"
      : "Add CAA records to restrict certificate issuance to authorized CAs",
  };

  // Dangling CNAME detection
  results.dangling_cnames = await checkDanglingCNAMEs(domain);

  // Calculate overall grade
  results.email_security_grade = calculateEmailGrade(results);

  return results;
}

function analyzeSPF(record?: string): object {
  if (!record) {
    return {
      present: false,
      issues: ["No SPF record found — any server can send email as this domain"],
      recommendation: "Add SPF record: v=spf1 include:<your-email-provider> -all",
    };
  }

  const issues: string[] = [];
  const mechanisms = record.split(" ").filter((m) => m !== "v=spf1");

  // Check for overly permissive
  if (record.includes("+all") || record.endsWith("?all")) {
    issues.push("SPF record is overly permissive (ends with +all or ?all)");
  }

  // Check include count (max 10 DNS lookups)
  const lookups = mechanisms.filter((m) =>
    m.startsWith("include:") || m.startsWith("a") || m.startsWith("mx") || m.startsWith("redirect=")
  );
  if (lookups.length > 10) {
    issues.push(`Too many DNS lookups (${lookups.length}/10 max) — SPF will fail`);
  }

  // Check for deprecated ptr mechanism
  if (mechanisms.some((m) => m.startsWith("ptr"))) {
    issues.push("Uses deprecated 'ptr' mechanism — remove for performance and reliability");
  }

  return {
    present: true,
    record,
    mechanisms: mechanisms.length,
    dns_lookups: lookups.length,
    policy: record.includes("-all") ? "fail" : record.includes("~all") ? "softfail" : "permissive",
    issues,
    pass: issues.length === 0,
  };
}

function analyzeDMARC(record?: string): object {
  if (!record) {
    return {
      present: false,
      issues: ["No DMARC record found — email spoofing protection not enforced"],
      recommendation: "Add DMARC record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
    };
  }

  const issues: string[] = [];
  const tags = Object.fromEntries(
    record.split(";").map((t) => t.trim().split("=")).filter((t) => t.length === 2)
  );

  const policy = tags.p || "none";
  if (policy === "none") {
    issues.push("DMARC policy is 'none' — spoofed emails are not blocked");
  }

  if (!tags.rua) {
    issues.push("No aggregate reporting URI (rua) — you won't receive DMARC reports");
  }

  const subdomainPolicy = tags.sp || policy;

  return {
    present: true,
    record,
    policy,
    subdomain_policy: subdomainPolicy,
    alignment_mode: tags.adkim || "relaxed",
    reporting: {
      aggregate: tags.rua || null,
      forensic: tags.ruf || null,
    },
    percentage: parseInt(tags.pct || "100"),
    issues,
    pass: policy !== "none" && issues.length === 0,
  };
}

async function checkDKIM(domain: string): Promise<object> {
  // Common selectors across major providers — Google/M365, Resend & AWS SES
  // (resend), SendGrid (s1/s2), Mailgun, Mailchimp/Mandrill (k1/k2/k3), Proton,
  // Zoho, Fastmail. Checked in parallel. (Not exhaustive — custom selectors exist.)
  const commonSelectors = [
    "google", "selector1", "selector2", "k1", "k2", "k3", "default", "dkim", "dkim1", "mail",
    "resend", "s1", "s2", "smtp", "mandrill", "mailgun", "mg", "sendgrid",
    "protonmail", "protonmail2", "protonmail3", "zmail", "fm1", "fm2", "fm3", "mte1",
  ];

  const checks = await Promise.allSettled(
    commonSelectors.map(async (selector) => {
      const records = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
      return records.length > 0 ? selector : null;
    }),
  );
  const found = checks
    .filter((r): r is PromiseFulfilledResult<string> => r.status === "fulfilled" && !!r.value)
    .map((r) => r.value);

  return {
    selectors_found: found,
    present: found.length > 0,
    note: found.length > 0
      ? `DKIM configured with selector(s): ${found.join(", ")}`
      : "No DKIM selectors found (checked common selectors). DKIM may use a custom selector.",
  };
}

async function checkDanglingCNAMEs(domain: string): Promise<object> {
  const subdomains = ["www", "mail", "app", "api", "staging", "dev"];
  const dangling: string[] = [];

  for (const sub of subdomains) {
    try {
      const cnames = await dns.resolveCname(`${sub}.${domain}`);
      for (const cname of cnames) {
        try {
          await dns.resolve(cname);
        } catch {
          dangling.push(`${sub}.${domain} → ${cname} (target does not resolve)`);
        }
      }
    } catch {
      // No CNAME for this subdomain
    }
  }

  return {
    checked: subdomains.length,
    dangling_found: dangling.length,
    dangling_records: dangling,
    risk: dangling.length > 0 ? "Dangling CNAMEs can be claimed for subdomain takeover" : "No dangling CNAMEs detected",
  };
}

function calculateEmailGrade(results: Record<string, any>): string {
  let score = 0;

  if (results.spf?.present && results.spf?.pass) score += 25;
  else if (results.spf?.present) score += 15;

  if (results.dmarc?.present && results.dmarc?.policy !== "none") score += 30;
  else if (results.dmarc?.present) score += 10;

  if (results.dkim?.present) score += 25;

  if (results.caa?.present) score += 10;
  if (!results.dangling_cnames?.dangling_found) score += 10;

  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 50) return "C";
  if (score >= 25) return "D";
  return "F";
}
