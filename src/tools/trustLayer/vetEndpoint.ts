// vet_endpoint — L2 trust-layer flagship.
//
// A composite PROCEED / CAUTION / BLOCK safety verdict for an endpoint an agent
// is about to call or pay. It runs several live security signals in parallel —
// TLS/cert health, DNS hygiene, threat-intel reputation (domain + resolved IP),
// and domain registration age — then synthesizes a single trust score and
// verdict with human-readable reasons.
//
// This is the tool the 2nd provisional patent covers: an endpoint-safety verdict
// derived from live assessments that can GATE a per-invocation agent payment.
// The scoring is a pure function (scoreEndpoint) so the verdict logic is
// unit-tested without any network.

import { z } from "zod";
import * as dns from "dns/promises";
import { validateTarget } from "../../utils/sanitize.js";
import { sslTlsAudit } from "../vulnManagement/sslTlsAudit.js";
import { dnsSecurityCheck } from "../blueTeam/dnsSecurityCheck.js";
import { threatIntelLookup } from "../blueTeam/threatIntelLookup.js";

export const vetEndpointSchema = z.object({
  endpoint: z
    .string()
    .min(1)
    .describe("The endpoint to vet — a full URL (https://api.example.com/pay) or a bare domain (example.com)."),
});
export type VetEndpointInput = z.infer<typeof vetEndpointSchema>;

export type Verdict = "PROCEED" | "CAUTION" | "BLOCK";

export interface EndpointSignals {
  reachable: boolean;
  tls: { available: boolean; grade?: string; certExpired?: boolean; certDays?: number; weakTls?: boolean; hsts?: boolean };
  dns: { available: boolean; emailGrade?: string; dmarcEnforced?: boolean; danglingCount?: number; caa?: boolean };
  threat: { available: boolean; verdict?: "CLEAN" | "SUSPICIOUS" | "MALICIOUS"; score?: number };
  domainAge: { available: boolean; ageDays?: number | null };
}

/**
 * Pure scoring: live signals → trust_score (0-100), verdict, and reasons.
 * Kept side-effect-free so the verdict policy is unit-testable. A "hard block"
 * (confirmed-malicious reputation or an invalid/expired certificate) forces
 * BLOCK regardless of the numeric score.
 */
export function scoreEndpoint(s: EndpointSignals): { trust_score: number; verdict: Verdict; reasons: string[] } {
  const reasons: string[] = [];
  let score = 100;
  let hardBlock = false;

  if (!s.reachable) {
    score -= 50;
    reasons.push("Endpoint does not resolve in DNS — cannot confirm it exists.");
  }

  // Threat intel — the strongest signal.
  if (s.threat.available) {
    if (s.threat.verdict === "MALICIOUS") {
      hardBlock = true;
      reasons.push(`Threat intel flags this endpoint as MALICIOUS (reputation ${s.threat.score ?? "?"}/100).`);
    } else if (s.threat.verdict === "SUSPICIOUS") {
      score -= 40;
      reasons.push(`Threat intel flags this endpoint as SUSPICIOUS (reputation ${s.threat.score ?? "?"}/100).`);
    } else {
      reasons.push("No malicious reputation found in threat-intel feeds.");
    }
  } else {
    score -= 5;
    reasons.push("Threat-intel reputation unavailable (no configured source matched).");
  }

  // TLS / certificate health.
  if (s.tls.available) {
    if (s.tls.certExpired) {
      hardBlock = true;
      reasons.push("TLS certificate is expired or invalid.");
    }
    if (s.tls.weakTls) {
      score -= 15;
      reasons.push("Deprecated TLS 1.0/1.1 still enabled (downgrade-attack surface).");
    }
    if (s.tls.grade === "F") { score -= 30; reasons.push("TLS configuration graded F."); }
    else if (s.tls.grade === "D") { score -= 20; reasons.push("TLS configuration graded D."); }
    else if (s.tls.grade === "C") { score -= 10; reasons.push("TLS configuration graded C."); }
    if (s.tls.hsts === false) { score -= 5; reasons.push("HSTS not enabled."); }
    if (typeof s.tls.certDays === "number" && s.tls.certDays > 0 && s.tls.certDays < 30) {
      score -= 5;
      reasons.push(`TLS certificate expires in ${s.tls.certDays} days.`);
    }
  } else {
    score -= 25;
    reasons.push("No valid HTTPS/TLS endpoint reachable — agents should not transact over plaintext.");
  }

  // Domain registration age — new domains are a strong fraud/phishing signal.
  if (s.domainAge.available && typeof s.domainAge.ageDays === "number") {
    const d = s.domainAge.ageDays;
    if (d < 30) { score -= 30; reasons.push(`Domain registered ${d} days ago — very new (common in fraud/phishing).`); }
    else if (d < 90) { score -= 15; reasons.push(`Domain registered ${d} days ago — recently created.`); }
    else if (d < 180) { score -= 5; reasons.push(`Domain registered ${d} days ago.`); }
    else { reasons.push(`Domain is established (~${Math.floor(d / 365)}y old).`); }
  } else {
    score -= 5;
    reasons.push("Domain registration age unavailable (RDAP not supported for this TLD).");
  }

  // DNS hygiene.
  if (s.dns.available) {
    if ((s.dns.danglingCount ?? 0) > 0) {
      score -= 20;
      reasons.push(`${s.dns.danglingCount} dangling CNAME(s) detected — subdomain-takeover risk.`);
    }
    if (s.dns.emailGrade === "F") { score -= 10; reasons.push("Email-auth posture (SPF/DKIM/DMARC) graded F."); }
    else if (s.dns.emailGrade === "D") { score -= 5; reasons.push("Email-auth posture graded D."); }
    if (s.dns.dmarcEnforced === false) { score -= 5; reasons.push("DMARC not enforced — domain is spoofable."); }
  }

  score = Math.max(0, Math.min(100, score));

  let verdict: Verdict;
  if (hardBlock) {
    verdict = "BLOCK";
    score = Math.min(score, 25); // a hard block should read as a low score too
  } else if (score < 45) {
    verdict = "BLOCK";
  } else if (score < 75) {
    verdict = "CAUTION";
  } else {
    verdict = "PROCEED";
  }

  return { trust_score: score, verdict, reasons };
}

/** Parse a hostname from a URL or bare-domain input. */
export function extractHostname(endpoint: string): string | null {
  const t = endpoint.trim();
  try {
    if (/^https?:\/\//i.test(t)) return new URL(t).hostname;
    if (t.includes("/") || t.includes(":")) return new URL("https://" + t).hostname;
    return t;
  } catch {
    return null;
  }
}

/** Domain registration age in days via RDAP (free, no API key). null if unknown. */
async function getDomainAgeDays(hostname: string): Promise<number | null> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(hostname)}`, {
      signal: ctrl.signal,
      headers: { accept: "application/rdap+json" },
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data: any = await res.json();
    const reg = (data.events || []).find((e: any) => e.eventAction === "registration");
    if (!reg?.eventDate) return null;
    const ms = Date.now() - new Date(reg.eventDate).getTime();
    return ms > 0 ? Math.floor(ms / 86_400_000) : null;
  } catch {
    return null;
  }
}

export async function vetEndpoint(input: VetEndpointInput) {
  const hostname = extractHostname(input.endpoint);
  if (!hostname) return { error: "Could not parse a hostname from the endpoint." };

  const v = validateTarget(hostname);
  if (!v.valid) return { error: v.reason };

  // Resolve once — gives reachability and an IP for IP-based threat intel.
  let ip: string | null = null;
  try {
    const addrs = await dns.resolve4(hostname);
    ip = addrs[0] || null;
  } catch {
    ip = null;
  }

  const [tlsR, dnsR, threatDomainR, threatIpR, ageR] = await Promise.allSettled([
    sslTlsAudit({ hostname }),
    dnsSecurityCheck({ domain: hostname }),
    threatIntelLookup({ indicator: hostname, indicator_type: "domain" }),
    ip ? threatIntelLookup({ indicator: ip, indicator_type: "ip" }) : Promise.resolve(null),
    getDomainAgeDays(hostname),
  ]);

  const settled = (r: PromiseSettledResult<any>): any => (r.status === "fulfilled" ? r.value : null);
  const tls = settled(tlsR);
  const dnsv = settled(dnsR);
  const td = settled(threatDomainR);
  const ti = settled(threatIpR);
  const age = settled(ageR) as number | null;

  // Threat = the worse of the domain and resolved-IP lookups.
  const rank: Record<string, number> = { CLEAN: 0, SUSPICIOUS: 1, MALICIOUS: 2 };
  const threatVals = [td, ti].filter((x) => x && !x.error && x.verdict);
  let threat: EndpointSignals["threat"] = { available: false };
  if (threatVals.length) {
    const worst = threatVals.reduce((a, b) => (rank[b.verdict] > rank[a.verdict] ? b : a));
    threat = { available: true, verdict: worst.verdict, score: worst.reputation_score };
  }

  const signals: EndpointSignals = {
    reachable: !!ip,
    tls:
      tls && !tls.error
        ? {
            available: true,
            grade: tls.grade,
            certExpired:
              typeof tls.certificate?.days_until_expiry === "number" ? tls.certificate.days_until_expiry <= 0 : undefined,
            certDays: tls.certificate?.days_until_expiry,
            weakTls: !!(tls.protocol_support?.tls_1_0 || tls.protocol_support?.tls_1_1),
            hsts: tls.hsts?.enabled,
          }
        : { available: false },
    dns:
      dnsv && !dnsv.error
        ? {
            available: true,
            emailGrade: dnsv.email_security_grade,
            dmarcEnforced: !!(dnsv.dmarc?.present && dnsv.dmarc?.policy && dnsv.dmarc.policy !== "none"),
            danglingCount: dnsv.dangling_cnames?.dangling_found ?? 0,
            caa: !!dnsv.caa?.present,
          }
        : { available: false },
    threat,
    domainAge: { available: age !== null, ageDays: age },
  };

  const { trust_score, verdict, reasons } = scoreEndpoint(signals);

  return {
    endpoint: input.endpoint,
    hostname,
    resolved_ip: ip,
    verdict,
    trust_score,
    recommendation:
      verdict === "PROCEED"
        ? "Safe to transact with based on current signals."
        : verdict === "CAUTION"
          ? "Proceed only with added safeguards (spending caps, human confirmation, retry-on-anomaly)."
          : "Do not transact — block this endpoint.",
    reasons,
    signals: {
      reachable: signals.reachable,
      tls: signals.tls,
      dns_hygiene: signals.dns,
      threat_intel: signals.threat,
      domain_age_days: age,
    },
    checked_at: new Date().toISOString(),
    disclaimer:
      "Heuristic composite verdict from live signals at check time; not a guarantee of safety. Re-vet before high-value transfers.",
  };
}
