import { z } from "zod";
import { checkIP } from "../../apis/abuseipdb.js";
import { lookupOTX, isOTXConfigured } from "../../apis/alienvault.js";
import { lookupAbuseCH, isAbusechConfigured } from "../../apis/abusech.js";

export const threatIntelLookupSchema = z.object({
  indicator: z.string(),
  indicator_type: z.enum(["ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"]),
});

export type ThreatIntelLookupInput = z.infer<typeof threatIntelLookupSchema>;

export async function threatIntelLookup(input: ThreatIntelLookupInput) {
  const { indicator, indicator_type } = input;
  const sources: Record<string, unknown> = {};
  let overallScore = 0;
  let isMalicious = false;
  const recommendations: string[] = [];
  const malwareFamilies = new Set<string>();
  const tags = new Set<string>();

  // === AbuseIPDB (IP-only) ===
  if (indicator_type === "ip") {
    try {
      const abuseResult = await checkIP(indicator);
      sources.abuseipdb = abuseResult;
      if (abuseResult) {
        overallScore = Math.max(overallScore, abuseResult.abuse_confidence_score);
        if (abuseResult.abuse_confidence_score > 50) isMalicious = true;
        abuseResult.categories.forEach((c) => tags.add(c));
      }
    } catch (err) {
      sources.abuseipdb = { error: String(err) };
    }
  }

  // === AlienVault OTX (all indicator types) ===
  if (isOTXConfigured()) {
    try {
      const otxResult = await lookupOTX(indicator, indicator_type);
      sources.alienvault_otx = otxResult;
      if (otxResult) {
        overallScore = Math.max(overallScore, otxResult.reputation);
        if (otxResult.pulse_count > 3 || otxResult.malware_families.length > 0) {
          isMalicious = true;
        }
        otxResult.malware_families.forEach((m) => malwareFamilies.add(m));
        otxResult.raw_tags.forEach((t) => tags.add(t));
      }
    } catch (err) {
      sources.alienvault_otx = { error: String(err) };
    }
  } else {
    sources.alienvault_otx = { skipped: "OTX_API_KEY not configured (free at otx.alienvault.com)" };
  }

  // === abuse.ch (URLhaus + ThreatFox + MalwareBazaar) ===
  if (isAbusechConfigured()) {
    try {
      const abusechResults = await lookupAbuseCH(indicator, indicator_type);
      sources.abuse_ch = abusechResults;
      for (const r of abusechResults) {
        if (r.found) {
          isMalicious = true;
          overallScore = Math.max(overallScore, r.confidence || 80);
          if (r.malware_family) malwareFamilies.add(r.malware_family);
          (r.tags || []).forEach((t) => tags.add(t));
        }
      }
    } catch (err) {
      sources.abuse_ch = { error: String(err) };
    }
  } else {
    sources.abuse_ch = { skipped: "ABUSECH_API_KEY not configured (free at auth.abuse.ch)" };
  }

  // === Generate recommendations ===
  if (isMalicious) {
    recommendations.push(`Block ${indicator} at firewall/WAF immediately`);
    if (indicator_type === "ip") {
      recommendations.push("Check logs for connections to/from this IP");
      recommendations.push("Investigate any systems that communicated with this IP");
    } else if (indicator_type === "domain") {
      recommendations.push("Block domain at DNS level");
      recommendations.push("Check for any DNS queries to this domain in logs");
    } else if (indicator_type === "url") {
      recommendations.push("Block URL at web filter / proxy");
      recommendations.push("Check email/web logs for clicks on this URL");
    } else if (indicator_type.startsWith("hash")) {
      recommendations.push("Search endpoints for this file hash via EDR");
      recommendations.push("Quarantine any systems where this file is found");
    }
    if (malwareFamilies.size > 0) {
      recommendations.push(`Associated with ${Array.from(malwareFamilies).slice(0, 3).join(", ")} — review the corresponding playbook`);
    }
  } else {
    recommendations.push("No immediate threat detected — continue monitoring");
  }

  return {
    indicator,
    indicator_type,
    reputation_score: Math.round(overallScore),
    is_malicious: isMalicious,
    verdict: overallScore > 75 ? "MALICIOUS" : overallScore > 25 ? "SUSPICIOUS" : "CLEAN",
    associated_malware: Array.from(malwareFamilies),
    tags: Array.from(tags).slice(0, 30),
    sources,
    recommendations,
    last_checked: new Date().toISOString(),
  };
}
