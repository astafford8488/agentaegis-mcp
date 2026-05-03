import { z } from "zod";
import { checkIP } from "../../apis/abuseipdb.js";
import { lookupIndicator } from "../../apis/virustotal.js";

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

  // AbuseIPDB (for IPs)
  if (indicator_type === "ip") {
    try {
      const abuseResult = await checkIP(indicator);
      sources.abuseipdb = abuseResult;
      if (abuseResult) {
        overallScore = Math.max(overallScore, abuseResult.abuse_confidence_score);
        if (abuseResult.abuse_confidence_score > 50) isMalicious = true;
      }
    } catch (err) {
      sources.abuseipdb = { error: String(err) };
    }
  }

  // VirusTotal (for all types)
  try {
    const vtResult = await lookupIndicator(indicator, indicator_type);
    sources.virustotal = vtResult;
    if (vtResult) {
      const detectionRate = vtResult.detection_ratio.total > 0
        ? (vtResult.detection_ratio.malicious / vtResult.detection_ratio.total) * 100
        : 0;
      overallScore = Math.max(overallScore, detectionRate);
      if (detectionRate > 10) isMalicious = true;
    }
  } catch (err) {
    sources.virustotal = { error: String(err) };
  }

  // Generate recommendations
  if (isMalicious) {
    recommendations.push(`Block ${indicator} at firewall/WAF immediately`);
    if (indicator_type === "ip") {
      recommendations.push("Check logs for connections to/from this IP");
      recommendations.push("Investigate any systems that communicated with this IP");
    } else if (indicator_type === "domain") {
      recommendations.push("Block domain at DNS level");
      recommendations.push("Check for any DNS queries to this domain in logs");
    } else if (indicator_type.startsWith("hash")) {
      recommendations.push("Search endpoints for this file hash");
      recommendations.push("Quarantine any systems where this file is found");
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
    sources,
    recommendations,
    last_checked: new Date().toISOString(),
  };
}
