// AlienVault OTX (Open Threat Exchange)
// API docs: https://otx.alienvault.com/api
// Free, commercial use OK with API key (free signup at otx.alienvault.com).

export interface OTXIndicator {
  indicator: string;
  indicator_type: "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" | "hash_sha256";
  pulse_count: number;
  malware_families: string[];
  attack_ids: string[];
  industries: string[];
  targeted_countries: string[];
  reputation: number;
  raw_geo?: {
    asn?: string;
    country_code?: string;
    country_name?: string;
    city?: string;
  };
  recent_pulses: { name: string; created: string; tlp: string }[];
  raw_tags: string[];
}

const OTX_BASE = "https://otx.alienvault.com/api/v1/indicators";

export function isOTXConfigured(): boolean {
  return !!process.env.OTX_API_KEY;
}

function endpointFor(type: string, indicator: string): string {
  const enc = encodeURIComponent(indicator);
  switch (type) {
    case "ip": return `${OTX_BASE}/IPv4/${enc}/general`;
    case "domain": return `${OTX_BASE}/domain/${enc}/general`;
    case "url": return `${OTX_BASE}/url/${enc}/general`;
    case "hash_md5":
    case "hash_sha1":
    case "hash_sha256":
      return `${OTX_BASE}/file/${enc}/general`;
    default:
      throw new Error(`Unsupported OTX indicator type: ${type}`);
  }
}

export async function lookupOTX(
  indicator: string,
  indicatorType: OTXIndicator["indicator_type"]
): Promise<OTXIndicator | null> {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    return null;
  }

  try {
    const response = await fetch(endpointFor(indicatorType, indicator), {
      headers: { "X-OTX-API-KEY": apiKey, Accept: "application/json" },
    });

    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`OTX API error: ${response.status}`);

    const data: any = await response.json();
    const pulseInfo = data.pulse_info || {};
    const pulses: any[] = pulseInfo.pulses || [];

    // Aggregate malware families and attack IDs from pulses
    const malwareFamilies = new Set<string>();
    const attackIds = new Set<string>();
    const industries = new Set<string>();
    const targetedCountries = new Set<string>();
    const tags = new Set<string>();

    for (const pulse of pulses.slice(0, 25)) {
      (pulse.malware_families || []).forEach((m: any) => malwareFamilies.add(m.display_name || m.target));
      (pulse.attack_ids || []).forEach((a: any) => attackIds.add(a.display_name || a.id));
      (pulse.industries || []).forEach((i: string) => industries.add(i));
      (pulse.targeted_countries || []).forEach((c: string) => targetedCountries.add(c));
      (pulse.tags || []).forEach((t: string) => tags.add(t));
    }

    // Reputation heuristic: more pulses + recent = higher reputation score
    const pulseCount = pulseInfo.count || 0;
    const reputation = Math.min(100, pulseCount * 8 + (data.reputation || 0));

    return {
      indicator,
      indicator_type: indicatorType,
      pulse_count: pulseCount,
      malware_families: Array.from(malwareFamilies),
      attack_ids: Array.from(attackIds),
      industries: Array.from(industries),
      targeted_countries: Array.from(targetedCountries),
      reputation,
      raw_geo: indicatorType === "ip" ? {
        asn: data.asn,
        country_code: data.country_code,
        country_name: data.country_name,
        city: data.city,
      } : undefined,
      recent_pulses: pulses.slice(0, 5).map((p: any) => ({
        name: p.name,
        created: p.created,
        tlp: p.tlp || "white",
      })),
      raw_tags: Array.from(tags).slice(0, 20),
    };
  } catch (err) {
    throw new Error(`OTX lookup failed: ${err}`);
  }
}
