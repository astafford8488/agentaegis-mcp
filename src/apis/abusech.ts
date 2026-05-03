// abuse.ch threat intelligence APIs
//   - URLhaus  : malicious URL database
//   - ThreatFox: IOC database (IPs, domains, hashes)
//   - MalwareBazaar: malware sample database (hashes)
// All free, commercial use OK with attribution.
// API key (free): https://auth.abuse.ch  (Auth-Key header)

export interface AbusechResult {
  source: "urlhaus" | "threatfox" | "malwarebazaar";
  found: boolean;
  threat_type?: string;
  malware_family?: string;
  tags?: string[];
  first_seen?: string;
  last_seen?: string;
  confidence?: number;
  raw?: Record<string, unknown>;
}

const URLHAUS_API = "https://urlhaus-api.abuse.ch/v1";
const THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1";
const MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1";

export function isAbusechConfigured(): boolean {
  return !!process.env.ABUSECH_API_KEY;
}

function authHeaders() {
  const key = process.env.ABUSECH_API_KEY;
  if (!key) throw new Error("ABUSECH_API_KEY not configured");
  return { "Auth-Key": key, Accept: "application/json" };
}

// === URLhaus — URL or host lookup ===
export async function lookupURLHaus(target: string, type: "url" | "host"): Promise<AbusechResult> {
  if (!isAbusechConfigured()) return { source: "urlhaus", found: false };

  try {
    const body = new URLSearchParams();
    body.append(type, target);

    const response = await fetch(`${URLHAUS_API}/${type}/`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) return { source: "urlhaus", found: false };

    const data: any = await response.json();
    if (data.query_status !== "ok" || !data.urls?.length && !data.url) {
      return { source: "urlhaus", found: false };
    }

    const first = data.urls?.[0] || data;
    return {
      source: "urlhaus",
      found: true,
      threat_type: first.threat || "malware_distribution",
      malware_family: first.tags?.find((t: string) => /^[A-Z]/.test(t)),
      tags: first.tags || [],
      first_seen: first.date_added || first.firstseen,
      last_seen: first.last_online,
      confidence: 95,
      raw: first,
    };
  } catch {
    return { source: "urlhaus", found: false };
  }
}

// === ThreatFox — IOC lookup (IP, domain, hash, etc.) ===
export async function lookupThreatFox(indicator: string): Promise<AbusechResult> {
  if (!isAbusechConfigured()) return { source: "threatfox", found: false };

  try {
    const response = await fetch(`${THREATFOX_API}/`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ query: "search_ioc", search_term: indicator }),
    });

    if (!response.ok) return { source: "threatfox", found: false };

    const data: any = await response.json();
    if (data.query_status !== "ok" || !data.data?.length) {
      return { source: "threatfox", found: false };
    }

    const tags = new Set<string>();
    const malwareFamilies = new Set<string>();
    let earliest: string | undefined;
    let latest: string | undefined;
    let maxConfidence = 0;

    for (const entry of data.data) {
      (entry.tags || []).forEach((t: string) => tags.add(t));
      if (entry.malware_printable) malwareFamilies.add(entry.malware_printable);
      if (entry.first_seen && (!earliest || entry.first_seen < earliest)) earliest = entry.first_seen;
      if (entry.last_seen && (!latest || entry.last_seen > latest)) latest = entry.last_seen;
      if (entry.confidence_level && entry.confidence_level > maxConfidence) maxConfidence = entry.confidence_level;
    }

    return {
      source: "threatfox",
      found: true,
      threat_type: data.data[0].threat_type,
      malware_family: Array.from(malwareFamilies)[0],
      tags: Array.from(tags),
      first_seen: earliest,
      last_seen: latest,
      confidence: maxConfidence,
      raw: { entry_count: data.data.length, malware_families: Array.from(malwareFamilies) },
    };
  } catch {
    return { source: "threatfox", found: false };
  }
}

// === MalwareBazaar — hash lookup ===
export async function lookupMalwareBazaar(hash: string): Promise<AbusechResult> {
  if (!isAbusechConfigured()) return { source: "malwarebazaar", found: false };

  try {
    const body = new URLSearchParams();
    body.append("query", "get_info");
    body.append("hash", hash);

    const response = await fetch(`${MALWAREBAZAAR_API}/`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!response.ok) return { source: "malwarebazaar", found: false };

    const data: any = await response.json();
    if (data.query_status !== "ok" || !data.data?.length) {
      return { source: "malwarebazaar", found: false };
    }

    const sample = data.data[0];
    return {
      source: "malwarebazaar",
      found: true,
      threat_type: sample.signature || "malware",
      malware_family: sample.signature,
      tags: sample.tags || [],
      first_seen: sample.first_seen,
      last_seen: sample.last_seen,
      confidence: 100, // Confirmed sample in DB
      raw: {
        file_name: sample.file_name,
        file_size: sample.file_size,
        file_type: sample.file_type,
        sha256: sample.sha256_hash,
      },
    };
  } catch {
    return { source: "malwarebazaar", found: false };
  }
}

/**
 * Convenience: dispatch to the right abuse.ch endpoint based on indicator type.
 * Returns an aggregated result merging URLhaus + ThreatFox (+ MalwareBazaar for hashes).
 */
export async function lookupAbuseCH(
  indicator: string,
  indicatorType: "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" | "hash_sha256"
): Promise<AbusechResult[]> {
  const results: Promise<AbusechResult>[] = [];

  if (indicatorType === "url") {
    results.push(lookupURLHaus(indicator, "url"));
    results.push(lookupThreatFox(indicator));
  } else if (indicatorType === "ip" || indicatorType === "domain") {
    results.push(lookupURLHaus(indicator, "host"));
    results.push(lookupThreatFox(indicator));
  } else {
    // Hash types
    results.push(lookupMalwareBazaar(indicator));
    results.push(lookupThreatFox(indicator));
  }

  return Promise.all(results);
}
