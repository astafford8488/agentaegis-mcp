export interface VirusTotalResult {
  indicator: string;
  indicator_type: string;
  detection_ratio: { malicious: number; total: number };
  reputation: number;
  tags: string[];
  last_analysis_date: string | null;
  community_score: number;
  details: Record<string, unknown>;
}

export function isVirusTotalConfigured(): boolean {
  return !!process.env.VIRUSTOTAL_API_KEY;
}

export async function lookupIndicator(
  indicator: string,
  indicatorType: "ip" | "domain" | "url" | "hash_md5" | "hash_sha1" | "hash_sha256"
): Promise<VirusTotalResult | null> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    // Caller should check isVirusTotalConfigured() first; if they didn't,
    // we return null rather than throwing so the surrounding logic can
    // gracefully aggregate from other sources.
    return null;
  }

  let endpoint: string;
  switch (indicatorType) {
    case "ip":
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`;
      break;
    case "domain":
      endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`;
      break;
    case "url":
      const urlId = Buffer.from(indicator).toString("base64url");
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      break;
    case "hash_md5":
    case "hash_sha1":
    case "hash_sha256":
      endpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`;
      break;
  }

  try {
    const response = await fetch(endpoint, {
      headers: {
        "x-apikey": apiKey,
        "Accept": "application/json",
      },
    });

    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`VirusTotal API error: ${response.status}`);
    }

    const data = await response.json();
    const attrs = data.data?.attributes;
    const stats = attrs?.last_analysis_stats || {};

    return {
      indicator,
      indicator_type: indicatorType,
      detection_ratio: {
        malicious: (stats.malicious || 0) + (stats.suspicious || 0),
        total: Object.values(stats).reduce((a: number, b: unknown) => a + (b as number), 0) as number,
      },
      reputation: attrs?.reputation || 0,
      tags: attrs?.tags || [],
      last_analysis_date: attrs?.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      community_score: attrs?.total_votes?.harmless - attrs?.total_votes?.malicious || 0,
      details: {
        as_owner: attrs?.as_owner,
        country: attrs?.country,
        network: attrs?.network,
      },
    };
  } catch (err) {
    throw new Error(`VirusTotal lookup failed: ${err}`);
  }
}
