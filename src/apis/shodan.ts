export interface ShodanHostResult {
  ip: string;
  hostnames: string[];
  org: string;
  os: string | null;
  ports: number[];
  vulns: string[];
  country_code: string;
  city: string;
  isp: string;
  last_update: string;
}

export async function lookupHost(ip: string): Promise<ShodanHostResult | null> {
  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) throw new Error("SHODAN_API_KEY not configured");

  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${apiKey}`;

  try {
    const response = await fetch(url);
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`Shodan API error: ${response.status}`);

    const data = await response.json();
    return {
      ip: data.ip_str,
      hostnames: data.hostnames || [],
      org: data.org || "",
      os: data.os || null,
      ports: data.ports || [],
      vulns: data.vulns ? Object.keys(data.vulns) : [],
      country_code: data.country_code || "",
      city: data.city || "",
      isp: data.isp || "",
      last_update: data.last_update || "",
    };
  } catch (err) {
    throw new Error(`Shodan lookup failed: ${err}`);
  }
}
