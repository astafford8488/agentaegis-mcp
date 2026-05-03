interface NVDResponse {
  vulnerabilities: {
    cve: {
      id: string;
      descriptions: { lang: string; value: string }[];
      metrics?: {
        cvssMetricV31?: {
          cvssData: {
            vectorString: string;
            baseScore: number;
            baseSeverity: string;
          };
          exploitabilityScore: number;
          impactScore: number;
        }[];
      };
      weaknesses?: {
        description: { lang: string; value: string }[];
      }[];
      configurations?: {
        nodes: {
          cpeMatch: {
            vulnerable: boolean;
            criteria: string;
          }[];
        }[];
      }[];
      references?: {
        url: string;
        source: string;
        tags?: string[];
      }[];
      published: string;
      lastModified: string;
    };
  }[];
}

export interface CVEDetail {
  id: string;
  description: string;
  published: string;
  last_modified: string;
  cvss_v3: {
    score: number;
    vector: string;
    severity: string;
    exploitability_score: number;
    impact_score: number;
  } | null;
  cwe: string[];
  affected_products: string[];
  references: { url: string; source: string; tags: string[] }[];
  is_in_kev: boolean;
}

const cache = new Map<string, { data: CVEDetail; timestamp: number }>();
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

export async function lookupCVE(cveId: string): Promise<CVEDetail | null> {
  const cached = cache.get(cveId);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }

  const apiKey = process.env.NVD_API_KEY;
  const headers: Record<string, string> = { "Accept": "application/json" };
  if (apiKey) headers["apiKey"] = apiKey;

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;

  try {
    const response = await fetch(url, { headers });
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`NVD API error: ${response.status}`);
    }

    const data: NVDResponse = await response.json();
    if (!data.vulnerabilities?.length) return null;

    const cve = data.vulnerabilities[0].cve;
    const cvssMetric = cve.metrics?.cvssMetricV31?.[0];

    const detail: CVEDetail = {
      id: cve.id,
      description: cve.descriptions.find((d) => d.lang === "en")?.value || "",
      published: cve.published,
      last_modified: cve.lastModified,
      cvss_v3: cvssMetric ? {
        score: cvssMetric.cvssData.baseScore,
        vector: cvssMetric.cvssData.vectorString,
        severity: cvssMetric.cvssData.baseSeverity,
        exploitability_score: cvssMetric.exploitabilityScore,
        impact_score: cvssMetric.impactScore,
      } : null,
      cwe: cve.weaknesses?.flatMap((w) => w.description.map((d) => d.value)) || [],
      affected_products: cve.configurations?.flatMap((c) =>
        c.nodes.flatMap((n) => n.cpeMatch.filter((m) => m.vulnerable).map((m) => m.criteria))
      ) || [],
      references: cve.references?.map((r) => ({
        url: r.url,
        source: r.source,
        tags: r.tags || [],
      })) || [],
      is_in_kev: false, // Will check CISA KEV separately
    };

    cache.set(cveId, { data: detail, timestamp: Date.now() });
    return detail;
  } catch (err) {
    throw new Error(`CVE lookup failed: ${err}`);
  }
}

export async function checkKEV(cveId: string): Promise<boolean> {
  try {
    const response = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!response.ok) return false;
    const data = await response.json();
    return data.vulnerabilities?.some((v: { cveID: string }) => v.cveID === cveId) || false;
  } catch {
    return false;
  }
}
