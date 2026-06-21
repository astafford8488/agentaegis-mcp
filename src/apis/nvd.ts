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

// NVD's API returns transient 503s and 429 rate-limits (especially without a key).
// A paid cve_lookup that hits one used to fail the whole call even though the caller
// already settled x402. Retry a few times with a short backoff so an upstream blip
// doesn't burn a paid request. Non-5xx/429 responses (incl. 404) return immediately.
async function fetchNvdWithRetry(url: string, headers: Record<string, string>, attempts = 3): Promise<Response> {
  let lastErr: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      const response = await fetch(url, { headers });
      if ((response.status >= 500 || response.status === 429) && i < attempts - 1) {
        lastErr = new Error(`NVD API error: ${response.status}`);
        await new Promise((r) => setTimeout(r, 600 * (i + 1)));
        continue;
      }
      return response;
    } catch (e) {
      lastErr = e;
      if (i < attempts - 1) {
        await new Promise((r) => setTimeout(r, 600 * (i + 1)));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

// Compute a CVSS v3.1 base score from its vector string (e.g. "CVSS:3.1/AV:N/...").
// OSV (our NVD fallback) returns the vector, not the numeric score, so we derive it.
// Deterministic per the CVSS 3.1 spec; returns null if the vector is malformed.
function cvss31BaseScoreFromVector(vector: string): number | null {
  const m: Record<string, string> = {};
  for (const part of vector.split("/")) {
    const [k, v] = part.split(":");
    if (k && v) m[k] = v;
  }
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62 };
  const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const scopeChanged = m["S"] === "C";
  const PR = (scopeChanged
    ? { N: 0.85, L: 0.68, H: 0.5 }
    : { N: 0.85, L: 0.62, H: 0.27 }) as Record<string, number>;
  const av = AV[m["AV"]], ac = AC[m["AC"]], ui = UI[m["UI"]], pr = PR[m["PR"]];
  const c = CIA[m["C"]], i = CIA[m["I"]], a = CIA[m["A"]];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged ? 1.08 * (impact + exploitability) : impact + exploitability;
  return Math.ceil(Math.min(raw, 10) * 10) / 10; // CVSS roundup to 1 decimal
}

// Fallback CVE source. NVD soft-blocks datacenter/cloud egress IPs with 503s even
// when an API key is set, which made cve_lookup unreliable on Railway. OSV (Google-
// run) answers reliably from cloud and keys by CVE id. We map its schema to CVEDetail.
async function lookupCVEViaOSV(cveId: string): Promise<CVEDetail | null> {
  const resp = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`, {
    headers: { Accept: "application/json" },
  });
  if (!resp.ok) return null;
  const v = (await resp.json()) as {
    id?: string; summary?: string; details?: string; published?: string; modified?: string;
    severity?: { type?: string; score?: string }[];
    references?: { type?: string; url?: string }[];
  };
  if (!v?.id) return null;

  const vector = (v.severity || []).find((s) => /CVSS_V3/i.test(s.type || ""))?.score;
  const score = vector ? cvss31BaseScoreFromVector(vector) : null;
  const severity = score == null ? "" : score >= 9 ? "CRITICAL" : score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW";

  return {
    id: v.id,
    description: (v.details || v.summary || "").slice(0, 1000),
    published: v.published || "",
    last_modified: v.modified || "",
    cvss_v3: vector && score != null
      ? { score, vector, severity, exploitability_score: 0, impact_score: 0 }
      : null,
    cwe: [],
    affected_products: [],
    references: (v.references || []).filter((r) => r.url).map((r) => ({ url: r.url as string, source: "OSV", tags: r.type ? [r.type] : [] })),
    is_in_kev: false,
  };
}

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
    const response = await fetchNvdWithRetry(url, headers);
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
    // NVD failed (commonly a 503 — NVD throttles datacenter/cloud egress IPs even
    // with an API key). Fall back to OSV so a paid cve_lookup still returns data
    // instead of an error the caller already settled for.
    const osv = await lookupCVEViaOSV(cveId).catch(() => null);
    if (osv) {
      cache.set(cveId, { data: osv, timestamp: Date.now() });
      return osv;
    }
    throw new Error(`CVE lookup failed (NVD + OSV both unavailable): ${err}`);
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
