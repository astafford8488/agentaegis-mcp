interface AbuseIPDBResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean;
    abuseConfidenceScore: number;
    countryCode: string;
    usageType: string;
    isp: string;
    domain: string;
    hostnames: string[];
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt: string;
    reports?: {
      reportedAt: string;
      comment: string;
      categories: number[];
    }[];
  };
}

export interface AbuseIPDBResult {
  ip_address: string;
  abuse_confidence_score: number;
  country_code: string;
  isp: string;
  domain: string;
  usage_type: string;
  total_reports: number;
  last_reported: string | null;
  is_whitelisted: boolean;
  categories: string[];
}

const CATEGORY_MAP: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Fraud Orders",
  4: "DDoS Attack",
  5: "FTP Brute-Force",
  6: "Ping of Death",
  7: "Phishing",
  8: "Fraud VoIP",
  9: "Open Proxy",
  10: "Web Spam",
  11: "Email Spam",
  12: "Blog Spam",
  14: "Port Scan",
  15: "Hacking",
  16: "SQL Injection",
  17: "Spoofing",
  18: "Brute-Force",
  19: "Bad Web Bot",
  20: "Exploited Host",
  21: "Web App Attack",
  22: "SSH",
  23: "IoT Targeted",
};

export async function checkIP(ipAddress: string): Promise<AbuseIPDBResult | null> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) throw new Error("ABUSEIPDB_API_KEY not configured");

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90&verbose`;

  try {
    const response = await fetch(url, {
      headers: {
        Key: apiKey,
        Accept: "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`AbuseIPDB API error: ${response.status}`);
    }

    const data: AbuseIPDBResponse = await response.json();
    const reportCategories = new Set<number>();
    data.data.reports?.forEach((r) => r.categories.forEach((c) => reportCategories.add(c)));

    return {
      ip_address: data.data.ipAddress,
      abuse_confidence_score: data.data.abuseConfidenceScore,
      country_code: data.data.countryCode,
      isp: data.data.isp,
      domain: data.data.domain,
      usage_type: data.data.usageType,
      total_reports: data.data.totalReports,
      last_reported: data.data.lastReportedAt || null,
      is_whitelisted: data.data.isWhitelisted,
      categories: Array.from(reportCategories).map((c) => CATEGORY_MAP[c] || `Category ${c}`),
    };
  } catch (err) {
    throw new Error(`AbuseIPDB lookup failed: ${err}`);
  }
}
