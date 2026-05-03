export interface BreachInfo {
  name: string;
  title: string;
  domain: string;
  breach_date: string;
  added_date: string;
  modified_date: string;
  pwn_count: number;
  description: string;
  data_classes: string[];
  is_verified: boolean;
  is_sensitive: boolean;
}

export interface DomainBreachSummary {
  domain: string;
  total_breached_accounts: number;
  breaches: {
    name: string;
    breach_date: string;
    pwn_count: number;
    data_classes: string[];
  }[];
}

export async function checkEmail(email: string): Promise<BreachInfo[]> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) throw new Error("HIBP_API_KEY not configured");

  const url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`;

  try {
    const response = await fetch(url, {
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": "AgentAegis-MCP",
      },
    });

    if (response.status === 404) return [];
    if (!response.ok) throw new Error(`HIBP API error: ${response.status}`);

    const data = await response.json();
    return data.map((b: any) => ({
      name: b.Name,
      title: b.Title,
      domain: b.Domain,
      breach_date: b.BreachDate,
      added_date: b.AddedDate,
      modified_date: b.ModifiedDate,
      pwn_count: b.PwnCount,
      description: b.Description,
      data_classes: b.DataClasses,
      is_verified: b.IsVerified,
      is_sensitive: b.IsSensitive,
    }));
  } catch (err) {
    throw new Error(`HIBP email check failed: ${err}`);
  }
}

export async function checkDomain(domain: string): Promise<DomainBreachSummary> {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey) throw new Error("HIBP_API_KEY not configured");

  const url = `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`;

  try {
    const response = await fetch(url, {
      headers: {
        "hibp-api-key": apiKey,
        "User-Agent": "AgentAegis-MCP",
      },
    });

    if (response.status === 404) {
      return { domain, total_breached_accounts: 0, breaches: [] };
    }
    if (!response.ok) throw new Error(`HIBP API error: ${response.status}`);

    const data = await response.json();
    const breaches = data.map((b: any) => ({
      name: b.Name,
      breach_date: b.BreachDate,
      pwn_count: b.PwnCount,
      data_classes: b.DataClasses,
    }));

    return {
      domain,
      total_breached_accounts: breaches.reduce((sum: number, b: any) => sum + b.pwn_count, 0),
      breaches,
    };
  } catch (err) {
    throw new Error(`HIBP domain check failed: ${err}`);
  }
}
