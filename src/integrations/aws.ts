// AWS evidence collection (read-only).
//
// Pulls observable security configuration from an AWS account so the
// evidence_collect tool can return real artifacts.
//
// This client uses AWS REST APIs over signed HTTPS rather than pulling in
// the full aws-sdk dependency. Functions are intentionally minimal — we
// only need a handful of read calls to demonstrate evidence collection.
//
// Required IAM permissions on the credentials supplied by the customer:
//   iam:ListUsers, iam:ListMFADevices, iam:GetAccountSummary,
//   iam:GetAccountPasswordPolicy, s3:ListAllMyBuckets, s3:GetBucketPolicyStatus,
//   s3:GetBucketEncryption, cloudtrail:DescribeTrails

import * as crypto from "crypto";

export interface AWSEvidenceBundle {
  collected_at: string;
  account_id: string | null;
  account_summary: Record<string, number> | null;
  password_policy: Record<string, unknown> | null;
  iam_users: { name: string; mfa_devices: number; access_keys_active: number; }[];
  s3_buckets: { name: string; public: boolean; encrypted: boolean | null; }[];
  cloudtrail_status: { trails_configured: number; multi_region: boolean; logging: boolean; } | null;
  control_evidence: {
    root_mfa: boolean | "unknown";
    iam_user_mfa_coverage: number; // 0–1
    password_policy_strong: boolean;
    public_buckets: number;
    unencrypted_buckets: number;
    cloudtrail_active: boolean;
  };
  warnings: string[];
}

export interface AWSCredentials {
  access_key_id: string;
  secret_access_key: string;
  session_token?: string;
  region?: string;
}

// === SigV4 signing ===
function hmac(key: Buffer | string, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

function getSigningKey(secretKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmac("AWS4" + secretKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, "aws4_request");
}

function sign(
  method: string,
  url: string,
  service: string,
  region: string,
  creds: AWSCredentials,
  body: string = "",
  extraHeaders: Record<string, string> = {}
): { headers: Record<string, string> } {
  const u = new URL(url);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.slice(0, 8);

  const canonicalUri = u.pathname || "/";
  const canonicalQuery = u.searchParams.toString();
  const payloadHash = crypto.createHash("sha256").update(body).digest("hex");

  const headers: Record<string, string> = {
    Host: u.hostname,
    "X-Amz-Date": amzDate,
    "X-Amz-Content-Sha256": payloadHash,
    ...extraHeaders,
  };
  if (creds.session_token) headers["X-Amz-Security-Token"] = creds.session_token;

  const sortedHeaderNames = Object.keys(headers).map((h) => h.toLowerCase()).sort();
  const canonicalHeaders = sortedHeaderNames.map((h) => `${h}:${headers[Object.keys(headers).find((k) => k.toLowerCase() === h)!].trim()}\n`).join("");
  const signedHeaders = sortedHeaderNames.join(";");

  const canonicalRequest = [method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const credScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, credScope, crypto.createHash("sha256").update(canonicalRequest).digest("hex")].join("\n");
  const signingKey = getSigningKey(creds.secret_access_key, dateStamp, region, service);
  const signature = crypto.createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");

  headers.Authorization = `AWS4-HMAC-SHA256 Credential=${creds.access_key_id}/${credScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers };
}

async function awsCall(method: string, url: string, service: string, region: string, creds: AWSCredentials, body: string = "", extraHeaders: Record<string, string> = {}): Promise<string> {
  const { headers } = sign(method, url, service, region, creds, body, extraHeaders);
  const r = await fetch(url, { method, headers, body: body || undefined });
  const text = await r.text();
  if (!r.ok) throw new Error(`AWS ${service} ${r.status}: ${text.slice(0, 200)}`);
  return text;
}

// === Public collectors ===

export async function collectAWSEvidence(creds: AWSCredentials): Promise<AWSEvidenceBundle> {
  const region = creds.region || "us-east-1";
  const warnings: string[] = [];
  const result: AWSEvidenceBundle = {
    collected_at: new Date().toISOString(),
    account_id: null,
    account_summary: null,
    password_policy: null,
    iam_users: [],
    s3_buckets: [],
    cloudtrail_status: null,
    control_evidence: {
      root_mfa: "unknown",
      iam_user_mfa_coverage: 0,
      password_policy_strong: false,
      public_buckets: 0,
      unencrypted_buckets: 0,
      cloudtrail_active: false,
    },
    warnings,
  };

  // Account summary (gives account ID, root MFA status indirectly)
  try {
    const xml = await awsCall(
      "POST",
      `https://iam.amazonaws.com/`,
      "iam",
      "us-east-1",
      creds,
      "Action=GetAccountSummary&Version=2010-05-08",
      { "Content-Type": "application/x-www-form-urlencoded" }
    );
    const summary: Record<string, number> = {};
    const matches = xml.matchAll(/<entry>\s*<key>([^<]+)<\/key>\s*<value>(\d+)<\/value>\s*<\/entry>/g);
    for (const m of matches) summary[m[1]] = parseInt(m[2]);
    result.account_summary = summary;
    result.control_evidence.root_mfa = summary.AccountMFAEnabled === 1;
  } catch (err) {
    warnings.push(`account_summary: ${String(err).slice(0, 100)}`);
  }

  // Password policy
  try {
    const xml = await awsCall(
      "POST",
      `https://iam.amazonaws.com/`,
      "iam",
      "us-east-1",
      creds,
      "Action=GetAccountPasswordPolicy&Version=2010-05-08",
      { "Content-Type": "application/x-www-form-urlencoded" }
    );
    const minLen = parseInt(xml.match(/<MinimumPasswordLength>(\d+)<\/MinimumPasswordLength>/)?.[1] || "0");
    const requireSymbols = /<RequireSymbols>true<\/RequireSymbols>/.test(xml);
    const requireNumbers = /<RequireNumbers>true<\/RequireNumbers>/.test(xml);
    const requireUpper = /<RequireUppercaseCharacters>true<\/RequireUppercaseCharacters>/.test(xml);
    const requireLower = /<RequireLowercaseCharacters>true<\/RequireLowercaseCharacters>/.test(xml);
    result.password_policy = { min_length: minLen, requires_symbols: requireSymbols, requires_numbers: requireNumbers, requires_upper: requireUpper, requires_lower: requireLower };
    result.control_evidence.password_policy_strong = minLen >= 12 && requireSymbols && requireNumbers && requireUpper && requireLower;
  } catch (err) {
    if (!String(err).includes("NoSuchEntity")) warnings.push(`password_policy: ${String(err).slice(0, 100)}`);
    else warnings.push("No account password policy configured (PCI / SOC 2 risk)");
  }

  // IAM users + their MFA
  try {
    const xml = await awsCall(
      "POST",
      `https://iam.amazonaws.com/`,
      "iam",
      "us-east-1",
      creds,
      "Action=ListUsers&Version=2010-05-08&MaxItems=100",
      { "Content-Type": "application/x-www-form-urlencoded" }
    );
    const usernames = Array.from(xml.matchAll(/<UserName>([^<]+)<\/UserName>/g)).map((m) => m[1]);
    let withMfa = 0;
    for (const username of usernames.slice(0, 25)) {
      try {
        const mfa = await awsCall(
          "POST",
          `https://iam.amazonaws.com/`,
          "iam",
          "us-east-1",
          creds,
          `Action=ListMFADevices&Version=2010-05-08&UserName=${encodeURIComponent(username)}`,
          { "Content-Type": "application/x-www-form-urlencoded" }
        );
        const deviceCount = (mfa.match(/<member>/g) || []).length;
        result.iam_users.push({ name: username, mfa_devices: deviceCount, access_keys_active: 0 });
        if (deviceCount > 0) withMfa++;
      } catch {
        // skip
      }
    }
    result.control_evidence.iam_user_mfa_coverage = result.iam_users.length > 0
      ? Math.round((withMfa / result.iam_users.length) * 100) / 100
      : 1;
  } catch (err) {
    warnings.push(`iam_users: ${String(err).slice(0, 100)}`);
  }

  // S3 buckets — list, then check public + encryption
  try {
    const xml = await awsCall("GET", `https://s3.amazonaws.com/`, "s3", "us-east-1", creds);
    const buckets = Array.from(xml.matchAll(/<Bucket>\s*<Name>([^<]+)<\/Name>/g)).map((m) => m[1]).slice(0, 15);
    let pub = 0, unenc = 0;
    for (const b of buckets) {
      let isPublic = false;
      let isEncrypted: boolean | null = null;
      try {
        const status = await awsCall("GET", `https://${b}.s3.amazonaws.com/?policyStatus`, "s3", region, creds);
        isPublic = /<IsPublic>true<\/IsPublic>/.test(status);
      } catch {
        // No policy = no explicit public access (still might be public via ACL — out of scope)
      }
      try {
        const enc = await awsCall("GET", `https://${b}.s3.amazonaws.com/?encryption`, "s3", region, creds);
        isEncrypted = /<SSEAlgorithm>/.test(enc);
      } catch {
        isEncrypted = false;
      }
      if (isPublic) pub++;
      if (isEncrypted === false) unenc++;
      result.s3_buckets.push({ name: b, public: isPublic, encrypted: isEncrypted });
    }
    result.control_evidence.public_buckets = pub;
    result.control_evidence.unencrypted_buckets = unenc;
  } catch (err) {
    warnings.push(`s3_buckets: ${String(err).slice(0, 100)}`);
  }

  // CloudTrail
  try {
    const json = await awsCall(
      "POST",
      `https://cloudtrail.${region}.amazonaws.com/`,
      "cloudtrail",
      region,
      creds,
      "{}",
      { "Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "CloudTrail_20131101.DescribeTrails" }
    );
    const parsed = JSON.parse(json);
    const trails = parsed.trailList || [];
    const multiRegion = trails.some((t: any) => t.IsMultiRegionTrail);
    const logging = trails.length > 0;
    result.cloudtrail_status = { trails_configured: trails.length, multi_region: multiRegion, logging };
    result.control_evidence.cloudtrail_active = logging;
  } catch (err) {
    warnings.push(`cloudtrail: ${String(err).slice(0, 100)}`);
  }

  return result;
}
