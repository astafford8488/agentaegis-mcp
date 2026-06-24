import { z } from "zod";
import * as net from "net";
import { lookup as dnsLookup } from "dns/promises";

const BLOCKED_IP_RANGES = [
  "127.0.0.0/8",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "0.0.0.0/8",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
];

function ipToLong(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function cidrContains(cidr: string, ip: string): boolean {
  const [range, bits] = cidr.split("/");
  const mask = ~(2 ** (32 - parseInt(bits)) - 1) >>> 0;
  return (ipToLong(range) & mask) === (ipToLong(ip) & mask);
}

export function isBlockedIP(ip: string): boolean {
  if (!net.isIPv4(ip)) return false;
  return BLOCKED_IP_RANGES.some((range) => {
    if (range.includes(":")) return false;
    return cidrContains(range, ip);
  });
}

export function validateTarget(target: string): { valid: boolean; reason?: string } {
  const trimmed = target.trim();

  if (!trimmed) {
    return { valid: false, reason: "Target cannot be empty" };
  }

  if (trimmed.includes(";") || trimmed.includes("|") || trimmed.includes("&") || trimmed.includes("`") || trimmed.includes("$") || trimmed.includes("(")) {
    return { valid: false, reason: "Target contains invalid characters (possible command injection)" };
  }

  if (net.isIPv4(trimmed)) {
    if (isBlockedIP(trimmed)) {
      return { valid: false, reason: "Target is a private/reserved IP address" };
    }
    return { valid: true };
  }

  const cidrMatch = trimmed.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (cidrMatch) {
    const [, ip, prefix] = cidrMatch;
    const prefixNum = parseInt(prefix);
    if (prefixNum < 24) {
      return { valid: false, reason: "CIDR range too large (minimum /24)" };
    }
    if (isBlockedIP(ip)) {
      return { valid: false, reason: "Target CIDR is in a private/reserved range" };
    }
    return { valid: true };
  }

  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
  if (domainRegex.test(trimmed)) {
    if (trimmed === "localhost" || trimmed.endsWith(".local") || trimmed.endsWith(".internal")) {
      return { valid: false, reason: "Target is a local/internal domain" };
    }
    return { valid: true };
  }

  return { valid: false, reason: "Target must be a valid IP address, CIDR range, or domain name" };
}

export function validateUrl(url: string): { valid: boolean; reason?: string } {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") {
      return { valid: false, reason: "Only HTTPS URLs are allowed" };
    }
    const hostnameValidation = validateTarget(parsed.hostname);
    if (!hostnameValidation.valid) {
      return hostnameValidation;
    }
    return { valid: true };
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }
}

/** Private / reserved IPv6 ranges (loopback, ULA fc00::/7, link-local fe80::/10,
 *  and v4-mapped addresses that fall in a blocked v4 range). */
export function isBlockedIPv6(ip: string): boolean {
  const low = ip.toLowerCase();
  if (low === "::1" || low === "::") return true;
  if (/^f[cd]/.test(low)) return true; // fc00::/7 unique-local
  if (/^fe[89ab]/.test(low)) return true; // fe80::/10 link-local
  const mapped = low.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped && isBlockedIP(mapped[1])) return true;
  return false;
}

/**
 * SSRF-safe validation for a git clone URL. The clone-based tools (sast_scan,
 * secret_scan, dependency_audit, scan_mcp_plugin, scan_skill) accept an
 * agent-supplied URL and hand it to `git clone`, so without this an agent could
 * point the server at internal services or the cloud metadata endpoint
 * (169.254.169.254) and use the paid scanner as an SSRF proxy.
 *
 * Enforces: https only (no git://, ssh, http, file); no embedded credentials;
 * a public hostname; and — crucially — that the host RESOLVES to a public IP
 * (defeats a public domain that points at a private/reserved address, i.e. DNS
 * rebinding). Residual TOCTOU (git re-resolves) is accepted: the repo is cloned
 * read-only into a throwaway sandbox dir with --depth=1, no code is executed.
 */
export async function validateGitUrl(url: string): Promise<{ valid: boolean; reason?: string }> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, reason: "Invalid URL format" };
  }
  if (parsed.protocol !== "https:") {
    return { valid: false, reason: "Only https:// git URLs are allowed (no git://, ssh, http, or file)" };
  }
  if (parsed.username || parsed.password) {
    return { valid: false, reason: "Credentials embedded in the URL are not allowed" };
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, ""); // strip any IPv6 brackets
  const basic = validateTarget(host);
  if (!basic.valid) return basic;

  let addrs: { address: string; family: number }[];
  try {
    addrs = await dnsLookup(host, { all: true });
  } catch {
    return { valid: false, reason: "Host did not resolve" };
  }
  for (const a of addrs) {
    if (a.family === 4 && isBlockedIP(a.address)) {
      return { valid: false, reason: `Host resolves to a private/reserved IP (${a.address})` };
    }
    if (a.family === 6 && isBlockedIPv6(a.address)) {
      return { valid: false, reason: `Host resolves to a private/reserved IPv6 (${a.address})` };
    }
  }
  return { valid: true };
}

export function sanitizeShellArg(arg: string): string {
  return arg.replace(/[^a-zA-Z0-9._:\/\-]/g, "");
}

export function redactSecret(secret: string): string {
  if (secret.length <= 8) return "****";
  return `${secret.slice(0, 4)}****${secret.slice(-4)}`;
}

export const targetSchema = z.string().refine(
  (val) => validateTarget(val).valid,
  (val) => ({ message: validateTarget(val).reason || "Invalid target" })
);

export const urlSchema = z.string().refine(
  (val) => validateUrl(val).valid,
  (val) => ({ message: validateUrl(val).reason || "Invalid URL" })
);
