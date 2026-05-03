import { z } from "zod";
import * as net from "net";

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
