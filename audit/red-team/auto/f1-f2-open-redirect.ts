/**
 * F1–F2 — Open redirect via `next` param
 *
 * The portal's middleware + login flow uses a `next` query parameter to
 * preserve the user's intended destination after auth. If the sanitization
 * is weak, an attacker can craft phishing links that authenticate the user
 * then redirect to an attacker-controlled site (where the user is now
 * authenticated and trusts the page).
 *
 * Test cases:
 *   F1: ?next=https://evil.com (full URL)
 *   F2: ?next=//evil.com (protocol-relative — bypasses naive "starts with /")
 *   F3: ?next=/\evil.com (backslash bypass)
 *   F4: ?next=javascript:alert(1) (XSS via redirect)
 *   F5: ?next=/account/keys (legitimate same-origin path — should work)
 *
 * Expected defense: Login form's `safeNext` logic in app/auth/callback/
 * route.ts only allows paths starting with "/" and not "//".
 *
 * This test fetches the redirect responses and inspects Location headers.
 * No auth is needed — we test the unauthenticated branch of the redirect
 * logic which still applies sanitization on the incoming URL.
 *
 * Output: audit/red-team/results/<DATE>-f1-f2-open-redirect.json
 */

import "dotenv/config";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const PORTAL = process.env.PORTAL_BASE_URL || "https://app.agentaegis.org";

const CASES = [
  { id: "F1", next: "https://evil.com", description: "Full external URL", should_redirect_to_external: false },
  { id: "F1b", next: "https://evil.com/path", description: "Full external URL with path", should_redirect_to_external: false },
  { id: "F2", next: "//evil.com", description: "Protocol-relative URL", should_redirect_to_external: false },
  { id: "F2b", next: "//evil.com/account", description: "Protocol-relative with path", should_redirect_to_external: false },
  { id: "F3", next: "/\\evil.com", description: "Backslash bypass", should_redirect_to_external: false },
  { id: "F4", next: "javascript:alert(1)", description: "JavaScript URL (XSS via redirect)", should_redirect_to_external: false },
  { id: "F5", next: "/account/keys", description: "Legitimate same-origin path", should_redirect_to_external: false },
  { id: "F6", next: "@evil.com", description: "URL with userinfo", should_redirect_to_external: false },
  { id: "F7", next: "/%2F%2Fevil.com", description: "URL-encoded //", should_redirect_to_external: false },
];

async function probe(next: string): Promise<{ status: number; location: string | null; body_excerpt: string }> {
  // Hit /auth/callback with a missing code — server returns redirect to /login.
  // The redirect path may include the unsafe `next` if not sanitized.
  const url = `${PORTAL}/auth/callback?code=fake-test-code&next=${encodeURIComponent(next)}`;
  const res = await fetch(url, { method: "GET", redirect: "manual" });
  const text = await res.text().catch(() => "");
  return {
    status: res.status,
    location: res.headers.get("location"),
    body_excerpt: text.slice(0, 200),
  };
}

function isSafeRedirect(location: string | null, expectedOrigin: string): boolean {
  if (!location) return true; // no redirect = safe
  // Must be either same-origin absolute URL OR a same-origin path
  try {
    const url = new URL(location, expectedOrigin);
    return url.origin === expectedOrigin;
  } catch {
    // Couldn't parse — relative path, still on same origin
    return location.startsWith("/") && !location.startsWith("//");
  }
}

async function main() {
  const expectedOrigin = new URL(PORTAL).origin;
  const cases: Array<{
    id: string;
    next: string;
    description: string;
    status: number;
    location: string | null;
    safe: boolean;
    verdict: "PASS" | "FAIL";
  }> = [];

  for (const c of CASES) {
    const { status, location } = await probe(c.next);
    const safe = isSafeRedirect(location, expectedOrigin);
    cases.push({
      id: c.id,
      next: c.next,
      description: c.description,
      status,
      location,
      safe,
      verdict: safe ? "PASS" : "FAIL",
    });
  }

  const failed = cases.filter((c) => c.verdict === "FAIL");
  const verdict: "PASS" | "FAIL" = failed.length === 0 ? "PASS" : "FAIL";

  const report = {
    test: "F1–F2 — Open redirect via `next` param",
    timestamp: new Date().toISOString(),
    portal: PORTAL,
    cases,
    failed_count: failed.length,
    verdict,
    failed_cases: failed.map((c) => ({ id: c.id, next: c.next, location: c.location })),
  };

  console.log(JSON.stringify(report, null, 2));

  const outDir = path.join(import.meta.dirname || ".", "..", "results");
  mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `${new Date().toISOString().slice(0, 10)}-f1-f2-open-redirect.json`);
  writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote: ${outPath}`);

  process.exit(verdict === "PASS" ? 0 : 1);
}

main().catch((err) => {
  console.error("[F1-F2] Fatal:", err);
  process.exit(2);
});
