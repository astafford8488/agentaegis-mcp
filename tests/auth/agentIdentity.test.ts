import { describe, it, expect } from "vitest";
import { anonSessionKey, identityFor } from "../../src/auth/agentIdentity.js";
import type { RequestContext } from "../../src/auth/requestContext.js";

const DAY_1 = new Date("2026-01-01T12:00:00Z");
const DAY_2 = new Date("2026-01-02T12:00:00Z");

describe("anonSessionKey", () => {
  it("returns null without an ip to anchor on", () => {
    expect(anonSessionKey(undefined, "ua", DAY_1)).toBeNull();
    expect(anonSessionKey("", "ua", DAY_1)).toBeNull();
  });

  it("is deterministic for the same ip+ua+day", () => {
    expect(anonSessionKey("1.2.3.4", "claude", DAY_1)).toBe(anonSessionKey("1.2.3.4", "claude", DAY_1));
  });

  it("is prefixed and fixed-length", () => {
    const key = anonSessionKey("1.2.3.4", "claude", DAY_1)!;
    expect(key.startsWith("anon_")).toBe(true);
    expect(key.length).toBe("anon_".length + 32);
  });

  it("differs by ip, by ua, and across UTC days (no cross-day tracking)", () => {
    const base = anonSessionKey("1.2.3.4", "claude", DAY_1);
    expect(anonSessionKey("5.6.7.8", "claude", DAY_1)).not.toBe(base);
    expect(anonSessionKey("1.2.3.4", "other", DAY_1)).not.toBe(base);
    expect(anonSessionKey("1.2.3.4", "claude", DAY_2)).not.toBe(base);
  });
});

describe("identityFor (precedence)", () => {
  it("prefers API-key customer_id over wallet and anon", () => {
    const ctx: RequestContext = {
      apiKey: { customer_id: "cust-1" } as any,
      payerWallet: "0xWALLET",
      ip: "1.2.3.4",
    };
    expect(identityFor(ctx)).toEqual({ customerId: "cust-1" });
  });

  it("falls back to the x402 payer wallet when there's no API key", () => {
    const ctx: RequestContext = { payerWallet: "0xWALLET", ip: "1.2.3.4" };
    expect(identityFor(ctx)).toEqual({ walletAddress: "0xWALLET" });
  });

  it("falls back to an anonymous session when only an ip is present", () => {
    const id = identityFor({ ip: "1.2.3.4", userAgent: "claude" });
    expect(id?.anonSession?.startsWith("anon_")).toBe(true);
    expect(id?.customerId).toBeUndefined();
    expect(id?.walletAddress).toBeUndefined();
  });

  it("returns null when there is no identity anchor at all", () => {
    expect(identityFor({})).toBeNull();
  });
});
