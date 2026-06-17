import { describe, it, expect } from "vitest";
import { scoreEndpoint, extractHostname, type EndpointSignals } from "../../src/tools/trustLayer/vetEndpoint.js";

// A clean, established, well-configured endpoint baseline.
const GOOD: EndpointSignals = {
  reachable: true,
  tls: { available: true, grade: "A", certExpired: false, certDays: 200, weakTls: false, hsts: true },
  dns: { available: true, emailGrade: "A", dmarcEnforced: true, danglingCount: 0, caa: true },
  threat: { available: true, flagged: false, suspicious: false, highConfidence: false, score: 0, ipOnly: false },
  domainAge: { available: true, ageDays: 1500 },
};

const clone = (over: Partial<EndpointSignals>): EndpointSignals => ({ ...structuredClone(GOOD), ...over });

describe("scoreEndpoint", () => {
  it("PROCEEDs for a clean, established, well-configured endpoint", () => {
    const r = scoreEndpoint(GOOD);
    expect(r.verdict).toBe("PROCEED");
    expect(r.trust_score).toBeGreaterThanOrEqual(75);
  });

  it("BLOCKs on a HIGH-CONFIDENCE malicious hit (abuse.ch / corroborated), regardless of other good signals", () => {
    const r = scoreEndpoint(clone({ threat: { available: true, flagged: true, suspicious: true, highConfidence: true, score: 95 } }));
    expect(r.verdict).toBe("BLOCK");
    expect(r.trust_score).toBeLessThanOrEqual(25); // hard block reads as a low score
  });

  it("does NOT hard-block a single-source / IP-only flag — CAUTION, not BLOCK (the github.com false-positive)", () => {
    // Popular domain flagged only via its shared hosting IP, no corroboration.
    const r = scoreEndpoint(clone({ threat: { available: true, flagged: true, suspicious: true, highConfidence: false, score: 100, ipOnly: true } }));
    expect(r.verdict).toBe("CAUTION");
    expect(r.verdict).not.toBe("BLOCK");
    expect(r.reasons.some((x) => /not corroborated/i.test(x))).toBe(true);
  });

  it("BLOCKs on an expired/invalid certificate (hard block)", () => {
    const r = scoreEndpoint(clone({ tls: { available: true, grade: "B", certExpired: true, certDays: -3, weakTls: false, hsts: true } }));
    expect(r.verdict).toBe("BLOCK");
  });

  it("CAUTIONs on a very new domain even when otherwise clean", () => {
    const r = scoreEndpoint(clone({ domainAge: { available: true, ageDays: 12 } }));
    expect(r.verdict).toBe("CAUTION");
    expect(r.trust_score).toBeLessThan(75);
    expect(r.trust_score).toBeGreaterThanOrEqual(45);
  });

  it("penalizes an unreachable endpoint toward BLOCK", () => {
    const r = scoreEndpoint(clone({ reachable: false, tls: { available: false }, domainAge: { available: false, ageDays: null } }));
    expect(r.verdict).toBe("BLOCK");
  });

  it("treats suspicious reputation + weak TLS as CAUTION, not PROCEED", () => {
    const r = scoreEndpoint(clone({
      threat: { available: true, flagged: false, suspicious: true, highConfidence: false, score: 50 },
      tls: { available: true, grade: "C", certExpired: false, certDays: 100, weakTls: true, hsts: false },
    }));
    expect(r.verdict).not.toBe("PROCEED");
  });

  it("surfaces at least one human-readable reason", () => {
    expect(scoreEndpoint(GOOD).reasons.length).toBeGreaterThan(0);
  });
});

describe("extractHostname", () => {
  it("parses URLs, bare domains, and host:port", () => {
    expect(extractHostname("https://api.example.com/pay")).toBe("api.example.com");
    expect(extractHostname("example.com")).toBe("example.com");
    expect(extractHostname("example.com:8443/x")).toBe("example.com");
  });
});
