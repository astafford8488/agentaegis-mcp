import { describe, it, expect } from "vitest";
import { validateTarget, validateUrl, redactSecret, isBlockedIP } from "../../src/utils/sanitize.js";

describe("validateTarget", () => {
  it("accepts public IPs", () => {
    expect(validateTarget("8.8.8.8").valid).toBe(true);
    expect(validateTarget("203.0.113.5").valid).toBe(true);
  });

  it("rejects private IPs", () => {
    expect(validateTarget("192.168.1.1").valid).toBe(false);
    expect(validateTarget("10.0.0.1").valid).toBe(false);
    expect(validateTarget("172.16.0.1").valid).toBe(false);
    expect(validateTarget("127.0.0.1").valid).toBe(false);
  });

  it("rejects link-local and infrastructure", () => {
    expect(validateTarget("169.254.1.1").valid).toBe(false);
    expect(validateTarget("0.0.0.0").valid).toBe(false);
  });

  it("rejects multicast", () => {
    expect(validateTarget("224.0.0.1").valid).toBe(false);
  });

  it("accepts public domains", () => {
    expect(validateTarget("example.com").valid).toBe(true);
    expect(validateTarget("www.google.com").valid).toBe(true);
    expect(validateTarget("api.test.io").valid).toBe(true);
  });

  it("rejects local domains", () => {
    expect(validateTarget("localhost").valid).toBe(false);
    expect(validateTarget("server.local").valid).toBe(false);
    expect(validateTarget("app.internal").valid).toBe(false);
  });

  it("rejects command injection attempts", () => {
    expect(validateTarget("example.com;rm -rf /").valid).toBe(false);
    expect(validateTarget("example.com|cat").valid).toBe(false);
    expect(validateTarget("$(whoami).com").valid).toBe(false);
    expect(validateTarget("`pwd`.com").valid).toBe(false);
  });

  it("validates CIDR ranges", () => {
    expect(validateTarget("203.0.113.0/24").valid).toBe(true);
    expect(validateTarget("203.0.113.0/16").valid).toBe(false); // too large
    expect(validateTarget("10.0.0.0/24").valid).toBe(false); // private
  });

  it("rejects empty/malformed", () => {
    expect(validateTarget("").valid).toBe(false);
    expect(validateTarget("   ").valid).toBe(false);
    expect(validateTarget("not a domain").valid).toBe(false);
  });
});

describe("validateUrl", () => {
  it("accepts HTTPS URLs to public domains", () => {
    expect(validateUrl("https://example.com").valid).toBe(true);
    expect(validateUrl("https://api.example.com/path").valid).toBe(true);
  });

  it("rejects HTTP URLs", () => {
    expect(validateUrl("http://example.com").valid).toBe(false);
  });

  it("rejects URLs to private hosts", () => {
    expect(validateUrl("https://localhost").valid).toBe(false);
    expect(validateUrl("https://192.168.1.1").valid).toBe(false);
  });

  it("rejects malformed URLs", () => {
    expect(validateUrl("not-a-url").valid).toBe(false);
    expect(validateUrl("javascript:alert(1)").valid).toBe(false);
  });
});

describe("redactSecret", () => {
  it("masks the middle of long secrets", () => {
    expect(redactSecret("sk_live_1234567890abcdefghij")).toBe("sk_l****ghij");
  });

  it("fully masks short secrets", () => {
    expect(redactSecret("short")).toBe("****");
    expect(redactSecret("12345678")).toBe("****");
  });
});

describe("isBlockedIP", () => {
  it("identifies private ranges", () => {
    expect(isBlockedIP("10.0.0.1")).toBe(true);
    expect(isBlockedIP("192.168.0.1")).toBe(true);
    expect(isBlockedIP("172.16.0.1")).toBe(true);
  });

  it("allows public IPs", () => {
    expect(isBlockedIP("8.8.8.8")).toBe(false);
    expect(isBlockedIP("1.1.1.1")).toBe(false);
  });
});
