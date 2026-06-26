import { describe, it, expect } from "vitest";
import { extractApiKey } from "../../src/auth/apiKeyAuth.js";

describe("extractApiKey", () => {
  it("accepts Authorization: Bearer <key>", () => {
    expect(extractApiKey({ authorization: "Bearer aegis_abc123" })).toBe("aegis_abc123");
  });

  it("accepts a bare Authorization key (Smithery gateway forwarding)", () => {
    expect(extractApiKey({ authorization: "aegis_abc123" })).toBe("aegis_abc123");
  });

  it("accepts X-API-Key", () => {
    expect(extractApiKey({ "x-api-key": "aegis_abc123" })).toBe("aegis_abc123");
  });

  it("is case-insensitive on the Bearer scheme", () => {
    expect(extractApiKey({ authorization: "bearer aegis_xyz" })).toBe("aegis_xyz");
    expect(extractApiKey({ authorization: "BEARER aegis_xyz" })).toBe("aegis_xyz");
  });

  it("ignores non-aegis tokens (falls through to x402/free)", () => {
    expect(extractApiKey({ authorization: "Bearer sk_live_123" })).toBeUndefined();
    expect(extractApiKey({ authorization: "Basic dXNlcjpwYXNz" })).toBeUndefined();
    expect(extractApiKey({ "x-api-key": "not-a-key" })).toBeUndefined();
  });

  it("returns undefined when no usable key is present", () => {
    expect(extractApiKey({})).toBeUndefined();
    expect(extractApiKey({ authorization: "" })).toBeUndefined();
    expect(extractApiKey({ authorization: "Bearer " })).toBeUndefined();
  });

  it("prefers Authorization over X-API-Key", () => {
    expect(extractApiKey({ authorization: "Bearer aegis_auth", "x-api-key": "aegis_xak" })).toBe("aegis_auth");
  });

  it("handles array-valued headers (uses the first)", () => {
    expect(extractApiKey({ "x-api-key": ["aegis_first", "aegis_second"] })).toBe("aegis_first");
  });

  it("trims surrounding whitespace", () => {
    expect(extractApiKey({ authorization: "Bearer   aegis_padded  " })).toBe("aegis_padded");
  });
});
