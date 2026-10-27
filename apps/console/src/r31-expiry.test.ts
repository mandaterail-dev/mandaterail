import { describe, expect, it } from "vitest";
import { classifyMandateAuth, parseStrictIsoUtc } from "./store.js";

// R31-P3-5: expiresAt must be strict ISO 8601 UTC with a trailing Z.
const NOW = Date.parse("2026-10-15T12:00:00Z");
const m = (expiresAt: string) => ({
  id: "m1", principal: "P", agent: "A", maxAmount: "1", asset: "USDC", allowlist: [],
  expiresAt, revoked: false, nonce: "n", signature: "realsig", createdAt: "2026-10-14T00:00:00Z",
}) as never;

describe("R31-P3-5 strict ISO UTC expiresAt", () => {
  it("accepts YYYY-MM-DDTHH:MM:SS[.sss]Z", () => {
    expect(parseStrictIsoUtc("2026-10-15T13:00:00Z")).toBe(Date.parse("2026-10-15T13:00:00Z"));
    expect(parseStrictIsoUtc("2026-10-15T13:00:00.5Z")).toBe(Date.parse("2026-10-15T13:00:00.500Z"));
    expect(classifyMandateAuth(m("2026-10-15T13:00:00.000Z"), { signatureVerified: true }, NOW).authorizedForExecute).toBe(true);
  });
  for (const bad of ["2026-10-15T13:00:00", "2026-10-15T13:00:00+00:00", "2026-10-15T15:00:00+02:00", "2026-10-15", "Thu, 15 Oct 2026 13:00:00 GMT", "2026-10-15 13:00:00Z", "2026-02-30T13:00:00Z", "2026-10-15T24:00:00Z", "2026-10-15T13:00:00z", "+002026-10-15T13:00:00Z", " 2026-10-15T13:00:00Z"]) {
    it(`refuses ${JSON.stringify(bad)}`, () => {
      expect(parseStrictIsoUtc(bad)).toBeNull();
      expect(classifyMandateAuth(m(bad), { signatureVerified: true }, NOW)).toMatchObject({ status: "expired", authorizedForExecute: false });
    });
  }
});
