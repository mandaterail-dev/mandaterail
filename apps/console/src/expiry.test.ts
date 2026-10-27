import { describe, expect, it } from "vitest";
import { classifyMandateAuth } from "./store.js";

// R30-P3-4: the console decides expiry by its own (server) clock.
const NOW = Date.parse("2026-10-15T12:00:00Z");
const m = (expiresAt: string) => ({
  id: "m1", principal: "P", agent: "A", maxAmount: "1", asset: "USDC", allowlist: [],
  expiresAt, revoked: false, nonce: "n", signature: "realsig", createdAt: "2026-10-14T00:00:00Z",
}) as never;

describe("R30-P3-4 classifyMandateAuth expiry", () => {
  it("verified and unexpired is authorized", () => {
    expect(classifyMandateAuth(m("2026-10-15T13:00:00Z"), { signatureVerified: true }, NOW)).toMatchObject({ status: "signature-verified", authorizedForExecute: true });
  });
  it("verified but expired by the server clock is not authorized", () => {
    expect(classifyMandateAuth(m("2026-10-15T11:59:59Z"), { signatureVerified: true }, NOW)).toMatchObject({ status: "expired", authorizedForExecute: false });
    expect(classifyMandateAuth(m("2026-10-15T12:00:00Z"), { signatureVerified: true }, NOW)).toMatchObject({ status: "expired", authorizedForExecute: false });
    expect(classifyMandateAuth(m("garbage"), { signatureVerified: true }, NOW)).toMatchObject({ status: "expired", authorizedForExecute: false });
  });
  it("defaults to Date.now()", () => {
    expect(classifyMandateAuth(m("2000-01-01T00:00:00Z"), { signatureVerified: true }).authorizedForExecute).toBe(false);
  });
});
