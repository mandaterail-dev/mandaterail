import { test } from "node:test";
import assert from "node:assert/strict";
import { mandateDisplayStatus } from "./mandateStatus.ts";
import type { IntentMandate } from "./types.ts";

const NOW = Date.parse("2026-10-15T00:00:00Z");
const base: IntentMandate = {
  id: "m1", principal: "P", agent: "A", maxAmount: "1", asset: "USDC",
  allowlist: [], expiresAt: "2026-10-16T00:00:00Z", revoked: false,
  nonce: "n", signature: "sig", createdAt: "2026-10-14T00:00:00Z",
};
const verified = { status: "signature-verified" as const, authorizedForExecute: true, message: "" };

test("verified, unexpired, not revoked is active", () => {
  assert.equal(mandateDisplayStatus({ ...base, authorization: verified }, NOW), "active");
});
test("unsigned mandate is never active (MR-P1R-P2-4)", () => {
  assert.equal(mandateDisplayStatus({ ...base, signature: null }, NOW), "unsigned");
  assert.equal(mandateDisplayStatus({ ...base, signature: null, authorization: verified }, NOW), "unsigned");
  assert.equal(mandateDisplayStatus({ ...base, authorization: { status: "unsigned-draft", authorizedForExecute: false, message: "" } }, NOW), "unsigned");
});
test("signature without server verification is not active", () => {
  assert.equal(mandateDisplayStatus(base, NOW), "unverified");
  for (const status of ["stub-signature", "signature-present-unverified"] as const) {
    assert.equal(mandateDisplayStatus({ ...base, authorization: { status, authorizedForExecute: false, message: "" } }, NOW), "unverified");
  }
  assert.equal(mandateDisplayStatus({ ...base, authorization: { ...verified, authorizedForExecute: false } }, NOW), "unverified");
  assert.equal(mandateDisplayStatus({ ...base, metadata: { draftStatus: "approved" } }, NOW), "unverified");
});
test("invalid, revoked and expired", () => {
  assert.equal(mandateDisplayStatus({ ...base, authorization: { status: "signature-invalid", authorizedForExecute: false, message: "" } }, NOW), "invalid");
  assert.equal(mandateDisplayStatus({ ...base, revoked: true, authorization: verified }, NOW), "revoked");
  assert.equal(mandateDisplayStatus({ ...base, expiresAt: "2026-10-14T00:00:00Z", authorization: verified }, NOW), "expired");
  assert.equal(mandateDisplayStatus({ ...base, expiresAt: "garbage", authorization: verified }, NOW), "expired");
});
test("R30-P3-4: server-reported expiry wins over a slow browser clock", () => {
  const slow = Date.parse("2026-10-13T00:00:00Z"); // browser clock behind
  const expired = { status: "expired" as const, authorizedForExecute: false, message: "" };
  assert.equal(mandateDisplayStatus({ ...base, expiresAt: "2026-10-14T00:00:00Z", authorization: expired }, slow), "expired");
  assert.equal(mandateDisplayStatus({ ...base, authorization: { ...verified, authorizedForExecute: false } }, slow), "unverified");
});
