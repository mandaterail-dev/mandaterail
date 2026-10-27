import { describe, expect, it } from "vitest";
import { escrowNonceSweepable, escrowNotAfter, EscrowTimingRefused, resolveEscrowNonce } from "./escrow-x402.js";

describe("R73-P3-3 §5.4 not_after <= C.expires - 30 s", () => {
  it("caps not_after at C.expires - 30 and at signed_at + 600", () => {
    expect(escrowNotAfter(1000, 1300)).toBe(1270);
    expect(escrowNotAfter(1000, 5000)).toBe(1600);
    expect(escrowNotAfter(1000, 1630)).toBe(1600);
  });
  it("refuses a challenge too close to expiry (or already expired)", () => {
    expect(() => escrowNotAfter(1000, 1049)).toThrow(EscrowTimingRefused);
    expect(escrowNotAfter(1000, 1050)).toBe(1020);
    expect(() => escrowNotAfter(1000, 900)).toThrow(/too soon/);
    expect(() => escrowNotAfter(1000.5, 2000)).toThrow(/integer/);
  });
});

describe("R73-P3-3 unknown landing timestamp keeps the nonce issued", () => {
  const n = { state: "issued" as const, expires: 2000 };
  it("unknown holds, even far past the grace", () => {
    for (const now of [1500, 2121, 99_999]) expect(resolveEscrowNonce(n, { kind: "unknown" }, now)).toMatchObject({ action: "hold", state: "issued" });
    expect(escrowNonceSweepable(n, true, 99_999)).toBe(false);
  });
  it("known in time serves and uses; known late refuses without burning", () => {
    expect(resolveEscrowNonce(n, { kind: "known", ts: 2000 }, 2500)).toMatchObject({ action: "serve", state: "used" });
    expect(resolveEscrowNonce(n, { kind: "known", ts: 2001 }, 2500)).toMatchObject({ action: "refuse", state: "issued" });
    expect(resolveEscrowNonce(n, { kind: "known", ts: Number.NaN }, 2500)).toMatchObject({ action: "hold" });
  });
  it("absent expires only past C.expires + 120; used/expired nonces refuse", () => {
    expect(resolveEscrowNonce(n, { kind: "absent" }, 2120)).toMatchObject({ action: "hold", state: "issued" });
    expect(resolveEscrowNonce(n, { kind: "absent" }, 2121)).toMatchObject({ action: "refuse", state: "expired" });
    expect(resolveEscrowNonce({ state: "used", expires: 2000 }, { kind: "known", ts: 1 }, 1)).toMatchObject({ action: "refuse", state: "used" });
    expect(escrowNonceSweepable(n, false, 2121)).toBe(true);
    expect(escrowNonceSweepable(n, false, 2120)).toBe(false);
  });
});
