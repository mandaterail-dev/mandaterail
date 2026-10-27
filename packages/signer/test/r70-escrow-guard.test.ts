import { describe, expect, it } from "vitest";
import { ABANDON_LEN, abandonMessage, abandonNotBefore, escrowPreflight, simulateGate, type EscrowAppState } from "../src/escrow-guard.js";

const st = (o: Partial<EscrowAppState> = {}): EscrowAppState => ({ bootstrapped: 1, breakerState: 0, keyEpoch: 1n, configEpoch: 1n, lastSeq: 100n, perReleaseCap: 10_000n, dailyHeadroom: 50_000n, releasesThisHour: 0, maxPerHour: 6, ...o });
const pins = { keyEpoch: 1n, configEpoch: 1n, operators: ["p1", "p2"] };
describe("R70-P2-1 escrow sign-side guard", () => {
  it("signs normally, warns at gap 32, refuses past 48 and asks for abandon first", () => {
    expect(escrowPreflight(st(), pins, 101n, 10_000n, null)).toEqual({ action: "sign", pages: [] });
    expect(escrowPreflight(st(), pins, 132n, 1n, null).pages).toEqual(["escrow seq window filling (gap 32/64)"]);
    const r = escrowPreflight(st(), pins, 149n, 1n, 148n);
    expect(r).toMatchObject({ action: "abandon-first", seqTo: 148n });
    expect(r.pages).toContain("escrow seq window: release refused");
    expect(escrowPreflight(st(), pins, 149n, 1n, null)).toMatchObject({ action: "refuse" });
  });
  it("preflight refuses (no seq burned) on breaker, epochs, caps, hour limit", () => {
    for (const [s, re] of [[st({ breakerState: 1 }), /breaker/], [st({ bootstrapped: 0 }), /bootstrapped/], [st({ configEpoch: 2n }), /config_epoch/],
      [st({ dailyHeadroom: 5n }), /headroom/], [st({ releasesThisHour: 6 }), /max_per_hour/]] as const) {
      const r = escrowPreflight(s, pins, 101n, 10n, null);
      expect(r.action).toBe("refuse");
      expect(r.pages.join()).toMatch(re);
    }
    expect(escrowPreflight(st(), pins, 101n, 10_001n, null).pages.join()).toMatch(/per_release_cap/);
  });
  it("abandon: not_before after every signed not_after; refuses live, landed or un-acked seqs", () => {
    const own = [{ seq: 101n, state: "abandoned" as const, lastNotAfter: 1000 }, { seq: 102n, state: "abandoned" as const, lastNotAfter: 1600 }];
    expect(abandonNotBefore(100n, 102n, own, own, 2000)).toBe(2000);
    expect(abandonNotBefore(100n, 102n, own, own, 1601)).toBe(1601);
    expect(() => abandonNotBefore(100n, 102n, own, own, 1500)).toThrow(/not_after has not passed/);
    expect(() => abandonNotBefore(100n, 102n, [{ ...own[0]!, state: "signed" }], own, 2000)).toThrow(/not abandoned/);
    expect(() => abandonNotBefore(100n, 102n, own, own.slice(0, 1), 2000)).toThrow(/no peer terminal ack/);
    expect(() => abandonNotBefore(100n, 165n, own, own, 2000)).toThrow(/outside/);
  });
  it("abandon message layout is 108 bytes with the v2 domain prefix; simulate gate pages", () => {
    const m = abandonMessage({ genesisHash: new Uint8Array(32), appId: 7n, keyEpoch: 1n, configEpoch: 1n, expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 });
    expect(m.length).toBe(ABANDON_LEN);
    expect(m.subarray(0, 20).toString()).toBe("MR-ESCROW-ABANDON-v2");
    expect(m.readBigUInt64BE(76)).toBe(100n);
    expect(m.readBigUInt64BE(84)).toBe(148n);
    expect(m.readBigUInt64BE(100)).toBe(2600n);
    expect(simulateGate({ failed: true, message: "logic eval error" })).toEqual({ submit: false, pages: ["escrow simulate failed: logic eval error"] });
    expect(simulateGate({ failed: false }).submit).toBe(true);
  });
});
