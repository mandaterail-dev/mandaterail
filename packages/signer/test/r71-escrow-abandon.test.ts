/** R71-P2-1 / R71-P3-4: a pending or stale abandon can't consume releases signed after it. */
import { describe, expect, it } from "vitest";
import { freshViews, ABANDON_TTL_MAX_S, abandonIssue, abandonMessage, escrowPreflight, pendingAbandonStatus, simulateGate, type EscrowAppState } from "../src/escrow-guard.js";

const st = (o: Partial<EscrowAppState> = {}): EscrowAppState => ({ bootstrapped: 1, breakerState: 0, keyEpoch: 1n, configEpoch: 1n, lastSeq: 100n, perReleaseCap: 10_000n, dailyHeadroom: 50_000n, releasesThisHour: 0, maxPerHour: 6, ...o });
const pins = { keyEpoch: 1n, configEpoch: 1n, operators: ["p1", "p2"] };
const PIN = ["p1", "p2"];
const PS = (p: Parameters<typeof pendingAbandonStatus>[0], vs: Parameters<typeof pendingAbandonStatus>[1], pin: readonly string[] = PIN) => pendingAbandonStatus(p, vs, pin);
const v = (lastSeq: bigint, chainNow: number) => [{ provider: "p1", lastSeq, chainNow }, { provider: "p2", lastSeq, chainNow }];
const ab = (n: number) => Array.from({ length: n }, (_, i) => ({ seq: 101n + BigInt(i), state: "abandoned" as const, lastNotAfter: 1000 }));

describe("R71-P2-1 pending abandon interlock", () => {
  const pending = { expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 };
  it("status: pending, landed, expired by time, expired by last_seq moving", () => {
    expect(PS(pending, v(100n, 2100))).toBe("pending");
    expect(PS(pending, v(148n, 2100))).toBe("landed");
    expect(PS(pending, v(100n, 2601))).toBe("expired");
    expect(PS(pending, v(120n, 2100))).toBe("expired"); // A asserts last_seq == expected_last_seq: can never pass now
  });
  it("refuses release seqs <= a pending seq_to (the scenario: A delayed while releases are re-issued)", () => {
    const r = escrowPreflight(st(), pins, 101n, 1n, null, pending, v(100n, 2100));
    expect(r.action).toBe("refuse");
    expect(r.pages.join()).toMatch(/pending abandon seq_to 148/);
    expect(escrowPreflight(st(), pins, 148n, 1n, null, pending, v(100n, 2100)).action).toBe("refuse");
    // after expiry the seq may be signed again
    expect(escrowPreflight(st(), pins, 101n, 1n, null, pending, v(100n, 2601)).action).toBe("sign");
  });
  it("refuses seq <= lastAbandoned (no second identity for an abandoned seq)", () => {
    const r = escrowPreflight(st({ lastSeq: 100n }), pins, 120n, 1n, 148n);
    expect(r.action).toBe("refuse");
    expect(r.pages.join()).toMatch(/abandoned 148/);
  });
  it("no re-issue while pending; re-issue after expiry or landing; bootstrapped required", () => {
    expect(() => abandonIssue(st(), 148n, ab(48), ab(48), v(100n, 2100), pending, PIN)).toThrow(/still pending/);
    const a = abandonIssue(st(), 148n, ab(48), ab(48), v(100n, 2601), pending, PIN);
    expect(a).toEqual({ expectedLastSeq: 100n, seqTo: 148n, notBefore: 2601, notAfter: 2601 + ABANDON_TTL_MAX_S });
    expect(() => abandonIssue(st({ bootstrapped: 0 }), 148n, ab(48), ab(48), v(100n, 2601), null, PIN)).toThrow(/bootstrapped/);
    expect(() => abandonIssue(st(), 148n, ab(48), ab(48), v(100n, 2601), null, PIN, ABANDON_TTL_MAX_S + 1)).toThrow(/ttl/);
    // the gap-guard path does not hand out a second abandon while one is pending
    expect(escrowPreflight(st(), pins, 149n, 1n, 148n, pending, v(100n, 2100)).action).toBe("refuse");
  });
  it("message rejects seq_to outside the window and an unbounded / inverted not_after", () => {
    const base = { genesisHash: new Uint8Array(32), appId: 7n, keyEpoch: 1n, configEpoch: 1n, expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 };
    expect(() => abandonMessage({ ...base, seqTo: 100n })).toThrow(/seq_to/);
    expect(() => abandonMessage({ ...base, seqTo: 165n })).toThrow(/seq_to/);
    expect(() => abandonMessage({ ...base, notAfter: 2000 })).toThrow(/not_after/);
    expect(() => abandonMessage({ ...base, notAfter: 2000 + ABANDON_TTL_MAX_S + 1 })).toThrow(/not_after/);
    const a = abandonMessage(base), b = abandonMessage({ ...base, expectedLastSeq: 101n });
    expect(a.equals(b)).toBe(false); // expected_last_seq is signed
  });
});
describe("R71-P3-4 guard nits", () => {
  it("simulate gate binds to the submitted group id", () => {
    expect(simulateGate({ failed: false, groupId: "g1" }, "g2")).toEqual({ submit: false, pages: ["escrow simulate gate: simulated group is not the group to submit"] });
    expect(simulateGate({ failed: false, groupId: "g1" }, "g1").submit).toBe(true);
  });
  it("test gaps: seq <= last_seq, key_epoch, amount < 1", () => {
    expect(escrowPreflight(st(), pins, 100n, 1n, null).pages.join()).toMatch(/<= last_seq/);
    expect(escrowPreflight(st({ keyEpoch: 2n }), pins, 101n, 1n, null).pages.join()).toMatch(/key_epoch/);
    expect(escrowPreflight(st(), pins, 101n, 0n, null).pages.join()).toMatch(/per_release_cap/);
  });
});
describe("R73-P3-2 pending-abandon expiry fails closed", () => {
  const pending = { expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 };
  it("a lagging read (last_seq < expected) is not expiry", () => {
    expect(PS(pending, v(99n, 2100))).toBe("pending");
  });
  it("one provider alone can't declare it expired or landed", () => {
    expect(PS(pending, [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }, { provider: "p2", lastSeq: 100n, chainNow: 2100 }])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 148n, chainNow: 2100 }, { provider: "p2", lastSeq: 100n, chainNow: 2100 }])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 100n, chainNow: 9999 }, { provider: "p2", lastSeq: 100n, chainNow: 2100 }])).toBe("pending"); // min chainNow
    expect(escrowPreflight(st(), pins, 101n, 1n, null, pending, [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }, { provider: "p2", lastSeq: 100n, chainNow: 2100 }]).action).toBe("refuse");
  });
  it("no views: pending (fail closed); abandonIssue requires views and uses the min chain time", () => {
    expect(PS(pending, [])).toBe("pending");
    expect(escrowPreflight(st(), pins, 101n, 1n, null, pending).action).toBe("refuse");
    expect(() => abandonIssue(st(), 148n, ab(48), ab(48), [], null, PIN)).toThrow(/distinct providers/);
    expect(abandonIssue(st(), 148n, ab(48), ab(48), [{ provider: "p1", lastSeq: 100n, chainNow: 3000 }, { provider: "p2", lastSeq: 100n, chainNow: 2700 }], null, PIN).notBefore).toBe(2700);
  });
});
describe("R74-P3-1 / R74-P3-2 distinct pinned providers and staleness", () => {
  const pending = { expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 };
  it("one view, or one provider repeated, is never agreement", () => {
    expect(PS(pending, [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 148n, chainNow: 2100 }])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }, { provider: "p1", lastSeq: 120n, chainNow: 2100 }])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }, { provider: "p1", lastSeq: 100n, chainNow: 2100 }, { provider: "p2", lastSeq: 120n, chainNow: 2100 }])).toBe("pending");
    expect(() => abandonIssue(st(), 148n, ab(48), ab(48), [{ provider: "p1", lastSeq: 100n, chainNow: 2700 }, { provider: "p1", lastSeq: 100n, chainNow: 2700 }], null, PIN)).toThrow(/distinct providers/);
  });
  it("only pinned providers count; NaN chain time stays pending", () => {
    const vs = [{ provider: "p1", lastSeq: 120n, chainNow: 2100 }, { provider: "rogue", lastSeq: 120n, chainNow: 2100 }];
    expect(PS(pending, vs, ["p1", "rogue"])).toBe("expired"); // only if config pins "rogue"
    expect(PS(pending, vs, ["p1", "p2"])).toBe("pending");
    expect(PS(pending, [{ provider: "p1", lastSeq: 100n, chainNow: Number.NaN }, { provider: "p2", lastSeq: 100n, chainNow: 2700 }])).toBe("pending");
  });
  it("freshViews drops (and pages) a provider trailing local time by > 60 s or ahead by > 30 s", () => {
    const r = freshViews([{ provider: "p1", lastSeq: 1n, chainNow: 1000 }, { provider: "p2", lastSeq: 1n, chainNow: 939 }, { provider: "p3", lastSeq: 1n, chainNow: 1031 }, { provider: "p4", lastSeq: 1n, chainNow: 940 }], 1000);
    expect(r.fresh.map((v) => v.provider)).toEqual(["p1", "p4"]);
    expect(r.pages.join()).toMatch(/stale: p2.*stale: p3/s);
  });
});
