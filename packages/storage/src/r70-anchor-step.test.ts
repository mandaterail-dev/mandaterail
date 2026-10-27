/** R70-P3-1: append and the head-1 check step over manifest-pinned skipped seqs; signed anchors required (MainNet fail closed). */
import { describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import type pg from "pg";
import { ANCHOR_PINS, anchorHead, anchorLine, anchorLineAcceptable, anchorRequiresSig, anchorTick, type AnchorSigner } from "./anchor.js";
import { seqKey } from "./b2-sink.js";
import { loadIntegrityManifest } from "./monitor.js";

let t = 0;
const fakePool = {
  connect: async () => ({
    query: async (q: string) => q.includes("clock_timestamp") ? { rows: [{ n: new Date(1_700_000_000_000 + (t += 1000)).toISOString(), cut: new Date(0).toISOString() }] }
      : q.includes("to_regclass") ? { rows: [{ ok: false }] } : { rows: [] },
    release: () => undefined,
  }),
} as unknown as pg.Pool;

/** Object-Locked store: a key is written once; last() steps over pinned bad seqs like B2ObjectLockSink. */
class LockedSink {
  m = new Map<number, string>();
  constructor(private pinned: Set<number>, private ok: (l: string) => boolean) {}
  async append(l: string) { const s = (JSON.parse(l.split("\t")[0]!) as { seq: number }).seq; if (this.m.has(s)) throw new Error(`seq ${s} locked`); this.m.set(s, l); }
  async at(s: number) { return this.m.get(s) ?? null; }
  async last() { for (const s of [...this.m.keys()].sort((a, b) => b - a)) { const l = this.m.get(s)!; if (this.pinned.has(s) && !this.ok(l)) continue; return l; } return null; }
}
const kp = generateKeyPairSync("ed25519");
const pub = new Uint8Array(kp.publicKey.export({ format: "der", type: "spki" }).subarray(12));
const signer: AnchorSigner = { sign: async (m) => new Uint8Array(edSign(null, m, kp.privateKey)) };

describe("R70-P3-1 anchor step-over and required signatures", () => {
  it("pinned junk at head+1: the next append writes head+2 (prev = head) and the chain keeps verifying", async () => {
    const skip = new Set([3]);
    const sink = new LockedSink(skip, (l) => anchorLineAcceptable(l, pub, "testnet", true));
    // R73-P3-4: anchorTick takes only (key, sha256) pins; the step-over set is resolved against the stored object
    const skipPins = { skip: [{ key: seqKey("mr-monitor-anchor/testnet", 3), sha256: createHash("sha256").update('{"seq":3}\tjunk\n').digest("hex") }] };
    const a = { pool: fakePool, network: "testnet", sink, signer, pubkey: pub, skipPins, requireSigned: true };
    expect((await anchorTick(a)).seq).toBe(1);
    expect((await anchorTick(a)).seq).toBe(2);
    sink.m.set(3, '{"seq":3}\tjunk'); // planted, Object-Locked
    const r = await anchorTick(a);
    expect(r).toMatchObject({ anchored: true, seq: 4 });
    expect(r.reasons).toEqual([expect.stringMatching(/stepping over manifest-pinned object at seq 3/)]);
    expect((await anchorHead(sink, 0, pub, "testnet", true, skipPins)).seq).toBe(4);
    expect((await anchorTick(a)).seq).toBe(5); // head-1 = 4, normal link again
    // without the pin the same chain is refused (no silent gap)
    await expect(anchorHead({ ...sink, last: async () => sink.m.get(4)!, at: async (s: number) => sink.m.get(s) ?? null, append: async () => undefined }, 0, pub, "testnet", true)).rejects.toThrow(/does not link/);
  });
  it("a pinned seq that holds the genuine predecessor is still linked normally", async () => {
    const skip = new Set([2]);
    const sink = new LockedSink(skip, (l) => anchorLineAcceptable(l, pub, "testnet", true));
    const a = { pool: fakePool, network: "testnet", sink, signer, pubkey: pub, requireSigned: true };
    await anchorTick(a); await anchorTick(a); await anchorTick(a);
    const pin2 = { skip: [{ key: seqKey("mr-monitor-anchor/testnet", 2), sha256: createHash("sha256").update(`${sink.m.get(2)}\n`).digest("hex") }] };
    expect((await anchorHead(sink, 0, pub, "testnet", true, pin2)).seq).toBe(3);
    // R74-P3-3: a pin that does not match the stored bytes is paged and not stepped over
    const bad = await anchorHead(sink, 0, pub, "testnet", true, { skip: [{ key: seqKey("mr-monitor-anchor/testnet", 2), sha256: "0".repeat(64) }] });
    expect(bad.pages.join()).toMatch(/does not match/);
  });
  it("required signatures: unsigned self-hashed lines are refused; MainNet fails closed without a pubkey", async () => {
    const facts = { at: new Date(0).toISOString(), network: "mainnet", tables: {} } as never;
    const unsigned = await anchorLine(1, "0".repeat(64), facts);
    expect(anchorLineAcceptable(unsigned, undefined, "mainnet")).toBe(false);
    expect(anchorLineAcceptable(unsigned, undefined, "mainnet", false)).toBe(false);
    const tn = unsigned.replace('"mainnet"', '"testnet"');
    expect(anchorLineAcceptable(tn, undefined, "testnet", true)).toBe(false);
    expect(anchorRequiresSig("mainnet", { requireSigned: false })).toBe(true);
    expect(anchorRequiresSig("testnet", { requireSigned: true })).toBe(true);
    const sink = { append: async () => undefined, last: async () => unsigned, at: async () => null };
    await expect(anchorHead(sink, 0, undefined, "mainnet")).rejects.toThrow(/required/);
    const r = await anchorTick({ pool: fakePool, network: "testnet", sink, requireSigned: true });
    expect(r.reasons[0]).toMatch(/requires signed anchors/);
  });
  it("the manifest pins requireSigned (MainNet true)", () => {
    const m = loadIntegrityManifest({});
    expect(m.anchor?.mainnet?.requireSigned).toBe(true);
    expect(m.anchor?.testnet?.requireSigned).toBe(ANCHOR_PINS.testnet.requireSigned);
  });
});
