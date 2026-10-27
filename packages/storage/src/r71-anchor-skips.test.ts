/** R71-P3-1: skip seqs come from pinned (key, sha256) matched against the stored object; every pin pages every tick. */
import { describe, expect, it } from "vitest";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import type pg from "pg";
import { anchorLineAcceptable, anchorResolveSkips, anchorTick, type AnchorSigner } from "./anchor.js";
import { seqKey } from "./b2-sink.js";

let t = 0;
const fakePool = {
  connect: async () => ({
    query: async (q: string) => q.includes("clock_timestamp") ? { rows: [{ n: new Date(1_700_000_000_000 + (t += 1000)).toISOString(), cut: new Date(0).toISOString() }] }
      : q.includes("to_regclass") ? { rows: [{ ok: false }] } : { rows: [] },
    release: () => undefined,
  }),
} as unknown as pg.Pool;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const P = "mr-monitor-anchor/testnet";
class LockedSink {
  m = new Map<number, string>();
  constructor(private skip: () => Set<number>, private ok: (l: string) => boolean) {}
  async append(l: string) { const s = (JSON.parse(l.split("\t")[0]!) as { seq: number }).seq; if (this.m.has(s)) throw new Error(`seq ${s} locked`); this.m.set(s, l); }
  async at(s: number) { return this.m.get(s) ?? null; }
  raw = new Map<number, Uint8Array>();
  async rawAt(s: number) { const r = this.raw.get(s); if (r) return r; const l = this.m.get(s); return l === undefined ? null : Buffer.from(`${l}\n`); }
  async last() { for (const s of [...this.m.keys()].sort((a, b) => b - a)) { const l = this.m.get(s)!; if (this.skip().has(s) && !this.ok(l)) continue; return l; } return null; }
}
const kp = generateKeyPairSync("ed25519");
const pub = new Uint8Array(kp.publicKey.export({ format: "der", type: "spki" }).subarray(12));
const signer: AnchorSigner = { sign: async (m) => new Uint8Array(edSign(null, m, kp.privateKey)) };
const JUNK = '{"seq":3}\tjunk';

describe("R71-P3-1 anchor skips resolved from (key, sha256)", () => {
  it("speculative pin (no object) fails loudly and is not stepped over: seq 3 is written normally", async () => {
    let live = new Set<number>();
    const sink = new LockedSink(() => live, (l) => anchorLineAcceptable(l, pub, "testnet", true));
    const skipPins = { skip: [{ key: seqKey(P, 3), sha256: sha(`${JUNK}\n`) }] };
    const a = { pool: fakePool, network: "testnet", sink, signer, pubkey: pub, skipPins, requireSigned: true };
    await anchorTick(a); await anchorTick(a);
    const r = await anchorTick(a);
    expect(r).toMatchObject({ anchored: true, seq: 3 });
    expect(r.reasons).toEqual([expect.stringMatching(/seq 3 names no stored object \(speculative pin/)]);
    // now the object at 3 is genuine: its sha does not match the pin -> still loud, never a silent skip
    const r2 = await anchorTick(a);
    expect(r2.seq).toBe(4);
    expect(r2.reasons).toEqual([expect.stringMatching(/seq 3 sha256 does not match/)]);
    live = new Set();
  });
  it("planted object matching the pin: stepped over, and paged on every tick (not only the first)", async () => {
    let live = new Set<number>();
    const sink = new LockedSink(() => live, (l) => anchorLineAcceptable(l, pub, "testnet", true));
    const skipPins = { skip: [{ key: seqKey(P, 3), sha256: sha(`${JUNK}\n`) }] };
    const a = { pool: fakePool, network: "testnet", sink, signer, pubkey: pub, skipPins, requireSigned: true };
    await anchorTick(a); await anchorTick(a);
    sink.m.set(3, JUNK);
    live = new Set([3]);
    for (const want of [4, 5, 6]) {
      const r = await anchorTick(a);
      expect(r).toMatchObject({ anchored: true, seq: want });
      expect(r.reasons).toEqual([expect.stringMatching(/stepping over manifest-pinned object at seq 3 \(key \+ sha256 matched/)]);
    }
  });
  it("wrong-sha pin over a plant: not stepped over (chain stalls loudly, no silent gap)", async () => {
    const sink = new LockedSink(() => new Set([3]), () => false);
    sink.m.set(3, JUNK);
    const r = await anchorResolveSkips(sink, { skip: [{ key: seqKey(P, 3), sha256: "0".repeat(64) }] });
    expect([...r.seqs]).toEqual([]);
    expect(r.pages).toEqual([expect.stringMatching(/sha256 does not match/)]);
    const bad = await anchorResolveSkips(sink, { skip: [{ key: "nope", sha256: "x" }] });
    expect(bad.pages).toEqual([expect.stringMatching(/malformed/)]);
  });
  it("R73-P3-1: a non-UTF-8 plant is pinned by the sha256 of its stored bytes (sha256sum), not of its decoded text", async () => {
    const bytes = Buffer.from("7bfffe7d096a", "hex");
    const sink = new LockedSink(() => new Set([3]), () => false);
    sink.m.set(3, bytes.toString("utf8")); sink.raw.set(3, bytes);
    const byBytes = createHash("sha256").update(bytes).digest("hex");
    expect(byBytes).not.toBe(sha(bytes.toString("utf8")));
    expect([...(await anchorResolveSkips(sink, { skip: [{ key: seqKey(P, 3), sha256: byBytes }] })).seqs]).toEqual([3]);
    expect([...(await anchorResolveSkips(sink, { skip: [{ key: seqKey(P, 3), sha256: sha(bytes.toString("utf8")) }] })).seqs]).toEqual([]);
  });
});
