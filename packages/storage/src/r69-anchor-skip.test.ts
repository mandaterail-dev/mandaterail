/** R69-P3-1: manifest-pinned (key, sha256) anchor skips: line acceptance, paging on every tick, manifest shape. */
import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import type pg from "pg";
import { ANCHOR_PINS, anchorLine, anchorLineAcceptable, anchorTick } from "./anchor.js";
import { loadIntegrityManifest } from "./monitor.js";

const facts = { at: new Date(0).toISOString(), network: "testnet", tables: {} } as never;
describe("R69-P3-1 anchor skips", () => {
  it("anchorLineAcceptable: good line yes; junk, bad hash, other network no", async () => {
    const l = await anchorLine(1, "0".repeat(64), facts);
    expect(anchorLineAcceptable(l, undefined, "testnet")).toBe(true);
    expect(anchorLineAcceptable(l, undefined, "mainnet")).toBe(false);
    expect(anchorLineAcceptable('{"seq":4}\tjunk')).toBe(false);
    expect(anchorLineAcceptable(l.replace(/\t.*/, "\t" + "ab".repeat(32)))).toBe(false);
  });
  it("every skip is paged on every tick, before the tick's own reasons", async () => {
    const r = await anchorTick({ pool: {} as pg.Pool, network: "mainnet", sink: { append: async () => undefined, last: async () => null, at: async () => null }, skipped: () => ["000000000001.jsonl"] });
    expect(r.reasons[0]).toMatch(/anchor: head listing stepped over manifest-pinned object .*000000000001\.jsonl \(key \+ sha256 matched\)/);
    expect(r.reasons[1]).toMatch(/no signing key/);
  });
  it("the checked-in manifest pins skip lists (empty) and keeps minSeq", () => {
    const m = loadIntegrityManifest({});
    for (const n of ["mainnet", "testnet"] as const) { expect(m.anchor?.[n]?.skip).toEqual([]); expect(m.anchor?.[n]?.minSeq).toBe(ANCHOR_PINS[n].minSeq); }
    expect(createHash("sha256").update("x").digest("hex")).toMatch(/^[0-9a-f]{64}$/);
  });
});
