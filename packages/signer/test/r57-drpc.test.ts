/** dRPC (operator 4) blockscan-full: txids computed from msgpack blocks match algod's /txids; HttpProbe absent/present/errors. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { msgpackRawDecodeAsMap, msgpackRawEncode } from "algosdk";
import path from "node:path";
import { blockTxIdsFromMsgpack, HttpProbe, type FetchFn } from "../src/providers.js";
import { GENESIS_PINS } from "../src/config.js";

const R = 66193660; // real MainNet block (public data), fetched from dRPC; txids from Nodely's /txids
const F = path.join(__dirname, "fixtures");
const BLOCK = new Uint8Array(readFileSync(path.join(F, `mainnet-block-${R}.msgpack`)));
const REF: string[] = JSON.parse(readFileSync(path.join(F, `mainnet-block-${R}.txids.json`), "utf8")).blockTxids;
const P = { host: "algorand.drpc.org", operator: "drpc", kind: "blockscan-full" as const, baseUrl: "https://algorand.drpc.org" };
const ABSENT = "A".repeat(52);

function fakeDrpc(over: Partial<Record<string, { status: number; body?: unknown; bin?: Uint8Array }>> = {}): { f: FetchFn; urls: string[] } {
  const urls: string[] = [];
  const f: FetchFn = async (url) => {
    urls.push(url);
    const p = url.replace(P.baseUrl, "");
    const o = over[p];
    const def = p === "/v2/status" ? { status: 200, body: { "last-round": R + 20 } }
      : p === "/v2/transactions/params" ? { status: 200, body: { "genesis-hash": GENESIS_PINS.mainnet } }
      : p === `/v2/blocks/${R}?format=msgpack` ? { status: 200, bin: BLOCK }
      : p.endsWith("/txids") ? { status: 400, body: { message: "method is not available on free plan" } }
      : { status: 404 };
    const r = o ?? def;
    return { status: r.status, json: async () => r.body ?? null, arrayBuffer: async () => (r.bin ? r.bin.buffer.slice(r.bin.byteOffset, r.bin.byteOffset + r.bin.byteLength) : new ArrayBuffer(0)) as ArrayBuffer };
  };
  return { f, urls };
}

describe("dRPC blockscan-full", () => {
  it("txids computed from the msgpack block equal algod's /v2/blocks/{r}/txids; genesis + round decoded", () => {
    const b = blockTxIdsFromMsgpack(BLOCK);
    expect(b.round).toBe(R);
    expect(b.genesisHash).toBe(GENESIS_PINS.mainnet);
    expect(new Set(b.txIds)).toEqual(new Set(REF));
    expect(b.txIds.length).toBe(REF.length);
  });
  it("absent: scans [fv, lv] via msgpack blocks only (never /txids); method blockscan-full, idxRound = lv", async () => {
    const { f, urls } = fakeDrpc();
    const pr = new HttpProbe(P, f, 1000, {});
    const r = await pr.probe([ABSENT], R, R);
    expect(r).toEqual({ kind: "absent", method: "blockscan-full", round: R + 20, idxRound: R, genesis: GENESIS_PINS.mainnet });
    expect(urls.some((u) => u.endsWith("/txids"))).toBe(false);
    expect(pr.requests).toBe(3); // status + params + 1 block
  });
  it("present: a txid in the block is found", async () => {
    const r = await new HttpProbe(P, fakeDrpc().f, 1000, {}).probe([ABSENT, REF[3]!], R, R);
    expect(r.kind).toBe("present");
  });
  it("errors: block not served, wrong round, undecodable bytes", async () => {
    expect(await new HttpProbe(P, fakeDrpc({ [`/v2/blocks/${R}?format=msgpack`]: { status: 400 } }).f, 1000, {}).probe([ABSENT], R, R)).toEqual({ kind: "error", reason: `block ${R} not served` });
    expect(await new HttpProbe(P, fakeDrpc({ [`/v2/blocks/${R + 1}?format=msgpack`]: { status: 200, bin: BLOCK } }).f, 1000, {}).probe([ABSENT], R + 1, R + 1)).toEqual({ kind: "error", reason: `block ${R + 1} round mismatch` });
    expect(await new HttpProbe(P, fakeDrpc({ [`/v2/blocks/${R}?format=msgpack`]: { status: 200, bin: new Uint8Array([1, 2, 3]) } }).f, 1000, {}).probe([ABSENT], R, R)).toEqual({ kind: "error", reason: `block ${R} undecodable` });
  });
  it("R58-P3-1: the RAW txn map is hashed (an SDK-unknown field changes the txid instead of being dropped)", () => {
    const top = msgpackRawDecodeAsMap(BLOCK) as Map<string, any>;
    const st = top.get("block").get("txns")[0] as Map<string, any>;
    st.get("txn").set("zzunknown", 7);
    const ids = blockTxIdsFromMsgpack(msgpackRawEncode(top as never)).txIds;
    expect(ids[0]).not.toBe(REF[0]);
    expect(new Set(ids.slice(1))).toEqual(new Set(REF.filter((x) => x !== REF[0])));
  });
  it("R58-P3-2: bounded parallelism (<= concurrency in flight) and an overall scan deadline", async () => {
    let inflight = 0, max = 0;
    const base = fakeDrpc().f;
    const slow: FetchFn = async (url, init) => {
      if (!url.includes("/v2/blocks/")) return base(url, init);
      inflight++; max = Math.max(max, inflight);
      await new Promise((r) => setTimeout(r, 5));
      inflight--;
      return base(url.replace(/blocks\/\d+/, `blocks/${R}`), init);
    };
    // every block is the fixture: rounds other than R are a round mismatch, so scan R..R with concurrency 4 and R-7..R checks the bound
    const p4 = new HttpProbe(P, slow, 1000, {}, { concurrency: 4 });
    await p4.probe([ABSENT], R - 7, R);
    expect(max).toBeLessThanOrEqual(4);
    expect(max).toBeGreaterThan(1);
    const stall: FetchFn = async (url, init) => (url.includes("/v2/blocks/") ? new Promise((r) => setTimeout(() => r(base(url, init) as never), 80)) : base(url, init));
    const pd = new HttpProbe(P, stall, 1000, {}, { deadlineMs: 50, concurrency: 1 });
    expect(await pd.probe([ABSENT], R, R)).toEqual({ kind: "error", reason: "scan deadline" });
    expect(() => new HttpProbe(P, base, 1000, {}, { deadlineMs: 300_000 })).toThrow(/240 s/);
    expect(() => new HttpProbe(P, base, 1000, {}, { concurrency: 50 })).toThrow(/1\.\.8/);
  });
});
