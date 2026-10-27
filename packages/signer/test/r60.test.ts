/** R60-P3-1: failed/finished scans abort background fetches; scan state is local to each probe() call. */
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { GENESIS_PINS } from "../src/config.js";
import { HttpProbe, type FetchFn } from "../src/providers.js";

const R = 66193660;
const BLOCK = new Uint8Array(readFileSync(path.join(__dirname, "fixtures", `mainnet-block-${R}.msgpack`)));
const P = { host: "algorand.drpc.org", operator: "drpc", kind: "blockscan-full" as const, baseUrl: "https://algorand.drpc.org" };
const ok = (body: unknown) => Promise.resolve({ status: 200, json: async () => body });
const bin = (b: Uint8Array) => Promise.resolve({ status: 200, json: async () => null, arrayBuffer: async () => b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function harness(block: (round: number, signal?: AbortSignal) => ReturnType<FetchFn>) {
  const signals: AbortSignal[] = [];
  let started = 0;
  const f: FetchFn = (u, init) => {
    if (u.endsWith("/v2/status")) return ok({ "last-round": R + 100 });
    if (u.endsWith("/v2/transactions/params")) return ok({ "genesis-hash": GENESIS_PINS.mainnet });
    started++;
    if (init?.signal) signals.push(init.signal);
    return block(Number(/blocks\/(\d+)/.exec(u)![1]), init?.signal);
  };
  return { f, signals, started: () => started };
}
const hangUntilAbort = (signal?: AbortSignal) => new Promise<never>((_r, rej) => signal?.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));

describe("R60-P3-1", () => {
  it("a failed block fetch stops the scan and aborts the other in-flight fetches; nothing runs after probe() returns", async () => {
    const h = harness((r, signal) => (r === 3 ? Promise.reject(new Error("boom")) : hangUntilAbort(signal)));
    const pr = new HttpProbe(P, h.f, 60_000, {}, { deadlineMs: 60_000, concurrency: 4 });
    const t0 = Date.now();
    expect(await pr.probe(["A".repeat(52)], 1, 500)).toEqual({ kind: "error", reason: "fetch failed" });
    expect(Date.now() - t0).toBeLessThan(2000); // not the 60 s deadline / per-request timeout
    expect(h.signals.length).toBe(4);
    expect(h.signals.every((s) => s.aborted)).toBe(true);
    const n = h.started();
    await sleep(50);
    expect(h.started()).toBe(n); // no background worker kept fetching
  });
  it("a found (present) txid cancels the remaining in-flight fetches", async () => {
    const h = harness((r, signal) => (r === R ? bin(BLOCK) : hangUntilAbort(signal)));
    const pr = new HttpProbe(P, h.f, 60_000, {}, { deadlineMs: 60_000, concurrency: 4 });
    const present = JSON.parse(readFileSync(path.join(__dirname, "fixtures", `mainnet-block-${R}.txids.json`), "utf8")).blockTxids[0];
    expect((await pr.probe([present], R - 3, R + 50)).kind).toBe("present");
    expect(h.signals.every((s) => s.aborted)).toBe(true);
  });
  it("probe() finally aborts its signal even after a normal (absent) result", async () => {
    const h = harness(() => bin(BLOCK));
    const pr = new HttpProbe(P, h.f, 60_000, {}, { concurrency: 1 });
    expect((await pr.probe(["A".repeat(52)], R, R)).kind).toBe("absent");
    expect(h.signals.length).toBe(1);
    expect(h.signals[0]!.aborted).toBe(true);
  });
  it("two concurrent probe() calls on one instance keep separate state (one hits its deadline, the other is absent)", async () => {
    const h = harness((r, signal) => (r === R ? sleep(150).then(() => bin(BLOCK)) : hangUntilAbort(signal)));
    const pr = new HttpProbe(P, h.f, 60_000, {}, { deadlineMs: 400, concurrency: 1 });
    const slow = pr.probe(["A".repeat(52)], 1, 2); // hangs -> deadline at 400 ms
    await sleep(100);
    const fast = pr.probe(["A".repeat(52)], R, R); // finishes at ~250 ms, before the slow one's deadline
    expect((await fast).kind).toBe("absent");
    expect(await slow).toEqual({ kind: "error", reason: "scan deadline" });
  });
});
