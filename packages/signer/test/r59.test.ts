/** R59-P3-1 (attestTtlS >= 600 on MainNet) and R59-P3-2 (deadline from probe() entry, in-flight abort, config wiring). */
import { describe, expect, it } from "vitest";
import { ConfigError, GENESIS_PINS, probeScanOpts, validateConfig, type SignerConfig } from "../src/config.js";
import { HttpProbe, type FetchFn } from "../src/providers.js";
import { setup } from "./fixtures.js";

const P = { host: "algorand.drpc.org", operator: "drpc", kind: "blockscan-full" as const, baseUrl: "https://algorand.drpc.org" };
const hang: FetchFn = (_u, init) => new Promise((_r, rej) => init?.signal?.addEventListener("abort", () => rej(Object.assign(new Error("aborted"), { name: "AbortError" }))));

describe("R59", () => {
  it("P3-1: MainNet requires attestTtlS >= 600; TestNet keeps [30, 900]; scan options validated", async () => {
    const { cfg } = await setup();
    const mn = (o: Partial<SignerConfig>): SignerConfig => ({ ...cfg, network: "mainnet", genesisHash: GENESIS_PINS.mainnet, ...o });
    expect(() => validateConfig(mn({ attestTtlS: 300 }))).toThrow(/>= 600 on MainNet/);
    expect(() => validateConfig(mn({ attestTtlS: 599 }))).toThrow(ConfigError);
    expect(() => validateConfig(mn({ attestTtlS: 600 }))).not.toThrow();
    expect(() => validateConfig({ ...cfg, attestTtlS: 300 })).not.toThrow();
    expect(() => validateConfig({ ...cfg, scan: { deadlineS: 241 } })).toThrow(/deadlineS/);
    expect(() => validateConfig({ ...cfg, scan: { deadlineS: 10 } })).toThrow(/deadlineS/);
    expect(() => validateConfig({ ...cfg, scan: { concurrency: 9 } })).toThrow(/concurrency/);
    expect(() => validateConfig({ ...cfg, scan: { deadlineS: 120, concurrency: 2 } })).not.toThrow();
    expect(probeScanOpts({ scan: { deadlineS: 120, concurrency: 2 } })).toEqual({ deadlineMs: 120_000, concurrency: 2 });
    expect(probeScanOpts({})).toEqual({ deadlineMs: undefined, concurrency: undefined });
  });
  it("P3-2: the deadline starts at probe() entry and aborts in-flight requests (a hanging /v2/status ends at the deadline)", async () => {
    const pr = new HttpProbe(P, hang, 60_000, {}, { deadlineMs: 80 });
    const t0 = Date.now();
    expect(await pr.probe(["A".repeat(52)], 1, 2)).toEqual({ kind: "error", reason: "scan deadline" });
    const el = Date.now() - t0;
    expect(el).toBeGreaterThanOrEqual(70);
    expect(el).toBeLessThan(1000); // not the 60 s per-request timeout
  });
  it("P3-2: in-flight block fetches are aborted at the deadline (indexer probes too)", async () => {
    const f: FetchFn = (u, init) => (u.endsWith("/v2/status") ? Promise.resolve({ status: 200, json: async () => ({ "last-round": 100 }) })
      : u.endsWith("/v2/transactions/params") ? Promise.resolve({ status: 200, json: async () => ({ "genesis-hash": GENESIS_PINS.mainnet }) })
      : hang(u, init));
    const pr = new HttpProbe(P, f, 60_000, {}, { deadlineMs: 80, concurrency: 4 });
    expect(await pr.probe(["A".repeat(52)], 1, 50)).toEqual({ kind: "error", reason: "scan deadline" });
    expect(pr.requests).toBe(6); // status + params + 4 in flight, all aborted
    const idx = new HttpProbe({ host: "idx-a.example", operator: "a", kind: "indexer", baseUrl: "https://idx-a.example" }, hang, 60_000, {}, { deadlineMs: 50 });
    expect(await idx.probe(["A".repeat(52)], 1, 2)).toEqual({ kind: "error", reason: "scan deadline" });
  });
});
