import { describe, expect, it } from "vitest";
import { HttpProbe, type FetchFn } from "../src/providers.js";
import { TN } from "./fixtures.js";

const fake = (routes: Record<string, [number, unknown]>): FetchFn => async (url) => {
  const path = new URL(url).pathname;
  const r = routes[path] ?? [404, {}];
  return { status: r[0], json: async () => r[1] };
};
describe("HttpProbe", () => {
  it("indexer: 404 -> idx404 absent; 200 -> present; health without genesis -> error", async () => {
    const p = { host: "idx-a.example", operator: "a", kind: "indexer" as const, baseUrl: "https://idx-a.example" };
    expect(await new HttpProbe(p, fake({ "/health": [200, { round: 1200, "genesis-hash": TN }] })).probe(["T1"], 100, 1100)).toEqual({ kind: "absent", method: "idx404", round: 1200, idxRound: 1200, genesis: TN });
    expect((await new HttpProbe(p, fake({ "/health": [200, { round: 1200, "genesis-hash": TN }], "/v2/transactions/T1": [200, {}] })).probe(["T1"], 100, 1100)).kind).toBe("present");
    expect((await new HttpProbe(p, fake({ "/health": [200, { round: 1200 }] })).probe(["T1"], 100, 1100)).kind).toBe("error");
    expect((await new HttpProbe(p, fake({ "/health": [200, { round: 1200, "genesis-hash": TN }], "/v2/transactions/T1": [500, {}] })).probe(["T1"], 100, 1100)).kind).toBe("error");
  });
  it("algod blockscan: scans fv..lv, any hit -> present, missing block -> error", async () => {
    const p = { host: "algod-b.example", operator: "b", kind: "algod" as const, baseUrl: "https://algod-b.example" };
    const routes: Record<string, [number, unknown]> = { "/v2/status": [200, { "last-round": 1300 }], "/v2/transactions/params": [200, { "genesis-hash": TN }] };
    for (let r = 100; r <= 110; r++) routes[`/v2/blocks/${r}/txids`] = [200, { blockTxids: r === 105 ? ["X"] : [] }];
    expect(await new HttpProbe(p, fake(routes)).probe(["T1"], 100, 110)).toEqual({ kind: "absent", method: "blockscan", round: 1300, idxRound: 110, genesis: TN });
    expect((await new HttpProbe(p, fake(routes)).probe(["X"], 100, 110)).kind).toBe("present");
    expect((await new HttpProbe(p, fake(routes)).probe(["T1"], 100, 111)).kind).toBe("error");
  });
  it("refuses forbidden hosts", () => {
    expect(() => new HttpProbe({ host: "127.0.0.1", operator: "x", kind: "indexer", baseUrl: "https://127.0.0.1" })).toThrow(/forbidden/);
  });
});
