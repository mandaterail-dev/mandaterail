/** internal reviewer run 76 P3s (R76-P3-1..5). */
import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { resolveEscrowNonce } from "@mandaterail/core";
import { assertEscrowProviders, EscrowRuntime, initialEscrowState, parseAlgodJson, readEscrowSnapshot, type EscrowLocalState, type EscrowRead, type EscrowReader } from "../src/escrow-release.js";
import { abandonIssue, pendingAbandonStatus, type EscrowAppState } from "../src/escrow-guard.js";
import { parseU64 } from "../src/main.js";
import { DurableJson } from "../src/state.js";
import { TN } from "./fixtures.js";

const NOW = 1_800_000_000;
const base: EscrowAppState = { bootstrapped: 1, breakerState: 0, keyEpoch: 1n, configEpoch: 1n, lastSeq: 100n, perReleaseCap: 10_000n, dailyHeadroom: 50_000n, releasesThisHour: 0, maxPerHour: 10 };
class R implements EscrowReader {
  constructor(readonly provider: string, readonly host?: string, public chainNow = NOW - 3, public st: Partial<EscrowAppState> = {}) {}
  async read(): Promise<EscrowRead> { return { provider: this.provider, genesis: TN, round: 1, chainNow: this.chainNow, state: { ...base, ...this.st } }; }
}
const row = { seq: 101n, receiver: new Uint8Array(32).fill(7), amount: 5000n, mandateHash: new Uint8Array(32).fill(9), challengeExpires: NOW + 300 };
function rt(readers: EscrowReader[], operators: string[], nowS = NOW) {
  const dir = mkdtempSync(path.join(tmpdir(), "mr-r78-"));
  DurableJson.init(path.join(dir, "e.json"), initialEscrowState());
  const store = new DurableJson<EscrowLocalState>(path.join(dir, "e.json"));
  return { store, r: new EscrowRuntime({ readers, appId: 777n, genesisB64: TN, pins: { keyEpoch: 1n, configEpoch: 1n, operators }, store, now: () => nowS * 1000 }) };
}

describe("R76-P3-1 provider distinctness: host dedupe + operator allowlist", () => {
  it("boot check: duplicate host, unlisted operator, MainNet host/operator mismatch and < 2 operators are refused", () => {
    expect(() => assertEscrowProviders([{ provider: "a", host: "x.example" }, { provider: "b", host: "X.example." }], ["a", "b"], "testnet")).toThrow(/duplicate host/);
    expect(() => assertEscrowProviders([{ provider: "a", host: "x.example" }, { provider: "z", host: "y.example" }], ["a", "b"], "testnet")).toThrow(/not in escrow.operators/);
    expect(() => assertEscrowProviders([{ provider: "nodely", host: "mainnet-api.4160.nodely.dev" }, { provider: "drpc", host: "mainnet-api.algonode.cloud" }], ["nodely", "drpc"], "mainnet")).toThrow(/belongs to operator nodely/);
    expect(() => assertEscrowProviders([{ provider: "a", host: "x.example" }], ["a", "b"], "testnet")).toThrow(/>= 2 operators/);
    expect(() => assertEscrowProviders([{ provider: "a", host: "x.example" }, { provider: "b", host: "y.example" }], ["a"], "testnet")).toThrow(/escrow.operators must list/);
    expect(() => assertEscrowProviders([{ provider: "nodely", host: "mainnet-api.4160.nodely.dev" }, { provider: "drpc", host: "algorand.drpc.org" }], ["nodely", "drpc"], "mainnet")).not.toThrow();
  });
  it("runtime: two readers on one host refuse the snapshot", async () => {
    const s = await readEscrowSnapshot([new R("a", "h.example"), new R("b", "h.example")], 777n, TN, NOW);
    expect(s.state).toBeNull();
    expect(s.pages.join()).toMatch(/share a host/);
  });
});

describe("R76-P3-2 pinned list comes from config and fails closed", () => {
  const pending = { expectedLastSeq: 100n, seqTo: 148n, notBefore: 2000, notAfter: 2600 };
  const vs = [{ provider: "p1", lastSeq: 148n, chainNow: 2100 }, { provider: "p2", lastSeq: 148n, chainNow: 2100 }];
  it("an empty pinned list is always pending; abandonIssue needs pinned operators", () => {
    expect(pendingAbandonStatus(pending, vs, [])).toBe("pending");
    expect(pendingAbandonStatus(pending, vs, undefined as never)).toBe("pending");
    expect(pendingAbandonStatus(pending, vs, ["p1", "p2"])).toBe("landed");
    expect(() => abandonIssue(base, 148n, [], [], vs, null, [])).toThrow(/no pinned operators/);
    expect(() => abandonIssue(base, 148n, [], [], vs, null, ["p1", "p9"])).toThrow(/distinct providers/);
  });
  it("settlePending judges with escrow.operators, not the readers' ids: an unlisted reader can't clear a pending abandon", async () => {
    const { r, store } = rt([new R("op-a", undefined, NOW - 3, { lastSeq: 120n }), new R("op-x", undefined, NOW - 3, { lastSeq: 120n })], ["op-a", "op-b"]);
    r.recordPendingAbandon({ expectedLastSeq: 100n, seqTo: 120n, notBefore: NOW - 100, notAfter: NOW + 100 });
    await r.prepareRelease({ ...row, seq: 121n });
    expect(store.get().pending).not.toBeNull();
  });
});

describe("R76-P3-3 signed_at bounded by min chain time + 30", () => {
  it("refuses when the local clock is > 30 s ahead of the min fresh chain time; signs at exactly +30", async () => {
    const p = await rt([new R("a", undefined, NOW - 31), new R("b", undefined, NOW - 3)], ["a", "b"]).r.prepareRelease(row);
    expect(p.action).toBe("refuse");
    expect(p.pages.join()).toMatch(/signed_at .* > min chain time/);
    expect((await rt([new R("a", undefined, NOW - 30), new R("b")], ["a", "b"]).r.prepareRelease(row)).action).toBe("sign");
  });
});

describe("R76-P3-5 nits", () => {
  it("global-state uints keep full u64 precision", () => {
    const j = parseAlgodJson('{"params":{"global-state":[{"key":"eA==","value":{"type":2,"uint":18446744073709551615}}]}}') as { params: { "global-state": { value: { uint: string } }[] } };
    expect(BigInt(j.params["global-state"][0].value.uint)).toBe(18446744073709551615n);
  });
  it("parseU64 refuses '' and non-decimal forms", () => {
    for (const v of ["", " 1", "0x10", "-1", "01", "1e3", "18446744073709551616", 7 as never]) expect(() => parseU64(v, "x")).toThrow();
    expect(parseU64("0", "x")).toBe(0n);
    expect(parseU64("18446744073709551615", "x")).toBe(18446744073709551615n);
  });
  it("resolveEscrowNonce refuses an unknown landing kind at runtime", () => {
    expect(resolveEscrowNonce({ state: "issued", expires: 10 }, { kind: "weird" } as never, 5)).toMatchObject({ action: "refuse", state: "issued" });
  });
});

import { assertPlatformConfig as apc } from "../src/verifier/main.js";
describe("R76-P3-6 AWS co-signer platforms removed", () => {
  const sc = { network: "testnet", providers: [{ operator: "nodely" }] };
  it("aws / aliyun-aws-kms / Roles Anywhere credentials are refused on every network", () => {
    for (const network of ["testnet", "mainnet"]) {
      expect(() => apc({ platform: "aws" as never, providers: [] }, { ...sc, network })).toThrow(/was removed/);
      expect(() => apc({ platform: "aliyun-aws-kms" as never, providers: [] }, { ...sc, network })).toThrow(/was removed/);
      expect(() => apc({ awskms: { region: "us-east-1", keyArn: "arn:aws:kms:us-east-1:000000000000:key/x", roleName: "r", credentialSource: "rolesanywhere-serve" }, providers: [] } as never, { ...sc, network })).toThrow(/was removed/);
    }
  });
});
