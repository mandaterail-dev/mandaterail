/** Run-74 drop: escrow-guard wired into the signer runtime (one pinned-provider snapshot -> guard -> M). */
import { describe, expect, it } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { EscrowRuntime, escrowReleaseMessage, HttpEscrowReader, hoursWindow, initialEscrowState, readEscrowSnapshot, RELEASE_LEN, type EscrowLocalState, type EscrowRead, type EscrowReader } from "../src/escrow-release.js";
import { DurableJson } from "../src/state.js";
import { startMain, type MainConfigFile } from "../src/main.js";
import { STANDIN_LABEL } from "../src/sinks/local-standin.js";
import { keyIdOf } from "@mandaterail/storage";
import { TN, payer, merchant, feePayer, USDC_TN, edKey } from "./fixtures.js";
import type { EscrowAppState } from "../src/escrow-guard.js";

const NOW = 1_800_000_000; // local clock, unix s
const base: EscrowAppState = { bootstrapped: 1, breakerState: 0, keyEpoch: 1n, configEpoch: 1n, lastSeq: 100n, perReleaseCap: 10_000n, dailyHeadroom: 50_000n, releasesThisHour: 0, maxPerHour: 10 };
class FakeReader implements EscrowReader {
  calls = 0;
  constructor(readonly provider: string, public st: Partial<EscrowAppState> = {}, public chainNow = NOW - 3, public genesis: string = TN, public fail = false) {}
  async read(): Promise<EscrowRead> {
    this.calls++;
    if (this.fail) throw new Error("timeout");
    return { provider: this.provider, genesis: this.genesis, round: 1, chainNow: this.chainNow, state: { ...base, ...this.st } };
  }
}
const row = (o: Partial<{ seq: bigint; amount: bigint; challengeExpires: number }> = {}) => ({ seq: 101n, receiver: new Uint8Array(32).fill(7), amount: 5000n, mandateHash: new Uint8Array(32).fill(9), challengeExpires: NOW + 300, ...o });
function rt(readers: EscrowReader[]) {
  const dir = mkdtempSync(path.join(tmpdir(), "mr-escrow-"));
  DurableJson.init(path.join(dir, "escrow.json"), initialEscrowState());
  const store = new DurableJson<EscrowLocalState>(path.join(dir, "escrow.json"));
  return { store, r: new EscrowRuntime({ readers, appId: 777n, genesisB64: TN, pins: { keyEpoch: 1n, configEpoch: 1n, operators: ["op-a", "op-b", "op-c"] }, store, now: () => NOW * 1000 }) };
}

describe("escrow release path: one snapshot feeds the guard and M", () => {
  it("signs M from the same read: epochs and seq checked by the guard are the ones in M; not_after <= C.expires - 30", async () => {
    const a = new FakeReader("op-a"), b = new FakeReader("op-b");
    const { r } = rt([a, b]);
    const p = await r.prepareRelease(row());
    expect(p.action).toBe("sign");
    if (p.action !== "sign") return;
    expect(a.calls).toBe(1); expect(b.calls).toBe(1);
    expect(p.msg.length).toBe(RELEASE_LEN);
    expect(p.notAfter).toBe(NOW + 270);
    expect(p.msg.readBigUInt64BE(20 + 32 + 8)).toBe(1n); // key_epoch
    expect(p.msg.readBigUInt64BE(20 + 32 + 24)).toBe(101n); // seq
    expect(p.msg.equals(escrowReleaseMessage({ genesisHash: Buffer.from(TN, "base64"), appId: 777n, keyEpoch: 1n, configEpoch: 1n, seq: 101n, receiver: row().receiver, amount: 5000n, signedAt: NOW, notAfter: NOW + 270, mandateHash: row().mandateHash }))).toBe(true);
    expect((await r.prepareRelease(row({ challengeExpires: NOW + 1000 }))).action === "sign").toBe(true);
  });
  it("a challenge too close to expiry is refused before M is built", async () => {
    const { r } = rt([new FakeReader("op-a"), new FakeReader("op-b")]);
    const p = await r.prepareRelease(row({ challengeExpires: NOW + 40 }));
    expect(p).toMatchObject({ action: "refuse" });
    expect(p.pages.join()).toMatch(/challenge expires too soon/);
  });
  it("the guard's refusals come from the snapshot (breaker, epoch, seq <= last_seq), merged fail-closed across providers", async () => {
    expect((await rt([new FakeReader("op-a", { breakerState: 1 }), new FakeReader("op-b")]).r.prepareRelease(row())).pages.join()).toMatch(/breaker not RUNNING/);
    const p = await rt([new FakeReader("op-a", { lastSeq: 101n }), new FakeReader("op-b")]).r.prepareRelease(row());
    expect(p.action).toBe("refuse");
    expect(p.pages.join()).toMatch(/escrow last_seq disagreement.*seq 101 <= last_seq 101/s);
    expect((await rt([new FakeReader("op-a", { configEpoch: 2n }), new FakeReader("op-b")]).r.prepareRelease(row())).pages.join()).toMatch(/disagree on app config/);
  });
  it("R74-P3-1/2: fewer than 2 distinct fresh pinned providers refuses; a stalled provider is paged and dropped", async () => {
    expect((await rt([new FakeReader("op-a"), new FakeReader("op-a")]).r.prepareRelease(row())).pages.join()).toMatch(/fewer than 2 fresh/);
    expect((await rt([new FakeReader("op-a"), new FakeReader("op-b", {}, NOW - 3, TN, true)]).r.prepareRelease(row())).pages.join()).toMatch(/read failed: op-b.*fewer than 2/s);
    expect((await rt([new FakeReader("op-a"), new FakeReader("op-b", {}, NOW - 3, "x")]).r.prepareRelease(row())).pages.join()).toMatch(/wrong network/);
    const stalled = new FakeReader("op-c", {}, NOW - 3600);
    const p = await rt([new FakeReader("op-a"), new FakeReader("op-b"), stalled]).r.prepareRelease(row());
    expect(p.action).toBe("sign");
    expect(p.pages.join()).toMatch(/escrow provider stale: op-c/);
  });
  it("pending abandon: refuses seq <= seq_to while pending; a stalled provider can't hold it pending past not_after; clears when every fresh provider agrees", async () => {
    const a = new FakeReader("op-a"), b = new FakeReader("op-b"), c = new FakeReader("op-c", {}, NOW - 9000);
    const { r, store } = rt([a, b, c]);
    r.recordPendingAbandon({ expectedLastSeq: 100n, seqTo: 120n, notBefore: NOW - 100, notAfter: NOW + 100 });
    expect((await r.prepareRelease(row({ seq: 110n }))).pages.join()).toMatch(/pending abandon seq_to 120/);
    a.chainNow = b.chainNow = NOW + 101; // both FRESH providers past not_after; op-c is stalled 2.5 h behind
    const r2 = new EscrowRuntime({ readers: [a, b, c], appId: 777n, genesisB64: TN, pins: { keyEpoch: 1n, configEpoch: 1n, operators: ["op-a", "op-b", "op-c"] }, store, now: () => (NOW + 102) * 1000 });
    const p = await r2.prepareRelease(row({ seq: 110n, challengeExpires: NOW + 500 }));
    expect(p.action).toBe("sign");
    expect(store.get().pending).toBeNull();
    expect(() => r2.recordPendingAbandon({ expectedLastSeq: 100n, seqTo: 120n, notBefore: 1, notAfter: 2 })).not.toThrow();
    expect(() => r2.recordPendingAbandon({ expectedLastSeq: 100n, seqTo: 120n, notBefore: 1, notAfter: 2 })).toThrow(/already pending/);
  });
});

describe("HttpEscrowReader (pinned algod)", () => {
  const ring = Buffer.alloc(600);
  const h = BigInt(Math.floor((NOW - 2) / 3600)); // the head block's hour
  ring.writeBigUInt64BE(h, 0); ring.writeBigUInt64BE(7000n, 8); ring.writeBigUInt64BE(2n, 16);
  ring.writeBigUInt64BE(h - 30n, 24); ring.writeBigUInt64BE(40000n, 32); ring.writeBigUInt64BE(9n, 40); // outside the 25 h window
  const gs = (o: Record<string, number>) => Object.entries(o).map(([k, v]) => ({ key: Buffer.from(k).toString("base64"), value: { type: 2, uint: v } }));
  const glob = { bootstrapped: 1, breaker_state: 0, key_epoch: 1, config_epoch: 3, last_seq: 100, per_release_cap: 10000, daily_cap: 50000, max_per_hour: 10 };
  const fetchFn = (async (url: string) => {
    const u = new URL(url);
    const body = u.pathname === "/v2/status" ? { "last-round": 55 }
      : u.pathname === "/v2/blocks/55" ? { block: { ts: NOW - 2, gh: TN } }
      : u.pathname === "/v2/applications/777" ? { params: { "global-state": gs(glob) } }
      : u.pathname === "/v2/applications/777/box" && u.searchParams.get("name") === "b64:" + Buffer.from("b:hours").toString("base64") ? { value: ring.toString("base64") }
      : null;
    return { status: body ? 200 : 404, json: async () => body };
  }) as never;
  it("reads status, head timestamp, global state and the b:hours ring; provider id = operator", async () => {
    const r = new HttpEscrowReader({ host: "algod-b.example", operator: "op-b", kind: "algod", baseUrl: "https://algod-b.example" }, fetchFn);
    const x = await r.read(777n);
    expect(x).toMatchObject({ provider: "op-b", round: 55, chainNow: NOW - 2, genesis: TN });
    expect(x.state).toMatchObject({ lastSeq: 100n, configEpoch: 3n, dailyHeadroom: 43_000n, releasesThisHour: 2, maxPerHour: 10 });
    const snap = await readEscrowSnapshot([r, new HttpEscrowReader({ host: "algod-c.example", operator: "op-c", kind: "algod", baseUrl: "https://algod-c.example" }, fetchFn)], 777n, TN, NOW);
    expect(snap.state).not.toBeNull();
  });
  it("fails closed: missing global, missing b:hours box, indexer provider", async () => {
    await expect(new HttpEscrowReader({ host: "algod-b.example", operator: "op-b", kind: "algod", baseUrl: "https://algod-b.example" }, fetchFn).read(778n)).rejects.toThrow(/status 404/);
    expect(() => hoursWindow(Buffer.alloc(0), NOW)).toThrow(/b:hours/);
    expect(() => new HttpEscrowReader({ host: "idx.example", operator: "op-a", kind: "indexer", baseUrl: "https://idx.example" })).toThrow(/indexer/);
  });
});

describe("main wiring", () => {
  function cfg(dir: string): MainConfigFile {
    const att = edKey(), rq = edKey();
    return {
      signer: {
        network: "testnet", genesisHash: TN, margin: 10, usdcAsaId: USDC_TN, payer: payer.addr.toString(), merchant: merchant.addr.toString(),
        feePayer: feePayer.addr.toString(), feePayerMaxFee: "2000", payerMaxFee: "1000", keyId: keyIdOf(att.pub),
        providers: [
          { host: "testnet-idx.4160.nodely.dev", operator: "op-a", kind: "indexer", baseUrl: "https://testnet-idx.4160.nodely.dev" },
          { host: "testnet-api.4160.nodely.dev", operator: "op-b", kind: "algod", baseUrl: "https://testnet-api.4160.nodely.dev" },
        ],
        requesters: [{ id: "cli-david", pubkeyB64: Buffer.from(rq.pub).toString("base64") }], requesterRatePerHour: 30, requestMaxAgeS: 30,
        maxClockSkewS: 5, maxSnapshotAgeS: 60, maxHeadSpreadRounds: 20, attestTtlS: 300,
        policy: { maxAmountMicro: "10000", maxReleasesPerHour: 3, maxReleasesPerDay: 5, maxReleasedMicroPerDay: "50000", windowUtcHours: [0, 24], anomalyPauseRefusalsPerHour: 6 },
      },
      attestPubkeyB64: Buffer.from(att.pub).toString("base64"), stateDir: dir, helperSocket: path.join(dir, "h.sock"),
      listen: { host: "127.0.0.1", port: 0, allowIps: ["127.0.0.1"] },
      audit: { kind: "testnet-standin", minSeq: 0, label: STANDIN_LABEL, file: path.join(dir, "audit.jsonl") }, heartbeatIntervalS: 3600,
      escrow: { appId: "777", keyEpoch: "1", configEpoch: "1", operators: ["op-a", "op-b"] },
    };
  }
  const o = (pages: string[]) => ({ pager: async (s: string) => { pages.push(s); }, ping: async () => {}, clock: async () => ({ synced: true, offsetS: 0, stratum: 2 }), probes: [] });
  it("refuses to boot with algod providers from one operator only", async () => {
    await expect(startMain(cfg(mkdtempSync(path.join(tmpdir(), "mr-esc-main-"))), {}, o([]))).rejects.toThrow(/>= 2 operators/);
  });
  it("MrSigner.escrowRelease runs the snapshot path and pages every refusal to the B2 chain", async () => {
    const pages: string[] = [];
    const now = Math.floor(Date.now() / 1000);
    const r = await startMain(cfg(mkdtempSync(path.join(tmpdir(), "mr-esc-main-"))), {}, { ...o(pages), escrowReaders: [new FakeReader("op-a", {}, now), new FakeReader("op-b", { breakerState: 1 }, now)] });
    try {
      const p = await r.signer.escrowRelease({ ...row(), challengeExpires: now + 300 });
      expect(p.action).toBe("refuse");
      expect(pages.join("\n")).toMatch(/\[signer\] escrow-refused/);
    } finally { r.stopHeartbeat(); r.server.close(); }
  });
  it("R76-P3-3: refuses on an unsynced clock (assertClock on the escrow path)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const r = await startMain(cfg(mkdtempSync(path.join(tmpdir(), "mr-esc-main-"))), {}, { ...o([]), escrowReaders: [new FakeReader("op-a", {}, now), new FakeReader("op-b", {}, now)] });
    try {
      let synced = false;
      (r.signer as unknown as { d: { clock: unknown } }).d.clock = async () => ({ synced, offsetS: 0, stratum: 2 });
      await expect(r.signer.escrowRelease({ ...row(), challengeExpires: now + 300 })).rejects.toThrow();
      synced = true;
      expect((await r.signer.escrowRelease({ ...row(), challengeExpires: now + 300 })).action).toBe("sign");
    } finally { r.stopHeartbeat(); r.server.close(); }
  });
  it("R76-P3-4: a pause that lands during prepareRelease still refuses", async () => {
    const now = Math.floor(Date.now() / 1000);
    let hook: () => void = () => {};
    class Hooked extends FakeReader { async read(): Promise<EscrowRead> { hook(); return super.read(); } }
    const r = await startMain(cfg(mkdtempSync(path.join(tmpdir(), "mr-esc-main-"))), {}, { ...o([]), escrowReaders: [new Hooked("op-a", {}, now), new FakeReader("op-b", {}, now)] });
    try {
      hook = () => { hook = () => {}; (r.signer as unknown as { d: { policy: { tamper(s: string): unknown } } }).d.policy.tamper("test: pause during prepareRelease"); };
      await expect(r.signer.escrowRelease({ ...row(), challengeExpires: now + 300 })).rejects.toThrow(/paused/);
    } finally { r.stopHeartbeat(); r.server.close(); }
  });
});

