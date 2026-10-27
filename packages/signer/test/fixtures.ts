import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import algosdk from "algosdk";
import { keyIdOf, isoSeconds } from "@mandaterail/storage";
import { GENESIS_PINS, type SignerConfig } from "../src/config.js";
import type { ChainProbe, ProbeResult } from "../src/providers.js";
import { DurableJson } from "../src/state.js";
import { initialPolicyState, PolicyEngine, type PolicyState } from "../src/policy.js";
import { initialReqState, RequestAuth, signRequest, type ReqState } from "../src/requests.js";
import { ChainedAudit } from "../src/audit.js";
import { MrSigner, type HelperLike } from "../src/signer.js";

export const TN = GENESIS_PINS.testnet;
export const GENESIS_MN = GENESIS_PINS.mainnet;
export class MemSink {
  lines: string[] = [];
  async append(l: string) { this.lines.push(l); }
  async last() { return this.lines.at(-1) ?? null; }
  async at(seq: number) { return this.lines.find((l) => (JSON.parse(l.split("\t")[0]!) as { seq?: number }).seq === seq) ?? null; }
}
export const payer = algosdk.generateAccount();
export const merchant = algosdk.generateAccount();
export const feePayer = algosdk.generateAccount();
export const USDC_TN = 10458941;

export function edKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { pub: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)), priv: privateKey };
}

export function signedPayment(o: { fv?: number; lv?: number; amount?: bigint; receiver?: string; asset?: number; group?: boolean; close?: boolean; rekey?: boolean; payerFee?: bigint } = {}): { bytes: Uint8Array; txId: string; groupId: string } {
  const sp = { fee: o.payerFee ?? 0n, minFee: 1000n, firstValid: BigInt(o.fv ?? 100), lastValid: BigInt(o.lv ?? 1100), genesisHash: Buffer.from(TN, "base64"), genesisID: "testnet-v1.0", flatFee: true };
  const t = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
    sender: payer.addr, receiver: o.receiver ?? merchant.addr, amount: o.amount ?? 10_000n, assetIndex: o.asset ?? USDC_TN, suggestedParams: sp,
    closeRemainderTo: o.close ? merchant.addr : undefined, rekeyTo: o.rekey ? merchant.addr : undefined,
  } as never);
  if (!o.group) return { bytes: t.signTxn(payer.sk), txId: t.txID(), groupId: "" };
  const f = algosdk.makePaymentTxnWithSuggestedParamsFromObject({ sender: feePayer.addr, receiver: feePayer.addr, amount: 0n, suggestedParams: { ...sp, fee: 2000n } });
  algosdk.assignGroupID([t, f]);
  return { bytes: new Uint8Array([...t.signTxn(payer.sk), ...f.signTxn(feePayer.sk)]), txId: t.txID(), groupId: Buffer.from(t.group!).toString("base64") };
}

export class FakeProbe implements ChainProbe {
  result: ProbeResult;
  calls = 0;
  constructor(readonly provider: { host: string; operator: string; kind: "indexer" | "algod"; baseUrl: string }, r?: ProbeResult) {
    this.result = r ?? (provider.kind === "indexer" ? { kind: "absent", method: "idx404", round: 1200, idxRound: 1200, genesis: TN } : { kind: "absent", method: "blockscan", round: 1201, idxRound: 1100, genesis: TN });
  }
  async probe(): Promise<ProbeResult> { this.calls++; return this.result; }
}

export async function setup(over: Partial<SignerConfig> = {}, helperOverride?: (signKey: ReturnType<typeof edKey>, requesterPub: Uint8Array) => HelperLike, opts: { sink?: MemSink; pageFail?: { on: boolean } } = {}) {
  const dir = mkdtempSync(path.join(tmpdir(), "mr-signer-"));
  const att = edKey();
  const requester = edKey();
  const providers = [
    { host: "idx-a.example", operator: "test-op-a", kind: "indexer" as const, baseUrl: "https://idx-a.example" },
    { host: "algod-b.example", operator: "test-op-b", kind: "algod" as const, baseUrl: "https://algod-b.example" },
    { host: "idx-c.example", operator: "test-op-c", kind: "indexer" as const, baseUrl: "https://idx-c.example" },
  ];
  const cfg: SignerConfig = {
    network: "testnet", genesisHash: TN, margin: 10, usdcAsaId: USDC_TN, payer: payer.addr.toString(), merchant: merchant.addr.toString(),
    feePayer: feePayer.addr.toString(), feePayerMaxFee: 2000n, payerMaxFee: 1000n, keyId: keyIdOf(att.pub), providers,
    requesters: [{ id: "cli-david", pubkey: requester.pub }], requesterRatePerHour: 30, requestMaxAgeS: 30,
    maxClockSkewS: 5, maxSnapshotAgeS: 60, maxHeadSpreadRounds: 20, attestTtlS: 300,
    policy: { maxAmountMicro: 10_000n, maxReleasesPerHour: 3, maxReleasesPerDay: 5, maxReleasedMicroPerDay: 50_000n, windowUtcHours: [0, 24], anomalyPauseRefusalsPerHour: 6 },
    ...over,
  };
  DurableJson.init<PolicyState>(path.join(dir, "policy.json"), initialPolicyState());
  DurableJson.init<ReqState>(path.join(dir, "requests.json"), initialReqState());
  const policy = new PolicyEngine(cfg.policy, new DurableJson<PolicyState>(path.join(dir, "policy.json")));
  const auth = new RequestAuth(cfg.requesters, new DurableJson<ReqState>(path.join(dir, "requests.json")), { maxAgeS: cfg.requestMaxAgeS, ratePerHour: cfg.requesterRatePerHour, network: cfg.network });
  const probes = providers.map((p) => new FakeProbe(p));
  const pages: string[] = [];
  const sink = opts.sink ?? new MemSink();
  const pageFail = opts.pageFail ?? { on: false };
  const logLines = sink.lines;
  const audit = await ChainedAudit.open(sink, async (subj) => { if (pageFail.on) throw new Error("ntfy down"); pages.push(subj); });
  const clockState = { synced: true, offsetS: 0.01, stratum: 2 };
  const helper: HelperLike = helperOverride ? helperOverride(att, requester.pub) : { sign: async (m) => new Uint8Array(sign(null, Buffer.from(m), att.priv)) };
  const deps = { cfg, auth, policy, probes, clock: async () => clockState, audit, helper, backend: { publicKey: async () => att.pub } };
  const signer = MrSigner.boot(deps);
  const req = (body: Record<string, unknown>) => signRequest({ requester: "cli-david", network: "testnet", ts: isoSeconds(Date.now()), reqNonce: randomBytes(32).toString("base64url"), ...body } as never, requester.priv);
  return { dir, cfg, att, requester, policy, auth, probes, logLines, pages, clockState, signer, req, sink, pageFail, deps, audit };
}

export function candidateBody(store: string, spendId: string, p: ReturnType<typeof signedPayment>, o: { kind?: "xpayment" | "group"; submitRound?: number; submitAgoS?: number; snapshotAgoS?: number; row?: Record<string, unknown> } = {}) {
  return {
    op: "candidate", store, spendId, kind: o.kind ?? "xpayment", signedTxn: Buffer.from(p.bytes).toString("base64"),
    snapshotAt: isoSeconds(Date.now() - (o.snapshotAgoS ?? 0) * 1000),
    row: { status: "ambiguous", txId: p.txId, firstValid: 100, lastValid: 1100, groupId: p.groupId, sender: payer.addr.toString(), amountMicro: "10000",
      submitRound: o.submitRound ?? 150, submitAt: isoSeconds(Date.now() - (o.submitAgoS ?? 3600) * 1000), ...o.row },
  };
}

/** A real PivHelper with its own nonce store and state, trusting `requesterPub` (TESTNET-ONLY software backend). */
export async function realHelper(network: "testnet" | "mainnet", requesterPub: Uint8Array, be?: import("../src/piv/backend.js").SignBackend, now?: () => number) {
  const { SoftwareEd25519Backend } = await import("../src/piv/backend-software.js");
  const { PivHelper, initialHelperState } = await import("../src/piv/helper.js");
  const { UsedStore } = await import("../src/piv/used-store.js");
  process.env.MR_SIGNER_SOFTWARE_KEY = "TESTNET-ONLY";
  const backend = be ?? new SoftwareEd25519Backend("testnet");
  const keyId = keyIdOf(await backend.publicKey());
  const dir = mkdtempSync(path.join(tmpdir(), "mr-piv-"));
  DurableJson.init(path.join(dir, "helper.json"), initialHelperState());
  DurableJson.init<ReqState>(path.join(dir, "requests.json"), initialReqState());
  const used = UsedStore.init(path.join(dir, "used.log"));
  const auth = new RequestAuth([{ id: "cli-david", pubkey: requesterPub }], new DurableJson<ReqState>(path.join(dir, "requests.json")), { maxAgeS: 30, ratePerHour: 30, network }, now);
  const helper = new PivHelper({ network, keyId, payer: payer.addr.toString(), margin: 10, operators: ["test-op-a", "test-op-b", "test-op-c"], maxSignsPerHour: 3, maxSignsPer24h: 5 },
    backend, used, auth, new DurableJson(path.join(dir, "helper.json")), now);
  return { helper, backend, keyId, dir, used, usedFile: path.join(dir, "used.log") };
}
