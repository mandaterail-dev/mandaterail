/**
 * §2.2 observations. Every pinned provider is queried; ANY provider showing the txn (or a group member)
 * present refuses and auto-pauses (R42-P3-1). At least two distinct operators must positively prove absence.
 */
import { isForbiddenProviderHost } from "@mandaterail/core";
import { createHash } from "node:crypto";
import { msgpackRawDecodeAsMap, msgpackRawEncode } from "algosdk";
import type { Observation } from "@mandaterail/storage";
import type { PinnedProvider, SignerConfig } from "./config.js";

export type ProbeResult =
  | { kind: "absent"; method: "idx404" | "blockscan" | "blockscan-full"; round: number; idxRound: number; genesis: string }
  | { kind: "present"; genesis: string }
  | { kind: "error"; reason: string };

export interface ChainProbe {
  readonly provider: PinnedProvider;
  /** absence of every txId in [fv, lv] */
  probe(txIds: string[], fv: number, lv: number): Promise<ProbeResult>;
}

export type FetchFn = (url: string, init?: { signal?: AbortSignal; redirect?: "error"; headers?: Record<string, string> }) => Promise<{ status: number; json(): Promise<unknown>; arrayBuffer?(): Promise<ArrayBuffer> }>;

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32NoPad(b: Uint8Array): string {
  let bits = 0, val = 0, out = "";
  for (const x of b) { val = (val << 8) | x; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

/**
 * blockscan-full: the txids of one msgpack block (algod /v2/blocks/{r}?format=msgpack), computed locally.
 * R58-P3-1: works on the RAW txn map (msgpackRawDecodeAsMap, canonical re-encode), never an algosdk model round-trip,
 * so fields the SDK doesn't know are still hashed. The block omits gen/gh from each txn: gen is restored when hgi is
 * set, gh always (MainNet/TestNet RequireGenesisHash). txid = base32(sha512_256("TX" || msgpack(txn))). Top-level only.
 */
export function blockTxIdsFromMsgpack(buf: Uint8Array): { genesisHash: string; round: number; txIds: string[] } {
  const top = msgpackRawDecodeAsMap(buf) as Map<unknown, unknown>;
  const blk = top.get("block");
  if (!(blk instanceof Map)) throw new Error("no block");
  const gh = blk.get("gh"), gen = blk.get("gen"), rnd = blk.get("rnd");
  if (!(gh instanceof Uint8Array) || gh.length !== 32) throw new Error("block gh");
  const txns = blk.get("txns") ?? [];
  if (!Array.isArray(txns)) throw new Error("block txns");
  const txIds = txns.map((st: unknown) => {
    if (!(st instanceof Map) || !(st.get("txn") instanceof Map)) throw new Error("block txn");
    const t = new Map(st.get("txn") as Map<unknown, unknown>);
    if (st.get("hgi")) { if (typeof gen !== "string") throw new Error("block gen"); t.set("gen", gen); }
    t.set("gh", gh);
    const enc = msgpackRawEncode(t as never);
    const h = createHash("sha512-256").update(Buffer.concat([Buffer.from("TX"), Buffer.from(enc)])).digest();
    return base32NoPad(h);
  });
  return { genesisHash: Buffer.from(gh).toString("base64"), round: Number(rnd ?? 0), txIds };
}

const num = (x: unknown) => (typeof x === "number" && Number.isSafeInteger(x) && x >= 0 ? x : null);

/** HTTPS probe for a pinned indexer (idx404) or algod (blockscan). No redirects, 10 s timeout. */
/** R60-P3-1: one probe() call's scan state: its abort signal (deadline, stop or exit) and whether the deadline fired. */
interface ScanCtx { signal: AbortSignal; deadlineHit: boolean; abort?: () => void }

export class HttpProbe implements ChainProbe {
  private readonly headers: Record<string, string>;
  /**
   * R58-P3-2 / R59-P3-2: the WHOLE probe (from probe() entry: status, params and every block) has an overall deadline
   * (default 240 s, below Node's 300 s server requestTimeout); at the deadline every in-flight request is aborted and
   * the probe returns error "scan deadline". blockscan-full fetches with small bounded parallelism (default 4 in
   * flight; dRPC free allows ~100 RPS). Both come from SignerConfig.scan.
   */
  private readonly scanDeadlineMs: number;
  private readonly scanConcurrency: number;
  constructor(readonly provider: PinnedProvider, private readonly fetchFn: FetchFn = fetch as unknown as FetchFn, private readonly timeoutMs = 10_000, env: Record<string, string | undefined> = process.env,
    scan: { deadlineMs?: number; concurrency?: number } = {}) {
    this.scanDeadlineMs = scan.deadlineMs ?? 240_000;
    this.scanConcurrency = scan.concurrency ?? 4;
    if (!(this.scanDeadlineMs > 0 && this.scanDeadlineMs <= 240_000)) throw new Error("scan deadline must be in (0, 240 s]");
    if (!(Number.isInteger(this.scanConcurrency) && this.scanConcurrency >= 1 && this.scanConcurrency <= 8)) throw new Error("scan concurrency must be 1..8");
    if (isForbiddenProviderHost(provider.host)) throw new Error(`forbidden provider host ${provider.host}`);
    // Blockdaemon: X-API-Key from the named env var (the key never appears in config, URLs, logs or errors)
    if (provider.apiKeyEnv) {
      const k = (env[provider.apiKeyEnv] ?? "").trim();
      if (!k) throw new Error(`provider ${provider.host}: env ${provider.apiKeyEnv} is not set`);
      this.headers = { "X-API-Key": k };
    } else this.headers = {};
  }
  private async get(ctx: ScanCtx, path: string): Promise<{ status: number; body: unknown }> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    const sig = AbortSignal.any([ac.signal, ctx.signal]);
    try {
      this.requests++;
      const r = await this.fetchFn(this.provider.baseUrl.replace(/\/$/, "") + path, { signal: sig, redirect: "error", headers: this.headers });
      let body: unknown = null;
      try { body = await r.json(); } catch { body = null; }
      return { status: r.status, body };
    } finally {
      clearTimeout(t);
    }
  }
  /** requests made by the last probe() (for limits / the live check) */
  requests = 0;
  private async getBin(ctx: ScanCtx, path: string): Promise<{ status: number; bytes: Uint8Array | null }> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    const sig = AbortSignal.any([ac.signal, ctx.signal]);
    try {
      this.requests++;
      const r = await this.fetchFn(this.provider.baseUrl.replace(/\/$/, "") + path, { signal: sig, redirect: "error", headers: { ...this.headers, Accept: "application/msgpack" } });
      if (r.status !== 200 || !r.arrayBuffer) return { status: r.status, bytes: null };
      return { status: r.status, bytes: new Uint8Array(await r.arrayBuffer()) };
    } finally {
      clearTimeout(t);
    }
  }
  async probe(txIds: string[], fv: number, lv: number): Promise<ProbeResult> {
    this.requests = 0;
    // R60-P3-1: per-call state (no shared fields between concurrent probe() calls)
    const scan = new AbortController();
    const ctx: ScanCtx = { signal: scan.signal, deadlineHit: false, abort: () => scan.abort() };
    const deadline = Date.now() + this.scanDeadlineMs; // R59-P3-2: from probe() entry
    const timer = setTimeout(() => { ctx.deadlineHit = true; scan.abort(); }, this.scanDeadlineMs);
    try {
      const r = await this.probeInner(ctx, txIds, fv, lv, deadline);
      return ctx.deadlineHit ? { kind: "error", reason: "scan deadline" } : r;
    } finally {
      clearTimeout(timer);
      scan.abort(); // R60-P3-1: whatever ended the probe, no background fetch keeps running
    }
  }
  private async probeInner(ctx: ScanCtx, txIds: string[], fv: number, lv: number, deadline: number): Promise<ProbeResult> {
    try {
      if (this.provider.kind === "indexer") {
        const h = await this.get(ctx, "/health");
        const b = h.body as Record<string, unknown> | null;
        const round = num(b?.round);
        let genesis = typeof b?.["genesis-hash"] === "string" ? (b["genesis-hash"] as string) : null;
        if (h.status !== 200 || round === null) return { kind: "error", reason: "indexer health" };
        if (!genesis) {
          // R44: Nodely's indexer /health has no genesis-hash; read it from the head block's header instead
          const blk = await this.get(ctx, `/v2/blocks/${round}?header-only=true`);
          const g = (blk.body as Record<string, unknown> | null)?.["genesis-hash"];
          genesis = blk.status === 200 && typeof g === "string" ? g : null;
          if (!genesis) return { kind: "error", reason: "indexer genesis" };
        }
        for (const id of txIds) {
          const r = await this.get(ctx, `/v2/transactions/${encodeURIComponent(id)}`);
          if (r.status === 200) return { kind: "present", genesis };
          if (r.status !== 404) return { kind: "error", reason: `indexer status ${r.status}` };
        }
        return { kind: "absent", method: "idx404", round, idxRound: round, genesis };
      }
      const st = await this.get(ctx, "/v2/status");
      const head = num((st.body as Record<string, unknown> | null)?.["last-round"]);
      const params = await this.get(ctx, "/v2/transactions/params");
      const gRaw = (params.body as Record<string, unknown> | null)?.["genesis-hash"];
      const genesis = typeof gRaw === "string" ? gRaw : null;
      if (st.status !== 200 || head === null || !genesis) return { kind: "error", reason: "algod status" };
      if (lv - fv > 1000 || head < lv) return { kind: "error", reason: "range" };
      const want = new Set(txIds);
      if (this.provider.kind === "blockscan-full") {
        let next = fv;
        let stop: ProbeResult | null = null;
        const worker = async () => {
          while (!stop && next <= lv) {
            if (Date.now() > deadline) { stop ??= { kind: "error", reason: "scan deadline" }; return; }
            const r = next++;
            let b: Awaited<ReturnType<HttpProbe["getBin"]>>;
            try {
              b = await this.getBin(ctx, `/v2/blocks/${r}?format=msgpack`);
            } catch (e) {
              // R60-P3-1: a failed fetch stops every worker and aborts the other in-flight fetches
              stop ??= { kind: "error", reason: ctx.deadlineHit ? "scan deadline" : (e as Error).name === "AbortError" ? "timeout" : "fetch failed" };
              ctx.abort?.();
              return;
            }
            if (stop) return;
            if (b.status !== 200 || !b.bytes) { stop = { kind: "error", reason: `block ${r} not served` }; return; }
            let blk: ReturnType<typeof blockTxIdsFromMsgpack>;
            try { blk = blockTxIdsFromMsgpack(b.bytes); } catch { stop = { kind: "error", reason: `block ${r} undecodable` }; return; }
            if (blk.round !== r) { stop = { kind: "error", reason: `block ${r} round mismatch` }; return; }
            if (blk.genesisHash !== genesis) { stop = { kind: "error", reason: `block ${r} genesis mismatch` }; return; }
            if (blk.txIds.some((x) => want.has(x))) { stop = { kind: "present", genesis }; return; }
          }
        };
        await Promise.all(Array.from({ length: Math.min(this.scanConcurrency, lv - fv + 1) }, async () => {
          await worker();
          if (stop) ctx.abort?.(); // first decisive result (present / error) cancels the rest
        }));
        if (stop) return stop;
        if (Date.now() > deadline) return { kind: "error", reason: "scan deadline" };
        return { kind: "absent", method: "blockscan-full", round: head, idxRound: lv, genesis };
      }
      for (let r = fv; r <= lv; r++) {
        if (Date.now() > deadline) return { kind: "error", reason: "scan deadline" };
        const b = await this.get(ctx, `/v2/blocks/${r}/txids`);
        const ids = (b.body as Record<string, unknown> | null)?.blockTxids;
        if (b.status !== 200 || !Array.isArray(ids)) return { kind: "error", reason: `block ${r} not served` };
        if (ids.some((x) => want.has(String(x)))) return { kind: "present", genesis };
      }
      return { kind: "absent", method: "blockscan", round: head, idxRound: lv, genesis };
    } catch (e) {
      if (ctx.deadlineHit) return { kind: "error", reason: "scan deadline" };
      return { kind: "error", reason: (e as Error).name === "AbortError" ? "timeout" : "fetch failed" };
    }
  }
}

export class AbsenceRefused extends Error {
  constructor(msg: string, readonly anomaly: boolean) { super(msg); }
}

/** Builds the observations or refuses. `nowIso` is the signer's (chrony-checked) UTC second. */
export async function observeAbsence(probes: ChainProbe[], c: SignerConfig, t: { txIds: string[]; fv: number; lv: number }, nowIso: () => string): Promise<{ observations: Observation[]; round: number }> {
  const results = await Promise.all(probes.map(async (p) => ({ p: p.provider, r: await p.probe(t.txIds, t.fv, t.lv), at: nowIso() })));
  for (const x of results) {
    if (x.r.kind === "present") throw new AbsenceRefused(`provider ${x.p.host} (${x.p.operator}) shows the transaction present`, true);
    if (x.r.kind !== "error" && x.r.genesis !== c.genesisHash) throw new AbsenceRefused(`provider ${x.p.host} genesis is not the ${c.network} pin`, true);
  }
  const need = t.lv + c.margin;
  const ok = results.filter((x): x is typeof x & { r: Extract<ProbeResult, { kind: "absent" }> } =>
    x.r.kind === "absent" && x.r.round >= need && (x.r.method === "idx404" ? x.r.idxRound >= need : x.r.idxRound === t.lv));
  const heads = ok.map((x) => x.r.round);
  if (heads.length && Math.max(...heads) - Math.min(...heads) > c.maxHeadSpreadRounds) {
    throw new AbsenceRefused("provider heads disagree beyond the staleness bound", true);
  }
  // one observation per operator (the best one), sorted by operator, 2..4
  const byOp = new Map<string, (typeof ok)[number]>();
  for (const x of ok) if (!byOp.has(x.p.operator)) byOp.set(x.p.operator, x);
  const chosen = [...byOp.values()].sort((a, b) => (a.p.operator < b.p.operator ? -1 : 1)).slice(0, 4);
  if (chosen.length < 2) throw new AbsenceRefused(`absence proven by ${chosen.length} operator(s); need 2`, false);
  const observations: Observation[] = chosen.map((x) => ({
    at: x.at, idxRound: x.r.idxRound, method: x.r.method, operator: x.p.operator, provider: x.p.host, round: x.r.round,
  }));
  return { observations, round: Math.min(...observations.map((o) => o.round)) };
}
