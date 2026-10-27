/**
 * Escrow release path (design rev 6 §1.2 / §1.4 / §5.4): ONE snapshot of the escrow app, read from every pinned algod
 * provider, feeds both the guard (escrowPreflight / pendingAbandonStatus) and the release message M, so the epochs and
 * seq bound into M are the ones the guard checked. Nothing here signs or submits: it returns M for the signing flow.
 */
import { escrowNotAfter, EscrowTimingRefused, isForbiddenProviderHost, MAINNET_PROVIDER_ALLOWLIST, normalizeProviderHost } from "@mandaterail/core";
import { escrowPreflight, freshViews, pendingAbandonStatus, ESCROW_MIN_PROVIDERS, type EscrowAppState, type EscrowPins, type PendingAbandon, type ProviderView } from "./escrow-guard.js";
import type { PinnedProvider } from "./config.js";
import type { FetchFn } from "./providers.js";
import type { DurableJson } from "./state.js";

export const RELEASE_PREFIX = "MR-ESCROW-RELEASE-v1"; // 20 bytes
export const RELEASE_LEN = 172;
/** R76-P3-3: the contract requires signed_at <= global timestamp + 30 (design :195). */
export const ESCROW_SIGNED_AT_MAX_AHEAD_S = 30;
const u64Field = (v: unknown): bigint => {
  if (v === undefined) return 0n;
  if (typeof v === "string" && /^\d+$/.test(v)) return BigInt(v);
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  throw new Error("global uint not a u64");
};

/** One provider's read of the app. */
export interface EscrowRead { provider: string; genesis: string; round: number; chainNow: number; state: EscrowAppState }
/** `provider` = operator id; `host` = normalized provider host (R76-P3-1: two readers on one host count once -> refused). */
export interface EscrowReader { readonly provider: string; readonly host?: string; read(appId: bigint): Promise<EscrowRead> }

/**
 * R76-P3-1/2 boot check for the escrow providers: every operator is on the config allowlist (escrow.operators), no two
 * providers share a normalized host, on MainNet the host must map to that operator in MAINNET_PROVIDER_ALLOWLIST (a
 * free-text label can't make one operator count twice), and >= ESCROW_MIN_PROVIDERS distinct operators remain.
 */
export function assertEscrowProviders(providers: ReadonlyArray<{ provider: string; host?: string }>, allowlist: readonly string[], network: string): void {
  if (!Array.isArray(allowlist) || allowlist.length < ESCROW_MIN_PROVIDERS || allowlist.some((x) => typeof x !== "string" || !x)) throw new Error(`escrow.operators must list >= ${ESCROW_MIN_PROVIDERS} operator ids`);
  if (new Set(allowlist).size !== allowlist.length) throw new Error("escrow.operators has duplicates");
  const hosts = new Set<string>();
  for (const p of providers) {
    if (!allowlist.includes(p.provider)) throw new Error(`escrow provider operator ${p.provider} is not in escrow.operators`);
    if (p.host !== undefined) {
      const h = normalizeProviderHost(p.host);
      if (hosts.has(h)) throw new Error(`escrow providers: duplicate host ${h}`);
      hosts.add(h);
      if (network === "mainnet") {
        const e = MAINNET_PROVIDER_ALLOWLIST.find((x) => x.host === h);
        if (!e) throw new Error(`escrow provider host ${h} is not on the MainNet provider allowlist`);
        if (e.operator !== p.provider) throw new Error(`escrow provider host ${h} belongs to operator ${e.operator}, not ${p.provider}`);
      }
    } else if (network === "mainnet") throw new Error("escrow providers on MainNet must carry a host");
  }
  if (new Set(providers.map((p) => p.provider)).size < ESCROW_MIN_PROVIDERS) throw new Error(`escrow needs algod providers from >= ${ESCROW_MIN_PROVIDERS} operators`);
}

/** R76-P3-5: algod global-state uints can exceed 2^53; quote them before JSON.parse so BigInt sees every digit. */
export function parseAlgodJson(text: string): unknown {
  return JSON.parse(text.replace(/("uint"\s*:\s*)(\d+)/g, '$1"$2"'));
}

const u64 = (v: bigint) => { if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new Error("u64 out of range"); const b = Buffer.alloc(8); b.writeBigUInt64BE(v); return b; };

/** §1.2: the 172-byte M both keys sign. */
export function escrowReleaseMessage(m: { genesisHash: Uint8Array; appId: bigint; keyEpoch: bigint; configEpoch: bigint; seq: bigint; receiver: Uint8Array; amount: bigint; signedAt: number; notAfter: number; mandateHash: Uint8Array }): Buffer {
  if (m.genesisHash.length !== 32 || m.receiver.length !== 32 || m.mandateHash.length !== 32) throw new Error("genesis / receiver / mandate_hash must be 32 bytes");
  const b = Buffer.concat([Buffer.from(RELEASE_PREFIX, "ascii"), Buffer.from(m.genesisHash), u64(m.appId), u64(m.keyEpoch), u64(m.configEpoch), u64(m.seq),
    Buffer.from(m.receiver), u64(m.amount), u64(BigInt(m.signedAt)), u64(BigInt(m.notAfter)), Buffer.from(m.mandateHash)]);
  if (b.length !== RELEASE_LEN) throw new Error("release message length");
  return b;
}

const GLOBAL_UINTS = ["bootstrapped", "breaker_state", "key_epoch", "config_epoch", "last_seq", "per_release_cap", "daily_cap", "max_per_hour"] as const;

/** Algod reader for one pinned provider (kind algod / blockscan-full): status, head block timestamp, global state, b:hours. */
export class HttpEscrowReader implements EscrowReader {
  readonly provider: string;
  readonly host: string;
  private readonly headers: Record<string, string>;
  constructor(private readonly p: PinnedProvider, private readonly fetchFn: FetchFn = fetch as unknown as FetchFn, private readonly timeoutMs = 10_000, env: Record<string, string | undefined> = process.env) {
    if (p.kind === "indexer") throw new Error(`escrow reader needs an algod provider, ${p.host} is an indexer`);
    if (isForbiddenProviderHost(p.host)) throw new Error(`forbidden provider host ${p.host}`);
    this.provider = p.operator; // R74-P3-1: distinct = distinct OPERATOR (Nodely and algonode.cloud count once)
    this.host = normalizeProviderHost(p.host);
    if (p.apiKeyEnv) {
      const k = (env[p.apiKeyEnv] ?? "").trim();
      if (!k) throw new Error(`provider ${p.host}: env ${p.apiKeyEnv} is not set`);
      this.headers = { "X-API-Key": k };
    } else this.headers = {};
  }
  private async get(path: string): Promise<Record<string, unknown>> {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), this.timeoutMs);
    try {
      const r = await this.fetchFn(this.p.baseUrl.replace(/\/$/, "") + path, { signal: ac.signal, redirect: "error", headers: this.headers });
      // R76-P3-5: parse the raw text so large uints keep their precision (json() only if the fetch has no text())
      const rt = r as { text?: () => Promise<string>; json(): Promise<unknown> };
      const body = (rt.text ? await rt.text().then(parseAlgodJson).catch(() => null) : await r.json().catch(() => null)) as Record<string, unknown> | null;
      if (r.status !== 200 || !body || typeof body !== "object") throw new Error(`${this.provider} ${path.split("?")[0]}: status ${r.status}`);
      return body as Record<string, unknown>;
    } finally { clearTimeout(t); }
  }
  async read(appId: bigint): Promise<EscrowRead> {
    const st = await this.get("/v2/status");
    const round = st["last-round"];
    if (typeof round !== "number" || !Number.isSafeInteger(round)) throw new Error(`${this.provider}: status last-round`);
    const hdr = (await this.get(`/v2/blocks/${round}?header-only=true`)).block as Record<string, unknown> | undefined;
    const chainNow = hdr?.ts, genesis = hdr?.gh;
    if (typeof chainNow !== "number" || typeof genesis !== "string") throw new Error(`${this.provider}: block header ts/gh`);
    const app = await this.get(`/v2/applications/${appId}`);
    const gs = ((app.params as Record<string, unknown> | undefined)?.["global-state"] ?? []) as { key: string; value: { type: number; uint?: number | string } }[];
    const g = new Map<string, bigint>();
    for (const kv of gs) if (kv.value?.type === 2) g.set(Buffer.from(kv.key, "base64").toString("latin1"), u64Field(kv.value.uint));
    for (const k of GLOBAL_UINTS) if (!g.has(k)) throw new Error(`${this.provider}: global ${k} missing`);
    const box = await this.get(`/v2/applications/${appId}/box?name=${encodeURIComponent("b64:" + Buffer.from("b:hours").toString("base64"))}`);
    const ring = Buffer.from(String(box.value ?? ""), "base64");
    const { sum, count } = hoursWindow(ring, chainNow);
    const st2: EscrowAppState = {
      bootstrapped: Number(g.get("bootstrapped")), breakerState: Number(g.get("breaker_state")), keyEpoch: g.get("key_epoch")!, configEpoch: g.get("config_epoch")!,
      lastSeq: g.get("last_seq")!, perReleaseCap: g.get("per_release_cap")!, dailyHeadroom: g.get("daily_cap")! > sum ? g.get("daily_cap")! - sum : 0n,
      releasesThisHour: count, maxPerHour: Number(g.get("max_per_hour")),
    };
    return { provider: this.provider, genesis, round, chainNow, state: st2 };
  }
}

/** §4.2 ring (25 x (hour_index, sum, count) u64 BE): sum over hours [h-24, h], count of the current hour. Missing box fails closed. */
export function hoursWindow(ring: Buffer, chainNow: number): { sum: bigint; count: number } {
  if (ring.length !== 600) throw new Error("b:hours box missing or not 600 bytes");
  const h = BigInt(Math.floor(chainNow / 3600));
  let sum = 0n, count = 0;
  for (let i = 0; i < 25; i++) {
    const hi = ring.readBigUInt64BE(i * 24), s = ring.readBigUInt64BE(i * 24 + 8), c = ring.readBigUInt64BE(i * 24 + 16);
    if (hi >= h - 24n && hi <= h) sum += s;
    if (hi === h) count = Number(c);
  }
  return { sum, count };
}

export interface EscrowSnapshot { state: EscrowAppState; views: ProviderView[]; pages: string[] }
/**
 * Reads every pinned provider once. Needs >= ESCROW_MIN_PROVIDERS distinct FRESH providers (R74-P3-2 staleness bound)
 * on the pinned genesis; config fields must agree exactly; the rest is merged in the fail-closed direction
 * (highest last_seq, lowest headroom, highest hour count, any breaker trip). Returns null state on refusal.
 */
export async function readEscrowSnapshot(readers: readonly EscrowReader[], appId: bigint, genesisB64: string, localNow: number): Promise<EscrowSnapshot | { state: null; views: ProviderView[]; pages: string[] }> {
  const pages: string[] = [];
  const hs = readers.map((r) => r.host).filter((h): h is string => h !== undefined);
  if (new Set(hs).size !== hs.length) { pages.push("escrow preflight refused: two pinned providers share a host"); return { state: null, views: [], pages }; }
  const got = await Promise.all(readers.map((r) => r.read(appId).then((x) => x, (e: unknown) => { pages.push(`escrow provider read failed: ${r.provider}: ${(e as Error).message.slice(0, 160)}`); return null; })));
  const reads = got.filter((x): x is EscrowRead => x !== null).filter((x) => {
    if (x.genesis !== genesisB64) { pages.push(`escrow provider on the wrong network: ${x.provider}`); return false; }
    return true;
  });
  const all: ProviderView[] = reads.map((x) => ({ provider: x.provider, lastSeq: x.state.lastSeq, chainNow: x.chainNow }));
  const { fresh, pages: stale } = freshViews(all, localNow);
  pages.push(...stale);
  const ok = reads.filter((x) => fresh.some((v) => v.provider === x.provider));
  if (new Set(ok.map((x) => x.provider)).size < ESCROW_MIN_PROVIDERS) {
    pages.push(`escrow preflight refused: fewer than ${ESCROW_MIN_PROVIDERS} fresh pinned providers`);
    return { state: null, views: fresh, pages };
  }
  const s0 = ok[0].state;
  for (const x of ok) {
    const s = x.state;
    if (s.keyEpoch !== s0.keyEpoch || s.configEpoch !== s0.configEpoch || s.perReleaseCap !== s0.perReleaseCap || s.maxPerHour !== s0.maxPerHour || s.bootstrapped !== s0.bootstrapped) {
      pages.push("escrow preflight refused: providers disagree on app config");
      return { state: null, views: fresh, pages };
    }
  }
  const seqs = new Set(ok.map((x) => x.state.lastSeq));
  if (seqs.size > 1) pages.push(`escrow last_seq disagreement: ${[...seqs].join(" / ")}`);
  const st: EscrowAppState = {
    ...s0,
    lastSeq: ok.reduce((m, x) => (x.state.lastSeq > m ? x.state.lastSeq : m), 0n),
    dailyHeadroom: ok.reduce((m, x) => (x.state.dailyHeadroom < m ? x.state.dailyHeadroom : m), s0.dailyHeadroom),
    releasesThisHour: Math.max(...ok.map((x) => x.state.releasesThisHour)),
    breakerState: Math.max(...ok.map((x) => x.state.breakerState)),
  };
  return { state: st, views: fresh, pages };
}

/** Signer-local escrow records (fsync'd DurableJson): the pending abandon and the highest terminal-abandoned seq. */
export interface EscrowLocalState { counter: number; pending: { expectedLastSeq: string; seqTo: string; notBefore: number; notAfter: number } | null; lastAbandoned: string | null }
export const initialEscrowState = (): EscrowLocalState => ({ counter: 0, pending: null, lastAbandoned: null });

export interface EscrowRuntimeDeps {
  readers: EscrowReader[]; appId: bigint; genesisB64: string; pins: EscrowPins; store: DurableJson<EscrowLocalState>; now?: () => number /* ms */;
}
export interface ReleaseRow { seq: bigint; receiver: Uint8Array; amount: bigint; mandateHash: Uint8Array; challengeExpires: number }
export type ReleasePrep =
  | { action: "sign"; msg: Buffer; signedAt: number; notAfter: number; pages: string[] }
  | { action: "abandon-first"; seqTo: bigint; pages: string[] }
  | { action: "refuse"; pages: string[] };

export class EscrowRuntime {
  private readonly now: () => number;
  constructor(private readonly d: EscrowRuntimeDeps) { this.now = d.now ?? Date.now; }
  private pending(): PendingAbandon | null {
    const p = this.d.store.get().pending;
    return p ? { expectedLastSeq: BigInt(p.expectedLastSeq), seqTo: BigInt(p.seqTo), notBefore: p.notBefore, notAfter: p.notAfter } : null;
  }
  /** Clears a pending abandon once every fresh pinned provider shows it landed or expired (it moves to lastAbandoned if landed). */
  private settlePending(views: ProviderView[]): void {
    const p = this.pending();
    if (!p) return;
    const s = pendingAbandonStatus(p, views, this.d.pins.operators); // R76-P3-2: the config allowlist, not the readers' ids
    if (s === "pending") return;
    const cur = this.d.store.get();
    const la = cur.lastAbandoned === null ? null : BigInt(cur.lastAbandoned);
    this.d.store.put({ ...cur, counter: cur.counter + 1, pending: null, lastAbandoned: s === "landed" && (la === null || p.seqTo > la) ? String(p.seqTo) : cur.lastAbandoned });
  }
  /** The release path: one snapshot -> guard -> M (same state). */
  async prepareRelease(row: ReleaseRow): Promise<ReleasePrep> {
    const localNow = Math.floor(this.now() / 1000);
    const snap = await readEscrowSnapshot(this.d.readers, this.d.appId, this.d.genesisB64, localNow);
    if (!snap.state) return { action: "refuse", pages: snap.pages };
    this.settlePending(snap.views);
    const la = this.d.store.get().lastAbandoned;
    const pre = escrowPreflight(snap.state, this.d.pins, row.seq, row.amount, la === null ? null : BigInt(la), this.pending(), snap.views);
    const pages = [...snap.pages, ...pre.pages];
    if (pre.action !== "sign") return { ...pre, pages };
    // signed_at: the signer's clock (chrony-checked by the caller, assertClock). R76-P3-3: the chain accepts
    // signed_at <= now + 30, so refuse when the local clock is ahead of the MIN fresh chain time by more than 30 s.
    const minChainNow = Math.min(...snap.views.map((v) => v.chainNow));
    if (!Number.isFinite(minChainNow) || localNow > minChainNow + ESCROW_SIGNED_AT_MAX_AHEAD_S) {
      return { action: "refuse", pages: [...pages, `escrow preflight refused: signed_at ${localNow} > min chain time ${minChainNow} + ${ESCROW_SIGNED_AT_MAX_AHEAD_S}`] };
    }
    const signedAt = localNow;
    let notAfter: number;
    try { notAfter = escrowNotAfter(signedAt, row.challengeExpires); } catch (e) {
      if (e instanceof EscrowTimingRefused) return { action: "refuse", pages: [...pages, `escrow preflight refused: ${e.message}`] };
      throw e;
    }
    const msg = escrowReleaseMessage({ genesisHash: Buffer.from(this.d.genesisB64, "base64"), appId: this.d.appId, keyEpoch: snap.state.keyEpoch, configEpoch: snap.state.configEpoch,
      seq: row.seq, receiver: row.receiver, amount: row.amount, signedAt, notAfter, mandateHash: row.mandateHash });
    return { action: "sign", msg, signedAt, notAfter, pages };
  }
  /** Records an issued abandon as pending (before its signature leaves the signer). */
  recordPendingAbandon(p: PendingAbandon): void {
    const cur = this.d.store.get();
    if (cur.pending) throw new Error("abandon: one is already pending");
    this.d.store.put({ ...cur, counter: cur.counter + 1, pending: { expectedLastSeq: String(p.expectedLastSeq), seqTo: String(p.seqTo), notBefore: p.notBefore, notAfter: p.notAfter } });
  }
}
