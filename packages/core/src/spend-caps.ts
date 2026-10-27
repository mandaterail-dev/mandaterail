/**
 * T7: per-payment and per-day-per-payer spend caps (Phase 2 approval:
 * 1 USDC / payment, 5 USDC / day). Defaults == hard maxima; env may only
 * lower them. Amounts are compared in micro-units (6 decimals) as bigint.
 */
import type { MaybePromise } from "./storage.js";
import { isForbiddenProviderHost, normalizeProviderHost, providerAuthHeaders, type ChainProviderAllowEntry } from "./network.js";
import { pinnedFetch, resolvePinned, type Resolver } from "./pinned-fetch.js";

export const USDC_DECIMALS = 6;
export const HARD_MAX_PER_PAYMENT = "1.00";
export const HARD_MAX_PER_DAY = "5.00";
export const DAY_MS = 86_400_000;

export interface SpendCaps {
  perPaymentMicro: bigint;
  perDayMicro: bigint;
}

export class SpendCapConfigError extends Error {}

/** "1.5" -> 1_500_000n. Rejects negatives, exponents and >6 decimals. */
export function toMicro(s: string, decimals = USDC_DECIMALS): bigint {
  const t = String(s).trim();
  const m = /^(\d+)(?:\.(\d+))?$/.exec(t);
  if (!m) throw new Error(`invalid decimal: ${s}`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`too many decimals: ${s}`);
  return BigInt(m[1]!) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0");
}

export function fromMicro(n: bigint, decimals = USDC_DECIMALS): string {
  const base = 10n ** BigInt(decimals);
  return `${n / base}.${(n % base).toString().padStart(decimals, "0")}`;
}

/**
 * SPEND_CAP_PER_PAYMENT_USDC / SPEND_CAP_PER_DAY_USDC (optional). Unset ->
 * hard maximum. Above the hard maximum, malformed or zero -> throws (startup
 * refuses). Raising the maxima needs the owner's approval + internal reviewer review.
 */
export function resolveSpendCaps(env: Record<string, string | undefined> = process.env): SpendCaps {
  const one = (name: string, hard: string): bigint => {
    const hardMicro = toMicro(hard);
    const raw = env[name]?.trim();
    if (!raw) return hardMicro;
    let v: bigint;
    try {
      v = toMicro(raw);
    } catch {
      throw new SpendCapConfigError(`${name}=${raw} is not a decimal`);
    }
    if (v <= 0n) throw new SpendCapConfigError(`${name} must be > 0`);
    if (v > hardMicro) throw new SpendCapConfigError(`${name}=${raw} exceeds hard maximum ${hard} USDC`);
    return v;
  };
  const perPaymentMicro = one("SPEND_CAP_PER_PAYMENT_USDC", HARD_MAX_PER_PAYMENT);
  const perDayMicro = one("SPEND_CAP_PER_DAY_USDC", HARD_MAX_PER_DAY);
  // A lowered daily cap (e.g. the 0.05 dry-run check) also bounds each payment.
  return { perPaymentMicro: perPaymentMicro < perDayMicro ? perPaymentMicro : perDayMicro, perDayMicro };
}

/** Start of the UTC calendar day containing `nowMs` (caps reset 00:00 UTC). */
export function utcDayStartMs(nowMs: number): number {
  return Math.floor(nowMs / DAY_MS) * DAY_MS;
}

/**
 * T7-P2-2: a reservation is written BEFORE settle and finalized after.
 *  pending   -> written by reserve(); counts as spent
 *  settled   -> facilitator settled (txId if known); counts as spent
 *  ambiguous -> settle failed / threw / timed out; counts as spent until
 *               reconcile() resolves it against the chain
 *  released  -> no money moved (payload invalid, verify failed); not counted
 * A crashed process leaves `pending`, which keeps counting (fail-safe) until
 * reconciled.
 */
export type SpendStatus = "pending" | "settled" | "ambiguous" | "released";
export const COUNTED_SPEND_STATUSES: readonly SpendStatus[] = ["pending", "settled", "ambiguous"];

export interface SpendReservation {
  id: string;
  payer: string;
  amountMicro: bigint;
  status: SpendStatus;
  createdMs: number;
  updatedMs: number;
  txId: string | null;
  /** Last valid round of the payment txn (from the signed group), if known. */
  lastValid: number | null;
}

export type ReserveResult =
  | { ok: true; reservation: SpendReservation; spentBeforeMicro: bigint }
  | { ok: false; reason: "per_payment_cap_exceeded" | "daily_cap_exceeded"; spentBeforeMicro: bigint };

export interface SpendStore {
  /**
   * Atomically (per payer, across all processes sharing the store): sum the
   * payer's counted reservations since the UTC day start and insert a
   * `pending` reservation only if the caps still hold.
   */
  reserve(i: { id: string; payer: string; amountMicro: bigint; caps: SpendCaps; nowMs: number }): MaybePromise<ReserveResult>;
  /**
   * R18-P3-2: record the payment's txId (the group's first txn id, derived
   * from the signed group) on a still-pending reservation BEFORE settle, so
   * ambiguous rows can be reconciled against the chain.
   */
  attachTxId(id: string, txId: string, nowMs: number, lastValid?: number | null): MaybePromise<boolean>;
  /**
   * v11 (launch blocker, R43): store the exact signed bytes before settle (kind 'xpayment' = the X-PAYMENT group,
   * unsigned members wrapped without a signature), deriving tx_id / first_valid / last_valid / group_id / sender
   * from those bytes; the reserved payer must be the payment's sender. Optional: stores without v11 omit it.
   * Returns the derived txId/lastValid, or null when the row is not pending / already has bytes.
   */
  attachSignedTxn?(id: string, i: { signedTxn: Uint8Array; kind: "xpayment" | "group"; submitRound: number; nowMs: number }): MaybePromise<{ txId: string; lastValid: number } | null>;
  /** pending -> settled | ambiguous | released. False if not pending. */
  finalize(id: string, outcome: "settled" | "ambiguous" | "released", nowMs: number, txId?: string | null): MaybePromise<boolean>;
  /** pending | ambiguous -> settled | released, after checking the chain. */
  reconcile(id: string, outcome: "settled" | "released", nowMs: number, txId?: string | null): MaybePromise<boolean>;
  get(id: string): MaybePromise<SpendReservation | null>;
  /** ambiguous, plus pending older than `pendingOlderThanMs`. */
  listUnresolved(nowMs: number, pendingOlderThanMs: number, limit: number): MaybePromise<SpendReservation[]>;
  spentSinceMicro(payer: string, sinceMs: number): MaybePromise<bigint>;
  /** Idempotent import of an already-settled payment (e.g. from receipts). */
  recordSettled(r: { id: string; payer: string; amountMicro: bigint; createdMs: number; txId?: string | null }): MaybePromise<boolean>;
}

function perPaymentDenied(amountMicro: bigint, caps: SpendCaps): boolean {
  return amountMicro > caps.perPaymentMicro;
}

/** Single-process store (memory backend / tests). Sync, therefore atomic. */
export class InMemorySpendStore implements SpendStore {
  private readonly rows = new Map<string, SpendReservation>();
  spentSinceMicro(payer: string, sinceMs: number): bigint {
    let sum = 0n;
    for (const r of this.rows.values()) {
      if (r.payer === payer && r.createdMs >= sinceMs && COUNTED_SPEND_STATUSES.includes(r.status)) sum += r.amountMicro;
    }
    return sum;
  }
  reserve(i: { id: string; payer: string; amountMicro: bigint; caps: SpendCaps; nowMs: number }): ReserveResult {
    const spent = this.spentSinceMicro(i.payer, utcDayStartMs(i.nowMs));
    if (perPaymentDenied(i.amountMicro, i.caps)) return { ok: false, reason: "per_payment_cap_exceeded", spentBeforeMicro: spent };
    if (spent + i.amountMicro > i.caps.perDayMicro) return { ok: false, reason: "daily_cap_exceeded", spentBeforeMicro: spent };
    if (this.rows.has(i.id)) throw new Error(`reservation ${i.id} exists`);
    const r: SpendReservation = { id: i.id, payer: i.payer, amountMicro: i.amountMicro, status: "pending", createdMs: i.nowMs, updatedMs: i.nowMs, txId: null, lastValid: null };
    this.rows.set(i.id, r);
    return { ok: true, reservation: { ...r }, spentBeforeMicro: spent };
  }
  private move(id: string, from: SpendStatus[], to: SpendStatus, nowMs: number, txId?: string | null): boolean {
    const r = this.rows.get(id);
    if (!r || !from.includes(r.status)) return false;
    r.status = to;
    r.updatedMs = nowMs;
    if (txId) r.txId = txId;
    return true;
  }
  attachTxId(id: string, txId: string, nowMs: number, lastValid?: number | null): boolean {
    const r = this.rows.get(id);
    if (!r || r.status !== "pending") return false;
    r.txId = txId;
    r.lastValid = lastValid ?? null;
    r.updatedMs = nowMs;
    return true;
  }
  finalize(id: string, outcome: "settled" | "ambiguous" | "released", nowMs: number, txId?: string | null): boolean {
    return this.move(id, ["pending"], outcome, nowMs, txId);
  }
  reconcile(id: string, outcome: "settled" | "released", nowMs: number, txId?: string | null): boolean {
    return this.move(id, ["pending", "ambiguous"], outcome, nowMs, txId);
  }
  get(id: string): SpendReservation | null {
    const r = this.rows.get(id);
    return r ? { ...r } : null;
  }
  listUnresolved(nowMs: number, pendingOlderThanMs: number, limit: number): SpendReservation[] {
    return [...this.rows.values()]
      .filter((r) => r.status === "ambiguous" || (r.status === "pending" && nowMs - r.createdMs >= pendingOlderThanMs))
      .slice(0, limit)
      .map((r) => ({ ...r }));
  }
  recordSettled(r: { id: string; payer: string; amountMicro: bigint; createdMs: number; txId?: string | null }): boolean {
    if (this.rows.has(r.id)) return false;
    this.rows.set(r.id, { ...r, txId: r.txId ?? null, lastValid: null, status: "settled", updatedMs: r.createdMs });
    return true;
  }
}

export interface SpendCheckInput {
  payer: string;
  amountMicro: bigint;
  caps: SpendCaps;
  store?: SpendStore;
  nowMs: number;
  /** Reservation id (default: random UUID). */
  reservationId?: string;
}

export type SpendCheckResult =
  | { ok: true; spentTodayMicro: bigint; reservationId?: string }
  | { ok: false; reason: "per_payment_cap_exceeded" | "daily_cap_exceeded" | "spend_ledger_unavailable"; message: string };

/**
 * Per-payment cap, then (with a store) an atomic check-and-reserve against
 * the daily cap. Store errors fail closed.
 */
export async function checkSpendCaps(i: SpendCheckInput): Promise<SpendCheckResult> {
  if (perPaymentDenied(i.amountMicro, i.caps)) {
    return {
      ok: false,
      reason: "per_payment_cap_exceeded",
      message: `amount ${fromMicro(i.amountMicro)} exceeds per-payment cap ${fromMicro(i.caps.perPaymentMicro)} USDC`,
    };
  }
  if (!i.store) {
    return { ok: false, reason: "spend_ledger_unavailable", message: "daily cap needs a spend store" };
  }
  const id = i.reservationId ?? crypto.randomUUID();
  let r: ReserveResult;
  try {
    r = await i.store.reserve({ id, payer: i.payer, amountMicro: i.amountMicro, caps: i.caps, nowMs: i.nowMs });
  } catch {
    return { ok: false, reason: "spend_ledger_unavailable", message: "spend store unavailable" };
  }
  if (!r.ok) {
    return {
      ok: false,
      reason: r.reason,
      message:
        r.reason === "daily_cap_exceeded"
          ? `payer daily spend ${fromMicro(r.spentBeforeMicro)} + ${fromMicro(i.amountMicro)} exceeds daily cap ${fromMicro(i.caps.perDayMicro)} USDC`
          : `amount exceeds per-payment cap ${fromMicro(i.caps.perPaymentMicro)} USDC`,
    };
  }
  return { ok: true, spentTodayMicro: r.spentBeforeMicro, reservationId: id };
}

export type ChainCheck = (r: SpendReservation) => Promise<"settled" | "released" | "unknown">;

/**
 * Resolve ambiguous (and stale pending) reservations against the chain via
 * `check` (e.g. an indexer lookup by txId). "unknown" leaves them counted.
 */
export async function reconcileSpend(
  store: SpendStore,
  check: ChainCheck,
  opts: { nowMs?: number; pendingOlderThanMs?: number; limit?: number } = {},
): Promise<{ settled: number; released: number; unknown: number }> {
  const nowMs = opts.nowMs ?? Date.now();
  const out = { settled: 0, released: 0, unknown: 0 };
  for (const r of await store.listUnresolved(nowMs, opts.pendingOlderThanMs ?? 15 * 60_000, opts.limit ?? 500)) {
    let v: "settled" | "released" | "unknown";
    try {
      v = await check(r);
    } catch {
      v = "unknown";
    }
    if (v === "unknown") out.unknown++;
    else if (await store.reconcile(r.id, v, nowMs, r.txId)) out[v]++;
  }
  return out;
}

/**
 * Chain check through an Algorand indexer (R18-P3-2):
 *  - txn found with a confirmed round       -> settled
 *  - not found and the indexer is past the
 *    txn's lastValid round (+ margin)       -> released (can never confirm)
 *  - otherwise (no txId, unknown lastValid,
 *    indexer behind, errors)                -> unknown (stays counted)
 */
export function indexerTxCheck(
  indexerUrl: string,
  fetchImpl: typeof fetch = fetch,
  opts: IndexerOpts & ProviderGuardOpts & { profile: IndexerOpts["profile"] & { providerAllowlist?: ReadonlyArray<ChainProviderAllowEntry> } },
): ChainCheck {
  // R27-P3-5: same allowlist, host check and DNS pinning as the release observers.
  const guard = providerGuard(indexerUrl, fetchImpl, opts);
  let o: ReturnType<typeof indexerSetup> | null = null;
  indexerSetup(indexerUrl, fetchImpl, opts); // construction-time option checks (no I/O)
  return async (r) => {
    if (!r.txId) return "unknown";
    try {
      if (!o) o = indexerSetup(indexerUrl, await guard(), opts); // resolved + pinned once per check instance (one reconcile run)
      const res = await o.get(`/v2/transactions/${encodeURIComponent(r.txId)}`);
      if (res.status === 200) {
        // R21-P3-4: a 200 from a wrong-network indexer is no more trustworthy than a 404.
        const j = (await res.json().catch(() => null)) as { transaction?: { "confirmed-round"?: unknown } } | null;
        const cr = j && typeof j === "object" ? j.transaction?.["confirmed-round"] : undefined;
        if (!(typeof cr === "number" && Number.isInteger(cr) && cr > 0)) return "unknown";
        if ((await o.genesisMismatch()) !== null) return "unknown";
        return "settled";
      }
      if (res.status !== 404 || r.lastValid === null || r.lastValid === undefined) return "unknown";
      if ((await o.genesisMismatch()) !== null) return "unknown"; // R20-P3-2
      const round = await o.round();
      return round !== null && round > r.lastValid + o.margin ? "released" : "unknown";
    } catch {
      return "unknown";
    }
  };
}

/**
 * Shared indexer options (R20-P3-2 / R20-P3-3).
 * - profile: the indexer's genesis id + hash (GET /v2/blocks/0) must match it
 *   before a 404 is trusted as "can never confirm" (wrong-network indexer).
 * - marginRounds: non-negative integer (default 10); anything else throws.
 * - timeoutMs: per-request timeout (default 10s).
 */
export interface IndexerOpts {
  profile: { name: "testnet" | "mainnet"; caip2: string };
  marginRounds?: number;
  token?: string;
  timeoutMs?: number;
}
export const INDEXER_GENESIS_IDS: Record<"testnet" | "mainnet", string> = { testnet: "testnet-v1.0", mainnet: "mainnet-v1.0" };
export class IndexerOptsError extends Error {}

function indexerSetup(indexerUrl: string, fetchImpl: typeof fetch, opts: IndexerOpts) {
  if (!opts || !opts.profile || !opts.profile.caip2?.startsWith("algorand:")) throw new IndexerOptsError("indexer profile (network) is required");
  const margin = opts.marginRounds ?? 10;
  if (!Number.isInteger(margin) || margin < 0) throw new IndexerOptsError("marginRounds must be a non-negative integer");
  const timeoutMs = opts.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new IndexerOptsError("timeoutMs must be a positive integer");
  const base = indexerUrl.replace(/\/$/, "");
  const headers: Record<string, string> = providerAuthHeaders(base, "indexer", opts.token);
  const wantHash = opts.profile.caip2.slice("algorand:".length);
  const wantId = INDEXER_GENESIS_IDS[opts.profile.name];
  const get = (path: string) => fetchImpl(`${base}${path}`, { headers, signal: AbortSignal.timeout(timeoutMs) });
  let genesisOk = false;
  return {
    margin,
    get,
    /** R23-P2-1: the genesis hash a 404 was checked against (stored with the proof). */
    genesisHash: wantHash,
    /**
     * null when the indexer serves the profile's chain; else a reason.
     * Only a MATCH is cached (R21-P3-4): a failed / mismatched / unreadable
     * check is retried on the next call and never turns into a pass.
     */
    async genesisMismatch(): Promise<string | null> {
      if (genesisOk) return null;
      let g: { "genesis-id"?: unknown; "genesis-hash"?: unknown } | null;
      try {
        const res = await get("/v2/blocks/0");
        if (!res.ok) return `indexer genesis block returned ${res.status}`;
        g = (await res.json()) as typeof g;
      } catch {
        return "indexer genesis unreadable";
      }
      if (!g || typeof g !== "object") return "indexer genesis unreadable";
      if (g["genesis-hash"] !== wantHash || g["genesis-id"] !== wantId) return `indexer genesis does not match ${opts.profile.name}`;
      genesisOk = true;
      return null;
    },
    async round(): Promise<number | null> {
      const h = await get("/health");
      if (!h.ok) return null;
      const b = (await h.json().catch(() => null)) as { round?: unknown } | null;
      if (!b || typeof b !== "object" || typeof b.round !== "number") return null;
      return Number.isInteger(b.round) && b.round >= 0 ? b.round : null;
    },
  };
}

/** R19-P2-1: evidence that a reservation's txn can never confirm. */
export type NoConfirmProof =
  | { ok: true; txId: string; lastValid: number; round: number; marginRounds: number; indexer: "404"; genesisHash: string }
  | { ok: false; why: string };
export type NoConfirmProver = (r: SpendReservation) => Promise<NoConfirmProof>;

/**
 * R19-P2-1: prove through an Algorand indexer that `r`'s txn can no longer
 * confirm: it has a txId and lastValid, the indexer returns 404 for the txId,
 * and the indexer's round is past lastValid + marginRounds. Anything else
 * (no txId, unknown lastValid, txn found, indexer error, round too low) is
 * not a proof.
 */
export function indexerNoConfirmProof(
  indexerUrl: string,
  fetchImpl: typeof fetch = fetch,
  opts: IndexerOpts,
): NoConfirmProver {
  const o = indexerSetup(indexerUrl, fetchImpl, opts);
  const margin = o.margin;
  return async (r) => {
    if (!r.txId) return { ok: false, why: "reservation has no txId" };
    if (r.lastValid === null || r.lastValid === undefined) return { ok: false, why: "reservation has no lastValid round" };
    let res: Response;
    try {
      res = await o.get(`/v2/transactions/${encodeURIComponent(r.txId)}`);
    } catch {
      return { ok: false, why: "indexer unreachable or timed out" };
    }
    if (res.status === 200) return { ok: false, why: "txn found on the indexer (may be settled); use reconcile" };
    if (res.status !== 404) return { ok: false, why: `indexer returned ${res.status} for the txId` };
    const gm = await o.genesisMismatch(); // R20-P3-2
    if (gm !== null) return { ok: false, why: gm };
    let round: number | null;
    try {
      round = await o.round();
    } catch {
      return { ok: false, why: "indexer health unreadable or timed out" };
    }
    if (round === null) return { ok: false, why: "indexer round unknown" };
    if (!(round > r.lastValid + margin)) return { ok: false, why: `current round ${round} is not past lastValid ${r.lastValid} + margin ${margin}` };
    return { ok: true, txId: r.txId, lastValid: r.lastValid, round, marginRounds: margin, indexer: "404", genesisHash: o.genesisHash };
  };
}

/**
 * R24-P2-1: one chain observation for a manual release. `provider` is the
 * lower-case host[:port] it came from. `status: 404` means the provider does
 * not know the txId (indexer: /v2/transactions/{id}; algod: not in the
 * pending pool, a weaker signal, so at least one observation must be an
 * indexer). `round` is that provider's current round.
 */
export interface ChainObservation {
  provider: string;
  /** R25-P2-1: operator id of `provider` from the network profile's allowlist. */
  operator?: string;
  kind: "indexer" | "algod";
  genesisHash: string;
  round: number;
  status: 404;
}
export interface ChainProviderSpec {
  url: string;
  kind: "indexer" | "algod";
  token?: string;
}
export type TwoObservationProof =
  | { ok: true; txId: string; lastValid: number; marginRounds: number; observations: [ChainObservation, ChainObservation] }
  | { ok: false; why: string };
export type TwoObservationProver = (r: SpendReservation) => Promise<TwoObservationProof>;

export function providerHost(url: string): string {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new IndexerOptsError("chain provider URL is not a valid URL");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new IndexerOptsError("chain provider URL must be http(s)");
  // R26-P3-4: canonical form (lower case, trailing dot stripped); the port is kept for the "different hosts" check.
  const host = normalizeProviderHost(u.hostname);
  return u.port ? `${host}:${u.port}` : host;
}

type Observer = (txId: string) => Promise<{ ok: true; obs: ChainObservation } | { ok: false; why: string }>;

function observer(p: ChainProviderSpec, fetchImpl: typeof fetch, opts: { profile: IndexerOpts["profile"]; timeoutMs?: number }): Observer {
  const host = providerHost(p.url);
  if (p.kind === "indexer") {
    const o = indexerSetup(p.url, fetchImpl, { profile: opts.profile, token: p.token, timeoutMs: opts.timeoutMs });
    return async (txId) => {
      try {
        const gm = await o.genesisMismatch();
        if (gm !== null) return { ok: false, why: `${host}: ${gm}` };
        const res = await o.get(`/v2/transactions/${encodeURIComponent(txId)}`);
        if (res.status === 200) return { ok: false, why: `${host}: txn found on the indexer (may be settled); use reconcile` };
        if (res.status !== 404) return { ok: false, why: `${host}: indexer returned ${res.status} for the txId` };
        const round = await o.round();
        if (round === null) return { ok: false, why: `${host}: indexer round unknown` };
        return { ok: true, obs: { provider: host, kind: "indexer", genesisHash: o.genesisHash, round, status: 404 } };
      } catch {
        return { ok: false, why: `${host}: indexer unreachable or timed out` };
      }
    };
  }
  if (p.kind !== "algod") throw new IndexerOptsError("chain provider kind must be indexer or algod");
  const timeoutMs = opts.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) throw new IndexerOptsError("timeoutMs must be a positive integer");
  const base = p.url.replace(/\/$/, "");
  const headers: Record<string, string> = providerAuthHeaders(p.url, "algod", p.token);
  const get = (path: string) => fetchImpl(`${base}${path}`, { headers, signal: AbortSignal.timeout(timeoutMs) });
  const wantHash = opts.profile.caip2.slice("algorand:".length);
  const wantId = INDEXER_GENESIS_IDS[opts.profile.name];
  return async (txId) => {
    try {
      const v = await get("/versions");
      if (!v.ok) return { ok: false, why: `${host}: algod /versions returned ${v.status}` };
      const vb = (await v.json().catch(() => null)) as { genesis_hash_b64?: unknown; genesis_id?: unknown } | null;
      if (!vb || typeof vb !== "object" || vb.genesis_hash_b64 !== wantHash || vb.genesis_id !== wantId) {
        return { ok: false, why: `${host}: algod genesis does not match ${opts.profile.name}` };
      }
      const t = await get(`/v2/transactions/pending/${encodeURIComponent(txId)}`);
      if (t.status === 200) return { ok: false, why: `${host}: txn is pending or recently confirmed on algod; use reconcile` };
      if (t.status !== 404) return { ok: false, why: `${host}: algod returned ${t.status} for the txId` };
      const s = await get("/v2/status");
      if (!s.ok) return { ok: false, why: `${host}: algod status returned ${s.status}` };
      const sb = (await s.json().catch(() => null)) as { "last-round"?: unknown } | null;
      const round = sb && typeof sb === "object" ? sb["last-round"] : undefined;
      if (typeof round !== "number" || !Number.isInteger(round) || round < 0) return { ok: false, why: `${host}: algod round unknown` };
      return { ok: true, obs: { provider: host, kind: "algod", genesisHash: wantHash, round, status: 404 } };
    } catch {
      return { ok: false, why: `${host}: algod unreachable or timed out` };
    }
  };
}

/**
 * R24-P2-1 mitigation: prove through TWO independent providers (different
 * hosts, each genesis-checked against the profile, at least one indexer)
 * that `r`'s txn can no longer confirm: both report the txId not found and a
 * current round past lastValid + marginRounds. Both observations go to the
 * DB (typed audit columns), which re-checks them. Still self-attested by the
 * release tool: see docs/ops/release-custody.md.
 */
export function twoProviderNoConfirmProof(
  providers: ChainProviderSpec[],
  fetchImpl: typeof fetch = fetch,
  opts: ProviderGuardOpts & { profile: IndexerOpts["profile"] & { providerAllowlist?: ReadonlyArray<ChainProviderAllowEntry> }; marginRounds?: number; timeoutMs?: number },
): TwoObservationProver {
  // Qwen flag (run 26): the allowlist comes ONLY from the network profile; a caller-supplied override is refused.
  if (opts && "allowlist" in (opts as object)) throw new IndexerOptsError("allowlist overrides are not accepted; the network profile's providerAllowlist is the only allowlist");
  if (!opts || !opts.profile || !opts.profile.caip2?.startsWith("algorand:")) throw new IndexerOptsError("profile (network) is required");
  const margin = opts.marginRounds ?? 10;
  if (!Number.isInteger(margin) || margin < 0) throw new IndexerOptsError("marginRounds must be a non-negative integer");
  if (!Array.isArray(providers) || providers.length !== 2) throw new IndexerOptsError("exactly two chain providers are required");
  const hosts = providers.map((p) => providerHost(p.url));
  if (hosts[0] === hosts[1]) throw new IndexerOptsError("the two chain providers must be different hosts");
  if (!providers.some((p) => p.kind === "indexer")) throw new IndexerOptsError("at least one chain provider must be an indexer");
  // R25-P2-1: hosts must be on the profile's provider allowlist, run by two different operators.
  const allow = (opts.profile as { providerAllowlist?: ReadonlyArray<ChainProviderAllowEntry> }).providerAllowlist ?? [];
  const ops = hosts.map((h) => {
    const bare = normalizeProviderHost(h);
    if (isForbiddenProviderHost(h)) throw new IndexerOptsError(`chain provider ${bare} is loopback / localhost / .invalid / an IP literal (refused)`);
    const e = allow.find((a) => normalizeProviderHost(a.host) === bare);
    if (!e) throw new IndexerOptsError(`chain provider ${bare} is not on the ${opts.profile.name} provider allowlist`);
    return e.operator;
  });
  if (ops[0] === ops[1]) {
    throw new IndexerOptsError(`the two chain providers must be run by different operators (both are ${ops[0]}); add a second operator to the ${opts.profile.name} allowlist`);
  }
  // Qwen flag (run 26) / R27-P3-4: each host is resolved once per proof, every address must be
  // public, and that observation's requests go to the pinned IP. A custom fetchImpl needs the
  // explicit unsafeTestCustomFetch flag (refused on mainnet); providerGuard enforces that.
  const guards = providers.map((p) => providerGuard(p.url, fetchImpl, opts));
  providers.forEach((p) => observer(p, fetchImpl, opts)); // construction-time checks only (no I/O)
  return async (r) => {
    if (!r.txId) return { ok: false, why: "reservation has no txId" };
    if (r.lastValid === null || r.lastValid === undefined) return { ok: false, why: "reservation has no lastValid round" };
    const obs: Observer[] = [];
    for (const [k, p] of providers.entries()) {
      let f: typeof fetch;
      try {
        f = await guards[k]!();
      } catch (e) {
        return { ok: false, why: (e as Error).message };
      }
      obs.push(observer(p, f, opts));
    }
    const got = await Promise.all(obs.map((o) => o(r.txId!)));
    const out: ChainObservation[] = [];
    for (const g of got) {
      if (!g.ok) return { ok: false, why: g.why };
      if (!(g.obs.round > r.lastValid + margin)) {
        return { ok: false, why: `${g.obs.provider}: current round ${g.obs.round} is not past lastValid ${r.lastValid} + margin ${margin}` };
      }
      out.push({ ...g.obs, operator: ops[out.length] });
    }
    return { ok: true, txId: r.txId, lastValid: r.lastValid, marginRounds: margin, observations: [out[0]!, out[1]!] };
  };
}

/**
 * R27-P3-4 / R27-P3-5: options shared by every chain-provider client.
 * - resolve: DNS resolver (tests); default node:dns.
 * - unsafeTestCustomFetch: TESTS ONLY. Lets a custom fetchImpl through
 *   without connection pinning (the resolver check still runs when `resolve`
 *   is given). Refused on mainnet. Without it a custom fetchImpl is refused.
 */
export interface ProviderGuardOpts {
  resolve?: Resolver;
  unsafeTestCustomFetch?: boolean;
}

/**
 * R27-P3-4 / R27-P3-5: construction-time host checks (forbidden host, profile
 * allowlist) and a lazy step that returns the fetch to use: with the real
 * fetch, resolve once, require public addresses, and pin to that IP.
 */
export function providerGuard(
  url: string,
  fetchImpl: typeof fetch,
  opts: ProviderGuardOpts & { profile: IndexerOpts["profile"] & { providerAllowlist?: ReadonlyArray<ChainProviderAllowEntry> } },
): () => Promise<typeof fetch> {
  if (!opts || !opts.profile || !opts.profile.caip2?.startsWith("algorand:")) throw new IndexerOptsError("profile (network) is required");
  const hp = providerHost(url);
  const bare = normalizeProviderHost(hp);
  if (isForbiddenProviderHost(hp)) throw new IndexerOptsError(`chain provider ${bare} is loopback / localhost / .invalid / an IP literal (refused)`);
  const allow = opts.profile.providerAllowlist ?? [];
  if (!allow.some((a) => normalizeProviderHost(a.host) === bare)) throw new IndexerOptsError(`chain provider ${bare} is not on the ${opts.profile.name} provider allowlist`);
  const real = fetchImpl === globalThis.fetch;
  if (!real) {
    if (opts.unsafeTestCustomFetch !== true) throw new IndexerOptsError("a custom fetch would skip DNS pinning; only tests may pass one (unsafeTestCustomFetch)");
    if (opts.profile.name === "mainnet") throw new IndexerOptsError("unsafeTestCustomFetch is refused on mainnet");
  } else if (opts.unsafeTestCustomFetch) {
    throw new IndexerOptsError("unsafeTestCustomFetch is only for a custom (test) fetch");
  }
  const host = normalizeProviderHost(new URL(url).hostname);
  return async () => {
    if (real) return pinnedFetch(await resolvePinned(host, opts.resolve));
    if (opts.resolve) await resolvePinned(host, opts.resolve);
    return fetchImpl;
  };
}
