/**
 * Storage interfaces for shared state (Phase 2 T1).
 *
 * Every method may return a value or a Promise (MaybePromise). Callers always
 * `await`. The in-memory implementations stay synchronous, so the
 * single-process behaviour (and every existing test) is unchanged, while the
 * Postgres / Redis implementations in @mandaterail/storage are async and
 * shared across processes.
 *
 * Time is always passed in by the caller (`now` in ms) so a test clock drives
 * every backend the same way; multi-process deployments need NTP-synced hosts.
 * Internal AI review (eng hygiene).
 */
import type { IntentMandate } from "@mandaterail/schema";
import type { OperatorAction, OperatorChallenge } from "./operator-challenge.js";

export type MaybePromise<T> = T | Promise<T>;

// ---------------------------------------------------------------------------
// Operator challenges (single-use nonces)
// ---------------------------------------------------------------------------

export type ChallengeConsumeResult =
  | { ok: true; challenge: OperatorChallenge }
  | { ok: false; error: "unknown_nonce" | "replayed_nonce" | "expired_nonce" };

/**
 * Single-use, audience-scoped operator challenges.
 * - `issue` throws when the store is at its live-entry cap (callers map to 503).
 * - `consume` burns the nonce on ANY presentation, atomically: across all
 *   processes sharing the store, exactly one consume of a nonce can be ok.
 * - Nonces of another audience are `unknown_nonce` (bridge vs console).
 */
export interface ChallengeStore {
  issue(action: OperatorAction, subjectId: string): MaybePromise<OperatorChallenge>;
  consume(nonce: string): MaybePromise<ChallengeConsumeResult>;
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

/**
 * Sliding-window limiter: per-key plus global log over `windowMs`. Only
 * admitted requests are recorded. `take` is atomic per limiter.
 */
export interface RateLimitStore {
  take(key: string): MaybePromise<boolean>;
}

// ---------------------------------------------------------------------------
// ac2-bridge signing queue
// ---------------------------------------------------------------------------

export type QueueStatus = "pending" | "approved" | "rejected" | "expired";

export interface QueueItem<R = unknown> {
  id: string;
  status: QueueStatus;
  createdAt: string;
  createdMs: number;
  /** When the item left `pending`. */
  finalizedMs?: number;
  /** Rate-limit client key of the requester (per-client pending cap). */
  clientKey: string;
  /** Set once the requester has read the final state. */
  collected?: boolean;
  request: R;
  /** sha256(requester token); the raw token is only returned once. */
  requesterTokenHash: Buffer;
  signature?: string;
  publicKey?: string;
  address?: string;
}

export type QueueLimits = {
  /** Max queued + retained items. */
  maxPending: number;
  /** pending -> expired after this. */
  pendingTtlMs: number;
  /** Finalized items (and their token hashes) evicted after this. */
  retentionMs: number;
  /** Max `pending` items per client key. */
  maxPendingPerClient: number;
};

export type QueueInsertResult = "ok" | "queue_full" | "client_pending_cap";

export type QueueFinalizeResult<R> =
  | { ok: true; item: QueueItem<R> }
  | { ok: false; error: "not_found" }
  | { ok: false; error: "not_pending"; status: QueueStatus };

/**
 * Bounded queue with TTL and retention. Every read sweeps first (expire stale
 * pending items, evict finalized items past retention). `insert` checks the
 * per-client cap and the total cap atomically; when full it evicts only the
 * oldest finalized item already collected by its requester (OA-P2-N), never
 * an uncollected result. `finalize` is a compare-and-set from `pending`.
 */
export interface QueueStore<R = unknown> {
  insert(item: QueueItem<R>, now: number): MaybePromise<QueueInsertResult>;
  get(id: string, now: number): MaybePromise<QueueItem<R> | null>;
  list(now: number): MaybePromise<QueueItem<R>[]>;
  countPending(now: number): MaybePromise<number>;
  finalize(
    id: string,
    status: "approved" | "rejected",
    patch: { signature?: string; publicKey?: string; address?: string },
    now: number,
  ): MaybePromise<QueueFinalizeResult<R>>;
  markCollected(id: string): MaybePromise<void>;
}

/** In-memory queue (single process) — the Phase 1 behaviour. */
export class InMemoryQueueStore<R = unknown> implements QueueStore<R> {
  /** Live map (tests inspect it). */
  readonly items = new Map<string, QueueItem<R>>();
  constructor(private readonly limits: QueueLimits) {}

  sweep(now: number): void {
    for (const [id, item] of this.items) {
      if (item.status === "pending" && now - item.createdMs >= this.limits.pendingTtlMs) {
        item.status = "expired";
        item.finalizedMs = now;
      }
      if (item.status !== "pending" && now - (item.finalizedMs ?? now) >= this.limits.retentionMs) {
        this.items.delete(id);
      }
    }
  }

  insert(item: QueueItem<R>, now: number): QueueInsertResult {
    this.sweep(now);
    let clientPending = 0;
    for (const it of this.items.values()) {
      if (it.status === "pending" && it.clientKey === item.clientKey) clientPending++;
    }
    if (clientPending >= this.limits.maxPendingPerClient) return "client_pending_cap";
    if (this.items.size >= this.limits.maxPending) {
      let oldest: QueueItem<R> | undefined;
      for (const it of this.items.values()) {
        if (
          it.status !== "pending" &&
          it.collected &&
          (!oldest || (it.finalizedMs ?? 0) < (oldest.finalizedMs ?? 0))
        ) {
          oldest = it;
        }
      }
      if (!oldest) return "queue_full";
      this.items.delete(oldest.id);
    }
    this.items.set(item.id, item);
    return "ok";
  }

  get(id: string, now: number): QueueItem<R> | null {
    this.sweep(now);
    return this.items.get(id) ?? null;
  }

  list(now: number): QueueItem<R>[] {
    this.sweep(now);
    return [...this.items.values()];
  }

  countPending(now: number): number {
    this.sweep(now);
    let n = 0;
    for (const it of this.items.values()) if (it.status === "pending") n++;
    return n;
  }

  finalize(
    id: string,
    status: "approved" | "rejected",
    patch: { signature?: string; publicKey?: string; address?: string },
    now: number,
  ): QueueFinalizeResult<R> {
    this.sweep(now);
    const item = this.items.get(id);
    if (!item) return { ok: false, error: "not_found" };
    if (item.status !== "pending") return { ok: false, error: "not_pending", status: item.status };
    item.status = status;
    item.finalizedMs = now;
    if (patch.signature !== undefined) item.signature = patch.signature;
    if (patch.publicKey !== undefined) item.publicKey = patch.publicKey;
    if (patch.address !== undefined) item.address = patch.address;
    return { ok: true, item };
  }

  markCollected(id: string): void {
    const item = this.items.get(id);
    if (item && item.status !== "pending") item.collected = true;
  }
}

// ---------------------------------------------------------------------------
// Console mandates
// ---------------------------------------------------------------------------

/**
 * Server-side state kept next to (never inside) the mandate, so signed bytes
 * are untouched. Set only by the console after verifying the AC2 signature.
 */
export type MandateServerState = { signatureVerified: boolean; verifiedAt?: string };
export type StoredMandate = { mandate: IntentMandate; server: MandateServerState };

/** Thrown when the mandate cap is reached. */
export class StoreFullError extends Error {
  constructor(max: number) {
    super(`console store is full (CONSOLE_MAX_MANDATES=${max})`);
    this.name = "StoreFullError";
  }
}

/** Thrown on a duplicate mandate id. */
export class MandateExistsError extends Error {
  constructor(id: string) {
    super(`mandate ${id} already exists`);
    this.name = "MandateExistsError";
  }
}

/**
 * Mandate store. `create` checks the id and the cap atomically with the
 * insert; `revoke` is atomic. Lists are in creation order.
 */
export interface MandateStore {
  list(): MaybePromise<StoredMandate[]>;
  get(id: string): MaybePromise<StoredMandate | null>;
  create(
    mandate: IntentMandate,
    opts?: { maxMandates?: number; signatureVerified?: boolean; now?: number },
  ): MaybePromise<StoredMandate>;
  revoke(id: string): MaybePromise<StoredMandate | null>;
}

// ---------------------------------------------------------------------------
// Receipts
// ---------------------------------------------------------------------------

export interface ReceiptLike {
  receiptId: string;
}

/** Append-only receipts; `list` is latest first. */
export interface ReceiptStore<T extends ReceiptLike = ReceiptLike> {
  add(receipt: T): MaybePromise<void>;
  get(receiptId: string): MaybePromise<T | null>;
  list(limit: number): MaybePromise<T[]>;
}

/** In-memory receipts (tests). */
export class InMemoryReceiptStore<T extends ReceiptLike> implements ReceiptStore<T> {
  private readonly all: T[] = [];
  add(r: T): void {
    this.all.push(r);
  }
  get(id: string): T | null {
    return this.all.find((r) => r.receiptId === id) ?? null;
  }
  list(limit: number): T[] {
    return this.all.slice().reverse().slice(0, Math.max(0, limit));
  }
}

/**
 * T6: factory for shared backends (satisfied by @mandaterail/storage's
 * StateBackend). Apps build their stores from it with their own limits.
 */
export interface StoreFactory {
  challengeStore(o: { audience: string; ttlMs?: number; maxEntries?: number; now?: () => number }): ChallengeStore;
  rateLimiter(o: { name: string; windowMs: number; perKey: number; global: number; now?: () => number }): RateLimitStore;
  queue<R>(name: string, limits: QueueLimits): QueueStore<R>;
  mandates(store?: string): MandateStore;
}
