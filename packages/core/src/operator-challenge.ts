/**
 * Signed-challenge OperatorAttestation binding (Ed25519 / Algorand account).
 *
 * Flow:
 *   1. Bridge issues a short-TTL, single-use nonce bound to
 *      (action, subjectId) via `OperatorChallengeStore.issue`.
 *   2. Operator signs the canonical challenge message with an Algorand
 *      account key whose address is on OPERATOR_ALLOWLIST:
 *        - `algosdk` format: algosdk.signBytes(message) ("MX" prefix)
 *        - `arc60` format: wallet signData (ARC-60 / use-wallet) where
 *          signature = Ed25519(sha256(data) || sha256(authenticatorData)) and
 *          data is a SIWA JSON whose `statement` equals the challenge message.
 *   3. Client sends base64(JSON evidence) in X-MandateRail-Operator-Attestation.
 *   4. `SignedChallengeOperatorVerifier` checks allowlist, nonce freshness,
 *      single-use (replay), action/subject binding, and signature.
 *
 * Agents never hold operator key material: signatures come from the human
 * operator's wallet / offline algosdk key. NOT audited.
 */
import { createHash, createPublicKey, randomBytes, verify as edVerify } from "node:crypto";
import type { ChallengeStore, RateLimitStore } from "./storage.js";
import algosdk from "algosdk";
import type {
  OperatorAttestation,
  OperatorAttestationContext,
  OperatorAttestationResult,
  OperatorAttestationVerifier,
} from "./operator-attestation.js";

export const OPERATOR_ATTESTATION_HEADER = "x-mandaterail-operator-attestation";
export const OPERATOR_CHALLENGE_PREFIX = "MandateRail operator attestation v1";
export const DEFAULT_CHALLENGE_TTL_MS = 120_000;

/** ac2-bridge operator actions. */
export type BridgeOperatorAction = "approve" | "reject" | "list";
/** console mandate-store operator actions (separate audience). */
export type ConsoleOperatorAction =
  | "mandate.create"
  | "mandate.revoke"
  | "mandate.read"
  | "mandate.list";
/** T8: requester-key auth for ac2-bridge POST /sign (subject = requester address). */
export type RequesterAction = "request.sign";
export type OperatorAction = BridgeOperatorAction | ConsoleOperatorAction | RequesterAction;
export const OPERATOR_ACTIONS: readonly BridgeOperatorAction[] = ["approve", "reject", "list"];
export const CONSOLE_OPERATOR_ACTIONS: readonly ConsoleOperatorAction[] = [
  "mandate.create",
  "mandate.revoke",
  "mandate.read",
  "mandate.list",
];

/** Bridge actions only (approve | reject | list). */
export function isOperatorAction(v: unknown): v is BridgeOperatorAction {
  return typeof v === "string" && (OPERATOR_ACTIONS as readonly string[]).includes(v);
}

export function isConsoleOperatorAction(v: unknown): v is ConsoleOperatorAction {
  return typeof v === "string" && (CONSOLE_OPERATOR_ACTIONS as readonly string[]).includes(v);
}

export type OperatorChallenge = {
  nonce: string;
  action: OperatorAction;
  subjectId: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  /** Canonical UTF-8 message the operator must sign. */
  message: string;
};

export function buildChallengeMessage(
  c: Omit<OperatorChallenge, "message">,
): string {
  return [
    OPERATOR_CHALLENGE_PREFIX,
    `audience:${c.audience}`,
    `action:${c.action}`,
    `subject:${c.subjectId}`,
    `nonce:${c.nonce}`,
    `issued:${c.issuedAt}`,
    `expires:${c.expiresAt}`,
  ].join("\n");
}

/** Fresh challenge: 192-bit random nonce, ISO times, canonical message. */
export function newOperatorChallenge(
  action: OperatorAction,
  subjectId: string,
  audience: string,
  nowMs: number,
  ttlMs: number,
): OperatorChallenge {
  const base = {
    nonce: randomBytes(24).toString("base64url"),
    action,
    subjectId,
    audience,
    issuedAt: new Date(nowMs).toISOString(),
    expiresAt: new Date(nowMs + ttlMs).toISOString(),
  };
  return { ...base, message: buildChallengeMessage(base) };
}

type Entry = { challenge: OperatorChallenge; expiresMs: number; used: boolean };

/** In-memory single-use nonce store (one bridge process). */
export class OperatorChallengeStore implements ChallengeStore {
  private readonly entries = new Map<string, Entry>();
  constructor(
    readonly opts: {
      ttlMs?: number;
      audience?: string;
      now?: () => number;
      maxEntries?: number;
    } = {},
  ) {}

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  issue(action: OperatorAction, subjectId: string): OperatorChallenge {
    this.sweep();
    const max = this.opts.maxEntries ?? 10_000;
    if (this.entries.size >= max) {
      throw new Error("operator challenge store full");
    }
    const now = this.now();
    const ttl = this.opts.ttlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    const challenge = newOperatorChallenge(
      action,
      subjectId,
      this.opts.audience ?? "mandaterail-ac2-bridge",
      now,
      ttl,
    );
    this.entries.set(challenge.nonce, { challenge, expiresMs: now + ttl, used: false });
    return challenge;
  }

  /**
   * Look up and burn a nonce. Any presentation (valid or not) consumes it,
   * so a nonce can never be tried twice.
   */
  consume(
    nonce: string,
  ):
    | { ok: true; challenge: OperatorChallenge }
    | { ok: false; error: "unknown_nonce" | "replayed_nonce" | "expired_nonce" } {
    const e = this.entries.get(nonce);
    if (!e) return { ok: false, error: "unknown_nonce" };
    if (e.used) return { ok: false, error: "replayed_nonce" };
    e.used = true;
    if (this.now() > e.expiresMs) return { ok: false, error: "expired_nonce" };
    return { ok: true, challenge: e.challenge };
  }

  sweep(): void {
    // Keep used entries until expiry so replays report `replayed_nonce`.
    const now = this.now();
    for (const [k, e] of this.entries) {
      if (now > e.expiresMs + 60_000) this.entries.delete(k);
    }
  }
}

export type SignedChallengeEvidence = {
  nonce: string;
  address: string;
  format: "algosdk" | "arc60";
  /** base64 Ed25519 signature. */
  signature: string;
  /** arc60 only: base64 of the exact `data` string passed to signData. */
  data?: string;
  /** arc60 only: base64 authenticatorData returned by the wallet. */
  authenticatorData?: string;
};

export function encodeAttestationHeader(e: SignedChallengeEvidence): string {
  return Buffer.from(JSON.stringify(e), "utf8").toString("base64");
}

export function decodeAttestationHeader(
  header: string | undefined | null,
): SignedChallengeEvidence | null {
  if (!header) return null;
  try {
    const obj = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    if (
      !obj ||
      typeof obj.nonce !== "string" ||
      typeof obj.address !== "string" ||
      typeof obj.signature !== "string" ||
      (obj.format !== "algosdk" && obj.format !== "arc60")
    ) {
      return null;
    }
    return obj as SignedChallengeEvidence;
  } catch {
    return null;
  }
}

/** Parse OPERATOR_ALLOWLIST (comma/space separated Algorand addresses). */
export function parseOperatorAllowlist(raw = process.env.OPERATOR_ALLOWLIST): string[] {
  return (raw ?? "")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && algosdk.isValidAddress(s));
}

const sha256 = (b: Uint8Array) => createHash("sha256").update(b).digest();

function ed25519Verify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (sig.length !== 64 || pub.length !== 32) return false;
  try {
    const key = createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(pub).toString("base64url") },
      format: "jwk",
    });
    return edVerify(null, msg, key, sig);
  } catch {
    return false;
  }
}

/** ARC-60 signed payload: sha256(data) || sha256(authenticatorData). */
export function arc60SignedBytes(data: Uint8Array, authenticatorData: Uint8Array): Uint8Array {
  return new Uint8Array(Buffer.concat([sha256(data), sha256(authenticatorData)]));
}

export type SignedChallengeContext = OperatorAttestationContext & {
  action: OperatorAction;
};

const deny = (error: string, message: string): OperatorAttestationResult => ({
  ok: false,
  status: 401,
  error,
  message,
});

export class SignedChallengeOperatorVerifier implements OperatorAttestationVerifier {
  readonly kind = "signed-challenge" as const;
  constructor(
    private readonly store: ChallengeStore,
    private readonly allowlist: readonly string[],
    private readonly opts: { domain?: string } = {},
  ) {}

  async verify(
    attestation: OperatorAttestation,
    context?: OperatorAttestationContext,
  ): Promise<OperatorAttestationResult> {
    if (attestation.kind !== "signed-challenge") {
      return deny("attestation_kind_mismatch", "expected signed-challenge attestation");
    }
    const ev = decodeAttestationHeader(attestation.evidence);
    if (!ev) return deny("attestation_malformed", "malformed X-MandateRail-Operator-Attestation");
    const ctx = context as SignedChallengeContext | undefined;
    if (!ctx?.action || !ctx.subjectId) {
      return deny("attestation_context_missing", "verifier requires action + subjectId");
    }
    if (!this.allowlist.includes(ev.address)) {
      // Still burn the nonce so a non-allowlisted presentation cannot be retried.
      await this.store.consume(ev.nonce);
      return deny("operator_not_allowlisted", "signer address is not on OPERATOR_ALLOWLIST");
    }
    const c = await this.store.consume(ev.nonce);
    if (!c.ok) return deny(c.error, `challenge nonce rejected: ${c.error}`);
    const ch = c.challenge;
    if (ch.action !== ctx.action || ch.subjectId !== ctx.subjectId) {
      return deny(
        "challenge_binding_mismatch",
        "challenge was issued for a different action or subject",
      );
    }
    let pub: Uint8Array;
    try {
      pub = algosdk.decodeAddress(ev.address).publicKey;
    } catch {
      return deny("attestation_malformed", "invalid signer address");
    }
    const sig = new Uint8Array(Buffer.from(ev.signature, "base64"));
    const msg = new TextEncoder().encode(ch.message);

    let valid = false;
    if (ev.format === "algosdk") {
      try {
        valid = algosdk.verifyBytes(msg, sig, ev.address);
      } catch {
        valid = false;
      }
    } else {
      if (!ev.data || !ev.authenticatorData) {
        return deny("attestation_malformed", "arc60 evidence requires data + authenticatorData");
      }
      const dataBytes = new Uint8Array(Buffer.from(ev.data, "base64"));
      const authData = new Uint8Array(Buffer.from(ev.authenticatorData, "base64"));
      let siwa: { statement?: unknown; account_address?: unknown; nonce?: unknown; domain?: unknown };
      try {
        siwa = JSON.parse(Buffer.from(dataBytes).toString("utf8"));
      } catch {
        return deny("attestation_malformed", "arc60 data is not JSON");
      }
      if (
        siwa.statement !== ch.message ||
        siwa.nonce !== ch.nonce ||
        siwa.account_address !== ev.address
      ) {
        return deny("challenge_binding_mismatch", "arc60 data does not embed this challenge");
      }
      if (this.opts.domain) {
        if (siwa.domain !== this.opts.domain) {
          return deny("challenge_binding_mismatch", "arc60 domain mismatch");
        }
        const rpIdHash = sha256(new TextEncoder().encode(this.opts.domain));
        if (authData.length < 32 || !Buffer.from(authData.slice(0, 32)).equals(rpIdHash)) {
          return deny("challenge_binding_mismatch", "arc60 authenticatorData rpIdHash mismatch");
        }
      }
      valid = ed25519Verify(pub, arc60SignedBytes(dataBytes, authData), sig);
    }
    if (!valid) return deny("invalid_signature", "operator signature did not verify");
    return { ok: true, kind: "signed-challenge", subject: ev.address };
  }
}

export type OperatorAttestationMode = "signed-challenge" | "token-lab";

/**
 * OPERATOR_ATTESTATION_MODE=signed-challenge|token-lab.
 * Default: signed-challenge on MainNet profile, token-lab otherwise.
 * Unknown values return null (callers refuse start).
 */
export function resolveOperatorAttestationMode(
  mainnetProfile: boolean,
  raw = process.env.OPERATOR_ATTESTATION_MODE,
): OperatorAttestationMode | null {
  const v = (raw ?? "").trim().toLowerCase();
  if (!v) return mainnetProfile ? "signed-challenge" : "token-lab";
  if (v === "signed-challenge" || v === "token-lab") return v;
  return null;
}

/**
 * Rolling-window rate limiter (OA-P2-G): exact sliding log per key plus a
 * global sliding log, so no window boundary allows 2x. Memory is bounded by
 * the global limit (each stored timestamp was admitted by the global log).
 * In-memory, single process.
 */
export class RollingWindowRateLimiter implements RateLimitStore {
  private readonly keys = new Map<string, number[]>();
  private readonly global: number[] = [];
  constructor(
    readonly opts: { windowMs: number; perKey: number; global: number; now?: () => number },
  ) {}

  private now(): number {
    return this.opts.now ? this.opts.now() : Date.now();
  }

  private static prune(log: number[], cutoff: number): void {
    let n = 0;
    while (n < log.length && log[n]! <= cutoff) n++;
    if (n) log.splice(0, n);
  }

  /** Returns true when the request is allowed (and records it). */
  take(key: string): boolean {
    const now = this.now();
    const cutoff = now - this.opts.windowMs;
    RollingWindowRateLimiter.prune(this.global, cutoff);
    if (this.keys.size > this.opts.global) {
      for (const [k, log] of this.keys) {
        RollingWindowRateLimiter.prune(log, cutoff);
        if (!log.length) this.keys.delete(k);
      }
    }
    if (this.global.length >= this.opts.global) return false;
    const log = this.keys.get(key) ?? [];
    RollingWindowRateLimiter.prune(log, cutoff);
    if (log.length >= this.opts.perKey) {
      this.keys.set(key, log);
      return false;
    }
    log.push(now);
    this.global.push(now);
    this.keys.set(key, log);
    return true;
  }

  /** Test/diagnostic: number of tracked keys. */
  get trackedKeys(): number {
    return this.keys.size;
  }
}
