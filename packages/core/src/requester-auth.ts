/**
 * T8: requester-key auth for ac2-bridge POST /sign.
 *
 * 1. Requester GETs a single-use nonce bound to its address
 *    (ChallengeStore.issue("request.sign", address)).
 * 2. It signs the canonical request (method, path, body sha256, nonce,
 *    timestamp, audience) with its allowlisted Ed25519 key
 *    (algosdk.signBytes, "MX" domain prefix).
 * 3. Sends base64(JSON {address, nonce, timestamp, signature}) in
 *    X-MandateRail-Requester-Auth.
 * The verifier burns the nonce on any presentation (replay-safe across
 * processes when the store is Redis/Postgres), checks the binding, the
 * timestamp skew and the signature over the exact body bytes.
 */
import { createHash } from "node:crypto";
import algosdk from "algosdk";
import type { ChallengeStore } from "./storage.js";

export const REQUESTER_AUTH_HEADER = "x-mandaterail-requester-auth";
export const REQUESTER_AUTH_PREFIX = "MandateRail requester request v1";
export const REQUESTER_ACTION = "request.sign" as const;
export const DEFAULT_REQUESTER_MAX_SKEW_MS = 60_000;

export interface RequesterAuthEvidence {
  address: string;
  nonce: string;
  /** ISO-8601, requester clock. */
  timestamp: string;
  /** base64 algosdk.signBytes signature of the canonical message. */
  signature: string;
}

export interface CanonicalRequestFields {
  audience: string;
  method: string;
  path: string;
  address: string;
  nonce: string;
  timestamp: string;
  bodySha256Hex: string;
}

export function bodySha256Hex(body: string | Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

export function buildRequesterMessage(f: CanonicalRequestFields): string {
  return [
    REQUESTER_AUTH_PREFIX,
    `audience:${f.audience}`,
    `method:${f.method.toUpperCase()}`,
    `path:${f.path}`,
    `address:${f.address}`,
    `nonce:${f.nonce}`,
    `timestamp:${f.timestamp}`,
    `body-sha256:${f.bodySha256Hex}`,
  ].join("\n");
}

export function encodeRequesterAuthHeader(e: RequesterAuthEvidence): string {
  return Buffer.from(JSON.stringify(e), "utf8").toString("base64");
}

export function decodeRequesterAuthHeader(raw: string | undefined): RequesterAuthEvidence | null {
  if (!raw || raw.length > 4096) return null;
  try {
    const o = JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as Record<string, unknown>;
    for (const k of ["address", "nonce", "timestamp", "signature"]) {
      if (typeof o[k] !== "string" || !(o[k] as string)) return null;
    }
    return o as unknown as RequesterAuthEvidence;
  } catch {
    return null;
  }
}

/** Client helper: sign a request body for POST /sign. */
export function signRequesterRequest(args: {
  sk: Uint8Array;
  address: string;
  nonce: string;
  audience: string;
  body: string | Uint8Array;
  method?: string;
  path?: string;
  timestamp?: string;
}): string {
  const timestamp = args.timestamp ?? new Date().toISOString();
  const msg = buildRequesterMessage({
    audience: args.audience,
    method: args.method ?? "POST",
    path: args.path ?? "/sign",
    address: args.address,
    nonce: args.nonce,
    timestamp,
    bodySha256Hex: bodySha256Hex(args.body),
  });
  const sig = algosdk.signBytes(new TextEncoder().encode(msg), args.sk);
  return encodeRequesterAuthHeader({
    address: args.address,
    nonce: args.nonce,
    timestamp,
    signature: Buffer.from(sig).toString("base64"),
  });
}

/** REQUESTER_ALLOWLIST: comma-separated Algorand addresses (Ed25519 keys). */
export function parseRequesterAllowlist(raw = process.env.REQUESTER_ALLOWLIST): string[] {
  if (!raw) return [];
  const out: string[] = [];
  for (const part of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    if (!algosdk.isValidAddress(part)) throw new Error(`REQUESTER_ALLOWLIST: invalid address ${part.slice(0, 8)}…`);
    out.push(part);
  }
  return out;
}

export type RequesterAuthResult =
  | { ok: true; address: string }
  | { ok: false; status: 401; error: string; message: string };

const GENERIC = "requester_auth_failed";
const GENERIC_MSG = "requester authentication failed";
const deny = (error: string, message: string): RequesterAuthResult => ({ ok: false, status: 401, error, message });

export class RequesterKeyVerifier {
  constructor(
    private readonly store: ChallengeStore,
    private readonly allowlist: readonly string[],
    /** `audience` optional: the store is already audience-scoped. */
    private readonly opts: { audience?: string; maxSkewMs?: number } = {},
  ) {}

  async verify(input: {
    header: string | undefined;
    method: string;
    path: string;
    /** Raw request body bytes (T8-P3-1: hash exactly what was received). */
    body: string | Uint8Array;
    nowMs: number;
  }): Promise<RequesterAuthResult> {
    const ev = decodeRequesterAuthHeader(input.header);
    if (!ev) return deny("requester_auth_malformed", "malformed X-MandateRail-Requester-Auth");
    if (!this.allowlist.includes(ev.address)) {
      await this.store.consume(ev.nonce); // burn: no retry with another key
      // T8-P3-1: same generic error as a bad signature (no allowlist oracle).
      return deny(GENERIC, GENERIC_MSG);
    }
    const c = await this.store.consume(ev.nonce);
    if (!c.ok) return deny(c.error, `requester nonce rejected: ${c.error}`);
    if (c.challenge.action !== REQUESTER_ACTION || c.challenge.subjectId !== ev.address) {
      return deny("challenge_binding_mismatch", "nonce was issued for a different action or requester");
    }
    if (this.opts.audience && c.challenge.audience !== this.opts.audience) {
      return deny("challenge_binding_mismatch", "nonce audience mismatch");
    }
    const ts = Date.parse(ev.timestamp);
    const skew = this.opts.maxSkewMs ?? DEFAULT_REQUESTER_MAX_SKEW_MS;
    if (!Number.isFinite(ts) || Math.abs(input.nowMs - ts) > skew) {
      return deny("stale_timestamp", "request timestamp outside the allowed skew");
    }
    const msg = buildRequesterMessage({
      audience: c.challenge.audience,
      method: input.method,
      path: input.path,
      address: ev.address,
      nonce: ev.nonce,
      timestamp: ev.timestamp,
      bodySha256Hex: bodySha256Hex(input.body),
    });
    let valid = false;
    try {
      valid = algosdk.verifyBytes(new TextEncoder().encode(msg), new Uint8Array(Buffer.from(ev.signature, "base64")), ev.address);
    } catch {
      valid = false;
    }
    if (!valid) return deny(GENERIC, GENERIC_MSG);
    return { ok: true, address: ev.address };
  }
}
