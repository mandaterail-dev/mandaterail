import algosdk from "algosdk";
import type { IntentMandate } from "@mandaterail/schema";
import type { Ac2VerifyInput } from "./types.js";

/**
 * AC2-compatible intent signature verification (ed25519).
 *
 * Phase-1: cryptographic mandate signatures using Algorand/ed25519 keys so
 * A→Z works headlessly. Full AC2 Wallet / WebRTC pairing is Phase-2 UX.
 *
 * Verification: ed25519 over canonical mandate bytes (stable JSON with
 * `signature` and `principalPubkey` omitted). The verify key is always bound
 * to `principal` (see resolvePrincipalAddress): an Algorand address, or an
 * Ed25519 `did:key` with a matching principalPubkey. A principalPubkey that
 * does not match the principal is rejected.
 *
 * `principalPubkey` is intentionally not part of the signed payload so clients
 * can attach the bridge-returned public key after signing (bridge auto-local /
 * phone approval) without invalidating the signature.
 */

/** Stable JSON bytes for signing/verifying (signature + principalPubkey omitted). */
export function canonicalMandateBytes(
  mandate:
    | IntentMandate
    | Omit<IntentMandate, "signature">
    | Record<string, unknown>,
): Uint8Array {
  const copy: Record<string, unknown> = {
    ...(mandate as Record<string, unknown>),
  };
  // Wire-only / key-resolution fields — not part of the signed intent body.
  delete copy.signature;
  delete copy.principalPubkey;
  return new TextEncoder().encode(stableStringify(copy));
}

/** Deterministic JSON stringify with sorted object keys (arrays keep order). */
export function stableStringify(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    out[key] = sortValue(obj[key]);
  }
  return out;
}

/**
 * Sign canonical mandate bytes with an Algorand secret key (64-byte seed||pk).
 * Returns base64 ed25519 signature.
 */
export function signMandate(
  mandate: IntentMandate | Omit<IntentMandate, "signature">,
  secretKey: Uint8Array,
): string {
  const bytes = canonicalMandateBytes(mandate);
  const sig = algosdk.signBytes(bytes, secretKey);
  return Buffer.from(sig).toString("base64");
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcDecode(str: string): Uint8Array | null {
  let n = 0n;
  for (const ch of str) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const ch of str) {
    if (ch !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}

/** Ed25519 public key from a `did:key:z6Mk...` (multicodec 0xed01), else null. */
export function ed25519KeyFromDidKey(did: string): Uint8Array | null {
  if (!did.startsWith("did:key:z")) return null;
  const raw = base58btcDecode(did.slice("did:key:z".length));
  if (!raw || raw.length !== 34 || raw[0] !== 0xed || raw[1] !== 0x01) {
    return null;
  }
  return raw.slice(2);
}

/** `did:key` for a raw 32-byte Ed25519 public key. */
export function didKeyFromEd25519(pk: Uint8Array): string {
  const bytes = Uint8Array.from([0xed, 0x01, ...pk]);
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    out = "1" + out;
  }
  return `did:key:z${out}`;
}

/**
 * The verify key is always bound to `principal` (CON-P2-8):
 * - Algorand address: key derived from the address; a `principalPubkey`
 *   that differs is rejected.
 * - `did:key` (Ed25519): key from the DID; `principalPubkey` is required and
 *   must equal it.
 * - Anything else: rejected. `principalPubkey` alone never names a signer.
 */
export function resolvePrincipalAddress(
  m: Pick<IntentMandate, "principal" | "principalPubkey">,
): { ok: true; address: string } | { ok: false; message: string } {
  let hinted: Uint8Array | null = null;
  if (m.principalPubkey !== undefined) {
    const pk = Buffer.from(m.principalPubkey, "base64");
    if (pk.length !== 32) {
      return { ok: false, message: "principalPubkey must be a base64 32-byte Ed25519 key" };
    }
    hinted = pk;
  }
  if (algosdk.isValidAddress(m.principal)) {
    const pk = algosdk.decodeAddress(m.principal).publicKey;
    if (hinted && !Buffer.from(hinted).equals(Buffer.from(pk))) {
      return { ok: false, message: "principalPubkey does not match principal address" };
    }
    return { ok: true, address: m.principal };
  }
  if (m.principal.startsWith("did:key:")) {
    const pk = ed25519KeyFromDidKey(m.principal);
    if (!pk) return { ok: false, message: "principal did:key is not an Ed25519 key" };
    if (!hinted) {
      return { ok: false, message: "did:key principal requires a matching principalPubkey" };
    }
    if (!Buffer.from(hinted).equals(Buffer.from(pk))) {
      return { ok: false, message: "principalPubkey does not match principal did:key" };
    }
    return { ok: true, address: algosdk.encodeAddress(pk) };
  }
  return {
    ok: false,
    message: "principal must be an Algorand address or an Ed25519 did:key",
  };
}

export async function verifyAc2Signature(
  input: Ac2VerifyInput,
  opts?: { allowUnsigned?: boolean },
): Promise<{ ok: true } | { ok: false; message: string }> {
  const allowUnsigned = opts?.allowUnsigned === true;

  if (!input.signature) {
    if (allowUnsigned) return { ok: true };
    return {
      ok: false,
      message: "AC2 signature missing and DEV_ALLOW_UNSIGNED is false",
    };
  }

  let sig: Uint8Array;
  try {
    sig = Buffer.from(input.signature, "base64");
  } catch {
    return { ok: false, message: "AC2 signature is not valid base64" };
  }
  if (sig.length !== 64) {
    return {
      ok: false,
      message: `AC2 signature must be 64 bytes (got ${sig.length})`,
    };
  }

  const resolved = resolvePrincipalAddress({
    principal: input.principal ?? input.mandate.principal,
    principalPubkey: input.mandate.principalPubkey,
  });
  if (!resolved.ok) return { ok: false, message: resolved.message };
  if (input.principal && input.principal !== input.mandate.principal) {
    return { ok: false, message: "principal does not match mandate principal" };
  }
  const address = resolved.address;

  const bytes = canonicalMandateBytes(input.mandate);
  try {
    const valid = algosdk.verifyBytes(bytes, sig, address);
    if (!valid) {
      return { ok: false, message: "AC2 ed25519 signature verification failed" };
    }
    return { ok: true };
  } catch (e) {
    return {
      ok: false,
      message:
        e instanceof Error
          ? `AC2 verify error: ${e.message}`
          : "AC2 verify error",
    };
  }
}

/** Read DEV_ALLOW_UNSIGNED from env; default false. */
export function isDevAllowUnsigned(): boolean {
  const v = process.env.DEV_ALLOW_UNSIGNED;
  if (v === undefined || v === "") return false;
  return v === "1" || v.toLowerCase() === "true" || v === "yes";
}
