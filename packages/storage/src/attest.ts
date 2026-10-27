/**
 * v11 attestation format (docs/ops/attested-release-signer.md §2.3): MR-RELEASE-ATTEST-v1\n + restricted JCS.
 * Shared by mr-signer, mr-piv-sign (checks), the CLI echo/verify path and the tests. The DB re-checks everything
 * in mr_spend_release_attested (mr_jcs byte equality + mr_crypto.mr_ed25519_verify).
 */
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { ATTEST_MSG_KEYS, ATTEST_OBS_KEYS, ATTEST_PREFIX, KEY_ID_HEX_LEN } from "./v11-attested.js";

export { ATTEST_MSG_KEYS, ATTEST_OBS_KEYS, ATTEST_PREFIX, KEY_ID_HEX_LEN };
export type JcsValue = string | number | JcsValue[] | { [k: string]: JcsValue };
export interface Observation {
  at: string; idxRound: number; method: "idx404" | "blockscan" | "blockscan-full"; operator: string; provider: string; round: number;
}
export interface AttestBody {
  expiry: string; firstValid: number; genesisHash: string; groupId: string; keyId: string; lastValid: number;
  network: "testnet" | "mainnet"; nonce: string; observations: Observation[]; round: number; sender: string;
  spendId: string; store: string; txId: string; v: 1;
}
export class AttestError extends Error {}

/** Restricted RFC 8785: ASCII-alnum keys sorted, printable ASCII strings w/o quote/backslash, safe non-negative ints. */
export function jcs(v: JcsValue): string {
  if (typeof v === "string") {
    if (!/^[ !#-[\]-~]*$/.test(v)) throw new AttestError("jcs: string outside the restricted ASCII profile");
    return `"${v}"`;
  }
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || v < 0) throw new AttestError("jcs: only non-negative safe integers");
    return String(v);
  }
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${keys.map((k) => {
      if (!/^[A-Za-z0-9]{1,32}$/.test(k)) throw new AttestError("jcs: bad key");
      return `"${k}":${jcs(v[k]!)}`;
    }).join(",")}}`;
  }
  throw new AttestError("jcs: type not allowed");
}

export function keyIdOf(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) throw new AttestError("pubkey must be 32 bytes");
  return createHash("sha256").update(pubkey).digest("hex").slice(0, KEY_ID_HEX_LEN);
}

function sameKeys(o: object, want: readonly string[]): boolean {
  const k = Object.keys(o).sort();
  return k.length === want.length && k.every((x, i) => x === [...want].sort()[i]);
}

const ISO_S = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
/** Attestation timestamps are UTC whole seconds (the DB format check). */
export const isoSeconds = (ms: number): string => new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");

export function encodeAttestation(b: AttestBody): Buffer {
  if (!sameKeys(b, ATTEST_MSG_KEYS)) throw new AttestError("attestation key set");
  if (!ISO_S.test(b.expiry)) throw new AttestError("expiry must be UTC whole seconds");
  for (const o of b.observations) {
    if (!sameKeys(o, ATTEST_OBS_KEYS)) throw new AttestError("observation key set");
    if (!ISO_S.test(o.at)) throw new AttestError("observation time must be UTC whole seconds");
  }
  const msg = Buffer.from(ATTEST_PREFIX + jcs(b as unknown as JcsValue), "utf8");
  if (msg.length > 4096) throw new AttestError("attestation too long");
  return msg;
}

/** Parses and strictly re-canonicalizes a message; throws unless the bytes are exactly canonical. */
export function decodeAttestation(msg: Uint8Array): AttestBody {
  const s = Buffer.from(msg).toString("utf8");
  if (!s.startsWith(ATTEST_PREFIX) || msg.length > 4096) throw new AttestError("attestation prefix / length");
  const body = s.slice(ATTEST_PREFIX.length);
  if (!/^[ -~]+$/.test(body)) throw new AttestError("attestation not printable ASCII");
  const b = JSON.parse(body) as AttestBody;
  if (!Buffer.from(encodeAttestation(b)).equals(Buffer.from(msg))) throw new AttestError("attestation not canonical");
  return b;
}

export function verifyAttestation(msg: Uint8Array, sig: Uint8Array, pubkey: Uint8Array): boolean {
  if (sig.length !== 64 || pubkey.length !== 32) return false;
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pubkey)]), format: "der", type: "spki" });
  return edVerify(null, Buffer.from(msg), key, Buffer.from(sig));
}
