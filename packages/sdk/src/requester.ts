/**
 * T9: requester-key signing for ac2-bridge POST /sign (no @mandaterail/core
 * dependency). Mirrors core buildRequesterMessage / signRequesterRequest:
 * the signature covers the canonical request over the EXACT body bytes sent.
 */
export const REQUESTER_AUTH_HEADER = "x-mandaterail-requester-auth";
export const REQUESTER_AUTH_PREFIX = "MandateRail requester request v1";

export type RequesterSigner = {
  /** Allowlisted Algorand address (REQUESTER_ALLOWLIST on the bridge). */
  address: string;
  /** algosdk.signBytes-compatible: signs "MX" || bytes with the address key. */
  signBytes: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>;
};

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

async function sha256Hex(body: Uint8Array): Promise<string> {
  const d = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new Uint8Array(body) as Uint8Array<ArrayBuffer>));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function buildRequesterMessage(f: {
  audience: string; method: string; path: string; address: string; nonce: string; timestamp: string; bodySha256Hex: string;
}): string {
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

/** Returns the X-MandateRail-Requester-Auth header value for `body`. */
export async function signRequesterRequest(args: {
  signer: RequesterSigner;
  nonce: string;
  audience: string;
  body: string | Uint8Array;
  method?: string;
  path?: string;
  timestamp?: string;
}): Promise<string> {
  const timestamp = args.timestamp ?? new Date().toISOString();
  const bytes = typeof args.body === "string" ? new TextEncoder().encode(args.body) : args.body;
  const msg = buildRequesterMessage({
    audience: args.audience,
    method: args.method ?? "POST",
    path: args.path ?? "/sign",
    address: args.signer.address,
    nonce: args.nonce,
    timestamp,
    bodySha256Hex: await sha256Hex(bytes),
  });
  const sig = await args.signer.signBytes(new TextEncoder().encode(msg));
  const json = JSON.stringify({ address: args.signer.address, nonce: args.nonce, timestamp, signature: b64(sig) });
  return b64(new TextEncoder().encode(json));
}
