/**
 * Shared signed-challenge OperatorAttestation for the SPA (ac2-bridge and
 * console). Fetches GET {baseUrl}/operator/challenge?action=&id=, signs with
 * the connected wallet (ARC-60 signData) or an offline algosdk.signBytes
 * fallback, and returns the X-MandateRail-Operator-Attestation value.
 * No shared secret or key material in the SPA. NOT audited.
 */
export type BridgeOperatorAction = "approve" | "reject" | "list";
export type ConsoleOperatorAction =
  | "mandate.create"
  | "mandate.revoke"
  | "mandate.read"
  | "mandate.list";
export type OperatorAction = BridgeOperatorAction | ConsoleOperatorAction;

export interface OperatorChallenge {
  nonce: string;
  action: OperatorAction;
  subjectId: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  message: string;
}

export interface SignDataResult {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
}

/** Wallet-side operator signer (no key material in the SPA). */
export interface OperatorSigner {
  address: string;
  /** ARC-60 signData(base64 data, {scope: AUTH, encoding: "base64"}), if supported. */
  signData?: (data: string) => Promise<SignDataResult>;
  /** Fallback: return base64 algosdk.signBytes(message) signature produced offline. */
  manualSign?: (message: string) => Promise<string | null>;
}

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const b64Utf8 = (s: string) => b64(new TextEncoder().encode(s));

export const OPERATOR_ATTESTATION_HEADER = "X-MandateRail-Operator-Attestation";

/** Build the attestation header for one (action, id) against `baseUrl`. */
export async function attestationHeaderFor(
  baseUrl: string,
  signer: OperatorSigner,
  action: OperatorAction,
  id: string,
): Promise<string> {
  const res = await fetch(
    `${baseUrl}/operator/challenge?action=${encodeURIComponent(action)}&id=${encodeURIComponent(id)}`,
  );
  if (!res.ok) throw new Error(`operator challenge: ${res.status}`);
  const ch = (await res.json()) as OperatorChallenge;
  if (signer.signData) {
    const domain = window.location.host;
    const siwa = {
      domain,
      account_address: signer.address,
      uri: window.location.origin,
      version: "1",
      statement: ch.message,
      nonce: ch.nonce,
      "issued-at": ch.issuedAt,
      "expiration-time": ch.expiresAt,
      chain_id: "283",
      type: "ed25519",
    };
    const data = b64Utf8(JSON.stringify(siwa));
    const res = await signer.signData(data);
    return b64Utf8(
      JSON.stringify({
        nonce: ch.nonce,
        address: signer.address,
        format: "arc60",
        signature: b64(res.signature),
        data,
        authenticatorData: b64(res.authenticatorData),
      }),
    );
  }
  if (signer.manualSign) {
    const sig = await signer.manualSign(ch.message);
    if (!sig) throw new Error("operator signature cancelled");
    return b64Utf8(
      JSON.stringify({
        nonce: ch.nonce,
        address: signer.address,
        format: "algosdk",
        signature: sig.trim(),
      }),
    );
  }
  throw new Error("connected wallet cannot sign operator challenges");
}
