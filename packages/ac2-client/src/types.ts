import type { IntentMandate } from "@mandaterail/schema";

/** Unsigned IntentMandate (signature omitted / null). */
export type UnsignedIntentMandate =
  | IntentMandate
  | Omit<IntentMandate, "signature">;

export interface Ac2SignResult {
  /** Base64 ed25519 signature over canonical mandate bytes. */
  signature: string;
  /** Base64 raw 32-byte ed25519 public key (when known). */
  publicKey: string;
  /** Algorand address of the signer (when known). */
  address?: string;
}

/**
 * SigningRequest-shaped payload sent to an AC2 bridge / OpenClaw ac2_sign tool.
 * sig_hint: raw-ed25519 | message-algorand
 * display_hint: json (human-readable mandate for phone approval UX)
 */
export interface SigningRequest {
  type: "IntentMandate/v1";
  sig_hint: "raw-ed25519" | "message-algorand";
  display_hint: "json";
  /** Canonical mandate JSON (signature omitted), UTF-8. */
  message: string;
  /** Same bytes as base64 for bridges that prefer binary. */
  message_b64: string;
  /** Optional mandate id for correlation. */
  mandateId?: string;
  /** Optional principal hint. */
  principal?: string;
}

export interface Ac2Signer {
  signIntentMandate(unsigned: UnsignedIntentMandate): Promise<Ac2SignResult>;
}
