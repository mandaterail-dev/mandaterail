/**
 * Operator attestation verifier interface.
 *
 * Bound today: `signed-challenge` (Ed25519 / Algorand account, see
 * operator-challenge.ts). Still TODO: device | hsm | vault bindings (501 stub).
 * InsecureDevOperatorAuth (token shim) is TestNet lab only (`token-lab`).
 */

import {
  authorizeOperator,
  OPERATOR_TOKEN_HEADER,
} from "./insecure-dev.js";

/** Attestation transport kinds planned for production operator binding. */
export type OperatorAttestationKind =
  | "signed-challenge"
  | "device"
  | "hsm"
  | "vault";

export type OperatorAttestation = {
  kind: OperatorAttestationKind;
  /** Opaque session / device / key handle — format TBD per binding. */
  sessionId?: string;
  /** Binding-specific evidence (JWT, quote, vault token, …). */
  evidence?: string;
  /** Optional wall-clock expiry (ISO-8601). */
  expiresAt?: string;
};

export type OperatorAttestationContext = {
  remoteAddress?: string | null;
  /** Pending approval / mandate id under attestation. */
  subjectId?: string;
  /** Operator action under attestation (approve | reject | list). */
  action?: "approve" | "reject" | "list" | "mandate.create" | "mandate.revoke" | "mandate.read" | "mandate.list" | "request.sign";
};

export type OperatorAttestationResult =
  | { ok: true; kind: OperatorAttestationKind; subject?: string }
  | { ok: false; status: 401 | 501; error: string; message: string };

/**
 * Production verifier interface. Implementations for device / HSM / vault
 * session bindings are not provided in this repository yet.
 */
export interface OperatorAttestationVerifier {
  readonly kind: OperatorAttestationKind | "multi";
  verify(
    attestation: OperatorAttestation,
    context?: OperatorAttestationContext,
  ): Promise<OperatorAttestationResult>;
}

/**
 * Stub verifier: always returns 501 Not Implemented.
 * Use to reserve the interface without implying production readiness.
 */
export class UnimplementedOperatorAttestationVerifier
  implements OperatorAttestationVerifier
{
  readonly kind = "multi" as const;

  async verify(
    attestation: OperatorAttestation,
    _context?: OperatorAttestationContext,
  ): Promise<OperatorAttestationResult> {
    return {
      ok: false,
      status: 501,
      error: "operator_attestation_unimplemented",
      message: `Operator attestation kind '${attestation.kind}' is not bound in this build (TODO: device | hsm | vault). Lab demos must use InsecureDevOperatorAuth only.`,
    };
  }
}

/**
 * Lab/demo operator auth via shared secret header.
 * NOT a production attestation binding — do not use as a substitute for
 * device / HSM / vault session verification.
 */
export const InsecureDevOperatorAuth = {
  header: OPERATOR_TOKEN_HEADER,
  authorize: authorizeOperator,
} as const;
