/**
 * OpenAPI-aligned types from openapi/openapi.yaml (MandateRail API 0.1.0-draft).
 * Stubs only — not a hosted multi-tenant API guarantee.
 */

export type ApiError = {
  error?: string;
  message?: string;
  [key: string]: unknown;
};

export type HealthStatus = {
  ok: boolean;
  service?: string;
  network?: string;
  merchantConfigured?: boolean;
  merchant?: string | null;
  usdcAsaId?: string;
  asset?: string;
  priceUsdc?: string;
  priceHints?: Record<string, unknown>;
  autoLocal?: boolean;
  paired?: boolean;
};

export type IntentMandate = {
  id: string;
  principal: string;
  principalPubkey?: string;
  agent: string;
  maxAmount: string;
  asset: string;
  allowlist: string[];
  expiresAt: string;
  revoked: boolean;
  nonce: string;
  signature?: string | null;
  createdAt: string;
  metadata?: Record<string, unknown>;
};

/** Create body; production must include a verified signature. */
export type IntentMandateCreate = IntentMandate;

export type Receipt = {
  receiptId: string;
  mandateId: string;
  txId: string;
  network: string;
  payer: string;
  merchant: string;
  amount: string;
  asset: string;
  createdAt: string;
  explorerUrl: string;
};

export type PairMode = "auto-local" | "manual" | "unpaired";

export type PairStatus = {
  paired: boolean;
  mode: PairMode;
  pendingCount?: number;
};

export type SigningRequest = {
  message: string;
  message_b64?: string;
  mandateId?: string;
  sig_hint?: string;
  display_hint?: string;
  [key: string]: unknown;
};

export type SignatureResult = {
  signature: string;
  publicKey?: string;
  address?: string;
};

export type PendingApproval = {
  id?: string;
  status?: "pending" | "approved" | "rejected" | "expired";
  createdAt?: string;
  mandateId?: string;
  sig_hint?: string;
  display_hint?: string;
  message?: string;
  signature?: string;
  publicKey?: string;
  address?: string;
};

export type SignPendingResponse = {
  id: string;
  status: "pending";
  /** Secret for GET /requests/{id}/status; returned once (OA-N1). */
  requesterToken?: string;
  statusUrl?: string;
};

/** GET /requests/{id}/status — requester-scoped (OA-N1). */
export type RequestStatus = {
  id: string;
  status: "pending" | "approved" | "rejected" | "expired";
  signature?: string;
  publicKey?: string;
  address?: string;
};

export type ApproveBody = {
  signature?: string;
  publicKey?: string;
  address?: string;
  /** CI only — sign with bridge-host mnemonic */
  useLocal?: boolean;
};

export type ApproveResult = SignatureResult & {
  id?: string;
  status?: "approved";
};

export type RejectResult = {
  id: string;
  status: "rejected";
};

export type PaymentRequiredBody = {
  error?: "payment_required";
  payment?: Record<string, unknown>;
  accepts?: Array<Record<string, unknown>>;
  mandate?: Record<string, unknown>;
};

/** Canonical OperatorAuth header (OpenAPI P0 / ac2-bridge). */
export const OPERATOR_TOKEN_HEADER = "X-MandateRail-Operator-Token";
export const OPERATOR_ATTESTATION_HEADER = "X-MandateRail-Operator-Attestation";
export const REQUESTER_TOKEN_HEADER = "X-MandateRail-Requester-Token";

/** Merchant ApiKeyAuth header (planned production). */
export const API_KEY_HEADER = "X-MandateRail-Key";

/** Default TestNet localhost base URLs (DEV ONLY). */
export const DEFAULT_DEMO_API_URL = "http://127.0.0.1:8787";
export const DEFAULT_CONSOLE_URL = "http://127.0.0.1:8788";
export const DEFAULT_AC2_BRIDGE_URL = "http://127.0.0.1:8790";

/** Live public TestNet hosts (single ECS box behind Caddy). TestNet only, not audited. */
export const TESTNET_DEMO_API_URL = "https://mr-api.8-221-97-26.sslip.io";
export const TESTNET_AC2_BRIDGE_URL = "https://mr-bridge.8-221-97-26.sslip.io";
export const TESTNET_CONSOLE_URL = "https://mr-console.8-221-97-26.sslip.io";
/** ARC-60 signData domain the live hosts require (`OPERATOR_SIGNDATA_DOMAIN`). */
export const TESTNET_SIGNDATA_DOMAIN = "mandaterail.pages.dev";

/** Evidence carried in X-MandateRail-Operator-Attestation (base64 JSON). */
export type OperatorAttestationEvidence = {
  nonce: string;
  /** Allowlisted Algorand address that signed. */
  address: string;
  /** "algosdk": algosdk.signBytes(utf8(message)); "arc60": wallet signData. */
  format: "algosdk" | "arc60";
  /** base64 Ed25519 signature. */
  signature: string;
  /** arc60 only: base64 signed data and authenticatorData from signData. */
  data?: string;
  authenticatorData?: string;
};

/** Operator challenge returned by GET /operator/challenge (bridge or console). */
export type OperatorChallenge = {
  nonce: string;
  action: string;
  subjectId: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  /** Exact UTF-8 text to sign. */
  message: string;
  header?: string;
};

/** Encode evidence as the X-MandateRail-Operator-Attestation header value. */
export function encodeOperatorAttestation(e: OperatorAttestationEvidence): string {
  const json = JSON.stringify(e);
  return typeof Buffer !== "undefined"
    ? Buffer.from(json, "utf8").toString("base64")
    : btoa(unescape(encodeURIComponent(json)));
}
