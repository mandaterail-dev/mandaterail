export interface IntentMandate {
  id: string;
  principal: string;
  agent: string;
  maxAmount: string;
  asset: string;
  allowlist: string[];
  expiresAt: string;
  revoked: boolean;
  nonce: string;
  signature: string | null;
  createdAt: string;
  metadata?: Record<string, unknown>;
  /** Server-side classification from the console (GET /mandates[/:id]). */
  authorization?: MandateAuthorization;
}

export interface MandateAuthorization {
  status:
    | "unsigned-draft"
    | "stub-signature"
    | "signature-present-unverified"
    | "signature-verified"
    | "signature-invalid"
    | "revoked"
    | "expired";
  authorizedForExecute: boolean;
  message: string;
}

export interface Receipt {
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
}

export type PendingStatus = "pending" | "approved" | "rejected";

export interface PendingApproval {
  id: string;
  status: PendingStatus;
  createdAt: string;
  mandateId?: string;
  sig_hint?: string;
  display_hint?: string;
  message?: string;
  signature?: string;
  publicKey?: string;
  address?: string;
}

export interface PairStatus {
  paired: boolean;
  mode: "auto-local" | "manual" | "unpaired";
  pendingCount?: number;
}

export interface HealthResponse {
  ok: boolean;
  service: string;
  [key: string]: unknown;
}
