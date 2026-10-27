import type { IntentMandate } from "@mandaterail/schema";
import type { SpendCaps, SpendStore } from "./spend-caps.js";

export type PolicyDenialReason =
  | "invalid_schema"
  | "revoked"
  | "expired"
  | "amount_exceeded"
  | "merchant_not_allowlisted"
  | "asset_mismatch"
  | "unsigned_not_allowed"
  | "ac2_verification_failed"
  | "per_payment_cap_exceeded"
  | "daily_cap_exceeded"
  | "spend_ledger_unavailable";

export interface PolicyContext {
  /** Requested spend amount as decimal string (human units) */
  amount: string;
  /** Asset for this payment (policy layer — e.g. USDC) */
  asset: string;
  /** Merchant id / origin being paid */
  merchantId: string;
  /** Evaluation time (defaults to now) */
  now?: Date;
  /**
   * When true, allow missing signature (DEV ONLY).
   * Default / env: DEV_ALLOW_UNSIGNED=false
   */
  allowUnsigned?: boolean;
  /**
   * T7 spend caps (per payment, per day per payer = mandate.principal).
   * Checked after the AC2 signature, so unauthenticated callers can't probe
   * the store. With a `store`, success writes a `pending` reservation
   * (returned as `spendReservationId`) that the caller must finalize after
   * settle. `requireLedger` (MainNet) denies when no store is given;
   * otherwise only the per-payment cap applies without a store.
   */
  spend?: {
    caps: SpendCaps;
    store?: SpendStore;
    requireLedger?: boolean;
    reservationId?: string;
  };
}

export type PolicyResult =
  | {
      ok: true;
      mandate: IntentMandate;
      /** T7: pending spend reservation to finalize after settle. */
      spendReservationId?: string;
    }
  | { ok: false; reason: PolicyDenialReason; message: string };

export interface Ac2VerifyInput {
  mandate: IntentMandate;
  principal: string;
  signature: string | null | undefined;
}
