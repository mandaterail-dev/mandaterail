import { z } from "zod";

/**
 * IntentMandate — delegated spend authorization for MandateRail.
 * Wire version: IntentMandate/v1
 *
 * Signature: ed25519 over canonical JSON (`signature` and `principalPubkey`
 * omitted), typically an Algorand account key. Full AC2 Wallet/WebRTC pairing
 * is Phase-2 UX; this is AC2-compatible intent signing so A→Z works headlessly.
 */
export const IntentMandateSchema = z.object({
  id: z.string().min(1),
  /** Principal identifier — Algorand address or DID. */
  principal: z.string().min(1),
  /**
   * Optional raw ed25519 public key (32 bytes, base64).
   * When set, verify uses this key; otherwise principal is treated as an
   * Algorand address and the pubkey is derived via algosdk.decodeAddress.
   */
  principalPubkey: z.string().min(1).optional(),
  agent: z.string().min(1),
  maxAmount: z
    .string()
    .regex(/^\d+(\.\d+)?$/, "maxAmount must be a non-negative decimal string"),
  asset: z.string().min(1),
  allowlist: z.array(z.string().min(1)),
  expiresAt: z.string().datetime({ offset: true }),
  revoked: z.boolean().default(false),
  nonce: z.string().min(1),
  /** ed25519 signature over canonical mandate bytes (base64). */
  signature: z.string().nullable().optional(),
  createdAt: z.string().datetime({ offset: true }),
  metadata: z.record(z.unknown()).optional(),
});

export type IntentMandate = z.infer<typeof IntentMandateSchema>;

export const INTENT_MANDATE_VERSION = "IntentMandate/v1" as const;

export const MandateHintsSchema = z.object({
  merchantId: z.string().min(1),
  maxAmountSuggested: z.string().optional(),
  asset: z.string().optional(),
});

export type MandateHints = z.infer<typeof MandateHintsSchema>;

export const PaymentRequiredExtrasSchema = z.object({
  error: z.literal("payment_required"),
  accepts: z
    .array(
      z.object({
        scheme: z.string(),
        network: z.string(),
        amount: z.string(),
        asset: z.string(),
        payTo: z.string(),
        maxTimeoutSeconds: z.number().optional(),
        extra: z.record(z.unknown()).optional(),
      }),
    )
    .optional(),
  payment: z
    .object({
      scheme: z.string(),
      network: z.string(),
      amount: z.string(),
      asset: z.string(),
      payTo: z.string(),
      maxTimeoutSeconds: z.number().optional(),
      extra: z.record(z.unknown()).optional(),
    })
    .optional(),
  mandate: z.object({
    required: z.boolean(),
    accept: z.array(z.string()),
    hints: MandateHintsSchema,
  }),
});

export type PaymentRequiredExtras = z.infer<typeof PaymentRequiredExtrasSchema>;
