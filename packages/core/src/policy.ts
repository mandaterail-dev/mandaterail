import {
  IntentMandateSchema,
  type IntentMandate,
} from "@mandaterail/schema";
import { isDevAllowUnsigned, verifyAc2Signature } from "./ac2.js";
import type { PolicyContext, PolicyResult } from "./types.js";
import { checkSpendCaps, toMicro } from "./spend-caps.js";

function parseDecimal(s: string): number {
  const n = Number(s);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`invalid decimal: ${s}`);
  }
  return n;
}

/**
 * Evaluate an IntentMandate against a spend context.
 * Order: schema → revoked → expiry → amount → allowlist → asset → AC2 →
 * spend caps (when `ctx.spend` is set).
 */
export async function evaluateMandate(
  raw: unknown,
  ctx: PolicyContext,
): Promise<PolicyResult> {
  const parsed = IntentMandateSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      reason: "invalid_schema",
      message: parsed.error.message,
    };
  }

  const mandate: IntentMandate = parsed.data;
  const now = ctx.now ?? new Date();
  const allowUnsigned = ctx.allowUnsigned ?? isDevAllowUnsigned();

  if (mandate.revoked === true) {
    return {
      ok: false,
      reason: "revoked",
      message: `mandate ${mandate.id} is revoked`,
    };
  }

  const expiresAt = new Date(mandate.expiresAt);
  if (Number.isNaN(expiresAt.getTime()) || now.getTime() > expiresAt.getTime()) {
    return {
      ok: false,
      reason: "expired",
      message: `mandate ${mandate.id} expired at ${mandate.expiresAt}`,
    };
  }

  let amount: number;
  let maxAmount: number;
  try {
    amount = parseDecimal(ctx.amount);
    maxAmount = parseDecimal(mandate.maxAmount);
  } catch (e) {
    return {
      ok: false,
      reason: "invalid_schema",
      message: e instanceof Error ? e.message : "invalid amount",
    };
  }

  if (amount > maxAmount) {
    return {
      ok: false,
      reason: "amount_exceeded",
      message: `amount ${ctx.amount} exceeds maxAmount ${mandate.maxAmount}`,
    };
  }

  if (!mandate.allowlist || mandate.allowlist.length === 0) {
    return {
      ok: false,
      reason: "merchant_not_allowlisted",
      message: "mandate allowlist is empty (deny)",
    };
  }

  if (!mandate.allowlist.includes(ctx.merchantId)) {
    return {
      ok: false,
      reason: "merchant_not_allowlisted",
      message: `merchant ${ctx.merchantId} not in allowlist`,
    };
  }

  if (ctx.asset !== mandate.asset) {
    return {
      ok: false,
      reason: "asset_mismatch",
      message: `asset ${ctx.asset} does not match mandate asset ${mandate.asset}`,
    };
  }

  const ac2 = await verifyAc2Signature(
    {
      mandate,
      principal: mandate.principal,
      signature: mandate.signature,
    },
    { allowUnsigned },
  );

  if (!ac2.ok) {
    const missing = !mandate.signature;
    return {
      ok: false,
      reason: missing && !allowUnsigned
        ? "unsigned_not_allowed"
        : "ac2_verification_failed",
      message: ac2.message,
    };
  }

  let spendReservationId: string | undefined;
  if (ctx.spend) {
    let amountMicro: bigint;
    try {
      amountMicro = toMicro(ctx.amount);
    } catch (e) {
      return { ok: false, reason: "invalid_schema", message: e instanceof Error ? e.message : "invalid amount" };
    }
    const { caps, store, requireLedger, reservationId } = ctx.spend;
    if (!store && !requireLedger) {
      if (amountMicro > caps.perPaymentMicro) {
        const r = await checkSpendCaps({ payer: mandate.principal, amountMicro, caps, nowMs: now.getTime() });
        if (!r.ok) return r;
      }
    } else {
      const r = await checkSpendCaps({ payer: mandate.principal, amountMicro, caps, store, reservationId, nowMs: now.getTime() });
      if (!r.ok) return r;
      spendReservationId = r.reservationId;
    }
  }

  return spendReservationId ? { ok: true, mandate, spendReservationId } : { ok: true, mandate };
}

export { parseDecimal };
