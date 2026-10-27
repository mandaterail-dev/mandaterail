import type { Context, MiddlewareHandler, Next } from "hono";
import algosdk from "algosdk";
import {
  evaluateMandate,
  isMainnetProfile,
  networkProfile,
  resolveSpendCaps,
  toMicro,
  USDC_MAINNET_ASA,
  ALGORAND_MAINNET_CAIP2,
  type SpendCaps,
  type SpendStore,
} from "@mandaterail/core";
import {
  INTENT_MANDATE_VERSION,
  type IntentMandate,
} from "@mandaterail/schema";
import {
  createGoPlausibleClient,
  type GoPlausibleClient,
  type PaymentPayload,
  type PaymentRequirements,
} from "@mandaterail/facilitator-goplausible";

export { ALGORAND_TESTNET_CAIP2, USDC_TESTNET_ASA } from "@mandaterail/core";

/** GoPlausible fee payer (from /supported extra.feePayer). */
export const GOPLAUSIBLE_FEE_PAYER =
  "ZMFK2OI7ZBD2U27ISERZC4S6LKM6WMFJPZQ4MYNJDZ2VNBNMBA67RA22AA";

export interface MandatePaymentConfig {
  merchantId: string;
  /**
   * Human-decimal amount for mandate policy (e.g. "0.01").
   * Converted to atomic for PaymentRequirements using `decimals`.
   */
  amount: string;
  /** Policy asset symbol (e.g. "USDC"). */
  asset: string;
  /** Merchant Algorand address (payTo). */
  payTo: string;
  /** CAIP-2 network. Defaults to Algorand TestNet. */
  network?: string;
  scheme?: string;
  /** ASA id string for PaymentRequirements.asset (default USDC TestNet). */
  assetId?: string;
  /** Token decimals (default 6 for USDC). */
  decimals?: number;
  /** Max payment timeout seconds (default 60). */
  maxTimeoutSeconds?: number;
  /** Fee payer address (default GoPlausible TestNet fee payer). */
  feePayer?: string;
  /** Resolve IntentMandate by id (and optional raw header). */
  loadMandate: (args: {
    mandateId: string | undefined;
    rawHeader: string | undefined;
    c: Context;
  }) => Promise<IntentMandate | unknown | null>;
  /** Optional: override X-PAYMENT parsing */
  parsePayment?: (c: Context) => PaymentPayload | null;
  facilitator?: GoPlausibleClient;
  /**
   * T7 spend caps. `caps` defaults to resolveSpendCaps() (1 / 5 USDC hard
   * maxima). `store` enables the per-day-per-payer cap with a pending
   * reservation written before settle (REQUIRED on MainNet).
   * `settleTimeoutMs` (default 30s): a slower settle is "ambiguous" and stays
   * counted as spent until reconciled against the chain.
   */
  spend?: { caps?: SpendCaps; store?: SpendStore; settleTimeoutMs?: number };
}

/** Policy spend context for a middleware instance. */
export function spendPolicyFor(cfg: MandatePaymentConfig, network: string) {
  const mainnet = network === ALGORAND_MAINNET_CAIP2 || isMainnetProfile();
  const caps = cfg.spend?.caps ?? resolveSpendCaps();
  if (mainnet && !cfg.spend?.store) {
    throw new Error("MainNet requires spend.store (daily cap with pending reservations)");
  }
  return { caps, store: cfg.spend?.store, requireLedger: mainnet };
}

export type SettlementOutcome =
  | { kind: "invalid_payment" }
  | { kind: "verify_failed"; error?: string; status?: number; data?: unknown }
  | { kind: "ambiguous"; message: string; status?: number; data?: unknown }
  | { kind: "reservation_error"; message: string }
  | { kind: "settled"; data: unknown };

class SettleTimeout extends Error {}

/**
 * R18-P3-2: txId of the group's first transaction (paymentGroup[0], a
 * base64 msgpack signed txn). Null if it can't be decoded.
 */
export function paymentGroupFirstTx(p: PaymentPayload | null | undefined): { txId: string; lastValid: number } | null {
  const first = p?.payload?.paymentGroup?.[0];
  if (typeof first !== "string" || !first) return null;
  try {
    const txn = algosdk.decodeSignedTransaction(new Uint8Array(Buffer.from(first, "base64"))).txn;
    return { txId: txn.txID(), lastValid: Number(txn.lastValid) };
  } catch {
    return null;
  }
}
/**
 * v11 (R43 launch blocker): the X-PAYMENT group as canonical concatenated SignedTransactions (kind 'xpayment').
 * Signed members are kept byte-exact; an unsigned member (the fee-payer's, signed later by the facilitator) is
 * wrapped as a SignedTransaction without a signature. Null if any member can't be decoded.
 */
export function xpaymentSignedBytes(p: PaymentPayload | null | undefined): { bytes: Uint8Array; firstValid: number } | null {
  const g = p?.payload?.paymentGroup;
  if (!Array.isArray(g) || g.length < 1 || g.length > 16) return null;
  const parts: Uint8Array[] = [];
  let fv = Number.MAX_SAFE_INTEGER;
  try {
    for (const m of g) {
      if (typeof m !== "string" || !m) return null;
      const raw = new Uint8Array(Buffer.from(m, "base64"));
      let st: algosdk.SignedTransaction;
      try {
        st = algosdk.decodeSignedTransaction(raw);
        const enc = algosdk.encodeMsgpack(st);
        if (!Buffer.from(enc).equals(Buffer.from(raw))) return null; // non-canonical: refuse
        parts.push(raw);
      } catch {
        const txn = algosdk.decodeUnsignedTransaction(raw);
        st = new algosdk.SignedTransaction({ txn });
        parts.push(algosdk.encodeMsgpack(st));
      }
      fv = Math.min(fv, Number(st.txn.firstValid));
    }
  } catch {
    return null;
  }
  const bytes = new Uint8Array(parts.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of parts) { bytes.set(x, o); o += x.length; }
  return { bytes, firstValid: fv };
}
export const paymentGroupFirstTxId = (p: PaymentPayload | null | undefined): string | null => paymentGroupFirstTx(p)?.txId ?? null;

function txIdOf(data: unknown): string | null {
  if (!data || typeof data !== "object") return null;
  const o = data as Record<string, unknown>;
  for (const k of ["transaction", "txId", "txid", "txID"]) if (typeof o[k] === "string" && o[k]) return o[k] as string;
  return null;
}

/**
 * T7-P2-2: verify + settle with the spend reservation finalized around it.
 *  - no payload / verify failed or threw -> released (no money moved)
 *  - settle !ok, threw, or timed out    -> ambiguous (counted until reconciled)
 *  - settle ok                           -> settled (+ txId), BEFORE the handler
 *    runs, so a failing handler or receipt write can't un-count it.
 * If finalize itself fails the row stays `pending`, which also counts.
 */
export async function settleWithReservation(args: {
  facilitator: GoPlausibleClient;
  paymentPayload: PaymentPayload | null;
  requirements: PaymentRequirements;
  store?: SpendStore;
  reservationId?: string;
  settleTimeoutMs?: number;
  now?: () => number;
}): Promise<SettlementOutcome> {
  const now = args.now ?? Date.now;
  const finalize = async (outcome: "settled" | "ambiguous" | "released", txId?: string | null) => {
    if (!args.store || !args.reservationId) return;
    try {
      await args.store.finalize(args.reservationId, outcome, now(), txId ?? null);
    } catch {
      console.error(`[mandaterail] spend reservation ${args.reservationId} finalize(${outcome}) failed; stays pending (counted)`);
    }
  };
  const p = args.paymentPayload;
  if (!p) {
    await finalize("released");
    return { kind: "invalid_payment" };
  }
  let verified: Awaited<ReturnType<GoPlausibleClient["verify"]>>;
  try {
    verified = await args.facilitator.verify({ paymentPayload: p, paymentRequirements: args.requirements, x402Version: p.x402Version ?? 2 });
  } catch (e) {
    await finalize("released");
    return { kind: "verify_failed", error: e instanceof Error ? e.message : "verify threw" };
  }
  if (!verified.ok) {
    await finalize("released");
    return { kind: "verify_failed", error: verified.error, status: verified.status, data: verified.data };
  }
  // R18-P3-2: pin the expected txId on the pending row before settle.
  const first = paymentGroupFirstTx(p);
  let expectedTxId = first?.txId ?? null;
  const signedBytes = args.store?.attachSignedTxn ? xpaymentSignedBytes(p) : null;
  if (args.store?.attachSignedTxn && args.reservationId) {
    // v11: store the exact X-PAYMENT bytes (and the txId/lastValid derived from them) before settle. Fail closed:
    // without stored bytes an ambiguous MainNet spend could never be released (unsigned releases are refused).
    // submit_round = the payment's firstValid: the earliest possible submit round, so lv_est is never early.
    let att: { txId: string; lastValid: number } | null = null;
    let attachErr: string | undefined;
    try {
      att = signedBytes ? await args.store.attachSignedTxn(args.reservationId, { signedTxn: signedBytes.bytes, kind: "xpayment", submitRound: signedBytes.firstValid, nowMs: now() }) : null;
    } catch (e) {
      // R44-P3: keep the failure context (class + SQLSTATE / message head), never the signed bytes
      const err = e as { name?: string; code?: string; message?: string };
      attachErr = `${err.name ?? "Error"}${err.code ? ` ${err.code}` : ""}: ${String(err.message ?? "").slice(0, 160)}`;
      att = null;
    }
    if (!att) {
      console.error(`[mandaterail] spend reservation ${args.reservationId}: attachSignedTxn failed (${attachErr ?? "no row / not pending"}); settle aborted (fail closed)`);
      await finalize("released");
      return { kind: "reservation_error", message: "could not record the signed payment before settle; nothing was settled, retry later" };
    }
    expectedTxId = att.txId;
  } else if (first && args.store && args.reservationId) {
    // R19-P3-4: fail closed. Settle has not been called yet, so no money can
    // have moved: release the reservation and refuse rather than settle a
    // payment that reconcile could not later prove on chain.
    let pinned = false;
    try {
      pinned = (await args.store.attachTxId(args.reservationId, first.txId, now(), first.lastValid)) === true;
    } catch {
      pinned = false;
    }
    if (!pinned) {
      console.error(`[mandaterail] spend reservation ${args.reservationId}: attachTxId failed; settle aborted (fail closed)`);
      await finalize("released");
      return { kind: "reservation_error", message: "could not record the payment txId before settle; nothing was settled, retry later" };
    }
  }
  const ms = args.settleTimeoutMs ?? 30_000;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const settled = await Promise.race([
      args.facilitator.settle({ paymentPayload: p, paymentRequirements: args.requirements, x402Version: p.x402Version ?? 2 }),
      new Promise<never>((_, rej) => {
        timer = setTimeout(() => rej(new SettleTimeout(`settle timed out after ${ms}ms`)), ms);
      }),
    ]);
    if (!settled.ok) {
      await finalize("ambiguous", expectedTxId);
      return { kind: "ambiguous", message: settled.error ?? "settle failed", status: settled.status, data: settled.data };
    }
    await finalize("settled", txIdOf(settled.data) ?? expectedTxId);
    return { kind: "settled", data: settled.data };
  } catch (e) {
    await finalize("ambiguous", expectedTxId);
    return { kind: "ambiguous", message: e instanceof SettleTimeout ? e.message : "settle threw" };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** HTTP mapping shared by the Hono and Express adapters. */
export function settlementErrorBody(o: Exclude<SettlementOutcome, { kind: "settled" }>): { status: 400 | 402 | 502 | 503; body: Record<string, unknown> } {
  switch (o.kind) {
    case "invalid_payment":
      return { status: 400, body: { error: "invalid_payment_header", message: "X-PAYMENT must be base64 JSON or raw JSON PaymentPayload" } };
    case "verify_failed":
      return { status: 402, body: { error: "facilitator_verify_failed", message: o.error, status: o.status, data: o.data } };
    case "reservation_error":
      return { status: 503, body: { error: "spend_ledger_unavailable", message: o.message } };
    case "ambiguous":
      // Fail closed — never fake settle; the amount stays counted until reconciled.
      return { status: 502, body: { error: "facilitator_settle_failed", message: o.message, status: o.status, data: o.data, spend: "ambiguous_until_reconciled" } };
  }
}

export function decodeMandateHeader(raw: string | undefined): unknown | null {
  if (!raw) return null;
  try {
    if (raw.trim().startsWith("{")) return JSON.parse(raw);
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
    const json = Buffer.from(b64, "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/** Convert human decimal string to atomic units string. */
export function toAtomicAmount(human: string, decimals: number): string {
  const neg = human.trim().startsWith("-");
  const s = neg ? human.trim().slice(1) : human.trim();
  const [wholeRaw, fracRaw = ""] = s.split(".");
  const whole = wholeRaw === "" ? "0" : wholeRaw;
  if (!/^\d+$/.test(whole) || !/^\d*$/.test(fracRaw)) {
    throw new Error(`invalid decimal amount: ${human}`);
  }
  if (fracRaw.length > decimals) {
    throw new Error(
      `amount ${human} has more than ${decimals} decimal places`,
    );
  }
  const frac = fracRaw.padEnd(decimals, "0");
  const atomic =
    BigInt(whole) * BigInt(10 ** decimals) + BigInt(frac || "0");
  return (neg ? "-" : "") + atomic.toString();
}

/** Build PaymentRequirements for GoPlausible / x402 exact on Algorand. */
export function buildPaymentRequirements(
  cfg: MandatePaymentConfig,
): PaymentRequirements {
  const decimals = cfg.decimals ?? 6;
  const amountAtomic = toAtomicAmount(cfg.amount, decimals);
  // T5: chain + USDC ASA from networkProfile() unless set explicitly.
  const profile = cfg.network && cfg.assetId ? null : networkProfile();
  const network = cfg.network ?? profile!.caip2;
  const asset = cfg.assetId ?? profile!.usdcAsaId;
  if (network === ALGORAND_MAINNET_CAIP2) {
    if (asset !== USDC_MAINNET_ASA) {
      throw new Error(`MainNet payment asset must be USDC ${USDC_MAINNET_ASA} (got ${asset})`);
    }
    if (!cfg.feePayer && !process.env.FEE_PAYER) {
      throw new Error("MainNet requires an explicit FEE_PAYER (no TestNet default)");
    }
  }
  return {
    scheme: cfg.scheme ?? "exact",
    network,
    asset,
    amount: amountAtomic,
    payTo: cfg.payTo,
    maxTimeoutSeconds: cfg.maxTimeoutSeconds ?? 60,
    extra: {
      feePayer:
        cfg.feePayer ?? process.env.FEE_PAYER ?? GOPLAUSIBLE_FEE_PAYER,
      decimals,
    },
  };
}

/**
 * Build 402 Payment Required JSON with payment requirements + mandate extras.
 */
export function paymentRequiredBody(cfg: MandatePaymentConfig) {
  const requirements = buildPaymentRequirements(cfg);
  return {
    error: "payment_required" as const,
    accepts: [requirements],
    payment: {
      scheme: requirements.scheme,
      network: requirements.network,
      amount: requirements.amount,
      asset: requirements.asset,
      payTo: requirements.payTo,
      maxTimeoutSeconds: requirements.maxTimeoutSeconds,
      extra: requirements.extra,
    },
    mandate: {
      required: true,
      accept: [INTENT_MANDATE_VERSION],
      hints: {
        merchantId: cfg.merchantId,
        maxAmountSuggested: cfg.amount,
        asset: cfg.asset,
      },
    },
  };
}

/**
 * Decode X-PAYMENT header: base64 JSON or raw JSON PaymentPayload.
 */
export function decodePaymentHeader(
  raw: string | undefined,
): PaymentPayload | null {
  if (!raw) return null;
  try {
    let json: string;
    if (raw.trim().startsWith("{")) {
      json = raw.trim();
    } else {
      const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
      json = Buffer.from(b64, "base64").toString("utf8");
    }
    const parsed = JSON.parse(json) as PaymentPayload;
    if (
      !parsed ||
      typeof parsed !== "object" ||
      !parsed.payload ||
      !Array.isArray(parsed.payload.paymentGroup)
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Hono middleware: unpaid → 402 with PaymentRequirements + mandate extras;
 * paid path → mandate policy (ed25519) then GoPlausible verify/settle (fail closed).
 */
export function mandateRail(cfg: MandatePaymentConfig): MiddlewareHandler {
  const facilitator = cfg.facilitator ?? createGoPlausibleClient();
  const requirements = buildPaymentRequirements(cfg);
  const spend = spendPolicyFor(cfg, requirements.network);
  toMicro(cfg.amount); // fail fast on a malformed price

  return async (c: Context, next: Next) => {
    const paymentHeader =
      c.req.header("x-payment") ??
      c.req.header("X-PAYMENT") ??
      c.req.header("PAYMENT-SIGNATURE");
    const mandateId =
      c.req.header("x-mandate-id") ?? c.req.header("X-MANDATE-ID");
    const mandateHeader =
      c.req.header("x-mandate") ?? c.req.header("X-MANDATE");

    if (!paymentHeader) {
      return c.json(paymentRequiredBody(cfg), 402);
    }

    const fromHeader = decodeMandateHeader(mandateHeader);
    const loaded = await cfg.loadMandate({
      mandateId,
      rawHeader: mandateHeader,
      c,
    });
    const rawMandate = loaded ?? fromHeader;

    if (!rawMandate) {
      return c.json(
        {
          ...paymentRequiredBody(cfg),
          error: "mandate_required",
          message: "X-MANDATE-ID or X-MANDATE required with payment",
        },
        402,
      );
    }

    // Policy uses human-decimal amount + symbol asset
    const policy = await evaluateMandate(rawMandate, {
      amount: cfg.amount,
      asset: cfg.asset,
      merchantId: cfg.merchantId,
      spend,
    });

    if (!policy.ok) {
      return c.json(
        {
          error: "mandate_denied",
          reason: policy.reason,
          message: policy.message,
        },
        403,
      );
    }

    const outcome = await settleWithReservation({
      facilitator,
      paymentPayload: cfg.parsePayment?.(c) ?? decodePaymentHeader(paymentHeader),
      requirements,
      store: spend.store,
      reservationId: policy.spendReservationId,
      settleTimeoutMs: cfg.spend?.settleTimeoutMs,
    });
    if (outcome.kind !== "settled") {
      const e = settlementErrorBody(outcome);
      return c.json(e.body, e.status);
    }
    const settled = { data: outcome.data };

    c.set("mandate", policy.mandate);
    c.set("facilitatorSettle", settled.data);
    c.set("paymentRequirements", requirements);
    await next();
  };
}
