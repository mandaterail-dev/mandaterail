/**
 * Thin Express surface for MandateRail.
 * Prefer @mandaterail/middleware-hono for the full implementation.
 */
export {
  paymentRequiredBody,
  decodeMandateHeader,
  decodePaymentHeader,
  buildPaymentRequirements,
  toAtomicAmount,
  ALGORAND_TESTNET_CAIP2,
  USDC_TESTNET_ASA,
  GOPLAUSIBLE_FEE_PAYER,
  type MandatePaymentConfig,
} from "@mandaterail/middleware-hono";

import type { Request, Response, NextFunction, RequestHandler } from "express";
import { evaluateMandate } from "@mandaterail/core";
import {
  createGoPlausibleClient,
  type GoPlausibleClient,
  type PaymentPayload,
} from "@mandaterail/facilitator-goplausible";
import {
  paymentRequiredBody,
  decodeMandateHeader,
  decodePaymentHeader,
  buildPaymentRequirements,
  spendPolicyFor,
  settleWithReservation,
  settlementErrorBody,
  type MandatePaymentConfig,
} from "@mandaterail/middleware-hono";
import { toMicro } from "@mandaterail/core";
import type { IntentMandate } from "@mandaterail/schema";

export interface ExpressMandateConfig
  extends Omit<MandatePaymentConfig, "loadMandate" | "parsePayment"> {
  loadMandate: (args: {
    mandateId: string | undefined;
    rawHeader: string | undefined;
    req: Request;
  }) => Promise<IntentMandate | unknown | null>;
  parsePayment?: (req: Request) => PaymentPayload | null;
  facilitator?: GoPlausibleClient;
}

/**
 * Express port of mandateRail — policy then GoPlausible verify/settle (fail closed).
 */
export function mandateRailExpress(cfg: ExpressMandateConfig): RequestHandler {
  const facilitator = cfg.facilitator ?? createGoPlausibleClient();
  const {
    loadMandate: _loadMandate,
    parsePayment: _parsePayment,
    facilitator: _facilitator,
    ...baseCfg
  } = cfg;
  const bodyCfg: MandatePaymentConfig = {
    ...baseCfg,
    loadMandate: async () => null,
  };
  const requirements = buildPaymentRequirements(bodyCfg);
  const spend = spendPolicyFor(bodyCfg, requirements.network);
  toMicro(cfg.amount); // fail fast on a malformed price

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const paymentHeader =
        (req.header("x-payment") as string | undefined) ??
        (req.header("X-PAYMENT") as string | undefined);
      const mandateId =
        (req.header("x-mandate-id") as string | undefined) ??
        (req.header("X-MANDATE-ID") as string | undefined);
      const mandateHeader =
        (req.header("x-mandate") as string | undefined) ??
        (req.header("X-MANDATE") as string | undefined);

      if (!paymentHeader) {
        res.status(402).json(paymentRequiredBody(bodyCfg));
        return;
      }

      const fromHeader = decodeMandateHeader(mandateHeader);
      const loaded = await cfg.loadMandate({
        mandateId,
        rawHeader: mandateHeader,
        req,
      });
      const rawMandate = loaded ?? fromHeader;

      if (!rawMandate) {
        res.status(402).json({
          ...paymentRequiredBody(bodyCfg),
          error: "mandate_required",
          message: "X-MANDATE-ID or X-MANDATE required with payment",
        });
        return;
      }

      const policy = await evaluateMandate(rawMandate, {
        amount: cfg.amount,
        asset: cfg.asset,
        merchantId: cfg.merchantId,
        spend,
      });

      if (!policy.ok) {
        res.status(403).json({
          error: "mandate_denied",
          reason: policy.reason,
          message: policy.message,
        });
        return;
      }

      const outcome = await settleWithReservation({
        facilitator,
        paymentPayload: cfg.parsePayment?.(req) ?? decodePaymentHeader(paymentHeader),
        requirements,
        store: spend.store,
        reservationId: policy.spendReservationId,
        settleTimeoutMs: cfg.spend?.settleTimeoutMs,
      });
      if (outcome.kind !== "settled") {
        const e = settlementErrorBody(outcome);
        res.status(e.status).json(e.body);
        return;
      }
      const settled = { data: outcome.data };

      (req as Request & { mandate?: IntentMandate; facilitatorSettle?: unknown }).mandate =
        policy.mandate;
      (req as Request & { facilitatorSettle?: unknown }).facilitatorSettle =
        settled.data;
      next();
    } catch (e) {
      next(e);
    }
  };
}
