/**
 * GoPlausible facilitator HTTP client.
 * Calls /verify and /settle only — does not vendor or clone GoPlausible.
 * Default base: https://facilitator.goplausible.xyz (TestNet + MainNet).
 * Fail closed: never invent a settle success.
 */

export const DEFAULT_FACILITATOR_BASE_URL =
  "https://facilitator.goplausible.xyz";

/** @deprecated Use DEFAULT_FACILITATOR_BASE_URL */
export const DEFAULT_TESTNET_BASE_URL = DEFAULT_FACILITATOR_BASE_URL;

export interface GoPlausibleClientOptions {
  /** Facilitator base URL. Defaults to GoPlausible public facilitator. */
  baseUrl?: string;
  /** Optional fetch implementation (for tests). */
  fetch?: typeof fetch;
  /** Request timeout ms (default 30_000). */
  timeoutMs?: number;
}

/** Decoded X-PAYMENT / payment payload (x402 v2). */
export type PaymentPayload = {
  x402Version: number;
  scheme: string;
  network: string;
  payload: {
    paymentGroup: string[];
    paymentIndex: number;
  };
  [key: string]: unknown;
};

/** Payment requirements advertised in 402 / sent to facilitator. */
export type PaymentRequirements = {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
  [key: string]: unknown;
};

export type FacilitatorRequestBody = {
  x402Version?: number;
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
};

export type FacilitatorResult<T = unknown> =
  | { ok: true; status: number; data: T }
  | { ok: false; status: number; error: string; data?: unknown };

export type VerifyResultData = {
  isValid?: boolean;
  invalidReason?: string | null;
  [key: string]: unknown;
};

export type SettleResultData = {
  success?: boolean;
  transaction?: string;
  network?: string;
  errorReason?: string | null;
  [key: string]: unknown;
};

export class GoPlausibleClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: GoPlausibleClientOptions = {}) {
    this.baseUrl = (
      opts.baseUrl ??
      process.env.GOPLAUSIBLE_BASE_URL ??
      DEFAULT_FACILITATOR_BASE_URL
    ).replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /**
   * POST /verify with OpenAPI body:
   * { x402Version?, paymentPayload, paymentRequirements }
   */
  async verify(
    body: FacilitatorRequestBody,
  ): Promise<FacilitatorResult<VerifyResultData>> {
    const result = await this.post<VerifyResultData>("/verify", {
      x402Version: body.x402Version ?? body.paymentPayload.x402Version ?? 2,
      paymentPayload: body.paymentPayload,
      paymentRequirements: body.paymentRequirements,
    });
    if (!result.ok) return result;
    if (result.data && result.data.isValid === false) {
      return {
        ok: false,
        status: result.status,
        error:
          typeof result.data.invalidReason === "string" &&
          result.data.invalidReason
            ? result.data.invalidReason
            : "facilitator verify returned isValid=false",
        data: result.data,
      };
    }
    return result;
  }

  /**
   * POST /settle — NEVER returns a synthetic / fake settle receipt.
   */
  async settle(
    body: FacilitatorRequestBody,
  ): Promise<FacilitatorResult<SettleResultData>> {
    const result = await this.post<SettleResultData>("/settle", {
      x402Version: body.x402Version ?? body.paymentPayload.x402Version ?? 2,
      paymentPayload: body.paymentPayload,
      paymentRequirements: body.paymentRequirements,
    });
    if (!result.ok) return result;
    if (result.data && result.data.success === false) {
      return {
        ok: false,
        status: result.status,
        error:
          typeof result.data.errorReason === "string" && result.data.errorReason
            ? result.data.errorReason
            : "facilitator settle returned success=false",
        data: result.data,
      };
    }
    return result;
  }

  async supported(): Promise<FacilitatorResult> {
    const url = `${this.baseUrl}/supported`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(url, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: controller.signal,
      });
      const text = await res.text();
      let data: unknown;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        return {
          ok: false,
          status: res.status,
          error: "facilitator /supported returned non-JSON body",
          data: text.slice(0, 200),
        };
      }
      if (!res.ok) {
        return {
          ok: false,
          status: res.status,
          error: `facilitator /supported HTTP ${res.status}`,
          data,
        };
      }
      return { ok: true, status: res.status, data };
    } catch (e) {
      const message =
        e instanceof Error ? e.message : "unknown facilitator network error";
      return { ok: false, status: 0, error: message };
    } finally {
      clearTimeout(timer);
    }
  }

  private async post<T = unknown>(
    path: string,
    body: Record<string, unknown>,
  ): Promise<FacilitatorResult<T>> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      let data: unknown;
      const text = await res.text();
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        return {
          ok: false,
          status: res.status,
          error: `facilitator ${path} returned non-JSON body`,
          data: text.slice(0, 200),
        };
      }

      if (!res.ok) {
        return {
          ok: false,
          status: res.status,
          error: `facilitator ${path} HTTP ${res.status}`,
          data,
        };
      }

      return { ok: true, status: res.status, data: data as T };
    } catch (e) {
      const message =
        e instanceof Error ? e.message : "unknown facilitator network error";
      return { ok: false, status: 0, error: message };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function createGoPlausibleClient(
  opts?: GoPlausibleClientOptions,
): GoPlausibleClient {
  return new GoPlausibleClient(opts);
}
