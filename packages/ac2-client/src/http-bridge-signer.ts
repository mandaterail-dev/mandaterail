import { canonicalMandateBytes, REQUESTER_AUTH_HEADER, signRequesterRequest, stableStringify } from "@mandaterail/core";
import type {
  Ac2SignResult,
  Ac2Signer,
  SigningRequest,
  UnsignedIntentMandate,
} from "./types.js";

export interface HttpAc2BridgeSignerOptions {
  /** Base URL of the AC2 bridge (e.g. http://127.0.0.1:8790). */
  baseUrl: string;
  /** Optional fetch (tests). */
  fetch?: typeof fetch;
  /** Poll / wait timeout for pending phone approval (ms). Default 120_000. */
  timeoutMs?: number;
  /** Prefer raw-ed25519 (default) or message-algorand. */
  sigHint?: SigningRequest["sig_hint"];
  /** Status poll interval (ms). Default 500. */
  pollIntervalMs?: number;
  /**
   * T9: allowlisted requester key (REQUESTER_ALLOWLIST on the bridge). When
   * set, each /sign is preceded by GET /requester/challenge and carries
   * X-MandateRail-Requester-Auth. Required on MainNet.
   */
  requester?: { address: string; sk: Uint8Array };
}

/** Requester token header for GET /requests/{id}/status (OA-N1). */
export const REQUESTER_TOKEN_HEADER = "x-mandaterail-requester-token";

/**
 * POSTs a SigningRequest to AC2_BRIDGE_URL and waits for a signature.
 *
 * The bridge is filled by:
 * - OpenClaw `ac2_sign` tool after `openclaw ac2 pair`, or
 * - apps/ac2-bridge (auto-local for CI, or pending+approve for phone).
 *
 * Expected response shapes (any one):
 * - { signature, publicKey?, address? }
 * - { result: { signature, publicKey?, address? } }
 * - { id, requesterToken } (202) then poll GET /requests/{id}/status with
 *   X-MandateRail-Requester-Token until approved / rejected (OA-N1). GET
 *   /pending is operator-only and is never polled by agents.
 */
export class HttpAc2BridgeSigner implements Ac2Signer {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly sigHint: SigningRequest["sig_hint"];
  private readonly pollIntervalMs: number;
  private readonly requester?: { address: string; sk: Uint8Array };

  constructor(opts: HttpAc2BridgeSignerOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.timeoutMs = opts.timeoutMs ?? 120_000;
    this.sigHint = opts.sigHint ?? "raw-ed25519";
    this.pollIntervalMs = opts.pollIntervalMs ?? 500;
    this.requester = opts.requester;
  }

  static fromEnv(env: NodeJS.ProcessEnv = process.env): HttpAc2BridgeSigner {
    const baseUrl = env.AC2_BRIDGE_URL;
    if (!baseUrl) {
      throw new Error("AC2_BRIDGE_URL is required for HttpAc2BridgeSigner");
    }
    return new HttpAc2BridgeSigner({ baseUrl });
  }

  buildSigningRequest(unsigned: UnsignedIntentMandate): SigningRequest {
    const bytes = canonicalMandateBytes(unsigned);
    const message = new TextDecoder().decode(bytes);
    const m = unsigned as { id?: string; principal?: string };
    return {
      type: "IntentMandate/v1",
      sig_hint: this.sigHint,
      display_hint: "json",
      message,
      message_b64: Buffer.from(bytes).toString("base64"),
      mandateId: typeof m.id === "string" ? m.id : undefined,
      principal: typeof m.principal === "string" ? m.principal : undefined,
    };
  }

  async signIntentMandate(
    unsigned: UnsignedIntentMandate,
  ): Promise<Ac2SignResult> {
    const request = this.buildSigningRequest(unsigned);
    // Ensure message matches stable stringify of unsigned (sans signature).
    void stableStringify(unsigned);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const bodyStr = JSON.stringify(request);
      const headers: Record<string, string> = {
        "content-type": "application/json",
        accept: "application/json",
      };
      if (this.requester) {
        headers[REQUESTER_AUTH_HEADER] = await this.requesterAuth(bodyStr, controller.signal);
      }
      const res = await this.fetchImpl(`${this.baseUrl}/sign`, {
        method: "POST",
        headers,
        body: bodyStr,
        signal: controller.signal,
      });
      const text = await res.text();
      let data: unknown;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        throw new Error(
          `AC2 bridge /sign returned non-JSON (HTTP ${res.status})`,
        );
      }
      if (!res.ok) {
        throw new Error(
          `AC2 bridge /sign HTTP ${res.status}: ${typeof data === "object" && data && "error" in data ? String((data as { error: unknown }).error) : text.slice(0, 200)}`,
        );
      }
      return await this.resolveSignResult(data, controller.signal);
    } finally {
      clearTimeout(timer);
    }
  }

  private async requesterAuth(body: string, signal: AbortSignal): Promise<string> {
    const r = this.requester!;
    const res = await this.fetchImpl(
      `${this.baseUrl}/requester/challenge?address=${encodeURIComponent(r.address)}`,
      { method: "GET", headers: { accept: "application/json" }, signal },
    );
    if (!res.ok) throw new Error(`AC2 bridge /requester/challenge HTTP ${res.status}`);
    const ch = (await res.json()) as { nonce?: unknown; audience?: unknown };
    if (typeof ch.nonce !== "string" || typeof ch.audience !== "string") {
      throw new Error("AC2 bridge /requester/challenge returned no nonce/audience");
    }
    return signRequesterRequest({ sk: r.sk, address: r.address, nonce: ch.nonce, audience: ch.audience, body });
  }

  private async resolveSignResult(
    data: unknown,
    signal: AbortSignal,
  ): Promise<Ac2SignResult> {
    const direct = normalizeSignResult(data);
    if (direct) return direct;

    // Pending approval flow: { id, status: "pending" }
    const id =
      data &&
      typeof data === "object" &&
      typeof (data as { id?: unknown }).id === "string"
        ? (data as { id: string }).id
        : null;
    if (!id) {
      throw new Error(
        "AC2 bridge /sign response missing signature and pending id",
      );
    }

    const requesterToken =
      typeof (data as { requesterToken?: unknown }).requesterToken === "string"
        ? (data as { requesterToken: string }).requesterToken
        : undefined;
    const headers: Record<string, string> = { accept: "application/json" };
    if (requesterToken) headers[REQUESTER_TOKEN_HEADER] = requesterToken;
    const statusUrl = `${this.baseUrl}/requests/${encodeURIComponent(id)}/status`;

    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      if (signal.aborted) throw new Error("AC2 bridge sign aborted");
      const res = await this.fetchImpl(statusUrl, { method: "GET", headers, signal });
      if (res.status === 401 || res.status === 403 || res.status === 404) {
        throw new Error(
          `AC2 bridge status HTTP ${res.status} for id=${id} (requester token missing or invalid)`,
        );
      }
      if (res.ok) {
        const item = (await res.json()) as {
          status?: string;
          signature?: string;
          publicKey?: string;
          address?: string;
          result?: Ac2SignResult;
        };
        if (item.status === "rejected" || item.status === "expired") {
          throw new Error(`AC2 bridge request id=${id} was ${item.status} (not approved)`);
        }
        const done = normalizeSignResult(item) ?? normalizeSignResult(item.result);
        if (done && done.signature) return done;
      }
      await sleep(this.pollIntervalMs, signal);
    }
    throw new Error(`AC2 bridge sign timed out waiting for approval id=${id}`);
  }
}

function normalizeSignResult(data: unknown): Ac2SignResult | null {
  if (!data || typeof data !== "object") return null;
  const o = data as Record<string, unknown>;
  if (o.result && typeof o.result === "object") {
    return normalizeSignResult(o.result);
  }
  if (typeof o.signature === "string" && o.signature.length > 0) {
    return {
      signature: o.signature,
      publicKey: typeof o.publicKey === "string" ? o.publicKey : "",
      address: typeof o.address === "string" ? o.address : undefined,
    };
  }
  return null;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("aborted"));
      return;
    }
    const t = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        reject(new Error("aborted"));
      },
      { once: true },
    );
  });
}
