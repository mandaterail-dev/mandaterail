import { HttpClient, type ClientOptions } from "../http.js";
import { REQUESTER_AUTH_HEADER, signRequesterRequest, type RequesterSigner } from "../requester.js";
import {
  DEFAULT_AC2_BRIDGE_URL,
  TESTNET_AC2_BRIDGE_URL,
  type OperatorChallenge,
  OPERATOR_TOKEN_HEADER,
  OPERATOR_ATTESTATION_HEADER,
  REQUESTER_TOKEN_HEADER,
  type RequestStatus,
  type ApproveBody,
  type ApproveResult,
  type PairStatus,
  type PendingApproval,
  type RejectResult,
  type SignatureResult,
  type SignPendingResponse,
  type SigningRequest,
} from "../types.js";

export type Ac2BridgeClientOptions = ClientOptions & {
  /**
   * Dev-only OperatorAuth shim (`X-MandateRail-Operator-Token`).
   * Production: device/HSM/vault attestation (see docs/api/auth.md)—not a merchant API key.
   */
  operatorToken?: string;
  /**
   * T9: allowlisted requester key. When set, sign() fetches
   * GET /requester/challenge and sends X-MandateRail-Requester-Auth
   * (required on MainNet; no loopback trust there).
   */
  requester?: RequesterSigner;
};

export type OperatorAuthOption = {
  /** Per-call OperatorAuth override (X-MandateRail-Operator-Token, token-lab). */
  operatorToken?: string;
  /** signed-challenge evidence (X-MandateRail-Operator-Attestation), single-use. */
  operatorAttestation?: string;
};

/**
 * Client for local `ac2-bridge` (default http://127.0.0.1:8790).
 *
 * Approve/reject use **OperatorAuth** (`X-MandateRail-Operator-Token`), never
 * merchant `X-MandateRail-Key`. Agents must not hold payer mnemonics.
 */
export class Ac2BridgeClient {
  private readonly http: HttpClient;
  private readonly operatorToken?: string;
  private readonly requester?: RequesterSigner;

  constructor(
    opts: Ac2BridgeClientOptions = { baseUrl: DEFAULT_AC2_BRIDGE_URL },
  ) {
    const { operatorToken, requester, ...rest } = opts;
    this.operatorToken = operatorToken;
    this.requester = requester;
    this.http = new HttpClient(rest);
  }

  static localhost(
    opts: Omit<Ac2BridgeClientOptions, "baseUrl"> = {},
  ): Ac2BridgeClient {
    return new Ac2BridgeClient({ ...opts, baseUrl: DEFAULT_AC2_BRIDGE_URL });
  }

  /** Live public TestNet bridge (signed-challenge only). */
  static testnet(
    opts: Omit<Ac2BridgeClientOptions, "baseUrl"> = {},
  ): Ac2BridgeClient {
    return new Ac2BridgeClient({ ...opts, baseUrl: TESTNET_AC2_BRIDGE_URL });
  }

  /**
   * GET /operator/challenge — action `list` (id `pending`), `approve` or
   * `reject` (id = pending request id). Sign `message`, then pass the encoded
   * evidence as `operatorAttestation`. Single-use; expires (default 120 s).
   */
  challenge(
    action: "list" | "approve" | "reject",
    id: string,
  ): Promise<OperatorChallenge> {
    return this.http.request<OperatorChallenge>(
      `/operator/challenge?action=${encodeURIComponent(action)}&id=${encodeURIComponent(id)}`,
    );
  }

  private operatorHeaders(opt?: OperatorAuthOption): Record<string, string> {
    const h: Record<string, string> = {};
    if (opt?.operatorAttestation) h[OPERATOR_ATTESTATION_HEADER] = opt.operatorAttestation;
    const token = opt?.operatorToken ?? this.operatorToken;
    if (token) h[OPERATOR_TOKEN_HEADER] = token;
    return h;
  }

  /** GET /requester/challenge — single-use nonce for a requester-signed POST /sign. */
  requesterChallenge(address: string): Promise<{ nonce: string; audience: string; expiresAt: string }> {
    return this.http.request(`/requester/challenge?address=${encodeURIComponent(address)}`);
  }

  /** GET /pair/status */
  pairStatus(): Promise<PairStatus> {
    return this.http.request<PairStatus>("/pair/status");
  }

  /** GET /pending — operator-only (OperatorAuth, action=list). */
  pending(opts?: OperatorAuthOption): Promise<{ pending: PendingApproval[] }> {
    return this.http.request<{ pending: PendingApproval[] }>("/pending", {
      headers: this.operatorHeaders(opts),
    });
  }

  /**
   * GET /requests/{id}/status — requester-scoped status for a queued /sign
   * (OA-N1). Pass the `requesterToken` returned by the 202 from `sign()`.
   */
  requestStatus(id: string, requesterToken: string): Promise<RequestStatus> {
    return this.http.request<RequestStatus>(
      `/requests/${encodeURIComponent(id)}/status`,
      { headers: { [REQUESTER_TOKEN_HEADER]: requesterToken } },
    );
  }

  /**
   * POST /sign — returns SignatureResult (auto-local 200) or pending (202).
   * Manual mode may require OperatorAuth (same header as approve/reject).
   */
  async sign(
    body: SigningRequest,
    opts?: OperatorAuthOption,
  ): Promise<SignatureResult | SignPendingResponse> {
    const headers = this.operatorHeaders(opts);
    const rawBody = JSON.stringify(body);
    if (this.requester) {
      const ch = await this.requesterChallenge(this.requester.address);
      headers[REQUESTER_AUTH_HEADER] = await signRequesterRequest({
        signer: this.requester,
        nonce: ch.nonce,
        audience: ch.audience,
        body: rawBody,
      });
    }
    return this.http.request<SignatureResult | SignPendingResponse>("/sign", {
      method: "POST",
      rawBody,
      headers,
      expectStatus: [200, 202],
    });
  }

  /**
   * POST /approve/{id} — OperatorAuth via optional `operatorToken`.
   */
  approve(
    id: string,
    body?: ApproveBody,
    opts?: OperatorAuthOption,
  ): Promise<ApproveResult> {
    return this.http.request<ApproveResult>(
      `/approve/${encodeURIComponent(id)}`,
      {
        method: "POST",
        body: body ?? {},
        headers: this.operatorHeaders(opts),
      },
    );
  }

  /**
   * POST /reject/{id} — OperatorAuth via optional `operatorToken`.
   */
  reject(id: string, opts?: OperatorAuthOption): Promise<RejectResult> {
    return this.http.request<RejectResult>(
      `/reject/${encodeURIComponent(id)}`,
      {
        method: "POST",
        body: {},
        headers: this.operatorHeaders(opts),
      },
    );
  }
}
