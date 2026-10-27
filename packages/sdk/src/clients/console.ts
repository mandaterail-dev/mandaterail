import { HttpClient, type ClientOptions } from "../http.js";
import {
  DEFAULT_CONSOLE_URL,
  OPERATOR_ATTESTATION_HEADER,
  type IntentMandate,
  type IntentMandateCreate,
} from "../types.js";
import { TESTNET_CONSOLE_URL } from "../types.js";

export type ConsoleClientOptions = ClientOptions;

/** Console challenge actions (audience `mandaterail-console`). */
export type ConsoleOperatorAction =
  | "mandate.create"
  | "mandate.revoke"
  | "mandate.read"
  | "mandate.list";

export type ConsoleOperatorChallenge = {
  nonce: string;
  action: ConsoleOperatorAction;
  subjectId: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  message: string;
};

/** Per-call signed-challenge evidence (X-MandateRail-Operator-Attestation). */
export type ConsoleAuthOption = { operatorAttestation?: string };

/**
 * Client for the console mandate store (default http://127.0.0.1:8788).
 *
 * Hosted (signed-challenge): every /mandates call needs a single-use
 * attestation: `challenge(action, id)` → sign `message` with an allowlisted
 * operator key → pass base64(JSON evidence) as `operatorAttestation`.
 * Local-only mode: direct loopback callers only. Not a multi-tenant product
 * API; TestNet only; NOT audited.
 */
export class ConsoleClient {
  private readonly http: HttpClient;

  constructor(opts: ConsoleClientOptions = { baseUrl: DEFAULT_CONSOLE_URL }) {
    this.http = new HttpClient(opts);
  }

  /** DEV ONLY helper targeting 127.0.0.1:8788 */
  /** Live public TestNet host. TestNet only, not audited. */
  static testnet(opts: Omit<ConsoleClientOptions, "baseUrl"> = {}): ConsoleClient {
    return new ConsoleClient({ ...opts, baseUrl: TESTNET_CONSOLE_URL });
  }

  static localhost(
    opts: Omit<ConsoleClientOptions, "baseUrl"> = {},
  ): ConsoleClient {
    return new ConsoleClient({ ...opts, baseUrl: DEFAULT_CONSOLE_URL });
  }

  private authHeaders(opts?: ConsoleAuthOption): Record<string, string> {
    return opts?.operatorAttestation
      ? { [OPERATOR_ATTESTATION_HEADER]: opts.operatorAttestation }
      : {};
  }

  /** GET /operator/challenge — id is the mandate id, or "mandates" for list. */
  challenge(action: ConsoleOperatorAction, id: string): Promise<ConsoleOperatorChallenge> {
    return this.http.request<ConsoleOperatorChallenge>(
      `/operator/challenge?action=${encodeURIComponent(action)}&id=${encodeURIComponent(id)}`,
    );
  }

  /** GET /mandates — action mandate.list, id "mandates" */
  listMandates(opts?: ConsoleAuthOption): Promise<{ items: IntentMandate[] }> {
    return this.http.request<{ items: IntentMandate[] }>("/mandates", {
      headers: this.authHeaders(opts),
    });
  }

  /** GET /mandates/{mandateId} — action mandate.read */
  getMandate(mandateId: string, opts?: ConsoleAuthOption): Promise<IntentMandate> {
    return this.http.request<IntentMandate>(
      `/mandates/${encodeURIComponent(mandateId)}`,
      { headers: this.authHeaders(opts) },
    );
  }

  /**
   * POST /mandates — action mandate.create bound to `body.id` (required in
   * signed-challenge mode). Unsigned bodies are stored as unsigned-draft.
   */
  createMandate(body: IntentMandateCreate, opts?: ConsoleAuthOption): Promise<IntentMandate> {
    return this.http.request<IntentMandate>("/mandates", {
      method: "POST",
      body,
      headers: this.authHeaders(opts),
      expectStatus: 201,
    });
  }

  /** POST /mandates/{mandateId}/revoke — action mandate.revoke */
  revokeMandate(mandateId: string, opts?: ConsoleAuthOption): Promise<IntentMandate> {
    return this.http.request<IntentMandate>(
      `/mandates/${encodeURIComponent(mandateId)}/revoke`,
      { method: "POST", body: {}, headers: this.authHeaders(opts) },
    );
  }
}
