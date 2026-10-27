import { HttpClient, type ClientOptions } from "../http.js";
import {
  DEFAULT_DEMO_API_URL,
  type HealthStatus,
  type Receipt,
} from "../types.js";
import { TESTNET_DEMO_API_URL } from "../types.js";

export type DemoApiClientOptions = ClientOptions;

/**
 * Client for local `demo-api` (default http://127.0.0.1:8787).
 * TestNet / DEV localhost trust — not a hosted production API.
 */
export class DemoApiClient {
  private readonly http: HttpClient;

  constructor(opts: DemoApiClientOptions = { baseUrl: DEFAULT_DEMO_API_URL }) {
    this.http = new HttpClient(opts);
  }

  /** Live public TestNet host. TestNet only, not audited. */
  static testnet(opts: Omit<DemoApiClientOptions, "baseUrl"> = {}): DemoApiClient {
    return new DemoApiClient({ ...opts, baseUrl: TESTNET_DEMO_API_URL });
  }

  static localhost(opts: Omit<DemoApiClientOptions, "baseUrl"> = {}): DemoApiClient {
    return new DemoApiClient({ ...opts, baseUrl: DEFAULT_DEMO_API_URL });
  }

  /** GET /health */
  health(): Promise<HealthStatus> {
    return this.http.request<HealthStatus>("/health");
  }

  /** GET /receipts?limit= */
  listReceipts(limit = 50): Promise<{ receipts: Receipt[] }> {
    return this.http.request<{ receipts: Receipt[] }>("/receipts", {
      query: { limit },
    });
  }

  /** GET /receipts/{receiptId} */
  getReceipt(receiptId: string): Promise<Receipt> {
    return this.http.request<Receipt>(
      `/receipts/${encodeURIComponent(receiptId)}`,
    );
  }
}
