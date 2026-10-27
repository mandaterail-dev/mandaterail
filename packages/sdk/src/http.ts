import type { ApiError } from "./types.js";
import { API_KEY_HEADER } from "./types.js";

export class MandateRailHttpError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(message: string, status: number, body: unknown) {
    super(message);
    this.name = "MandateRailHttpError";
    this.status = status;
    this.body = body;
  }
}

export type ClientOptions = {
  /** Service base URL (no trailing slash required). */
  baseUrl: string;
  /** Optional fetch (tests / custom agents). */
  fetch?: typeof fetch;
  /** Optional merchant API key → X-MandateRail-Key. */
  apiKey?: string;
  /** Default headers merged into every request. */
  headers?: Record<string, string>;
};

export type RequestOptions = {
  method?: string;
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  /** Send this exact string as the body (no JSON.stringify); for signed bodies. */
  rawBody?: string;
  headers?: Record<string, string>;
  /** When set, expects this HTTP status (default: 2xx). */
  expectStatus?: number | number[];
};

function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

function withQuery(
  url: string,
  query?: RequestOptions["query"],
): string {
  if (!query) return url;
  const u = new URL(url);
  for (const [k, v] of Object.entries(query)) {
    if (v === undefined || v === null) continue;
    u.searchParams.set(k, String(v));
  }
  return u.toString();
}

export class HttpClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly apiKey?: string;
  private readonly defaultHeaders: Record<string, string>;

  constructor(opts: ClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.fetchImpl = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.apiKey = opts.apiKey;
    this.defaultHeaders = { ...(opts.headers ?? {}) };
  }

  async request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const method = opts.method ?? (opts.body !== undefined || opts.rawBody !== undefined ? "POST" : "GET");
    const url = withQuery(joinUrl(this.baseUrl, path), opts.query);
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.defaultHeaders,
      ...(opts.headers ?? {}),
    };
    if (this.apiKey && !headers[API_KEY_HEADER]) {
      headers[API_KEY_HEADER] = this.apiKey;
    }
    let body: string | undefined;
    if (opts.body !== undefined) {
      headers["content-type"] = headers["content-type"] ?? "application/json";
      body = JSON.stringify(opts.body);
    }
    if (opts.rawBody !== undefined) {
      headers["content-type"] = headers["content-type"] ?? "application/json";
      body = opts.rawBody;
    }

    const res = await this.fetchImpl(url, { method, headers, body });
    const text = await res.text();
    let data: unknown = null;
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }

    const expected = opts.expectStatus;
    const ok = expected
      ? Array.isArray(expected)
        ? expected.includes(res.status)
        : res.status === expected
      : res.ok;

    if (!ok) {
      const errObj = data as ApiError | null;
      const detail =
        errObj && typeof errObj === "object"
          ? String(errObj.message ?? errObj.error ?? text.slice(0, 200))
          : text.slice(0, 200);
      throw new MandateRailHttpError(
        `HTTP ${res.status} ${method} ${path}: ${detail}`,
        res.status,
        data,
      );
    }
    return data as T;
  }
}
