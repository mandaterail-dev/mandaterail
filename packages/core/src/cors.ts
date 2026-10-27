/**
 * Deny-by-default CORS allowlist helper.
 *
 * CORS_ORIGINS: comma-separated exact origins.
 * Empty / unset → no Access-Control-* headers (localhost SPAs should proxy).
 */

export function parseCorsOrigins(
  raw: string | undefined = process.env.CORS_ORIGINS,
): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

export type CorsHeaderMap = Record<string, string>;

/**
 * Build CORS response headers for a request Origin.
 * Returns null when allowlist is empty or Origin is not allowed
 * (caller should omit CORS headers entirely).
 */
export function buildCorsHeaders(
  requestOrigin: string | undefined | null,
  allowlist: string[] = parseCorsOrigins(),
): CorsHeaderMap | null {
  if (allowlist.length === 0) return null;
  const origin = (requestOrigin ?? "").trim();
  if (!origin || !allowlist.includes(origin)) return null;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type, X-MandateRail-Key, X-MandateRail-Operator-Token, X-MandateRail-Operator-Attestation, X-MandateRail-Requester-Token, X-PAYMENT, X-MandateRail-Mandate",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    Vary: "Origin",
  };
}

/** Apply CORS headers onto a Headers-like / Hono context header setter. */
export function applyCorsHeaders(
  setHeader: (name: string, value: string) => void,
  requestOrigin: string | undefined | null,
  allowlist?: string[],
): boolean {
  const headers = buildCorsHeaders(requestOrigin, allowlist);
  if (!headers) return false;
  for (const [k, v] of Object.entries(headers)) setHeader(k, v);
  return true;
}
