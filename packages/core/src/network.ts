/**
 * T5: one place that maps NETWORK to the chain + USDC ASA + explorer.
 * Fails closed on anything ambiguous so a MainNet process can never quote
 * the TestNet ASA (or the reverse).
 */
import {
  ALGORAND_MAINNET_CAIP2,
  ALGORAND_TESTNET_CAIP2,
  isNetworkMainnetIsh,
  isNetworkTestnet,
} from "./insecure-dev.js";

export const USDC_TESTNET_ASA = "10458941";
export const USDC_MAINNET_ASA = "31566704";

export interface NetworkProfile {
  name: "testnet" | "mainnet";
  caip2: string;
  usdcAsaId: string;
  /** Base URL; append `/<txId>`. */
  explorerTxBase: string;
  isMainnet: boolean;
  /**
   * R25-P2-1: chain providers a manual-release proof may come from. Each
   * host maps to an operator id; the two observations must come from two
   * DIFFERENT operator ids on this list. The DB holds the same list
   * (mr_network_provider, seeded by migrate) and enforces it itself.
   */
  providerAllowlist: ReadonlyArray<ChainProviderAllowEntry>;
}

/** R25-P2-1: one allowlisted chain provider host (no port, lower case) and the operator that runs it. */
export interface ChainProviderAllowEntry {
  host: string;
  operator: string;
}

/**
 * Nodely runs the algonode.cloud endpoints too: on both networks this is ONE
 * operator. A release proof therefore needs a second operator (e.g. a future
 * own node, operator id "own-node") added here AND in mr_network_provider.
 */
export const TESTNET_PROVIDER_ALLOWLIST: ReadonlyArray<ChainProviderAllowEntry> = Object.freeze([
  { host: "testnet-idx.algonode.cloud", operator: "nodely" },
  { host: "testnet-api.algonode.cloud", operator: "nodely" },
  { host: "testnet-idx.4160.nodely.dev", operator: "nodely" },
  { host: "testnet-api.4160.nodely.dev", operator: "nodely" },
]);
export const MAINNET_PROVIDER_ALLOWLIST: ReadonlyArray<ChainProviderAllowEntry> = Object.freeze([
  { host: "mainnet-idx.algonode.cloud", operator: "nodely" },
  { host: "mainnet-api.algonode.cloud", operator: "nodely" },
  { host: "mainnet-idx.4160.nodely.dev", operator: "nodely" },
  { host: "mainnet-api.4160.nodely.dev", operator: "nodely" },
  // Operator 2 (the owner, Oct 19 2026): GetBlock shared EU algod. algod-only (no
  // indexer), token in the URL path; pair it with a Nodely indexer.
  { host: "shared.eu-central-1.getblock.io", operator: "getblock" },
  // Operator 3 (the owner, Oct 20 2026; NOT USED: paid, the owner rejected it Oct 20 — kept for a future paid setup): Blockdaemon API Suite, algod at /algorand/mainnet/native and indexer at
  // /algorand/mainnet/native/indexer on ONE multi-chain host. Key in the X-API-Key header (BLOCKDAEMON_API_KEY),
  // never in the URL. The v12 co-signer (verifier) pins this operator so it is independent of the signer's two.
  { host: "svc.blockdaemon.com", operator: "blockdaemon" },
  // Operator 4 (the owner, Oct 21 2026; replaces Blockdaemon, which is paid): dRPC free public algod. No key, no
  // indexer, /v2/blocks/{r}/txids is paid-only, so the co-signer uses the blockscan-full probe (msgpack blocks,
  // txids computed locally). dRPC aggregates node providers: accepted risk (docs/ops/mainnet-provider-drpc.md).
  { host: "algorand.drpc.org", operator: "drpc" },
]);

/** R54-P3-4: hosts whose credential is a URL path segment (the whole URL is then a secret). */
export const PATH_TOKEN_PROVIDER_HOSTS: ReadonlyArray<string> = Object.freeze(["shared.eu-central-1.getblock.io"]);

/**
 * R54-P3-1/2: a URL path segment that looks like a credential (>= 20 chars of [A-Za-z0-9_-] with a digit
 * and a letter, not kebab-case words, e.g. GetBlock's 32-hex token). Plain words like "health" or "indexer" never match.
 */
export function isTokenLikePathSegment(seg: string): boolean {
  if (!/^[A-Za-z0-9_-]{20,}$/.test(seg) || !/[0-9]/.test(seg) || !/[A-Za-z]/.test(seg)) return false;
  // kebab-case words ("mainnet-v1-indexer-health") are route names, not credentials
  return !/^[a-z]+[0-9]*(-[a-z]+[0-9]*)+$/.test(seg);
}

/** True when the URL carries a credential in its path (a path-token provider host or a token-like segment). */
export function urlHasPathToken(url: string): boolean {
  let u: URL;
  try { u = new URL(url); } catch { return false; }
  const segs = u.pathname.split("/").filter(Boolean);
  if (PATH_TOKEN_PROVIDER_HOSTS.includes(normalizeProviderHost(u.hostname)) && segs.length > 0) return true;
  return segs.some((x) => isTokenLikePathSegment(decodeURIComponent(x)));
}

/** Hosts whose API key goes in the X-API-Key header (not the algod/indexer token headers, never the URL). */
export const X_API_KEY_PROVIDER_HOSTS: ReadonlyArray<string> = Object.freeze(["svc.blockdaemon.com"]);

/** Run 55 note: an X-API-Key host (Blockdaemon) without a key is refused up front, naming the env var (never the value). */
export function requireProviderKey(url: string | undefined, token: string | undefined, envName: string): void {
  if (!url) return;
  let host = "";
  try { host = normalizeProviderHost(new URL(url).hostname); } catch { return; }
  if (X_API_KEY_PROVIDER_HOSTS.includes(host) && !(token ?? "").trim()) {
    throw new Error(`${envName} is required for ${host} (sent as X-API-Key); set it to the Blockdaemon API key`);
  }
}

/**
 * R54 / Blockdaemon: the auth header for a chain provider. Blockdaemon wants X-API-Key; algod / indexer
 * (Nodely, own nodes) keep X-Algo-API-Token / X-Indexer-API-Token. No token = no header.
 */
export function providerAuthHeaders(url: string, kind: "indexer" | "algod", token: string | undefined): Record<string, string> {
  if (!token) return {};
  let host = "";
  try { host = normalizeProviderHost(new URL(url).hostname); } catch { /* caller validates the URL */ }
  if (X_API_KEY_PROVIDER_HOSTS.includes(host)) return { "X-API-Key": token };
  return kind === "indexer" ? { "X-Indexer-API-Token": token } : { "X-Algo-API-Token": token };
}

/**
 * R26-P3-4: canonical provider host: lower case, IPv6 brackets and a port
 * removed, one trailing dot stripped. Every allowlist comparison uses this.
 */
export function normalizeProviderHost(host: string): string {
  let h = String(host).trim().toLowerCase();
  if (h.startsWith("[")) h = h.replace(/^\[([^\]]*)\](:\d+)?$/, "$1");
  else if ((h.match(/:/g) ?? []).length === 1) h = h.replace(/:\d*$/, "");
  return h.replace(/\.$/, "");
}

/** R26-P3-4: suffixes that are never public chain providers. */
export const FORBIDDEN_PROVIDER_SUFFIXES = ["localhost", "invalid", "local", "internal", "home.arpa"] as const;

/**
 * R25-P2-1 / R26-P3-4: loopback, localhost, .invalid / .localhost / .local /
 * .internal / .home.arpa, and every IP form (dotted, decimal 2130706433, hex
 * 0x7f000001, octal 0177.0.0.1, mixed, IPv6, a numeric last label) are never
 * chain providers. Same rule as the DB function mr_provider_host_refused.
 */
export function isForbiddenProviderHost(host: string): boolean {
  const h = normalizeProviderHost(host);
  if (!h || h.length > 253) return true;
  if (h.includes(":") || h.includes("[") || h.includes("]")) return true; // IPv6
  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(h) || h.includes("..")) return true;
  for (const s of FORBIDDEN_PROVIDER_SUFFIXES) if (h === s || h.endsWith(`.${s}`)) return true;
  const labels = h.split(".");
  // any label that is a number in any base, or a numeric last label (WHATWG parses those as IPv4)
  const numeric = (l: string) => /^(0x[0-9a-f]*|[0-9]+)$/.test(l);
  if (labels.every(numeric) || numeric(labels[labels.length - 1]!)) return true;
  return false;
}

export const TESTNET_PROFILE: NetworkProfile = Object.freeze({
  name: "testnet",
  caip2: ALGORAND_TESTNET_CAIP2,
  usdcAsaId: USDC_TESTNET_ASA,
  explorerTxBase: "https://explore.algokit.io/testnet/transaction",
  isMainnet: false,
  providerAllowlist: TESTNET_PROVIDER_ALLOWLIST,
});

export const MAINNET_PROFILE: NetworkProfile = Object.freeze({
  name: "mainnet",
  caip2: ALGORAND_MAINNET_CAIP2,
  usdcAsaId: USDC_MAINNET_ASA,
  explorerTxBase: "https://explore.algokit.io/mainnet/transaction",
  isMainnet: true,
  providerAllowlist: MAINNET_PROVIDER_ALLOWLIST,
});

export class NetworkProfileError extends Error {}

type Env = Record<string, string | undefined>;

/**
 * Resolve the profile from env:
 * - NETWORK unset / TestNet CAIP-2 / "testnet" -> TestNet (Phase-1 default).
 *   USDC_ASA_ID may override the ASA on TestNet only (lab tokens).
 * - NETWORK MainNet CAIP-2 / "mainnet" -> MainNet USDC 31566704. A
 *   different USDC_ASA_ID is refused.
 * - ALLOW_MAINNET=1 with a non-MainNet NETWORK, or an unknown NETWORK -> throws.
 */
export function networkProfile(env: Env = process.env): NetworkProfile {
  const raw = (env.NETWORK ?? "").trim();
  const flag = env.ALLOW_MAINNET ?? "";
  const allowMainnetFlag = flag === "1" || flag.toLowerCase() === "true" || flag === "yes";
  const asaOverride = env.USDC_ASA_ID?.trim() || undefined;

  if (isNetworkMainnetIsh(raw)) {
    if (raw !== ALGORAND_MAINNET_CAIP2 && raw.toLowerCase() !== "mainnet") {
      throw new NetworkProfileError(`NETWORK=${raw} is not a recognised MainNet id (use "mainnet" or ${ALGORAND_MAINNET_CAIP2})`);
    }
    if (asaOverride && asaOverride !== USDC_MAINNET_ASA) {
      throw new NetworkProfileError(`USDC_ASA_ID=${asaOverride} refused on MainNet (USDC is ${USDC_MAINNET_ASA})`);
    }
    return MAINNET_PROFILE;
  }
  if (allowMainnetFlag) {
    throw new NetworkProfileError("ALLOW_MAINNET is set but NETWORK is not MainNet; refusing ambiguous profile");
  }
  if (raw && !isNetworkTestnet(raw)) {
    throw new NetworkProfileError(`unknown NETWORK=${raw}`);
  }
  if (raw && raw !== ALGORAND_TESTNET_CAIP2 && raw.toLowerCase() !== "testnet") {
    throw new NetworkProfileError(`NETWORK=${raw} is not a recognised TestNet id (use "testnet" or ${ALGORAND_TESTNET_CAIP2})`);
  }
  if (asaOverride === USDC_MAINNET_ASA) {
    throw new NetworkProfileError(`USDC_ASA_ID=${USDC_MAINNET_ASA} is MainNet USDC; refused on TestNet`);
  }
  return asaOverride ? { ...TESTNET_PROFILE, usdcAsaId: asaOverride } : TESTNET_PROFILE;
}
