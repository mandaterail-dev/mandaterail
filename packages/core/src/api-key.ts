/**
 * Merchant API key prefix validation (runtime).
 *
 * Contract (docs/api/auth.md, OpenAPI ApiKeyAuth):
 * - `mr_test_` — TestNet / lab only
 * - `mr_live_` — MainNet only, and only when MainNet is explicitly enabled
 *
 * Demo apps may run without a key; when `X-MandateRail-Key` is present,
 * the prefix MUST match the configured network.
 */

import {
  envFlagTrue,
  isNetworkTestnet,
  ALGORAND_MAINNET_CAIP2,
} from "./insecure-dev.js";

export { ALGORAND_MAINNET_CAIP2 };

export const API_KEY_HEADER = "x-mandaterail-key";
export const API_KEY_PREFIX_TESTNET = "mr_test_";
export const API_KEY_PREFIX_MAINNET = "mr_live_";

/**
 * MainNet is never the default. Explicit enablement requires NETWORK to
 * indicate MainNet (CAIP-2 or substring) AND `ALLOW_MAINNET=1`.
 */
export function isNetworkMainnetExplicit(
  network = process.env.NETWORK,
): boolean {
  if (!envFlagTrue("ALLOW_MAINNET")) return false;
  const n = (network ?? "").trim();
  if (!n) return false;
  if (n === ALGORAND_MAINNET_CAIP2) return true;
  const lower = n.toLowerCase();
  if (lower.includes("mainnet")) return true;
  if (n.includes("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8")) return true;
  return false;
}

export type ApiKeyNetworkMode = "testnet" | "mainnet";

export function resolveApiKeyNetworkMode(
  network = process.env.NETWORK,
): ApiKeyNetworkMode {
  if (isNetworkMainnetExplicit(network)) return "mainnet";
  // Default / TestNet lab profile — including unset NETWORK for demos
  return "testnet";
}

export type ApiKeyPrefixResult =
  | { ok: true; mode: ApiKeyNetworkMode; prefix: string }
  | { ok: false; status: 401; error: string; message: string };

/**
 * Validate merchant API key prefix against the active network mode.
 * Empty/missing keys are not validated here — callers decide whether a key
 * is required for a given route.
 */
export function validateMerchantApiKeyPrefix(
  apiKey: string,
  opts?: { network?: string },
): ApiKeyPrefixResult {
  const key = (apiKey ?? "").trim();
  const mode = resolveApiKeyNetworkMode(opts?.network);
  const expected =
    mode === "mainnet" ? API_KEY_PREFIX_MAINNET : API_KEY_PREFIX_TESTNET;

  if (!key) {
    return {
      ok: false,
      status: 401,
      error: "invalid_api_key",
      message: "Merchant API key is empty",
    };
  }

  if (mode === "testnet" && key.startsWith(API_KEY_PREFIX_MAINNET)) {
    return {
      ok: false,
      status: 401,
      error: "api_key_network_mismatch",
      message:
        "mr_live_ keys require MainNet explicitly enabled (ALLOW_MAINNET=1 and MainNet NETWORK); TestNet rejects mr_live_",
    };
  }

  if (mode === "mainnet" && key.startsWith(API_KEY_PREFIX_TESTNET)) {
    return {
      ok: false,
      status: 401,
      error: "api_key_network_mismatch",
      message: "mr_test_ keys are TestNet/lab only; MainNet requires mr_live_",
    };
  }

  if (!key.startsWith(expected)) {
    return {
      ok: false,
      status: 401,
      error: "invalid_api_key_prefix",
      message: `Merchant API key must start with ${expected} for ${mode}`,
    };
  }

  // Soft consistency check: TestNet mode should also look like TestNet when NETWORK set
  if (
    mode === "testnet" &&
    opts?.network &&
    !isNetworkTestnet(opts.network) &&
    !isNetworkMainnetExplicit(opts.network)
  ) {
    // NETWORK set but neither testnet nor explicit mainnet — still enforce mr_test_
  }

  return { ok: true, mode, prefix: expected };
}
