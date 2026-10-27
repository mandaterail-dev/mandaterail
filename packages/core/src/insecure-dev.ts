/**
 * Insecure-dev / CI footguns — hard-fail outside explicit TestNet lab profiles.
 * Not a production hardening claim; only a config-drift brake.
 */

import {
  parseOperatorAllowlist,
  resolveOperatorAttestationMode,
} from "./operator-challenge.js";

/** Algorand TestNet CAIP-2 (GoPlausible /supported). */
export const ALGORAND_TESTNET_CAIP2 =
  "algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=";

/** Algorand MainNet CAIP-2 genesis marker (common demo / explorer form). */
export const ALGORAND_MAINNET_CAIP2 =
  "algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=";

export function envFlagTrue(name: string): boolean {
  const v = process.env[name];
  if (v === undefined || v === "") return false;
  return v === "1" || v.toLowerCase() === "true" || v === "yes";
}

export function isAllowInsecureDev(): boolean {
  return envFlagTrue("ALLOW_INSECURE_DEV");
}

export function isAllowMainnet(): boolean {
  return envFlagTrue("ALLOW_MAINNET");
}

export function isAc2BridgeAutoLocal(): boolean {
  return envFlagTrue("AC2_BRIDGE_AUTO_LOCAL");
}

/** True when NETWORK env looks like Algorand TestNet (not MainNet). */
export function isNetworkTestnet(network = process.env.NETWORK): boolean {
  const n = (network ?? "").trim();
  if (!n) return false;
  if (n === ALGORAND_TESTNET_CAIP2) return true;
  const lower = n.toLowerCase();
  if (lower.includes("testnet")) return true;
  // CAIP-2 TestNet genesis marker used across MandateRail demos
  if (n.includes("SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9")) return true;
  return false;
}

/**
 * True when NETWORK looks like MainNet (CAIP-2 / substring), regardless of
 * ALLOW_MAINNET. Used for operator-gate startup checks.
 */
export function isNetworkMainnetIsh(network = process.env.NETWORK): boolean {
  const n = (network ?? "").trim();
  if (!n) return false;
  if (n === ALGORAND_MAINNET_CAIP2) return true;
  const lower = n.toLowerCase();
  if (lower.includes("mainnet")) return true;
  if (n.includes("wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8")) return true;
  return false;
}

/**
 * MainNet-ish profile: MainNet NETWORK **or** ALLOW_MAINNET=1.
 * Either way, operator token must be set at process start and loopback
 * tokenless bypass is forbidden.
 */
export function isMainnetProfile(network = process.env.NETWORK): boolean {
  return isAllowMainnet() || isNetworkMainnetIsh(network);
}

/**
 * Insecure lab flags that require an explicit TestNet lab profile.
 * Includes ALLOW_INSECURE_DEV itself — setting it outside TestNet is refused.
 */
export function listEnabledInsecureFlags(): string[] {
  const flags: string[] = [];
  if (isAc2BridgeAutoLocal()) flags.push("AC2_BRIDGE_AUTO_LOCAL");
  if (envFlagTrue("DEV_ALLOW_UNSIGNED")) flags.push("DEV_ALLOW_UNSIGNED");
  if (isAllowInsecureDev()) flags.push("ALLOW_INSECURE_DEV");
  return flags;
}

export type InsecureDevCheck =
  | { ok: true; flags: string[]; warned: boolean }
  | { ok: false; flags: string[]; reason: string };

/**
 * Non-exit helper for tests / callers that prefer structured results.
 * If insecure flags are on: require ALLOW_INSECURE_DEV=1 and TestNet NETWORK.
 */
export function checkInsecureDev(): InsecureDevCheck {
  const flags = listEnabledInsecureFlags();
  if (flags.length === 0) return { ok: true, flags: [], warned: false };

  const allow = isAllowInsecureDev();
  const testnet = isNetworkTestnet();
  if (!allow || !testnet) {
    const parts: string[] = [];
    if (!allow) {
      parts.push("set ALLOW_INSECURE_DEV=1 (explicit lab/CI consent)");
    }
    if (!testnet) {
      parts.push(
        "set NETWORK to Algorand TestNet CAIP-2 (or a value containing 'testnet')",
      );
    }
    return {
      ok: false,
      flags,
      reason: `insecure flag(s) enabled (${flags.join(
        ", ",
      )}) without a valid TestNet lab profile. Required: ${parts.join("; ")}.`,
    };
  }

  return { ok: true, flags, warned: true };
}

/**
 * Call once at process start for demo-api / ac2-bridge.
 * If insecure flags are on: require ALLOW_INSECURE_DEV=1 and TestNet NETWORK,
 * else process.exit(1). Logs a single warning when flags are enabled under a
 * valid lab profile.
 */
export function assertInsecureDevOrExit(service: string): void {
  const result = checkInsecureDev();
  if (!result.ok) {
    console.error(`[${service}] REFUSING TO START: ${result.reason}`);
    console.error(
      `[${service}] These flags must never ship outside explicit CI/dev. See docs/security/02-remediation-status.md.`,
    );
    process.exit(1);
  }

  if (result.warned) {
    console.warn(
      `[${service}] WARNING: insecure lab flags enabled: ${result.flags.join(
        ", ",
      )}. ALLOW_INSECURE_DEV=1 + TestNet NETWORK only. Not production.`,
    );
  }
}

export type OperatorGateCheck =
  | { ok: true }
  | { ok: false; reason: string };

/** Allowed range for OPERATOR_CHALLENGE_TTL_MS (P2-B). */
export const MIN_CHALLENGE_TTL_MS = 10_000;
export const MAX_CHALLENGE_TTL_MS = 600_000;

/**
 * Parse OPERATOR_CHALLENGE_TTL_MS. Unset/empty -> 120000. Returns null when
 * not a finite integer in [10s, 600s] (callers refuse start).
 */
export function parseChallengeTtlMs(
  raw = process.env.OPERATOR_CHALLENGE_TTL_MS,
): number | null {
  const v = (raw ?? "").trim();
  if (!v) return 120_000;
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < MIN_CHALLENGE_TTL_MS || n > MAX_CHALLENGE_TTL_MS) return null;
  return n;
}

/** Challenge store cap and post-expiry grace (see OperatorChallengeStore). */
export const CHALLENGE_STORE_MAX_ENTRIES = 10_000;
export const CHALLENGE_SWEEP_GRACE_MS = 60_000;
export const CHALLENGE_RATE_WINDOW_MS = 60_000;
/** OA-P2-G clamps. Cap math: MAX_GLOBAL * (ceil((MAX_TTL+GRACE)/WINDOW)+1) < store cap. */
export const MAX_CHALLENGE_RATE_PER_IP = 120;
export const MAX_CHALLENGE_RATE_GLOBAL = 800;
export const MAX_TRUSTED_PROXY_HOPS = 5;

/** Worst-case live challenge entries for a given global rate and TTL. */
export function maxLiveChallenges(globalPerWindow: number, ttlMs: number): number {
  return globalPerWindow * (Math.ceil((ttlMs + CHALLENGE_SWEEP_GRACE_MS) / CHALLENGE_RATE_WINDOW_MS) + 1);
}

function parseBoundedInt(raw: string | undefined, def: number, min: number, max: number): number | null {
  const v = (raw ?? "").trim();
  if (!v) return def;
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < min || n > max) return null;
  return n;
}

/**
 * OPERATOR_CHALLENGE_RATE_PER_IP (default 30, 1..120) and
 * OPERATOR_CHALLENGE_RATE_GLOBAL (default 600, 1..800), per rolling 60s.
 * null = invalid (refuse start). perIp must be <= global.
 */
export function parseChallengeRateLimits(
  env: NodeJS.ProcessEnv = process.env,
): { perIp: number; global: number } | null {
  const perIp = parseBoundedInt(env.OPERATOR_CHALLENGE_RATE_PER_IP, 30, 1, MAX_CHALLENGE_RATE_PER_IP);
  const global = parseBoundedInt(env.OPERATOR_CHALLENGE_RATE_GLOBAL, 600, 1, MAX_CHALLENGE_RATE_GLOBAL);
  if (perIp === null || global === null || perIp > global) return null;
  return { perIp, global };
}

/**
 * OA-P2-I ac2-bridge queue limits (all clamped; null = refuse start):
 * - AC2_BRIDGE_MAX_PENDING (default 1000, 1..10000): max queued + retained items
 * - AC2_BRIDGE_PENDING_TTL_MS (default 900000, 60000..86400000): pending -> expired
 * - AC2_BRIDGE_RETENTION_MS (default 600000, 60000..86400000): finalized items
 *   (approved/rejected/expired) and their requester-token hashes are evicted after this
 * - AC2_BRIDGE_MAX_PENDING_PER_CLIENT (default 50, 1..10000, <= max): pending items per client key
 * - AC2_BRIDGE_SIGN_RATE_PER_MIN (default 60, 1..600): POST /sign global, rolling 60 s
 * - AC2_BRIDGE_SIGN_RATE_PER_CLIENT (default 10, 1..600, <= global): POST /sign per client
 */
export function parseBridgeQueueLimits(env: NodeJS.ProcessEnv = process.env): {
  maxPending: number;
  pendingTtlMs: number;
  retentionMs: number;
  signRatePerMin: number;
  signRatePerClient: number;
  maxPendingPerClient: number;
} | null {
  const maxPending = parseBoundedInt(env.AC2_BRIDGE_MAX_PENDING, 1000, 1, 10_000);
  const pendingTtlMs = parseBoundedInt(env.AC2_BRIDGE_PENDING_TTL_MS, 900_000, 60_000, 86_400_000);
  const retentionMs = parseBoundedInt(env.AC2_BRIDGE_RETENTION_MS, 600_000, 60_000, 86_400_000);
  const signRatePerMin = parseBoundedInt(env.AC2_BRIDGE_SIGN_RATE_PER_MIN, 60, 1, 600);
  const signRatePerClient = parseBoundedInt(env.AC2_BRIDGE_SIGN_RATE_PER_CLIENT, 10, 1, 600);
  const maxPendingPerClient = parseBoundedInt(env.AC2_BRIDGE_MAX_PENDING_PER_CLIENT, 50, 1, 10_000);
  if (
    maxPending === null || pendingTtlMs === null || retentionMs === null || signRatePerMin === null ||
    signRatePerClient === null || maxPendingPerClient === null
  ) return null;
  // Per-client limits must not exceed the global ones (OA-P2-M / OA-P2-N).
  if (signRatePerClient > signRatePerMin || maxPendingPerClient > maxPending) return null;
  return { maxPending, pendingTtlMs, retentionMs, signRatePerMin, signRatePerClient, maxPendingPerClient };
}

/**
 * Console limits (all clamped; null = refuse start):
 * - CONSOLE_RATE_PER_IP (default 30, 1..120) / CONSOLE_RATE_GLOBAL (default 300,
 *   1..800, >= per-IP): all /operator/challenge + /mandates requests, rolling 60 s
 * - CONSOLE_MAX_BODY_BYTES (default 16384, 1024..65536)
 * - CONSOLE_MAX_MANDATES (default 1000, 1..10000): store cap
 */
export function parseConsoleLimits(env: NodeJS.ProcessEnv = process.env): {
  ratePerIp: number;
  rateGlobal: number;
  maxBodyBytes: number;
  maxMandates: number;
} | null {
  const ratePerIp = parseBoundedInt(env.CONSOLE_RATE_PER_IP, 30, 1, MAX_CHALLENGE_RATE_PER_IP);
  const rateGlobal = parseBoundedInt(env.CONSOLE_RATE_GLOBAL, 300, 1, MAX_CHALLENGE_RATE_GLOBAL);
  const maxBodyBytes = parseBoundedInt(env.CONSOLE_MAX_BODY_BYTES, 16_384, 1024, 65_536);
  const maxMandates = parseBoundedInt(env.CONSOLE_MAX_MANDATES, 1000, 1, 10_000);
  if (ratePerIp === null || rateGlobal === null || maxBodyBytes === null || maxMandates === null) return null;
  if (ratePerIp > rateGlobal) return null;
  return { ratePerIp, rateGlobal, maxBodyBytes, maxMandates };
}

/**
 * AC2_BRIDGE_TRUSTED_PROXY_HOPS (default 0 = off, max 5). When > 0 the
 * rate-limit client key is taken from X-Forwarded-For, `hops` entries from
 * the right. Never used for loopback/auth decisions.
 */
export function parseTrustedProxyHops(raw = process.env.AC2_BRIDGE_TRUSTED_PROXY_HOPS): number | null {
  return parseBoundedInt(raw, 0, 0, MAX_TRUSTED_PROXY_HOPS);
}

function isIPv4Loopback(a: string): boolean {
  const m = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(a);
  return !!m && m.slice(1).every((o) => Number(o) <= 255);
}

/**
 * OA-P2-H strict loopback check for hosts / remote addresses:
 * 'localhost', IPv4 127.0.0.0/8, ::1, ::ffff:127.x.y.z (brackets allowed).
 * Hostnames such as 127.example.com are NOT loopback.
 */
export function isLoopbackHost(h: string | undefined | null): boolean {
  if (!h) return false;
  let a = h.trim().toLowerCase();
  if (a.startsWith("[") && a.endsWith("]")) a = a.slice(1, -1);
  if (a === "localhost" || a === "::1" || a === "0:0:0:0:0:0:0:1") return true;
  if (isIPv4Loopback(a)) return true;
  if (a.startsWith("::ffff:")) return isIPv4Loopback(a.slice(7));
  return false;
}


/**
 * Startup gate. `bindHost` defaults to AC2_BRIDGE_HOST (or 127.0.0.1).
 * P1-A: signed-challenge on a MainNet profile or a non-loopback bind
 * requires OPERATOR_SIGNDATA_DOMAIN (ARC-60 origin / rpIdHash binding).
 */
/**
 * Non-exit helper: MainNet-ish / ALLOW_MAINNET=1 requires
 * OPERATOR_ATTESTATION_MODE=signed-challenge (default on MainNet) with a
 * non-empty OPERATOR_ALLOWLIST. `token-lab` (shared secret) is refused.
 * Any profile: signed-challenge requires a non-empty allowlist; unknown modes refuse.
 */
export function checkOperatorGate(
  opts: { bindHost?: string } = {},
): OperatorGateCheck {
  const mainnet = isMainnetProfile();
  const mode = resolveOperatorAttestationMode(mainnet);
  if (mode === null) {
    return {
      ok: false,
      reason: `OPERATOR_ATTESTATION_MODE='${process.env.OPERATOR_ATTESTATION_MODE}' is invalid (use signed-challenge | token-lab).`,
    };
  }
  if (parseBridgeQueueLimits() === null) {
    return {
      ok: false,
      reason:
        "AC2_BRIDGE_MAX_PENDING (1..10000), AC2_BRIDGE_PENDING_TTL_MS / AC2_BRIDGE_RETENTION_MS (60000..86400000) and AC2_BRIDGE_SIGN_RATE_PER_MIN / _PER_CLIENT (1..600, per-client <= global) and AC2_BRIDGE_MAX_PENDING_PER_CLIENT (<= AC2_BRIDGE_MAX_PENDING) must be integers in range.",
    };
  }
  const hops = parseTrustedProxyHops();
  if (hops === null) {
    return {
      ok: false,
      reason: `AC2_BRIDGE_TRUSTED_PROXY_HOPS must be an integer 0..${MAX_TRUSTED_PROXY_HOPS}.`,
    };
  }
  if (hops > 0 && isAc2BridgeAutoLocal()) {
    // OA-P2-R: auto-local signs without any operator; never behind a proxy.
    return {
      ok: false,
      reason: "AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0 refuses AC2_BRIDGE_AUTO_LOCAL (auto-signing must never be proxied / tunneled).",
    };
  }
  if (hops > 0) {
    // OA-P1-O: behind a proxy/tunnel nothing is local; demand real auth.
    if (!(process.env.OPERATOR_SIGNDATA_DOMAIN ?? "").trim()) {
      return {
        ok: false,
        reason: "AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0 (proxied / tunneled) requires OPERATOR_SIGNDATA_DOMAIN.",
      };
    }
    if (mode === "token-lab" && !(process.env.AC2_OPERATOR_TOKEN ?? "")) {
      return {
        ok: false,
        reason: "AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0 refuses tokenless token-lab: set AC2_OPERATOR_TOKEN (never tunnel tokenless lab).",
      };
    }
  }
  if (mainnet && mode !== "signed-challenge") {
    return {
      ok: false,
      reason:
        "MainNet profile (MainNet NETWORK or ALLOW_MAINNET=1) refuses OPERATOR_ATTESTATION_MODE=token-lab; use signed-challenge with OPERATOR_ALLOWLIST.",
    };
  }
  if (mode === "signed-challenge" && parseOperatorAllowlist().length === 0) {
    return {
      ok: false,
      reason:
        "OPERATOR_ATTESTATION_MODE=signed-challenge requires OPERATOR_ALLOWLIST (comma-separated valid Algorand addresses).",
    };
  }
  if (mode === "signed-challenge") {
    const bindHost = opts.bindHost ?? process.env.AC2_BRIDGE_HOST ?? "127.0.0.1";
    const domain = (process.env.OPERATOR_SIGNDATA_DOMAIN ?? "").trim();
    // OA-P2-Q: required for EVERY signed-challenge deployment (any network,
    // bind or hops); ARC-60 evidence must always be origin-bound.
    if (!domain) {
      return {
        ok: false,
        reason: `OPERATOR_SIGNDATA_DOMAIN is required for every signed-challenge deployment (bind=${bindHost}); ARC-60 evidence must be origin-bound.`,
      };
    }
    if (parseChallengeRateLimits() === null) {
      return {
        ok: false,
        reason: `OPERATOR_CHALLENGE_RATE_PER_IP / OPERATOR_CHALLENGE_RATE_GLOBAL must be integers (per-IP 1..${MAX_CHALLENGE_RATE_PER_IP}, global 1..${MAX_CHALLENGE_RATE_GLOBAL}, per-IP <= global).`,
      };
    }
    if (parseTrustedProxyHops() === null) {
      return {
        ok: false,
        reason: `AC2_BRIDGE_TRUSTED_PROXY_HOPS must be an integer 0..${MAX_TRUSTED_PROXY_HOPS}.`,
      };
    }
    if (parseChallengeTtlMs() === null) {
      return {
        ok: false,
        reason: `OPERATOR_CHALLENGE_TTL_MS='${process.env.OPERATOR_CHALLENGE_TTL_MS}' must be an integer between ${MIN_CHALLENGE_TTL_MS} and ${MAX_CHALLENGE_TTL_MS}.`,
      };
    }
  }
  return { ok: true };
}

/**
 * Call once at process start (same sites as assertInsecureDevOrExit).
 * Refuses start when MainNet-ish without AC2_OPERATOR_TOKEN.
 */
export function assertOperatorGateOrExit(service: string): void {
  const result = checkOperatorGate();
  if (!result.ok) {
    console.error(`[${service}] REFUSING TO START: ${result.reason}`);
    console.error(
      `[${service}] Set OPERATOR_ATTESTATION_MODE=signed-challenge + OPERATOR_ALLOWLIST before enabling MainNet / ALLOW_MAINNET. See docs/security/02-remediation-status.md.`,
    );
    process.exit(1);
  }
}

/** Loopback remote address check (IPv4 / IPv6 / mapped). */
export function isLoopbackAddress(addr: string | undefined | null): boolean {
  return isLoopbackHost(addr);
}

/** Headers set by tunnels / reverse proxies (OA-P1-O). */
export const PROXY_FORWARDING_HEADERS = [
  "x-forwarded-for",
  "forwarded",
  "cf-connecting-ip",
  "x-real-ip",
  "true-client-ip",
  "x-forwarded-host",
  "x-forwarded-proto",
  "via",
  "x-client-ip",
  "fastly-client-ip",
] as const;

/**
 * OA-P1-O: the single helper for every localhost-trust decision.
 * A request is local only if the socket peer is loopback AND no trusted
 * proxy hops are configured AND no forwarding header is present. A tunnel
 * or reverse proxy on the same host (e.g. cloudflared) makes internet
 * traffic arrive from 127.0.0.1, so loopback alone is never enough.
 * Proxies that add no header (raw TCP / ssh -R) cannot be detected:
 * never tunnel a bridge that relies on localhost trust.
 */
export function isTrustedLocalRequest(opts: {
  remoteAddress: string | undefined | null;
  header: (name: string) => string | undefined | null;
  trustedProxyHops?: number;
}): boolean {
  // T9: no localhost trust on MainNet, anywhere (every caller goes through here).
  if (isMainnetProfile()) return false;
  const hops = opts.trustedProxyHops ?? parseTrustedProxyHops() ?? 1;
  if (hops > 0) return false;
  for (const h of PROXY_FORWARDING_HEADERS) {
    const v = opts.header(h);
    if (v !== undefined && v !== null) return false;
  }
  return isLoopbackHost(opts.remoteAddress);
}

/** OA-P3-P: every 127.0.0.0/8 / ::1 / ::ffff:127.x peer shares one key. */
export function normalizeClientKey(addr: string | undefined | null): string {
  if (!addr) return "unknown";
  return isLoopbackHost(addr) ? "loopback" : addr.trim().toLowerCase();
}

export const OPERATOR_TOKEN_HEADER = "x-mandaterail-operator-token";

/**
 * Operator gate for AC2 approve/reject (and manual /sign).
 * - If AC2_OPERATOR_TOKEN is set: header must match (constant-time-ish).
 * - If unset: allow ONLY when remote is loopback AND ALLOW_INSECURE_DEV=1
 *   AND NETWORK is TestNet AND ALLOW_MAINNET is not set.
 */
export function authorizeOperator(opts: {
  headerToken: string | undefined | null;
  remoteAddress: string | undefined | null;
  /**
   * Result of isTrustedLocalRequest (OA-P1-O). When omitted, only a bare
   * loopback peer with no trusted proxy hops counts as local (no header view).
   */
  isLocal?: boolean;
}): { ok: true } | { ok: false; status: 401; error: string; message: string } {
  // token-lab is never valid on a MainNet profile (signed-challenge only).
  if (isMainnetProfile()) {
    return {
      ok: false,
      status: 401,
      error: "unauthorized",
      message:
        "MainNet profile refuses token-lab OperatorAuth; use signed-challenge (X-MandateRail-Operator-Attestation)",
    };
  }
  const expected = process.env.AC2_OPERATOR_TOKEN;
  if (expected !== undefined && expected !== "") {
    const got = opts.headerToken ?? "";
    if (!tokensEqual(got, expected)) {
      return {
        ok: false,
        status: 401,
        error: "unauthorized",
        message:
          "X-MandateRail-Operator-Token required and must match AC2_OPERATOR_TOKEN",
      };
    }
    return { ok: true };
  }

  // Tokenless lab bypass: loopback + ALLOW_INSECURE_DEV + TestNet only.
  // Never when ALLOW_MAINNET=1 or MainNet NETWORK.
  const local =
    opts.isLocal ??
    ((parseTrustedProxyHops() ?? 1) === 0 && isLoopbackAddress(opts.remoteAddress));
  if (
    local &&
    isAllowInsecureDev() &&
    isNetworkTestnet() &&
    !isAllowMainnet() &&
    !isNetworkMainnetIsh()
  ) {
    return { ok: true };
  }

  return {
    ok: false,
    status: 401,
    error: "unauthorized",
    message:
      "AC2_OPERATOR_TOKEN unset: operator routes allowed only from loopback with ALLOW_INSECURE_DEV=1 and TestNet NETWORK (not ALLOW_MAINNET / MainNet)",
  };
}

function tokensEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // still walk to reduce trivial timing leaks on length
    let x = 0;
    for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i);
    for (let i = 0; i < b.length; i++) x |= b.charCodeAt(i);
    return x === -1; // always false
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * T6/T9 MainNet startup gate. On a MainNet profile refuses:
 *  - dev/lab switches: ALLOW_INSECURE_DEV, AC2_BRIDGE_AUTO_LOCAL,
 *    DEV_ALLOW_UNSIGNED, DEMO_MOCK_FACILITATOR, OPERATOR_ATTESTATION_MODE=token-lab,
 *    AC2_OPERATOR_TOKEN (token-lab secret)
 *  - any *MNEMONIC* variable (no signing keys in services)
 *  - STATE_BACKEND unset/memory (persistent backend required)
 * and requires FEE_PAYER (payment services) and REQUESTER_ALLOWLIST (bridge).
 * Only names are reported, never values.
 */
export function checkMainnetEnvGate(
  opts: { requireFeePayer?: boolean; requireRequesterAllowlist?: boolean } = {},
  env: NodeJS.ProcessEnv = process.env,
): { ok: true } | { ok: false; problems: string[] } {
  const allow = ["1", "true", "yes"].includes((env.ALLOW_MAINNET ?? "").trim().toLowerCase());
  if (!isNetworkMainnetIsh(env.NETWORK) && !allow) return { ok: true };
  const problems: string[] = [];
  const on = (k: string) => {
    const v = (env[k] ?? "").trim().toLowerCase();
    return v !== "" && v !== "0" && v !== "false" && v !== "no";
  };
  for (const k of ["ALLOW_INSECURE_DEV", "AC2_BRIDGE_AUTO_LOCAL", "DEV_ALLOW_UNSIGNED", "DEMO_MOCK_FACILITATOR"]) {
    if (on(k)) problems.push(`${k} is forbidden on MainNet`);
  }
  if ((env.OPERATOR_ATTESTATION_MODE ?? "").trim().toLowerCase() === "token-lab") {
    problems.push("OPERATOR_ATTESTATION_MODE=token-lab is forbidden on MainNet");
  }
  if ((env.AC2_OPERATOR_TOKEN ?? "") !== "") problems.push("AC2_OPERATOR_TOKEN (token-lab) is forbidden on MainNet");
  for (const k of Object.keys(env)) {
    if (/MNEMONIC/i.test(k) && (env[k] ?? "") !== "") problems.push(`${k} is forbidden on MainNet (no signing keys in services)`);
  }
  const backend = (env.STATE_BACKEND ?? "").trim().toLowerCase();
  if (backend !== "postgres" && backend !== "redis+postgres") {
    problems.push("STATE_BACKEND must be postgres or redis+postgres on MainNet");
  }
  if (opts.requireFeePayer && !(env.FEE_PAYER ?? "").trim()) problems.push("FEE_PAYER is required on MainNet");
  if (opts.requireRequesterAllowlist && !(env.REQUESTER_ALLOWLIST ?? "").trim()) {
    problems.push("REQUESTER_ALLOWLIST is required on MainNet (no loopback /sign)");
  }
  return problems.length ? { ok: false, problems } : { ok: true };
}

export function assertMainnetEnvGateOrExit(
  service: string,
  opts: { requireFeePayer?: boolean; requireRequesterAllowlist?: boolean } = {},
): void {
  const r = checkMainnetEnvGate(opts);
  if (!r.ok) {
    for (const p of r.problems) console.error(`[${service}] REFUSING TO START: ${p}`);
    process.exit(1);
  }
}
