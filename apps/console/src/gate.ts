/**
 * Console startup gate (NOT audited). Refuses start when the store could be
 * reached by anyone other than a direct loopback caller without
 * signed-challenge OperatorAttestation.
 */
import {
  checkOperatorGate,
  isLoopbackHost,
  isMainnetProfile,
  parseConsoleLimits,
  parseTrustedProxyHops,
  resolveOperatorAttestationMode,
  MAX_CHALLENGE_RATE_GLOBAL,
  MAX_CHALLENGE_RATE_PER_IP,
} from "@mandaterail/core";

export type ConsoleGateCheck = { ok: true } | { ok: false; reason: string };

export function checkConsoleGate(
  opts: { bindHost?: string } = {},
): ConsoleGateCheck {
  const bindHost = opts.bindHost ?? process.env.CONSOLE_HOST ?? "127.0.0.1";
  // Shared OperatorAttestation gate: valid mode, allowlist, domain, TTL, rates, hops.
  const base = checkOperatorGate({ bindHost });
  if (!base.ok) return base;
  const mode = resolveOperatorAttestationMode(isMainnetProfile());
  if (mode !== "signed-challenge") {
    if (!isLoopbackHost(bindHost)) {
      return {
        ok: false,
        reason: `console bind ${bindHost} is not loopback: set OPERATOR_ATTESTATION_MODE=signed-challenge (+ OPERATOR_ALLOWLIST, OPERATOR_SIGNDATA_DOMAIN) to host it.`,
      };
    }
    if ((parseTrustedProxyHops() ?? 1) > 0) {
      return {
        ok: false,
        reason: "AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0 (proxied / tunneled) requires OPERATOR_ATTESTATION_MODE=signed-challenge for the console.",
      };
    }
  }
  if (parseConsoleLimits() === null) {
    return {
      ok: false,
      reason: `CONSOLE_RATE_PER_IP (1..${MAX_CHALLENGE_RATE_PER_IP}) <= CONSOLE_RATE_GLOBAL (1..${MAX_CHALLENGE_RATE_GLOBAL}), CONSOLE_MAX_BODY_BYTES (1024..65536) and CONSOLE_MAX_MANDATES (1..10000) must be integers in range.`,
    };
  }
  return { ok: true };
}
