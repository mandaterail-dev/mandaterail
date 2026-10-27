/**
 * Minimal AC2 bridge stub for MandateRail.
 *
 * - POST /pair/status → { paired, mode }
 * - POST /sign → queue approval (or auto-local when AC2_BRIDGE_AUTO_LOCAL=true)
 * - GET /pending → list pending approvals (OperatorAuth)
 * - GET /requests/:id/status → requester-scoped status (requester token)
 * - POST /approve/:id → complete with { signature, publicKey?, address? }
 * - POST /reject/:id
 *
 * OperatorAuth (OPERATOR_ATTESTATION_MODE):
 *  - signed-challenge (required on MainNet / ALLOW_MAINNET): GET
 *    /operator/challenge?action=approve|reject|list&id=<pendingId|pending>
 *    then send X-MandateRail-Operator-Attestation (base64 JSON evidence)
 *    signed by an OPERATOR_ALLOWLIST Algorand account. Single-use, short TTL.
 *  - token-lab (TestNet only): X-MandateRail-Operator-Token when
 *    AC2_OPERATOR_TOKEN is set; else loopback + ALLOW_INSECURE_DEV=1 + TestNet.
 * GET /pending is operator-gated (action=list, id=pending).
 *
 * Default bind is 127.0.0.1 — do not expose beyond loopback without auth.
 */
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

function loadDotEnv() {
  for (const p of [
    resolve(process.cwd(), ".env"),
    resolve(process.cwd(), "../../.env"),
    resolve(process.cwd(), "../../../.env"),
  ]) {
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, "utf8").split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const i = t.indexOf("=");
      if (i <= 0) continue;
      const key = t.slice(0, i).trim();
      let val = t.slice(i + 1).trim();
      if (
        (val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'"))
      )
        val = val.slice(1, -1);
      if (process.env[key] === undefined) process.env[key] = val;
    }
    break;
  }
}
loadDotEnv();

import { serve } from "@hono/node-server";
import {
  assertInsecureDevOrExit,
  assertOperatorGateOrExit,
  isAc2BridgeAutoLocal,
  isLoopbackHost,
} from "@mandaterail/core";
import { loadStateEnvFile, openStateBackendOrExit } from "@mandaterail/storage";
import { assertMainnetEnvGateOrExit } from "@mandaterail/core";
import { createBridgeApp } from "./app.js";

assertInsecureDevOrExit("ac2-bridge");
assertOperatorGateOrExit("ac2-bridge");
// T6: MainNet env gate (after the state env file is loaded; names only, never values).
try {
  loadStateEnvFile("bridge");
} catch {
  // reported (redacted) by openStateBackendOrExit below
}
assertMainnetEnvGateOrExit("ac2-bridge", { requireRequesterAllowlist: true });

/** Default MUST stay loopback — block non-localhost exposure without auth. */
const PORT = Number(process.env.AC2_BRIDGE_PORT ?? 8790);
const HOST = process.env.AC2_BRIDGE_HOST ?? "127.0.0.1";

// T6: STATE_BACKEND (from /etc/mandaterail/state-bridge.env or env); memory default on TestNet.
const backend = await openStateBackendOrExit("bridge");
const { app, mode } = createBridgeApp({ backend: backend ?? undefined });

// OA-P2-H: strict loopback check (127.example.com is not loopback).
if (!isLoopbackHost(HOST)) {
  console.warn(
    `[ac2-bridge] WARNING: bind host is ${HOST} (not loopback). signed-challenge requires OPERATOR_SIGNDATA_DOMAIN here; do not expose without auth. Default is 127.0.0.1.`,
  );
}

console.log(`MandateRail ac2-bridge listening on http://${HOST}:${PORT}`);
console.log(`  AC2_BRIDGE_AUTO_LOCAL=${isAc2BridgeAutoLocal()}`);
console.log(`  ALGORAND_MNEMONIC=${process.env.ALGORAND_MNEMONIC ? "(set)" : "(unset)"}`);
console.log(`  AC2_OPERATOR_TOKEN=${process.env.AC2_OPERATOR_TOKEN ? "(set)" : "(unset)"}`);
console.log(`  OPERATOR_ATTESTATION_MODE=${mode}`);
console.log(`  Pair status: POST/GET /pair/status`);
console.log(`  Sign: POST /sign (202 -> { id, requesterToken })`);
console.log(`  Requester status: GET /requests/:id/status (X-MandateRail-Requester-Token)`);
console.log(`  Challenge: GET /operator/challenge?action=&id=`);
console.log(`  Pending: GET /pending (OperatorAuth, action=list)`);
console.log(`  Approve: POST /approve/:id (OperatorAuth)`);
console.log(`  Reject: POST /reject/:id (OperatorAuth)`);

serve({ fetch: app.fetch, port: PORT, hostname: HOST });
