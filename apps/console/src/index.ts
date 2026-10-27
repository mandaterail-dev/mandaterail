/**
 * MandateRail console — mandate store server entry. See src/app.ts for auth.
 * Unsigned / stub-signed mandates are unsigned-draft and never authorized for
 * execute; the console does not replace the AC2 human gate. NOT audited.
 */
import { serve } from "@hono/node-server";
import { assertInsecureDevOrExit } from "@mandaterail/core";
import { loadStateEnvFile, openStateBackendOrExit } from "@mandaterail/storage";
import { assertMainnetEnvGateOrExit } from "@mandaterail/core";
import { createConsoleApp } from "./app.js";
import { checkConsoleGate } from "./gate.js";

assertInsecureDevOrExit("console");
// T6: MainNet env gate (after the state env file is loaded; names only, never values).
try {
  loadStateEnvFile("console");
} catch {
  // reported (redacted) by openStateBackendOrExit below
}
assertMainnetEnvGateOrExit("console", {});
const gate = checkConsoleGate();
if (!gate.ok) {
  console.error(`[console] REFUSING TO START: ${gate.reason}`);
  process.exit(1);
}

const PORT = Number(process.env.CONSOLE_PORT ?? 8788);
/** Default loopback. Non-loopback requires signed-challenge (gate above). */
const HOST = process.env.CONSOLE_HOST ?? "127.0.0.1";

// T6: STATE_BACKEND (from /etc/mandaterail/state-console.env or env); file store default on TestNet.
const backend = await openStateBackendOrExit("console");
const { app, mode, limits } = createConsoleApp({ backend: backend ?? undefined });

console.log(`MandateRail console listening on http://${HOST}:${PORT}`);
console.log(`  auth: ${mode}`);
console.log(`  limits: ${JSON.stringify(limits)}`);
console.log(
  "  WARNING: unsigned-draft mandates are NOT authorized for execute; AC2 human gate required.",
);
serve({ fetch: app.fetch, port: PORT, hostname: HOST });
