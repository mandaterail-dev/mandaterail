/**
 * `mr-piv-sign --stdio` entry (exec'd by mr-peercred-gate, one connection on fd 0/1). TestNet builds only use the
 * software backend; the MainNet image builds this file against main-mainnet.ts (hardware backend only).
 * Config: MR_PIV_CONFIG (JSON: helper pins, requester pubkeys, state dir). Never logs request contents.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { DurableJson } from "../state.js";
import { RequestAuth, type ReqState } from "../requests.js";
import { PivHelper, type HelperConfig, type HelperState } from "./helper.js";
import { UsedStore } from "./used-store.js";
import { serveOnce } from "./socket.js";
import type { SignBackend } from "./backend.js";
import { backendFromEnv } from "./backend-from-env.js";

export interface PivMainConfig { helper: HelperConfig; requesters: { id: string; pubkeyB64: string }[]; stateDir: string }

export async function runStdio(cfg: PivMainConfig, backend: SignBackend): Promise<void> {
  const d = cfg.stateDir;
  const auth = new RequestAuth(cfg.requesters.map((r) => ({ id: r.id, pubkey: new Uint8Array(Buffer.from(r.pubkeyB64, "base64")) })),
    new DurableJson<ReqState>(path.join(d, "requests.json")), { maxAgeS: 30, ratePerHour: 30, network: cfg.helper.network });
  const helper = new PivHelper(cfg.helper, backend, UsedStore.open(path.join(d, "used.log")), auth, new DurableJson<HelperState>(path.join(d, "helper.json")));
  await serveOnce(helper, process.stdin, process.stdout);
}
export const loadPivConfig = (): PivMainConfig => JSON.parse(readFileSync(process.env.MR_PIV_CONFIG ?? "/etc/mr-piv/config.json", "utf8")) as PivMainConfig;

/** `mr-piv-sign --stdio`: config from MR_PIV_CONFIG, backend from MR_PIV_BACKEND / MR_KMS_CONFIG (R79-P3-2). */
export async function mainStdio(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const cfg = loadPivConfig();
  await runStdio(cfg, backendFromEnv(cfg.helper.network as "testnet" | "mainnet", env));
}
