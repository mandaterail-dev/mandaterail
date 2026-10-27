/**
 * R79-P3-2 (punchlist; run 81 brief P3-1): build glue for mr-piv-sign. The signing backend is built ONLY from
 * MR_PIV_BACKEND / MR_KMS_CONFIG (deploy/gcp/mr-piv-sign@.service) through cloudKmsFromConfig, so the role check and
 * the CloudKmsBackend constructor's key-order checks (backup refusal; MainNet active-signer pin) always run.
 * No other backend is wired here; this file must never import backend-software.ts (MainNet image graph).
 */
import { readFileSync } from "node:fs";
import type { SignBackend } from "./backend.js";
import { cloudKmsFromConfig, CloudKmsError } from "./cloudkms.js";

export const DEFAULT_KMS_CONFIG = "/etc/mr-piv/cloudkms.mainnet.json";

export function backendFromEnv(network: "testnet" | "mainnet", env: NodeJS.ProcessEnv = process.env): SignBackend {
  const kind = env.MR_PIV_BACKEND;
  if (kind !== "cloudkms") throw new CloudKmsError(`MR_PIV_BACKEND=${String(kind)}: only "cloudkms" is wired in mr-piv-sign (refusing to start)`);
  const p = env.MR_KMS_CONFIG ?? DEFAULT_KMS_CONFIG;
  let j: Parameters<typeof cloudKmsFromConfig>[0];
  try { j = JSON.parse(readFileSync(p, "utf8")); } catch (e) { throw new CloudKmsError(`MR_KMS_CONFIG ${p} unreadable or not JSON: ${(e as Error).message}`); }
  if (j.network !== network) throw new CloudKmsError(`MR_KMS_CONFIG ${p} is for ${String(j.network)}, the helper config is ${network}`);
  return cloudKmsFromConfig(j);
}
