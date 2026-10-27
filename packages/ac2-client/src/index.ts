export type {
  Ac2Signer,
  Ac2SignResult,
  SigningRequest,
  UnsignedIntentMandate,
} from "./types.js";
export { LocalEd25519Signer } from "./local-signer.js";
export {
  HttpAc2BridgeSigner,
  REQUESTER_TOKEN_HEADER,
  type HttpAc2BridgeSignerOptions,
} from "./http-bridge-signer.js";

import { LocalEd25519Signer } from "./local-signer.js";
import { HttpAc2BridgeSigner } from "./http-bridge-signer.js";
import type { Ac2Signer } from "./types.js";

/**
 * Resolve signer from AC2_MODE env:
 * - local (default): LocalEd25519Signer from ALGORAND_MNEMONIC
 * - bridge: HttpAc2BridgeSigner from AC2_BRIDGE_URL
 */
export function createSignerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): Ac2Signer {
  const mode = (env.AC2_MODE ?? "local").toLowerCase();
  if (mode === "bridge") {
    return HttpAc2BridgeSigner.fromEnv(env);
  }
  const mnemonic = env.ALGORAND_MNEMONIC;
  if (!mnemonic) {
    throw new Error(
      "ALGORAND_MNEMONIC is required when AC2_MODE=local (or unset)",
    );
  }
  return LocalEd25519Signer.fromMnemonic(mnemonic);
}
