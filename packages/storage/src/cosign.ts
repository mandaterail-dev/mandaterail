/** v12 co-signature format (§15): MR-RELEASE-COSIGN-v1\n + restricted JCS, bound to sha256(primary attestation). */
import { AttestError, isoSeconds, jcs, type JcsValue, type Observation } from "./attest.js";
import { ATTEST_OBS_KEYS } from "./v11-attested.js";
import { COSIGN_MSG_KEYS, COSIGN_PREFIX } from "./v12-cosign.js";

export interface CosignBody {
  attestHash: string; expiry: string; genesisHash: string; keyId: string; lastValid: number; network: "testnet" | "mainnet";
  nonce: string; observations: Observation[]; round: number; spendId: string; store: string; txId: string; v: 1;
}
const ISO_S = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const same = (o: object, want: readonly string[]) => { const k = Object.keys(o).sort(); const w = [...want].sort(); return k.length === w.length && k.every((x, i) => x === w[i]); };

export function encodeCosign(b: CosignBody): Buffer {
  if (!same(b, COSIGN_MSG_KEYS)) throw new AttestError("co-signature key set");
  if (!/^[0-9a-f]{64}$/.test(b.attestHash) || !ISO_S.test(b.expiry)) throw new AttestError("co-signature formats");
  for (const o of b.observations) if (!same(o, ATTEST_OBS_KEYS) || !ISO_S.test(o.at)) throw new AttestError("co-signature observation");
  const m = Buffer.from(COSIGN_PREFIX + jcs(b as unknown as JcsValue), "utf8");
  if (m.length > 4096) throw new AttestError("co-signature too long");
  return m;
}
export function decodeCosign(msg: Uint8Array): CosignBody {
  const s = Buffer.from(msg).toString("utf8");
  if (!s.startsWith(COSIGN_PREFIX)) throw new AttestError("co-signature prefix");
  const b = JSON.parse(s.slice(COSIGN_PREFIX.length)) as CosignBody;
  if (!encodeCosign(b).equals(Buffer.from(msg))) throw new AttestError("co-signature not canonical");
  return b;
}
void isoSeconds;
