/** v16 resume attestations (§23): PREFIX + restricted JCS, exact key sets. The co-signature binds sha256(signer msg). */
import { AttestError, jcs, type JcsValue } from "./attest.js";
import { RESUME_COSIGN_KEYS, RESUME_COSIGN_PREFIX, RESUME_MSG_KEYS, RESUME_PREFIX } from "./v16-resume.js";

export interface ResumeBody {
  chainHead: string; chainSeq: number; expiry: string; genesisHash: string; issuedAt: string; keyId: string;
  network: "testnet" | "mainnet"; nonce: string; pauseSeq: number; tamperCount: number; v: 1;
}
export interface ResumeCosignBody {
  attestHash: string; chainHead: string; chainSeq: number; expiry: string; genesisHash: string; issuedAt: string; keyId: string;
  network: "testnet" | "mainnet"; nonce: string; pauseSeq: number; v: 1;
}
const ISO_S = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const same = (o: object, want: readonly string[]) => { const k = Object.keys(o).sort(); const w = [...want].sort(); return k.length === w.length && k.every((x, i) => x === w[i]); };
function enc(prefix: string, keys: readonly string[], b: object): Buffer {
  if (!same(b, keys)) throw new AttestError("resume key set");
  const r = b as Record<string, unknown>;
  if (!ISO_S.test(String(r.expiry)) || !ISO_S.test(String(r.issuedAt)) || !/^[0-9a-f]{64}$/.test(String(r.chainHead)) || !/^[A-Za-z0-9_-]{43}$/.test(String(r.nonce))) throw new AttestError("resume formats");
  if ("attestHash" in r && !/^[0-9a-f]{64}$/.test(String(r.attestHash))) throw new AttestError("resume attestHash");
  return Buffer.from(prefix + jcs(b as unknown as JcsValue), "utf8");
}
function dec<T>(prefix: string, keys: readonly string[], msg: Uint8Array): T {
  const s = Buffer.from(msg).toString("utf8");
  if (!s.startsWith(prefix) || msg.length > 2048) throw new AttestError("resume prefix / length");
  const b = JSON.parse(s.slice(prefix.length)) as T;
  if (!enc(prefix, keys, b as object).equals(Buffer.from(msg))) throw new AttestError("resume not canonical");
  return b;
}
export const encodeResume = (b: ResumeBody) => enc(RESUME_PREFIX, RESUME_MSG_KEYS, b);
export const decodeResume = (m: Uint8Array) => dec<ResumeBody>(RESUME_PREFIX, RESUME_MSG_KEYS, m);
export const encodeResumeCosign = (b: ResumeCosignBody) => enc(RESUME_COSIGN_PREFIX, RESUME_COSIGN_KEYS, b);
export const decodeResumeCosign = (m: Uint8Array) => dec<ResumeCosignBody>(RESUME_COSIGN_PREFIX, RESUME_COSIGN_KEYS, m);
