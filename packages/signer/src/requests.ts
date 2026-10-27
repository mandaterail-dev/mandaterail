/**
 * Request authentication (rev 10 §13 "Request authentication"): every request is signed by a pinned requester
 * Ed25519 key over "MR-SIGNER-REQ-v1\n" || JCS(body); timestamp window, single-use request nonces (persistent)
 * and a per-requester hourly rate limit. Transport is WireGuard (+ source-IP allowlist in server.ts).
 */
import { createPublicKey, verify as edVerify, sign as edSign, type KeyObject } from "node:crypto";
import { jcs, type JcsValue } from "@mandaterail/storage";
import { DurableJson } from "./state.js";

export const REQ_PREFIX = "MR-SIGNER-REQ-v1\n";
export type ReqOp = "candidate" | "confirm" | "cosign" | "status" | "reconcile-ack" | "resume-candidate" | "resume-confirm" | "resume-apply" | "resume-cosign" | "resume-observed";
export interface SignedRequest { body: Record<string, JcsValue>; sig: string /* b64 */ }
export interface ReqState { counter: number; nonces: { n: string; at: number }[]; hits: { r: string; at: number }[] }
export const initialReqState = (): ReqState => ({ counter: 0, nonces: [], hits: [] });
export class RequestRefused extends Error {}

const ED_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const spki = (pk: Uint8Array) => createPublicKey({ key: Buffer.concat([ED_SPKI, Buffer.from(pk)]), format: "der", type: "spki" });
export const requestBytes = (body: Record<string, JcsValue>) => Buffer.from(REQ_PREFIX + jcs(body), "utf8");

/** Requester side (CLI / automation): sign a request body. */
export function signRequest(body: Record<string, JcsValue>, key: KeyObject): SignedRequest {
  return { body, sig: edSign(null, requestBytes(body), key).toString("base64") };
}

export class RequestAuth {
  constructor(
    private readonly requesters: { id: string; pubkey: Uint8Array }[],
    private readonly st: DurableJson<ReqState>,
    private readonly opts: { maxAgeS: number; ratePerHour: number; network: string },
    private readonly now: () => number = Date.now,
  ) {}

  counter(): number { return this.st.get().counter; }

  verify(req: SignedRequest, op: ReqOp): Record<string, JcsValue> {
    const b = req.body;
    if (!b || typeof b !== "object" || b.op !== op) throw new RequestRefused("op");
    const who = this.requesters.find((r) => r.id === b.requester);
    if (!who) throw new RequestRefused("unknown requester");
    let bytes: Buffer;
    try { bytes = requestBytes(b); } catch { throw new RequestRefused("request is not canonical"); }
    const sig = Buffer.from(String(req.sig), "base64");
    if (sig.length !== 64 || !edVerify(null, bytes, spki(who.pubkey), sig)) throw new RequestRefused("request signature");
    if (b.network !== this.opts.network) throw new RequestRefused("request network");
    const t = this.now();
    const ts = Date.parse(String(b.ts));
    if (!Number.isFinite(ts) || Math.abs(t - ts) > this.opts.maxAgeS * 1000) throw new RequestRefused("request timestamp outside the window");
    const n = String(b.reqNonce);
    if (!/^[A-Za-z0-9_-]{43}$/.test(n)) throw new RequestRefused("request nonce format");
    const s = this.st.get();
    const keep = t - 2 * this.opts.maxAgeS * 1000;
    s.nonces = s.nonces.filter((x) => x.at > keep);
    if (s.nonces.some((x) => x.n === n)) throw new RequestRefused("request nonce replay");
    s.hits = s.hits.filter((x) => x.at > t - 3_600_000);
    if (s.hits.filter((x) => x.r === who.id).length >= this.opts.ratePerHour) throw new RequestRefused("requester rate limit");
    s.nonces.push({ n, at: t });
    s.hits.push({ r: who.id, at: t });
    s.counter += 1;
    this.st.put(s); // persisted before acting: a crash cannot re-open a nonce
    return b;
  }
}
