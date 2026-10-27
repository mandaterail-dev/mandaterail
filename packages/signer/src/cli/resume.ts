/**
 * rev 21 (§23): the automatic tamper-resume driver (runs on a timer as mr_release, no human step).
 *  1. read the signer's status and the DB pause row. A signer tamper pause the DB doesn't know yet is recorded
 *     with mr_tamper_pause (the DB counts it: backoff).
 *  2. before the DB's cooldown ends: wait (nothing to do).
 *  3. after it: signer resume-candidate (it re-runs its chain checks) -> requester checks the message names the DB
 *     pause -> resume-confirm (helper signs; counter bump) -> mr-verifier resume-cosign (its own chain + reconcile
 *     checks) -> DB mr_tamper_resume (2-of-2, trust domains, nonces) -> signer resume-apply. Every step pages.
 * Any refusal leaves everything paused; the next run starts over with fresh nonces.
 */
import { createHash, randomBytes, type KeyObject } from "node:crypto";
import type pg from "pg";
import { decodeResume, isoSeconds, type JcsValue } from "@mandaterail/storage";
import { signRequest, type SignedRequest } from "../requests.js";
import type { Pause } from "../policy.js";

export interface ResumeSigner {
  status(r: SignedRequest): Promise<{ paused: Pause | null; tamperCount: number; resumeNotBefore: string | null }>;
  resumeCandidate(r: SignedRequest): Promise<{ msg: string; msgHash: string }>;
  resumeConfirm(r: SignedRequest): Promise<{ msg: string; sig: string }>;
  resumeApply(r: SignedRequest): Promise<{ resumed: true }>;
}
export interface ResumeDeps {
  db: pg.Pool | pg.PoolClient; network: "testnet" | "mainnet"; requesterId: string; requesterKey: KeyObject;
  signer: ResumeSigner;
  verifier: {
    resumeCosign(r: SignedRequest): Promise<{ msg: string; sig: string }>;
    resumeObserved?(r: SignedRequest): Promise<{ resumed: boolean }>;
    /** R63-P2-2 */
    status?(r: SignedRequest): Promise<{ paused: null | { at: number; reason: string }; pendingResume: null | { pauseSeq: number; at: number } }>;
  };
  page: (subject: string, body: string) => Promise<void>; now?: () => number;
}
export type ResumeOutcome = "running" | "rate-paused" | "waiting" | "resumed";

export async function autoResumeOnce(d: ResumeDeps): Promise<ResumeOutcome> {
  const now = d.now ?? Date.now;
  const req = (op: string, extra: Record<string, JcsValue> = {}) => signRequest({ op, requester: d.requesterId, network: d.network, ts: isoSeconds(now()), reqNonce: randomBytes(32).toString("base64url"), ...extra }, d.requesterKey);
  const st = await d.signer.status(req("status"));
  // R63-P2-2: the verifier side. A co-signed resume it has not seen applied yet is retried on every tick; a verifier
  // tamper pause the DB doesn't know is mirrored into the DB (counted, backoff) so the normal quorum resume lifts it.
  if (d.verifier.status) {
    let vs = await d.verifier.status(req("status"));
    if (vs.pendingResume && d.verifier.resumeObserved) {
      const ok = await d.verifier.resumeObserved(req("resume-observed", {})).then(() => true, () => false);
      if (ok) { await d.page("[resume] verifier observed the resume (own pause lifted)", `pause ${vs.pendingResume.pauseSeq}`); vs = await d.verifier.status(req("status")); }
    }
    // (a pending marker younger than 15 min means a resume was just applied and the chain may lag: don't re-pause yet)
    // R64-P3-1: a marker naming the CURRENT pause_seq means the DB already lifted that pause and only the verifier's
    // observation is lagging: re-pausing would open a new pause_seq and escalate the backoff on every tick. Page instead.
    // R65-P3-2: a verifier pause NEWER than the marker is a new anomaly: it supersedes the marker and is mirrored.
    if (vs.paused) {
      const p = vs.pendingResume;
      const newer = !!p && vs.paused.at > p.at;
      const row = (await d.db.query("SELECT paused, pause_seq::text AS seq FROM mr_pause_state WHERE network = $1", [d.network])).rows[0] as { paused: boolean; seq: string } | undefined;
      const old = !!p && now() - p.at > 15 * 60_000;
      if (row && !row.paused) {
        if (!p || newer || (old && p.pauseSeq !== Number(row.seq))) {
          await d.db.query("SELECT * FROM mr_tamper_pause($1)", [`verifier: ${vs.paused.reason}`.slice(0, 500)]);
          await d.page("[resume] DB pause recorded (verifier pause mirrored)", vs.paused.reason);
        } else if (old) {
          await d.page("[resume] verifier observation stuck (not re-pausing)", `pause ${row.seq} resumed in the DB; the verifier has not observed it for ${Math.floor((now() - p.at) / 60_000)} min; verifier pause: ${vs.paused.reason}`);
        }
      }
    }
  }
  if (st.paused?.kind === "tamper") {
    const row = (await d.db.query("SELECT paused FROM mr_pause_state WHERE network = $1", [d.network])).rows[0] as { paused: boolean } | undefined;
    if (!row?.paused) {
      await d.db.query("SELECT * FROM mr_tamper_pause($1)", [`signer: ${st.paused.reason}`.slice(0, 500)]);
      await d.page("[resume] DB pause recorded", st.paused.reason);
    }
  }
  const db = (await d.db.query("SELECT paused, pause_seq::text AS seq, tamper_count AS cnt, paused_at + mr_v16_cooldown(base_cooldown_s, tamper_count) AS nb, clock_timestamp() AS dbnow FROM mr_pause_state WHERE network = $1", [d.network])).rows[0] as
    { paused: boolean; seq: string; cnt: number; nb: Date | null; dbnow: Date } | undefined;
  if (!db) throw new Error("no mr_pause_state row");
  if (!db.paused) return st.paused?.kind === "rate" ? "rate-paused" : "running";
  if (db.nb && db.dbnow < db.nb) return "waiting";
  const cand = await d.signer.resumeCandidate(req("resume-candidate", { dbPauseSeq: Number(db.seq), dbTamperCount: db.cnt }));
  const msg = Buffer.from(cand.msg, "base64");
  const body = decodeResume(msg);
  if (createHash("sha256").update(msg).digest("hex") !== cand.msgHash || body.pauseSeq !== Number(db.seq) || body.tamperCount !== db.cnt || body.network !== d.network) {
    throw new Error("resume candidate does not name the DB's current pause");
  }
  const signed = await d.signer.resumeConfirm(req("resume-confirm", { msgHash: cand.msgHash }));
  if (signed.msg !== cand.msg) throw new Error("resume confirm returned another message");
  const co = await d.verifier.resumeCosign(req("resume-cosign", { resumeMsg: signed.msg, resumeSig: signed.sig }));
  await d.db.query("SELECT * FROM mr_tamper_resume($1, $2, $3, $4)", [msg, Buffer.from(signed.sig, "base64"), Buffer.from(co.msg, "base64"), Buffer.from(co.sig, "base64")]);
  await d.signer.resumeApply(req("resume-apply", { cosignMsg: co.msg, cosignSig: co.sig }));
  // R62-P3-2: the verifier lifts its own pause only now, after checking the applied resume in the signer chain
  if (d.verifier.resumeObserved) await d.verifier.resumeObserved(req("resume-observed", {})).catch(async (e: Error) => { await d.page("[resume] verifier did not observe the resume yet", e.message).catch(() => undefined); });
  await d.page("[resume] AUTO-RESUMED after tamper pause", `pause ${db.seq}, tamper count ${db.cnt}`);
  return "resumed";
}
