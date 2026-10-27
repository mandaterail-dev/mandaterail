/**
 * mr-signer, automated (rev 10 §13). Two-phase protocol per spend:
 *   1. candidate: authenticated request with the DB snapshot (stored signed bytes + app-derived fields).
 *      The signer re-derives and checks the txn, checks clock, snapshot staleness, policy and lv_est, queries
 *      every pinned provider (any "present" refuses + pauses), builds the attestation and returns it (echo).
 *   2. confirm: the requester (CLI) has verified the echo byte-for-byte and run its own independent absence
 *      check; it returns SHA-256(msg) signed. Only then does the helper sign. The signer self-verifies the
 *      signature against the pinned key before returning it.
 * Every refusal is logged off-host and counts toward the anomaly auto-pause. Nothing secret is logged.
 * Rev 21 (§23), fully automatic: no unlock, no remote pause, no runtime path that changes caps or config (config
 * changes only by redeploy, recorded in the manifest and the B2 chain at boot). Rate pauses clear when their window
 * rolls; tamper pauses resume only after the cooldown with a fresh 2-of-2 resume quorum (resumeCandidate ->
 * resumeConfirm -> [verifier resume-cosign, DB mr_tamper_resume] -> resumeApply). Every pause and resume is logged
 * to the B2 chain and paged.
 */
import { createHash, randomBytes } from "node:crypto";
import { decodeResumeCosign, encodeAttestation, encodeResume, isoSeconds, keyIdOf, verifyAttestation, type AttestBody, type ResumeBody, type SignedTxnKind } from "@mandaterail/storage";
import { GENESIS_PINS } from "./config.js";
import type { SignerConfig } from "./config.js";
import { assertClock, ClockRefused, type ClockSource } from "./clock.js";
import { checkSignedTxn, TxCheckError } from "./txcheck.js";
import { AbsenceRefused, observeAbsence, type ChainProbe } from "./providers.js";
import { PolicyEngine, PolicyRefused, type Pause } from "./policy.js";
import { RequestAuth, RequestRefused, type SignedRequest } from "./requests.js";
import { PageFailed, RollbackDetected, type AuditEvent, type ChainedAudit } from "./audit.js";
import type { EscrowRuntime, ReleasePrep, ReleaseRow } from "./escrow-release.js";

/**
 * The helper boundary (mr-piv-sign, separate uid). R43-P2-4: the helper receives the requester's own signed
 * confirm and verifies it itself (own pinned keys, own nonce store, own window, own caps); mr-signer can't
 * supply the msgHash on its own.
 */
export interface HelperLike {
  sign(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array>;
  /** R44-P3-1: the helper's state counter from its last sign reply (when the transport reports it). */
  lastCounter?(): number | undefined;
  /** in-process helper: its state counter */
  stateCounter?(): number;
  /** rev 21: sign a resume attestation against the requester's resume-confirm */
  signResume?(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array>;
}
export interface PublicKeySource { publicKey(): Promise<Uint8Array> }

export class SignerRefused extends Error {}
export interface CandidateResponse { msg: string /* b64 */; msgHash: string }
export interface ConfirmResponse { msg: string; sig: string }
interface Pending { msg: Buffer; msgHash: string; expiresAt: number; amountMicro: bigint; spendId: string; txId: string; requester: string }

const ROUND_S = 2.5;

export interface SignerDeps {
  cfg: SignerConfig; auth: RequestAuth; policy: PolicyEngine; probes: ChainProbe[]; clock: ClockSource;
  audit: ChainedAudit; helper: HelperLike; backend: PublicKeySource; now?: () => number;
  /** rev 21: mr-verifier's pinned public key (its resume co-signature); required on MainNet (main.ts) */
  cosignerPubkey?: Uint8Array;
  /** escrow release path (design rev 6 §1.4): one pinned-provider snapshot feeds the guard and M */
  escrow?: EscrowRuntime;
}
interface PendingResume { msg: Buffer; msgHash: string; body: ResumeBody; localSeq: number; requester: string; expiresAt: number; signed: boolean }

export class MrSigner {
  private readonly pending = new Map<string, Pending>();
  private pendingResume: PendingResume | null = null;
  private readonly now: () => number;
  constructor(private readonly d: SignerDeps) { this.now = d.now ?? Date.now; }

  /** R43-P2-1: boot gate. Refuses unless the local counters are >= the last ones in the off-host log. */
  static boot(d: SignerDeps): MrSigner {
    d.audit.assertNotRolledBack({ policy: d.policy.counter(), requests: d.auth.counter() });
    return new MrSigner(d);
  }

  /**
   * Escrow release path: refuses while paused; otherwise runs EscrowRuntime.prepareRelease (snapshot -> escrowPreflight /
   * pendingAbandonStatus -> M with not_after <= C.expires - 30 s). Every page goes to the B2 chain and is paged (alert),
   * so a failed page pauses the signer like any other alert.
   */
  async escrowRelease(row: ReleaseRow): Promise<ReleasePrep> {
    const p = this.d.policy.paused();
    if (p) throw new SignerRefused(`paused (${p.kind}): ${p.reason}`);
    if (!this.d.escrow) throw new SignerRefused("escrow release path not configured");
    // R76-P3-3: signed_at comes from this clock, so it must be chrony-synced within maxClockSkewS (as on every other path)
    await assertClock(this.d.clock, this.d.cfg.maxClockSkewS);
    const r = await this.d.escrow.prepareRelease(row);
    for (const pg of r.pages) await this.log({ kind: r.action === "sign" ? "escrow-warn" : "escrow-refused", reason: pg.slice(0, 300), at: this.now() }, true);
    // R76-P3-4: a pause that landed during the provider reads / page writes still refuses (no M leaves a paused signer)
    const p2 = this.d.policy.paused();
    if (p2) throw new SignerRefused(`paused (${p2.kind}): ${p2.reason}`);
    return r;
  }

  /** Heartbeat self-check (R43-P2-2): clock, not paused, last page delivered, a test publish succeeds. */
  async selfCheck(): Promise<void> {
    await assertClock(this.d.clock, this.d.cfg.maxClockSkewS);
    await this.autoResume();
    const p = this.d.policy.paused();
    if (p) throw new SignerRefused(`paused (${p.kind}): ${p.reason}`);
    if (!this.d.audit.pageHealthy()) throw new SignerRefused("last page was not delivered");
    await this.d.audit.testPage();
  }

  /** Logs with the current counters. R43-P2-2: a failed page on an alert event pauses the signer. */
  private async log(e: AuditEvent, alert = false): Promise<void> {
    try {
      const helper = this.d.audit.helperCounter();
      await this.d.audit.log({ ...e, counters: { policy: this.d.policy.counter(), requests: this.d.auth.counter(), ...(helper !== undefined ? { helper } : {}) } }, alert);
    } catch (err) {
      if (err instanceof PageFailed) {
        let p: Pause | null = null;
        try { p = this.d.policy.tamper(`page failed (${e.kind})`); } catch { /* state failure: still refuse */ }
        this.pending.clear();
        if (p) await this.logPause(p).catch(() => undefined); // B2 line still written; its page may fail too
      }
      throw err;
    }
  }

  /** rev 21: every pause goes to the B2 chain and pages (alert). */
  private async logPause(p: Pause): Promise<void> {
    await this.log({ kind: `pause-${p.kind}`, reason: p.reason, at: this.now() }, true);
  }

  /** rev 21: a rate pause whose window rolled clears itself; logged + paged. */
  async autoResume(): Promise<void> {
    let cleared: Pause | null = null;
    try { cleared = this.d.policy.poll().cleared; } catch { return; }
    if (cleared) await this.log({ kind: "auto-resume-rate", reason: cleared.reason, at: this.now() }, true);
  }

  private tamper(reason: string): Promise<void> {
    let p: Pause | null = null;
    try { p = this.d.policy.tamper(reason); } catch { /* still refuse */ }
    this.pending.clear();
    this.pendingResume = null;
    return p ? this.logPause(p).catch(() => undefined) : Promise.resolve();
  }

  private async refuse(e: unknown, spendKey?: string): Promise<never> {
    const anomaly = e instanceof AbsenceRefused ? e.anomaly : e instanceof RollbackDetected || e instanceof TxCheckError || (e instanceof SignerRefused && /echo|mismatch/.test(e.message));
    const reason = (e as Error).message;
    let p: Pause | null = null;
    try { p = this.d.policy.refusal(reason, anomaly); } catch { /* state failure: still refuse */ }
    if (p?.kind === "tamper") { this.pending.clear(); this.pendingResume = null; }
    try {
      await this.log({ kind: anomaly ? "refusal-anomaly" : "refusal", spendKey, reason, at: this.now() }, true);
    } catch { /* paused if the page failed; the refusal stands */ }
    if (p) await this.logPause(p).catch(() => undefined);
    throw e instanceof SignerRefused ? e : new SignerRefused(reason);
  }

  async candidate(req: SignedRequest): Promise<CandidateResponse> {
    let spendKey: string | undefined;
    try {
      const b = this.d.auth.verify(req, "candidate");
      const c = this.d.cfg;
      spendKey = `${String(b.store)}/${String(b.spendId)}`;
      await assertClock(this.d.clock, c.maxClockSkewS);
      await this.autoResume();
      const row = b.row as Record<string, string | number>;
      const snap = Date.parse(String(b.snapshotAt));
      const t = this.now();
      if (!Number.isFinite(snap) || t - snap > c.maxSnapshotAgeS * 1000 || snap - t > 5000) throw new SignerRefused("DB snapshot is stale");
      if (row.status !== "ambiguous") throw new SignerRefused("row is not ambiguous");
      const facts = checkSignedTxn(Buffer.from(String(b.signedTxn), "base64"), String(b.kind) as SignedTxnKind, c);
      // echo check 1: the app-derived DB columns must equal the signer's own derivation
      if (facts.txId !== row.txId || facts.firstValid !== row.firstValid || facts.lastValid !== row.lastValid
          || facts.groupId !== row.groupId || facts.sender !== row.sender || facts.amountMicro.toString() !== String(row.amountMicro)) {
        throw new SignerRefused("echo: DB-derived fields mismatch the signed bytes");
      }
      this.d.policy.check(spendKey, facts.amountMicro);
      const submitAt = Date.parse(String(row.submitAt));
      const lvEst = submitAt + (facts.lastValid - Number(row.submitRound)) * ROUND_S * 1000;
      if (!Number.isFinite(lvEst) || t < lvEst) throw new SignerRefused("too early: lastValid not yet passed by the submit-time estimate");
      const { observations, round } = await observeAbsence(this.d.probes, c, { txIds: facts.memberTxIds, fv: facts.firstValid, lv: facts.lastValid }, () => isoSeconds(this.now()));
      const body: AttestBody = {
        v: 1, network: c.network, genesisHash: c.genesisHash, keyId: c.keyId, store: String(b.store), spendId: String(b.spendId),
        txId: facts.txId, sender: facts.sender, groupId: facts.groupId, firstValid: facts.firstValid, lastValid: facts.lastValid,
        round, nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(t + c.attestTtlS * 1000), observations,
      };
      const msg = encodeAttestation(body);
      const msgHash = createHash("sha256").update(msg).digest("hex");
      this.pending.set(spendKey, { msg, msgHash, expiresAt: Math.min(Date.parse(body.expiry), t + 15 * 60_000), amountMicro: facts.amountMicro, spendId: body.spendId, txId: body.txId, requester: String(b.requester) });
      await this.log({ kind: "candidate", spendKey, msgHash, at: t });
      return { msg: msg.toString("base64"), msgHash };
    } catch (e) {
      return this.refuse(e, spendKey);
    }
  }

  async confirm(req: SignedRequest): Promise<ConfirmResponse> {
    let spendKey: string | undefined;
    try {
      const b = this.d.auth.verify(req, "confirm");
      spendKey = `${String(b.store)}/${String(b.spendId)}`;
      const p = this.pending.get(spendKey);
      if (!p || p.requester !== b.requester) throw new SignerRefused("no pending candidate for this spend");
      if (this.now() > p.expiresAt) { this.pending.delete(spendKey); throw new SignerRefused("candidate expired"); }
      if (b.msgHash !== p.msgHash) throw new SignerRefused("confirm msgHash mismatch");
      await assertClock(this.d.clock, this.d.cfg.maxClockSkewS);
      this.pending.delete(spendKey);
      this.d.policy.record(spendKey, p.amountMicro); // counted before the signature exists
      const sig = await this.d.helper.sign(p.msg, req); // the requester's own signed confirm goes through
      const hc = this.d.helper.lastCounter?.();
      if (hc !== undefined) {
        try { this.d.audit.assertHelperAdvanced(hc); } catch (err) {
          await this.tamper("helper state rolled back");
          throw err; // signature withheld
        }
      }
      const pk = await this.d.backend.publicKey();
      if (keyIdOf(pk) !== this.d.cfg.keyId || !verifyAttestation(p.msg, sig, pk)) throw new SignerRefused("self-verify failed (key mismatch)");
      // R43-P2-2: if the page for "signed" fails, the signer pauses and the signature is withheld
      await this.log({ kind: "signed", spendKey, msgHash: p.msgHash, at: this.now() }, true);
      return { msg: p.msg.toString("base64"), sig: Buffer.from(sig).toString("base64") };
    } catch (e) {
      return this.refuse(e, spendKey);
    }
  }

  /** rev 21: read-only status (requester-signed): pause kind / reason / sequence, tamper count, earliest resume. */
  async status(req: SignedRequest): Promise<{ paused: Pause | null; tamperCount: number; resumeNotBefore: string | null }> {
    this.d.auth.verify(req, "status");
    await this.autoResume();
    const nb = this.d.policy.resumeNotBefore();
    return { paused: this.d.policy.paused(), tamperCount: this.d.policy.tamperCount(), resumeNotBefore: nb === null ? null : new Date(nb).toISOString() };
  }

  /**
   * rev 21 resume step 1: after the cooldown, re-run the signer's own integrity checks (clock, local counters vs
   * the off-host chain, the off-host chain head re-read and link-checked) and build a resume attestation naming the
   * DB's pause_seq / tamper_count (from the request; the DB checks them) and the chain head it verified.
   */
  async resumeCandidate(req: SignedRequest): Promise<{ msg: string; msgHash: string }> {
    const b = this.d.auth.verify(req, "resume-candidate");
    // a DB-only pause (e.g. monitor drift) also needs the signer's attestation; the DB checks its own cooldown
    const p = this.d.policy.paused();
    if (p && p.kind !== "tamper") throw new SignerRefused("rate-paused: clears by itself");
    const nb = this.d.policy.resumeNotBefore();
    const t = this.now();
    if (nb !== null && t < nb) throw new SignerRefused(`cooldown not over (not before ${new Date(nb).toISOString()})`);
    await assertClock(this.d.clock, this.d.cfg.maxClockSkewS);
    this.d.audit.assertNotRolledBack({ policy: this.d.policy.counter(), requests: this.d.auth.counter() });
    const head = await this.d.audit.checkHead();
    const dbSeq = Number(b.dbPauseSeq), dbCount = Number(b.dbTamperCount);
    if (!Number.isSafeInteger(dbSeq) || dbSeq < 1 || !Number.isSafeInteger(dbCount) || dbCount < 1) throw new SignerRefused("dbPauseSeq / dbTamperCount");
    const c = this.d.cfg;
    const body: ResumeBody = { v: 1, network: c.network, genesisHash: GENESIS_PINS[c.network], keyId: c.keyId, pauseSeq: dbSeq, tamperCount: dbCount,
      chainSeq: head.seq, chainHead: head.head, nonce: randomBytes(32).toString("base64url"), issuedAt: isoSeconds(t), expiry: isoSeconds(t + 300_000) };
    const msg = encodeResume(body);
    const msgHash = createHash("sha256").update(msg).digest("hex");
    this.pendingResume = { msg, msgHash, body, localSeq: p?.seq ?? 0, requester: String(b.requester), expiresAt: t + 300_000, signed: false };
    await this.log({ kind: "resume-candidate", msgHash, reason: `chain seq ${head.seq}`, at: t });
    return { msg: msg.toString("base64"), msgHash };
  }

  /** rev 21 resume step 2: the helper signs it against the requester's own resume-confirm; the helper counter is bumped. */
  async resumeConfirm(req: SignedRequest): Promise<{ msg: string; sig: string }> {
    const b = this.d.auth.verify(req, "resume-confirm");
    const r = this.pendingResume;
    if (!r || r.requester !== b.requester || b.msgHash !== r.msgHash || this.now() > r.expiresAt) throw new SignerRefused("no pending resume for this msgHash");
    if (!this.d.helper.signResume) throw new SignerRefused("helper cannot sign resume attestations");
    const sig = await this.d.helper.signResume(r.msg, req);
    const hc = this.d.helper.lastCounter?.() ?? this.d.helper.stateCounter?.();
    if (hc !== undefined) {
      try { this.d.audit.assertHelperAdvanced(hc); } catch (err) { await this.tamper("helper state rolled back (resume)"); throw err; }
    }
    const pk = await this.d.backend.publicKey();
    if (keyIdOf(pk) !== this.d.cfg.keyId || !verifyAttestation(r.msg, sig, pk)) throw new SignerRefused("self-verify failed (key mismatch)");
    r.signed = true;
    await this.log({ kind: "resume-attested", msgHash: r.msgHash, at: this.now() }, true); // counter-anchor bump recorded off-host
    return { msg: r.msg.toString("base64"), sig: Buffer.from(sig).toString("base64") };
  }

  /**
   * rev 21 resume step 3: mr-verifier's co-signature over THIS resume attestation (its own chain check agreed:
   * same chain seq / head), verified against its pinned key. Lifts the local tamper pause. The DB lifts its own
   * pause only through mr_tamper_resume with the same pair.
   */
  async resumeApply(req: SignedRequest): Promise<{ resumed: true }> {
    const b = this.d.auth.verify(req, "resume-apply");
    const r = this.pendingResume;
    const t = this.now();
    if (!r || !r.signed || r.requester !== b.requester || t > r.expiresAt) throw new SignerRefused("no signed pending resume");
    if (!this.d.cosignerPubkey) throw new SignerRefused("no pinned verifier key");
    const cm = Buffer.from(String(b.cosignMsg), "base64"), cs = Buffer.from(String(b.cosignSig), "base64");
    if (!verifyAttestation(cm, cs, this.d.cosignerPubkey)) throw new SignerRefused("verifier resume co-signature does not verify");
    const c = decodeResumeCosign(cm);
    if (c.attestHash !== r.msgHash || c.pauseSeq !== r.body.pauseSeq || c.chainSeq !== r.body.chainSeq || c.chainHead !== r.body.chainHead
        || c.network !== r.body.network || c.genesisHash !== r.body.genesisHash || c.keyId !== keyIdOf(this.d.cosignerPubkey)) {
      throw new SignerRefused("verifier co-signature does not match this resume");
    }
    const iss = Date.parse(c.issuedAt), exp = Date.parse(c.expiry);
    if (!(Math.abs(t - iss) <= 60_000 && exp > t && exp - t <= 15 * 60_000)) throw new SignerRefused("verifier co-signature issuedAt / expiry");
    const p = r.localSeq > 0 ? this.d.policy.resumeTamper(r.localSeq) : null;
    this.pendingResume = null;
    await this.log({ kind: "auto-resume-tamper", msgHash: r.msgHash, reason: p?.reason ?? "DB pause only", at: t }, true);
    return { resumed: true };
  }
}
export { ClockRefused, PolicyRefused, RequestRefused, TxCheckError, AbsenceRefused };
