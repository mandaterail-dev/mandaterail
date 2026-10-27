/**
 * Second verifier (v12, §15): an independent service with its own key, its own pinned providers (operators
 * disjoint from the signer's observations), its own request nonces, its own caps and pause. It co-signs a
 * primary attestation only after re-deriving the stored transaction and re-proving absence itself; the DB
 * requires both signatures (quorum 2 on MainNet). It never sees the signer's key and the signer never sees its.
 *
 * Deploy on a different host / account from mr-signer (deploy/verifier/); nothing is provisioned here.
 */
import { SoftkeyFileEd25519Backend } from "../piv/softkey-file.js";
import { createHash, randomBytes } from "node:crypto";
import { decodeAttestation, decodeResume, encodeCosign, encodeResumeCosign, isoSeconds, keyIdOf, tamperCooldownS, verifyAttestation, type CosignBody, type Observation, type ResumeCosignBody, type SignedTxnKind } from "@mandaterail/storage";
import { GENESIS_PINS, type SignerConfig } from "../config.js";
import { checkSignedTxn } from "../txcheck.js";
import type { ChainProbe } from "../providers.js";
import type { RequestAuth, SignedRequest } from "../requests.js";
import type { SignBackend } from "../piv/backend.js";
import type { DurableJson } from "../state.js";
import { assertClock, type ClockSource } from "../clock.js";

export interface VerifierConfig {
  signer: SignerConfig; // the pins it shares with the signer (network, payer, merchant, ASA, fees, margin, keyId = PRIMARY keyId)
  primaryPubkey: Uint8Array; // the pinned primary attestation key
  cosignerKeyId: string; // its own key id (must differ)
  providers: { host: string; operator: string; kind: "indexer" | "algod" | "blockscan-full" }[]; // its own pinned providers
  maxPerHour: number; maxPer24h: number; // <= 5
  attestTtlS: number;
}
export interface VerifierState { counter: number; signs: number[]; used: string[]; paused: null | { at: number; reason: string };
  /** rev 21: tamper pauses so far (backoff) and resume nonces co-signed */
  tamperCount?: number; resumeNonces?: string[];
  /** R62-P3-2: a resume co-signed but not yet observed applied (DB resumed -> signer logged auto-resume-tamper) */
  pendingResume?: null | { attestHash: string; pauseSeq: number; chainSeq: number; at: number } }
export const initialVerifierState = (): VerifierState => ({ counter: 0, signs: [], used: [], paused: null });
export class VerifierRefused extends Error {}
const ROUND_S = 2.5;

export class SecondVerifier {
  private readonly now: () => number;
  constructor(private readonly c: VerifierConfig, private readonly d: {
    auth: RequestAuth; probes: ChainProbe[]; backend: SignBackend; st: DurableJson<VerifierState>; clock: ClockSource;
    page: (subject: string, body: string) => Promise<void>; now?: () => number;
    /** rev 21: its own independent chain check + reconcile state, run before co-signing a resume */
    resumeChecks?: (chainSeq: number, chainHead: string) => Promise<void>;
    /** rev 21: pause cooldown base (s); MainNet floor 6 h */
    tamperBaseCooldownS?: number;
    /** R62-P3-2: true once the signer's chain (after chainSeq) holds auto-resume-tamper for exactly this attestation */
    resumeObservedCheck?: (chainSeq: number, attestHash: string) => Promise<boolean>;
  }) {
    this.now = d.now ?? Date.now;
    if (c.cosignerKeyId === c.signer.keyId) throw new Error("second verifier: its key must differ from the signer key");
    if (keyIdOf(c.primaryPubkey) !== c.signer.keyId) throw new Error("second verifier: primary pubkey does not match the pinned keyId");
    if (c.maxPer24h > 5 || c.maxPerHour > 5) throw new Error("second verifier: caps above 5");
    if (c.signer.network === "mainnet" && (d.tamperBaseCooldownS ?? 21_600) < 21_600) throw new Error("second verifier: tamper cooldown below the MainNet floor of 6 h");
    // rev 24 (§24.8): a softkey-file backend is accepted on MainNet only if its own gate passed for mainnet
    // (manifest pin verifierSoftkey.mainnet = true AND softkey.allowMainnet); the constructor refuses otherwise.
    const softkeyMainnetOk = d.backend instanceof SoftkeyFileEd25519Backend && d.backend.gatePassed === "mainnet";
    // R75-P2-1: key order (docs/ops/kms-key-order.md): the only active MainNet co-signer is aliyun-softkey; AWS KMS is a
    // locked backup, cloudkms is refused (R48-P2-1: the signer is on Google), YubiKey is not in the order
    if (c.signer.network === "mainnet" && !softkeyMainnetOk) throw new Error(`second verifier: MainNet co-signer must be the manifest-gated aliyun-softkey (got ${d.backend.kind}); awskms is a locked backup and cloudkms is refused`);
  }

  /**
   * R66-P3-2: compare-and-set. `prev` is the state the decision was made on, read AFTER the last await; if anything
   * was written since (another request interleaved at an await), the write is refused instead of clobbering it.
   */
  private commit(prev: VerifierState, next: Omit<VerifierState, "counter">): void {
    if (this.d.st.get().counter !== prev.counter) throw new VerifierRefused("verifier state changed concurrently; retry");
    this.d.st.put({ ...next, counter: prev.counter + 1 } as VerifierState);
  }

  private async refuse(reason: string, anomaly = false): Promise<never> {
    if (anomaly) {
      const s = this.d.st.get();
      // R65-P3-2: an anomaly after a co-signed resume (marker pending) supersedes it: a NEW pause, later than the marker,
      // so the older resume can't lift it and the driver mirrors it into the DB as a new tamper pause.
      // R66-P3-2: the marker is cleared (one supersede per marker), and a supersede does not bump tamperCount again:
      // the pause it replaces was already counted, and the DB (still paused, idempotent) does not count it either.
      const supersede = !!s.pendingResume && this.now() >= s.pendingResume.at;
      if (!s.paused || supersede) {
        this.commit(s, { ...s, paused: { at: Math.max(this.now(), (s.pendingResume?.at ?? 0) + 1), reason: `anomaly: ${reason}` },
          tamperCount: s.paused ? (s.tamperCount ?? 1) : (s.tamperCount ?? 0) + 1, pendingResume: supersede ? null : s.pendingResume ?? null });
        try { await this.d.page(supersede ? "[verifier] pause-tamper (supersedes the co-signed resume)" : "[verifier] pause-tamper", reason); } catch { /* still refuse */ }
      }
    }
    try { await this.d.page(`[verifier] ${anomaly ? "ANOMALY " : ""}refused`, reason); } catch { /* still refuse */ }
    throw new VerifierRefused(reason);
  }

  async cosign(req: SignedRequest): Promise<{ msg: string; sig: string }> {
    let b;
    try { b = this.d.auth.verify(req, "cosign"); } catch (e) { return this.refuse(`request: ${(e as Error).message}`); }
    const st = this.d.st.get();
    if (st.paused) return this.refuse(`paused: ${st.paused.reason}`);
    const c = this.c, sc = c.signer;
    try { await assertClock(this.d.clock, sc.maxClockSkewS); } catch (e) { return this.refuse((e as Error).message); }
    // 1. the primary attestation: pinned key, canonical, this network
    const am = Buffer.from(String(b.attestMsg), "base64"), as = Buffer.from(String(b.attestSig), "base64");
    if (!verifyAttestation(am, as, c.primaryPubkey)) return this.refuse("primary attestation signature does not verify", true);
    let a;
    try { a = decodeAttestation(am); } catch (e) { return this.refuse(`primary attestation: ${(e as Error).message}`, true); }
    if (a.network !== sc.network || a.genesisHash !== GENESIS_PINS[sc.network] || a.keyId !== sc.keyId || a.store !== b.store || a.spendId !== b.spendId) {
      return this.refuse("primary attestation pins / spend", true);
    }
    // 2. re-derive the stored signed bytes itself
    let f;
    try { f = checkSignedTxn(Buffer.from(String(b.signedTxn), "base64"), String(b.kind) as SignedTxnKind, sc); } catch (e) { return this.refuse(`signed txn: ${(e as Error).message}`, true); }
    if (f.txId !== a.txId || f.firstValid !== a.firstValid || f.lastValid !== a.lastValid || f.groupId !== a.groupId || f.sender !== a.sender) {
      return this.refuse("attested fields differ from the signed bytes", true);
    }
    const row = b.row as Record<string, string | number>;
    const t = this.now();
    const lvEst = Date.parse(String(row.submitAt)) + (f.lastValid - Number(row.submitRound)) * ROUND_S * 1000;
    if (!Number.isFinite(lvEst) || t < lvEst) return this.refuse("too early: lastValid not yet passed by the submit-time estimate");
    // 3. caps and one co-signature per spend
    const key = `${a.store}/${a.spendId}`;
    const recent = st.signs.filter((x) => x > t - 86_400_000);
    if (recent.filter((x) => x > t - 3_600_000).length >= c.maxPerHour || recent.length >= c.maxPer24h) return this.refuse("verifier cap");
    if (st.used.includes(key)) return this.refuse("spend already co-signed", true);
    // 4. its own absence check, on operators the signer did not use
    const primOps = new Set(a.observations.map((o) => o.operator));
    const mine = this.d.probes.filter((p) => !primOps.has(p.provider.operator));
    if (mine.length < 1) return this.refuse("no provider independent of the signer's operators");
    const need = f.lastValid + sc.margin;
    const obs: Observation[] = [];
    for (const p of mine) {
      const r = await p.probe(f.memberTxIds, f.firstValid, f.lastValid);
      if (r.kind === "present") return this.refuse(`${p.provider.host} (${p.provider.operator}) shows the transaction present`, true);
      if (r.kind === "error") continue;
      if (r.genesis !== GENESIS_PINS[sc.network]) return this.refuse(`${p.provider.host} genesis`, true);
      if (r.round >= need && (r.method === "idx404" ? r.idxRound >= need : r.idxRound === f.lastValid)) {
        obs.push({ at: isoSeconds(this.now()), idxRound: r.idxRound, method: r.method, operator: p.provider.operator, provider: p.provider.host, round: r.round });
      }
    }
    if (obs.length < 1) return this.refuse("independent absence not proven (no provider past lastValid + margin)");
    // 5. record before signing, then sign and self-verify. R66-P3-2: re-read after the awaits above (clock, probes) and
    // re-check what another request may have changed meanwhile (a pause, the same spend, the caps); then CAS.
    const cur = this.d.st.get();
    if (cur.paused) return this.refuse(`paused: ${cur.paused.reason}`);
    if (cur.used.includes(key)) return this.refuse("spend already co-signed", true);
    const recentNow = cur.signs.filter((x) => x > t - 86_400_000);
    if (recentNow.filter((x) => x > t - 3_600_000).length >= c.maxPerHour || recentNow.length >= c.maxPer24h) return this.refuse("verifier cap");
    this.commit(cur, { ...cur, signs: [...recentNow, t], used: [...cur.used, key].slice(-10_000) });
    const body: CosignBody = {
      v: 1, network: sc.network, genesisHash: GENESIS_PINS[sc.network], keyId: c.cosignerKeyId, attestHash: createHash("sha256").update(am).digest("hex"),
      store: a.store, spendId: a.spendId, txId: a.txId, lastValid: a.lastValid, round: Math.min(...obs.map((o) => o.round)),
      nonce: randomBytes(32).toString("base64url"), expiry: isoSeconds(t + Math.min(c.attestTtlS, 900) * 1000), observations: obs.slice(0, 4),
    };
    const msg = encodeCosign(body);
    const sig = await this.d.backend.sign(msg);
    const pk = await this.d.backend.publicKey();
    if (keyIdOf(pk) !== c.cosignerKeyId || !verifyAttestation(msg, sig, pk)) return this.refuse("self-verify failed (key mismatch)", true);
    try { await this.d.page("[verifier] co-signed", key); } catch { /* the DB and signer pages still show the release */ }
    return { msg: msg.toString("base64"), sig: Buffer.from(sig).toString("base64") };
  }

  /**
   * rev 21: co-sign the signer's resume attestation after re-running its OWN checks (resumeChecks: the off-host
   * chain walked and link-checked to the signer's named head, no open reconcile mismatch). Freshness (+-60 s,
   * expiry <= 15 min) and a single-use nonce. If the verifier is itself tamper-paused, its own cooldown must be
   * over; co-signing then lifts its pause (paged).
   */
  async resumeCosign(req: SignedRequest): Promise<{ msg: string; sig: string }> {
    let b;
    try { b = this.d.auth.verify(req, "resume-cosign"); } catch (e) { return this.refuse(`request: ${(e as Error).message}`); }
    const c = this.c, sc = c.signer, t = this.now();
    try { await assertClock(this.d.clock, sc.maxClockSkewS); } catch (e) { return this.refuse((e as Error).message); }
    const sm = Buffer.from(String(b.resumeMsg), "base64"), ss = Buffer.from(String(b.resumeSig), "base64");
    if (!verifyAttestation(sm, ss, c.primaryPubkey)) return this.refuse("resume attestation signature does not verify", true);
    let r;
    try { r = decodeResume(sm); } catch (e) { return this.refuse(`resume attestation: ${(e as Error).message}`, true); }
    if (r.network !== sc.network || r.genesisHash !== GENESIS_PINS[sc.network] || r.keyId !== sc.keyId) return this.refuse("resume pins", true);
    const iss = Date.parse(r.issuedAt), exp = Date.parse(r.expiry);
    if (!(Math.abs(t - iss) <= 60_000 && exp > t && exp - t <= 15 * 60_000)) return this.refuse("resume issuedAt / expiry");
    const pre = (st: VerifierState) => {
      if ((st.resumeNonces ?? []).includes(r.nonce)) return this.refuse("resume nonce already co-signed", true);
      if (st.paused) {
        const nb = st.paused.at + tamperCooldownS(this.d.tamperBaseCooldownS ?? 21_600, st.tamperCount ?? 1) * 1000;
        if (t < nb) return this.refuse(`verifier cooldown not over (not before ${new Date(nb).toISOString()})`);
      }
      return null;
    };
    { const e = pre(this.d.st.get()); if (e) return e; }
    if (!this.d.resumeChecks) return this.refuse("no resume checks configured");
    try { await this.d.resumeChecks(r.chainSeq, r.chainHead); } catch (e) { return this.refuse(`resume check: ${(e as Error).message}`, true); }
    // R66-P3-2: re-read after the await (an anomaly may have paused it meanwhile: a fresh cooldown applies) and CAS
    const st = this.d.st.get();
    { const e = pre(st); if (e) return e; }
    // R62-P3-2: its own pause stays until the resume is observed applied (resumeObserved); only the pending marker is set
    const attestHash = createHash("sha256").update(sm).digest("hex");
    this.commit(st, { ...st, pendingResume: { attestHash, pauseSeq: r.pauseSeq, chainSeq: r.chainSeq, at: t }, resumeNonces: [...(st.resumeNonces ?? []), r.nonce].slice(-1000) });
    const body: ResumeCosignBody = { v: 1, network: sc.network, genesisHash: GENESIS_PINS[sc.network], keyId: c.cosignerKeyId, attestHash: createHash("sha256").update(sm).digest("hex"),
      pauseSeq: r.pauseSeq, chainSeq: r.chainSeq, chainHead: r.chainHead, nonce: randomBytes(32).toString("base64url"), issuedAt: isoSeconds(t), expiry: isoSeconds(t + 300_000) };
    const msg = encodeResumeCosign(body);
    const sig = await this.d.backend.sign(msg);
    const pk = await this.d.backend.publicKey();
    if (keyIdOf(pk) !== c.cosignerKeyId || !verifyAttestation(msg, sig, pk)) return this.refuse("self-verify failed (key mismatch)", true);
    try { await this.d.page("[verifier] resume co-signed (own pause lifts once the resume is observed)", `pause ${r.pauseSeq} chain ${r.chainSeq}`); } catch { /* the signer and DB page too */ }
    return { msg: msg.toString("base64"), sig: Buffer.from(sig).toString("base64") };
  }
  /**
   * R62-P3-2: lift the verifier's own pause only after the co-signed resume was APPLIED: the signer's off-host chain,
   * after the attested head, holds auto-resume-tamper for exactly the attestation hash it co-signed (the signer writes
   * it only after the DB's mr_tamper_resume succeeded and the co-signature verified). The marker stays until observed or replaced (R63-P2-2).
   */
  /** R63-P2-2: read-only status for the resume driver (it mirrors a verifier pause into the DB, retries resumeObserved). */
  async status(req: SignedRequest): Promise<{ paused: null | { at: number; reason: string }; tamperCount: number; pendingResume: null | { pauseSeq: number; at: number } }> {
    try { this.d.auth.verify(req, "status"); } catch (e) { throw new VerifierRefused(`request: ${(e as Error).message}`); }
    const st = this.d.st.get();
    return { paused: st.paused, tamperCount: st.tamperCount ?? 0, pendingResume: st.pendingResume ? { pauseSeq: st.pendingResume.pauseSeq, at: st.pendingResume.at } : null };
  }

  async resumeObserved(req: SignedRequest): Promise<{ resumed: boolean }> {
    try { this.d.auth.verify(req, "resume-observed"); } catch (e) { return this.refuse(`request: ${(e as Error).message}`); }
    const st = this.d.st.get();
    const p = st.pendingResume;
    const t = this.now();
    if (!p) return this.refuse("no co-signed resume pending");
    // R63-P2-2: no expiry. The driver retries on every tick until the applied resume shows up in the signer chain; a
    // newer co-signed resume replaces the marker. (Lifting needs that exact attestation applied, so waiting is safe.)
    if (!this.d.resumeObservedCheck) return this.refuse("no resume observation check configured");
    let ok = false;
    try { ok = await this.d.resumeObservedCheck(p.chainSeq, p.attestHash); } catch (e) { return this.refuse(`resume observation: ${(e as Error).message}`); }
    if (!ok) return this.refuse("resume not observed in the signer chain yet");
    // R66-P3-2: re-read after the await; the marker must still be the one just observed (a supersede clears it, a newer
    // co-signed resume replaces it), then CAS
    const cur = this.d.st.get();
    if (!cur.pendingResume || cur.pendingResume.attestHash !== p.attestHash || cur.pendingResume.at !== p.at) {
      return this.refuse("the co-signed resume marker changed while it was being observed (superseded or replaced)");
    }
    // R65-P3-2: a pause newer than the co-signed resume stays (only a fresh 2-of-2 for the new DB pause lifts it)
    if (cur.paused && cur.paused.at > p.at) {
      this.commit(cur, { ...cur, pendingResume: null });
      try { await this.d.page("[verifier] resume observed, but a newer pause stays", `pause ${p.pauseSeq} resumed; newer: ${cur.paused.reason}`); } catch { /* best effort */ }
      return { resumed: false };
    }
    this.commit(cur, { ...cur, paused: null, pendingResume: null });
    try { await this.d.page(cur.paused ? "[verifier] auto-resume (own pause lifted after the observed resume)" : "[verifier] resume observed", `pause ${p.pauseSeq}`); } catch { /* best effort */ }
    return { resumed: true };
  }
}
