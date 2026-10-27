/**
 * mr-piv-sign (§6.2 checks 1-5c, §6.2b, rev 10 §13; R43-P2-4). Sole card access. It signs only an attestation
 * that passes every check AND matches a confirm signed by a pinned requester, verified HERE with the helper's
 * own pinned keys, own nonce store and own timestamp window; mr-signer cannot supply the msgHash itself.
 * It keeps its own cap counter (independent of mr-signer's policy and of the DB limit).
 * Lockout (persisted, R43-P3; rev 21 automatic): 3 consecutive refusals lock 10 min; > 2 lockouts in 1 h is a
 * LONG lock of 6 h * 2^(n-1) (n = persisted long-lock count, exponent capped at 6). It clears by itself; there is no
 * unlock key, no unlock op and no state-reset path. The counter only goes up.
 * Resume attestations (MR-RESUME-ATTEST-v1, §23): signed only against a requester confirm for that exact msgHash,
 * fresh (issuedAt +-60 s, expiry <= 15 min), nonce once, never while locked; each one bumps the counter.
 */
import { createHash } from "node:crypto";
import { decodeAttestation, decodeResume, tamperCooldownS, type AttestBody } from "@mandaterail/storage";
import { GENESIS_PINS, type Network } from "../config.js";
import { DurableJson } from "../state.js";
import { RequestAuth, type SignedRequest } from "../requests.js";
import type { HelperLike } from "../signer.js";
import type { SignBackend } from "./backend.js";
import type { UsedStore } from "./used-store.js";

export interface HelperConfig {
  network: Network; keyId: string; payer: string; margin: number; operators: string[];
  maxSignsPerHour: number; maxSignsPer24h: number; // helper's own caps (<= 5)
}
export interface HelperState {
  counter: number;
  signs: number[];
  misses: number; lockedUntil: number; lockouts: number[];
  /** true while a LONG (backoff) lock is in force; clears by itself at lockedUntil */
  hard: boolean;
  /** rev 21: long locks so far (backoff exponent) */
  longLocks?: number;
  /** rev 21: resume-attestation nonces already signed (newest last, bounded) */
  resumeNonces?: string[];
}
export const initialHelperState = (): HelperState => ({ counter: 0, signs: [], misses: 0, lockedUntil: 0, lockouts: [], hard: false, longLocks: 0, resumeNonces: [] });
export const HELPER_LONG_LOCK_BASE_S = 21_600;
export class HelperRefused extends Error {}

export class PivHelper implements HelperLike {
  constructor(
    private readonly cfg: HelperConfig,
    private readonly backend: SignBackend,
    private readonly used: UsedStore,
    private readonly auth: RequestAuth, // the helper's OWN instance (own nonce file)
    private readonly st: DurableJson<HelperState>,
    private readonly now: () => number = Date.now,
  ) {
    if (backend.kind === "software-testnet-only" && cfg.network !== "testnet") throw new Error("PivHelper: the software backend is refused for a non-testnet helper (R43-P2-3)");
    if (cfg.maxSignsPer24h > 5 || cfg.maxSignsPerHour > 5) throw new Error("PivHelper: caps above 5");
  }

  status(): { locked: boolean; hard: boolean } {
    const s = this.st.get();
    const locked = this.now() < s.lockedUntil;
    return { locked, hard: locked && s.hard };
  }

  /** rev 21: read-only status (counter included) for the signer's status op. */
  statusWithCounter(): { locked: boolean; hard: boolean; counter: number; lockedUntil: number } { return { ...this.status(), counter: this.st.get().counter, lockedUntil: this.st.get().lockedUntil }; }

  private refuse(reason: string): never {
    const s = this.st.get();
    const t = this.now();
    s.misses += 1;
    if (s.misses >= 3) {
      s.misses = 0;
      s.lockedUntil = t + 10 * 60_000;
      s.lockouts = [...s.lockouts.filter((x) => x > t - 3_600_000), t];
      if (s.lockouts.length > 2) {
        s.longLocks = (s.longLocks ?? 0) + 1;
        s.hard = true;
        s.lockouts = [];
        s.lockedUntil = t + tamperCooldownS(HELPER_LONG_LOCK_BASE_S, s.longLocks) * 1000;
      }
    }
    s.counter += 1;
    this.st.put(s);
    throw new HelperRefused(reason);
  }

  check(msg: Uint8Array, p: { spendKey: string; msgHash: string }): AttestBody {
    const c = this.cfg;
    let b: AttestBody;
    try { b = decodeAttestation(msg); } catch (e) { return this.refuse(`1: ${(e as Error).message}`); } // 1 strict JCS + prefix
    if (b.network !== c.network || b.keyId !== c.keyId) this.refuse("2: network / keyId pin"); // 2
    if (b.sender !== c.payer) this.refuse("3: sender is not the pinned payer"); // 3
    const h = createHash("sha256").update(msg).digest("hex");
    if (`${b.store}/${b.spendId}` !== p.spendKey || h !== p.msgHash) this.refuse("4: requester confirm / msgHash mismatch"); // 4
    const t = this.now();
    const exp = Date.parse(b.expiry);
    if (!(exp > t && exp - t <= 15 * 60_000)) this.refuse("5: expiry"); // 5
    if (b.genesisHash !== GENESIS_PINS[b.network]) this.refuse("5a: genesis pin"); // 5a
    const need = b.lastValid + c.margin;
    if (b.round < need) this.refuse("5b: round");
    for (const o of b.observations) {
      if (o.round < need) this.refuse("5b: observation round");
      if (o.method === "idx404" ? o.idxRound < need : (o.method === "blockscan" || o.method === "blockscan-full") ? o.idxRound !== b.lastValid : true) this.refuse("5b: idxRound rule");
    }
    const ops = new Set(b.observations.map((o) => o.operator));
    if (b.observations.length < 2 || b.observations.length > 4 || ops.size < 2 || [...ops].some((o) => !c.operators.includes(o))) this.refuse("5c: observations / operators"); // 5c
    return b;
  }

  /** R44-P3-1: reported in each sign reply so mr-signer anchors it off-host. */
  counter(): number { return this.st.get().counter; }
  stateCounter(): number { return this.st.get().counter; }

  /** rev 21: sign a resume attestation (own checks; requester confirm op "resume-confirm" over this msgHash). */
  async signResume(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array> {
    if (this.status().locked) throw new HelperRefused(this.status().hard ? "long-locked" : "locked");
    let body;
    try { body = this.auth.verify(confirm, "resume-confirm"); } catch (e) { return this.refuse(`resume confirm: ${(e as Error).message}`); }
    let b;
    try { b = decodeResume(msg); } catch (e) { return this.refuse(`resume 1: ${(e as Error).message}`); }
    const c = this.cfg, t = this.now();
    if (b.network !== c.network || b.keyId !== c.keyId || b.genesisHash !== GENESIS_PINS[c.network]) this.refuse("resume 2: network / keyId / genesis pin");
    if (createHash("sha256").update(msg).digest("hex") !== String(body.msgHash)) this.refuse("resume 3: confirm msgHash mismatch");
    const iss = Date.parse(b.issuedAt), exp = Date.parse(b.expiry);
    if (!(Math.abs(t - iss) <= 60_000 && exp > t && exp - t <= 15 * 60_000)) this.refuse("resume 4: issuedAt / expiry");
    const s = this.st.get();
    const used = s.resumeNonces ?? [];
    if (used.includes(b.nonce)) this.refuse("resume 5: nonce already used");
    this.st.put({ ...s, misses: 0, counter: s.counter + 1, resumeNonces: [...used, b.nonce].slice(-1000) }); // counter bump before the signature exists
    return this.backend.sign(msg);
  }

  async sign(msg: Uint8Array, confirm: SignedRequest): Promise<Uint8Array> {
    if (this.status().locked) throw new HelperRefused(this.status().hard ? "long-locked" : "locked");
    let body;
    try { body = this.auth.verify(confirm, "confirm"); } catch (e) { return this.refuse(`confirm: ${(e as Error).message}`); }
    const spendKey = `${String(body.store)}/${String(body.spendId)}`;
    this.check(msg, { spendKey, msgHash: String(body.msgHash) });
    const s = this.st.get();
    const t = this.now();
    s.signs = s.signs.filter((x) => x > t - 86_400_000);
    if (s.signs.filter((x) => x > t - 3_600_000).length >= this.cfg.maxSignsPerHour) throw new HelperRefused("helper cap: signs per hour");
    if (s.signs.length >= this.cfg.maxSignsPer24h) throw new HelperRefused("helper cap: signs per 24 h");
    if (this.used.has(spendKey)) this.refuse("used: spend already signed");
    this.used.markUsed(spendKey, String(body.msgHash));
    this.st.put({ ...s, signs: [...s.signs, t], misses: 0, counter: s.counter + 1 }); // counted before the signature exists
    return this.backend.sign(msg);
  }
}
