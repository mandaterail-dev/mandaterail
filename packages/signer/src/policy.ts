/**
 * Policy engine (rev 10 §13; rev 21 §23 fully automatic): caps, per-hour/day limits, persistent monotonic counters,
 * time window (limits over rolling windows) and automatic pauses. Fail-closed: any state error refuses.
 *
 * Two pause kinds, no human pause or unpause path:
 *  - "rate": too many refusals in an hour. It clears by itself when the 1 h refusal window rolls (until = oldest
 *    counted refusal + 1 h). The cap refusals themselves (hourly / daily / amount) never pause: they just refuse
 *    until the rolling window frees room.
 *  - "tamper": an integrity anomaly (rollback, chain / echo mismatch, helper rollback, failed page, provider or
 *    manifest drift, unexpected KMS Sign). It resumes only after the cooldown (base * 2^(n-1), n = tamper count,
 *    exponent capped; MainNet base >= 6 h) AND a fresh 2-of-2 resume quorum (signer.ts resume*, DB v16).
 *    tamperCount is persisted locally and in the DB (mr_pause_state); a resume never lowers it.
 */
import type { PolicyConfig } from "./config.js";
import { DurableJson } from "./state.js";
import { tamperCooldownS } from "@mandaterail/storage";

export type PauseKind = "rate" | "tamper";
export interface Pause { at: number; reason: string; kind: PauseKind; until?: number; seq?: number }
export interface PolicyState {
  counter: number;
  releases: { at: number; spendKey: string; amountMicro: string }[]; // last 48 h
  refusals: number[]; // timestamps, last 1 h
  paused: null | Pause;
  /** rev 21: tamper pauses so far (backoff), and the local tamper pause sequence */
  tamperCount?: number;
  tamperSeq?: number;
  lastTamperAt?: number;
}
export const initialPolicyState = (): PolicyState => ({ counter: 0, releases: [], refusals: [], paused: null, tamperCount: 0, tamperSeq: 0 });
export class PolicyRefused extends Error {}

const HOUR = 3_600_000;
const DAY = 86_400_000;
export const TAMPER_DECAY_MS = 30 * DAY;

export class PolicyEngine {
  constructor(private readonly cfg: PolicyConfig, private readonly st: DurableJson<PolicyState>, private readonly now: () => number = Date.now) {}

  /**
   * The current pause, after clearing a rate pause whose window has rolled. Returns `cleared` when this call
   * lifted one (the caller logs + pages the auto-resume).
   */
  poll(): { paused: Pause | null; cleared: Pause | null } {
    const s = this.st.get();
    const p = s.paused;
    if (p && p.kind === "rate" && p.until !== undefined && this.now() >= p.until) {
      s.paused = null;
      s.refusals = [];
      s.counter += 1;
      this.st.put(s);
      return { paused: null, cleared: p };
    }
    return { paused: p, cleared: null };
  }
  paused(): Pause | null { return this.poll().paused; }
  counter(): number { return this.st.get().counter; }
  tamperCount(): number { return this.st.get().tamperCount ?? 0; }

  /** When the current tamper pause may resume (cooldown over), or null if not tamper-paused. */
  resumeNotBefore(): number | null {
    const s = this.st.get();
    if (!s.paused || s.paused.kind !== "tamper") return null;
    return s.paused.at + tamperCooldownS(this.cfg.tamperBaseCooldownS ?? 21_600, s.tamperCount ?? 1) * 1000;
  }

  /** Throws unless a release of `amountMicro` for `spendKey` is allowed right now (no state change). */
  check(spendKey: string, amountMicro: bigint): void {
    const p = this.paused();
    const s = this.st.get();
    const t = this.now();
    if (p) throw new PolicyRefused(`signer paused (${p.kind}): ${p.reason}`);
    const h = new Date(t).getUTCHours();
    const [a, b] = this.cfg.windowUtcHours;
    if (!(a <= h && h < b)) throw new PolicyRefused(`outside the signing window ${a}-${b} UTC`);
    if (amountMicro > this.cfg.maxAmountMicro) throw new PolicyRefused("amount above the per-release cap");
    if (s.releases.some((r) => r.spendKey === spendKey)) throw new PolicyRefused("spend already released by this signer");
    if (s.releases.filter((r) => r.at > t - HOUR).length >= this.cfg.maxReleasesPerHour) throw new PolicyRefused("hourly release limit");
    const today = s.releases.filter((r) => r.at > t - DAY); // R43-P3: rolling 24 h, not the UTC day
    if (today.length >= this.cfg.maxReleasesPerDay) throw new PolicyRefused("daily release limit");
    const sum = today.reduce((x, r) => x + BigInt(r.amountMicro), 0n);
    if (sum + amountMicro > this.cfg.maxReleasedMicroPerDay) throw new PolicyRefused("daily released amount limit");
  }

  /** Records a signed release (before the signature leaves the host: counts even if delivery fails). */
  record(spendKey: string, amountMicro: bigint): void {
    this.check(spendKey, amountMicro);
    const s = this.st.get();
    const t = this.now();
    s.releases = [...s.releases.filter((r) => r.at > t - 48 * HOUR), { at: t, spendKey, amountMicro: amountMicro.toString() }];
    s.counter += 1;
    this.st.put(s);
  }

  /** Every refusal counts. An anomaly is a tamper pause; too many refusals in an hour is a rate pause. Returns a NEW pause. */
  refusal(reason: string, anomaly: boolean): Pause | null {
    if (anomaly) return this.tamper(reason);
    const s = this.st.get();
    const t = this.now();
    s.refusals = [...s.refusals.filter((x) => x > t - HOUR), t];
    let fresh: Pause | null = null;
    if (!s.paused && s.refusals.length >= this.cfg.anomalyPauseRefusalsPerHour) {
      fresh = s.paused = { at: t, kind: "rate", reason: `${s.refusals.length} refusals within 1 h`, until: s.refusals[0]! + HOUR };
    }
    s.counter += 1;
    this.st.put(s);
    return fresh;
  }

  /** A tamper / integrity pause (machine detectors only). A tamper during a rate pause upgrades it. Returns a NEW pause. */
  tamper(reason: string): Pause | null {
    const s = this.st.get();
    const t = this.now();
    if (s.paused?.kind === "tamper") { s.counter += 1; this.st.put(s); return null; }
    const decayed = s.lastTamperAt !== undefined && t - s.lastTamperAt > TAMPER_DECAY_MS;
    s.tamperCount = decayed ? 1 : (s.tamperCount ?? 0) + 1;
    s.tamperSeq = (s.tamperSeq ?? 0) + 1;
    s.lastTamperAt = t;
    const p: Pause = { at: t, kind: "tamper", reason: `anomaly: ${reason}`, seq: s.tamperSeq };
    s.paused = p;
    s.counter += 1;
    this.st.put(s);
    return p;
  }

  /** Lifts a tamper pause. Only MrSigner.resumeApply calls it, after verifying the 2-of-2 resume quorum. */
  resumeTamper(seq: number): Pause {
    const s = this.st.get();
    const p = s.paused;
    if (!p || p.kind !== "tamper" || p.seq !== seq) throw new PolicyRefused("no tamper pause with this sequence");
    const nb = this.resumeNotBefore()!;
    if (this.now() < nb) throw new PolicyRefused(`cooldown not over (not before ${new Date(nb).toISOString()})`);
    s.paused = null;
    s.refusals = [];
    s.counter += 1;
    this.st.put(s);
    return p;
  }
}
