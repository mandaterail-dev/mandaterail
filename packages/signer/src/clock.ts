/** R42-P3-1: refuse to sign unless chrony is synchronised and |offset| <= maxClockSkewS (~5 s). */
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export interface ClockStatus { synced: boolean; offsetS: number; stratum: number }
export type ClockSource = () => Promise<ClockStatus>;
export class ClockRefused extends Error {}

/** Parses `chronyc -c tracking` CSV (fields: refid, name, stratum, reftime, system-offset, ..., leap status). */
export function parseChronyTracking(csv: string): ClockStatus {
  const f = csv.trim().split(",");
  if (f.length < 14) throw new ClockRefused("chronyc tracking: unexpected output");
  const stratum = Number(f[2]);
  const offsetS = Number(f[4]);
  const leap = f[f.length - 1]!.trim();
  if (!Number.isFinite(stratum) || !Number.isFinite(offsetS)) throw new ClockRefused("chronyc tracking: unparsable");
  return { synced: leap !== "Not synchronised" && stratum > 0 && stratum < 16, offsetS, stratum };
}

export const chronySource: ClockSource = async () => {
  const { stdout } = await promisify(execFile)("chronyc", ["-c", "tracking"], { timeout: 3000 });
  return parseChronyTracking(stdout);
};

export async function assertClock(src: ClockSource, maxSkewS: number): Promise<void> {
  let s: ClockStatus;
  try {
    s = await src();
  } catch (e) {
    throw new ClockRefused(`clock status unavailable: ${(e as Error).message}`);
  }
  if (!s.synced) throw new ClockRefused("clock is not synchronised");
  if (!(Math.abs(s.offsetS) <= maxSkewS)) throw new ClockRefused(`clock offset ${s.offsetS.toFixed(3)} s exceeds ${maxSkewS} s`);
}
