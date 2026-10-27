/**
 * P2-T10 kill switch. Paid routes (demo-api /paid/*) and the bridge /sign refuse
 * with 503 `paused` while paused. Reads and /health stay up.
 *
 * Paused when EITHER:
 *  - env MANDATERAIL_PAUSE=1 (needs a restart to flip), or
 *  - the pause file exists (default /etc/mandaterail/PAUSE; override MANDATERAIL_PAUSE_FILE).
 *    Checked on every request, so `touch` / `rm` flips it with no restart.
 * Fail closed: any stat error other than ENOENT (e.g. EACCES) counts as paused.
 */
import { statSync } from "node:fs";

export const DEFAULT_PAUSE_FILE = "/etc/mandaterail/PAUSE";

export function pauseState(env: NodeJS.ProcessEnv = process.env): { paused: boolean; reason?: "env" | "file" | "file_unreadable" } {
  if ((env.MANDATERAIL_PAUSE ?? "").trim() === "1") return { paused: true, reason: "env" };
  const f = (env.MANDATERAIL_PAUSE_FILE ?? "").trim() || DEFAULT_PAUSE_FILE;
  try {
    statSync(f);
    return { paused: true, reason: "file" };
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { paused: false };
    return { paused: true, reason: "file_unreadable" };
  }
}

export const PAUSED_BODY = { error: "paused", message: "MandateRail is paused by the operator" } as const;
