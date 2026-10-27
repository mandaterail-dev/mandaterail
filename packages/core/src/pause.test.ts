import { mkdtempSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { pauseState } from "./pause.js";

describe("P2-T10 pause switch", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "mr-pause-"));
  const f = path.join(dir, "PAUSE");
  it("is off when neither env nor file", () => {
    expect(pauseState({ MANDATERAIL_PAUSE_FILE: f }).paused).toBe(false);
  });
  it("env MANDATERAIL_PAUSE=1 pauses", () => {
    expect(pauseState({ MANDATERAIL_PAUSE: "1", MANDATERAIL_PAUSE_FILE: f })).toEqual({ paused: true, reason: "env" });
  });
  it("the pause file pauses without restart", () => {
    writeFileSync(f, "");
    expect(pauseState({ MANDATERAIL_PAUSE_FILE: f })).toEqual({ paused: true, reason: "file" });
  });
  it("fails closed when the path can't be stat'ed (ENOTDIR)", () => {
    const notDir = path.join(dir, "file");
    writeFileSync(notDir, "");
    expect(pauseState({ MANDATERAIL_PAUSE_FILE: path.join(notDir, "PAUSE") }).paused).toBe(true);
    void mkdirSync; void chmodSync;
  });
});
