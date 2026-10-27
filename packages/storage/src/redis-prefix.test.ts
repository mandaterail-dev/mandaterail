import { describe, expect, it } from "vitest";
import { redisKeyPrefix, STATE_ENV_KEYS } from "./backend.js";

describe("REDIS_KEY_PREFIX (MainNet stack next to TestNet)", () => {
  it("defaults to mr and accepts mr-prefixed names", () => {
    expect(redisKeyPrefix({})).toBe("mr");
    expect(redisKeyPrefix({ REDIS_KEY_PREFIX: "mrm" })).toBe("mrm");
    expect(STATE_ENV_KEYS).toContain("REDIS_KEY_PREFIX");
  });
  it("refuses anything else", () => {
    for (const v of ["x", "mr:", "MRM", "mr*", "mr{a}", "mr" + "a".repeat(15)]) expect(() => redisKeyPrefix({ REDIS_KEY_PREFIX: v })).toThrow(/REDIS_KEY_PREFIX/);
  });
});
