import { afterEach, describe, expect, it } from "vitest";
import { parseCorsOrigins, buildCorsHeaders } from "./cors.js";

afterEach(() => {
  delete process.env.CORS_ORIGINS;
});

describe("CORS allowlist", () => {
  it("defaults to empty allowlist (no CORS headers)", () => {
    expect(parseCorsOrigins(undefined)).toEqual([]);
    expect(buildCorsHeaders("http://localhost:5173", [])).toBeNull();
  });

  it("reflects only allowlisted origins", () => {
    const list = parseCorsOrigins(
      "http://localhost:5173, https://console.example.com",
    );
    expect(list).toEqual([
      "http://localhost:5173",
      "https://console.example.com",
    ]);
    const ok = buildCorsHeaders("http://localhost:5173", list);
    expect(ok?.["Access-Control-Allow-Origin"]).toBe("http://localhost:5173");
    expect(buildCorsHeaders("https://evil.example", list)).toBeNull();
  });
});
