import { afterEach, describe, expect, it } from "vitest";
import { checkMainnetEnvGate, isTrustedLocalRequest } from "./index.js";

const good = {
  NETWORK: "mainnet",
  STATE_BACKEND: "redis+postgres",
  FEE_PAYER: "FEE",
  REQUESTER_ALLOWLIST: "ADDR",
  OPERATOR_ATTESTATION_MODE: "signed-challenge",
} as NodeJS.ProcessEnv;

describe("T6 MainNet env gate", () => {
  it("TestNet: no-op", () => {
    expect(checkMainnetEnvGate({ requireFeePayer: true }, { ALLOW_INSECURE_DEV: "1", ALGORAND_MNEMONIC: "x" })).toEqual({ ok: true });
  });
  it("clean MainNet env passes", () => {
    expect(checkMainnetEnvGate({ requireFeePayer: true, requireRequesterAllowlist: true }, good)).toEqual({ ok: true });
  });
  it("refuses each forbidden dev switch, token-lab, mnemonics; names only, never values", () => {
    const r = checkMainnetEnvGate({}, {
      ...good,
      ALLOW_INSECURE_DEV: "1", AC2_BRIDGE_AUTO_LOCAL: "true", DEV_ALLOW_UNSIGNED: "yes", DEMO_MOCK_FACILITATOR: "true",
      OPERATOR_ATTESTATION_MODE: "token-lab", AC2_OPERATOR_TOKEN: "tok-secret",
      ALGORAND_MNEMONIC: "abandon secret words", PAYER_MNEMONIC: "more secret",
    });
    expect(r.ok).toBe(false);
    const text = r.ok ? "" : r.problems.join("\n");
    for (const k of ["ALLOW_INSECURE_DEV", "AC2_BRIDGE_AUTO_LOCAL", "DEV_ALLOW_UNSIGNED", "DEMO_MOCK_FACILITATOR", "token-lab", "AC2_OPERATOR_TOKEN", "ALGORAND_MNEMONIC", "PAYER_MNEMONIC"]) {
      expect(text).toContain(k);
    }
    expect(text).not.toMatch(/secret/);
  });
  it("disabled flags (0/false) are fine; ALLOW_MAINNET alone triggers the gate", () => {
    expect(checkMainnetEnvGate({}, { ...good, ALLOW_INSECURE_DEV: "0", AC2_BRIDGE_AUTO_LOCAL: "false" }).ok).toBe(true);
    expect(checkMainnetEnvGate({}, { ALLOW_MAINNET: "1" }).ok).toBe(false);
  });
  it("requires a persistent backend, FEE_PAYER and REQUESTER_ALLOWLIST when asked", () => {
    for (const STATE_BACKEND of [undefined, "memory"]) {
      const r = checkMainnetEnvGate({}, { ...good, STATE_BACKEND });
      expect(r.ok ? "" : r.problems.join()).toContain("STATE_BACKEND");
    }
    const r = checkMainnetEnvGate({ requireFeePayer: true, requireRequesterAllowlist: true }, { ...good, FEE_PAYER: "", REQUESTER_ALLOWLIST: "" });
    expect(r.ok ? "" : r.problems.join()).toMatch(/FEE_PAYER.*REQUESTER_ALLOWLIST/);
  });
});

describe("T9 no localhost trust on MainNet", () => {
  const prev = process.env.NETWORK;
  afterEach(() => { if (prev === undefined) delete process.env.NETWORK; else process.env.NETWORK = prev; });
  it("loopback is trusted on TestNet (hops 0) but never on MainNet", () => {
    const req = { remoteAddress: "127.0.0.1", header: () => undefined, trustedProxyHops: 0 };
    process.env.NETWORK = "testnet";
    expect(isTrustedLocalRequest(req)).toBe(true);
    process.env.NETWORK = "mainnet";
    expect(isTrustedLocalRequest(req)).toBe(false);
    expect(isTrustedLocalRequest({ ...req, remoteAddress: "::1" })).toBe(false);
  });
});
