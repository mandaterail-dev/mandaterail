import { describe, expect, it } from "vitest";
import {
  InsecureDevOperatorAuth,
  UnimplementedOperatorAttestationVerifier,
} from "./operator-attestation.js";
import { OPERATOR_TOKEN_HEADER } from "./insecure-dev.js";

describe("OperatorAttestation stub", () => {
  it("UnimplementedOperatorAttestationVerifier returns 501 for all kinds", async () => {
    const v = new UnimplementedOperatorAttestationVerifier();
    for (const kind of ["device", "hsm", "vault"] as const) {
      const r = await v.verify({ kind, sessionId: "sess-1" });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.status).toBe(501);
        expect(r.error).toBe("operator_attestation_unimplemented");
      }
    }
  });

  it("InsecureDevOperatorAuth wraps the token shim only", () => {
    expect(InsecureDevOperatorAuth.header).toBe(OPERATOR_TOKEN_HEADER);
    expect(typeof InsecureDevOperatorAuth.authorize).toBe("function");
  });
});
