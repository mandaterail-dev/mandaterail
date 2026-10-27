import { describe, it, expect } from "vitest";
import algosdk from "algosdk";
import { verifyAc2Signature, canonicalMandateBytes } from "@mandaterail/core";
import type { IntentMandate } from "@mandaterail/schema";
import { LocalEd25519Signer } from "./local-signer.js";
import { HttpAc2BridgeSigner } from "./http-bridge-signer.js";

function unsignedFor(acct: algosdk.Account): Omit<IntentMandate, "signature"> {
  const now = new Date();
  const later = new Date(now.getTime() + 60 * 60 * 1000);
  return {
    id: "t-1",
    principal: acct.addr.toString(),
    agent: "did:example:agent",
    maxAmount: "1.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: later.toISOString(),
    revoked: false,
    nonce: "n-1",
    createdAt: now.toISOString(),
  };
}

describe("LocalEd25519Signer", () => {
  it("signs a mandate verifiable by core.verifyAc2Signature", async () => {
    const acct = algosdk.generateAccount();
    const signer = LocalEd25519Signer.fromAccount(acct);
    const unsigned = unsignedFor(acct);
    const { signature, publicKey, address } =
      await signer.signIntentMandate(unsigned);
    expect(signature.length).toBeGreaterThan(0);
    expect(publicKey).toBeTruthy();
    expect(address).toBe(acct.addr.toString());

    const mandate: IntentMandate = { ...unsigned, signature };
    const v = await verifyAc2Signature({
      mandate,
      principal: mandate.principal,
      signature,
    });
    expect(v.ok).toBe(true);
  });

  it("fromMnemonic round-trips", async () => {
    const acct = algosdk.generateAccount();
    const mn = algosdk.secretKeyToMnemonic(acct.sk);
    const signer = LocalEd25519Signer.fromMnemonic(mn);
    expect(signer.address).toBe(acct.addr.toString());
  });
});

describe("HttpAc2BridgeSigner", () => {
  it("builds SigningRequest with raw-ed25519 + display_hint json", () => {
    const acct = algosdk.generateAccount();
    const unsigned = unsignedFor(acct);
    const signer = new HttpAc2BridgeSigner({
      baseUrl: "http://127.0.0.1:8790",
      fetch: (async () => {
        throw new Error("should not fetch in this test");
      }) as typeof fetch,
    });
    const req = signer.buildSigningRequest(unsigned);
    expect(req.type).toBe("IntentMandate/v1");
    expect(req.sig_hint).toBe("raw-ed25519");
    expect(req.display_hint).toBe("json");
    expect(req.mandateId).toBe("t-1");
    const bytes = canonicalMandateBytes(unsigned);
    expect(req.message_b64).toBe(Buffer.from(bytes).toString("base64"));
    expect(req.message).toBe(new TextDecoder().decode(bytes));
  });

  it("POSTs /sign and returns signature (no OpenClaw)", async () => {
    const acct = algosdk.generateAccount();
    const unsigned = unsignedFor(acct);
    const local = LocalEd25519Signer.fromAccount(acct);
    const expected = await local.signIntentMandate(unsigned);

    const signer = new HttpAc2BridgeSigner({
      baseUrl: "http://bridge.test",
      fetch: (async (_url, init) => {
        expect(init?.method).toBe("POST");
        const body = JSON.parse(String(init?.body)) as { sig_hint: string };
        expect(body.sig_hint).toBe("raw-ed25519");
        return new Response(
          JSON.stringify({
            signature: expected.signature,
            publicKey: expected.publicKey,
            address: expected.address,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }) as typeof fetch,
    });

    const result = await signer.signIntentMandate(unsigned);
    expect(result.signature).toBe(expected.signature);
    expect(result.address).toBe(acct.addr.toString());
  });
});
