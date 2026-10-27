import { describe, it, expect, beforeEach, afterEach } from "vitest";
import algosdk from "algosdk";
import { didKeyFromEd25519, ed25519KeyFromDidKey, evaluateMandate, signMandate } from "./index.js";
import type { IntentMandate } from "@mandaterail/schema";

function signedMandate(
  over: Partial<IntentMandate> = {},
  account?: algosdk.Account,
): { mandate: IntentMandate; account: algosdk.Account } {
  const acct = account ?? algosdk.generateAccount();
  const now = new Date();
  const later = new Date(now.getTime() + 60 * 60 * 1000);
  const unsigned: Omit<IntentMandate, "signature"> = {
    id: "m-1",
    principal: acct.addr.toString(),
    agent: "did:example:agent-1",
    maxAmount: "10.00",
    asset: "USDC",
    allowlist: ["demo-merchant"],
    expiresAt: later.toISOString(),
    revoked: false,
    nonce: "n-1",
    createdAt: now.toISOString(),
    ...over,
  };
  if (!over.principal && !over.principalPubkey) {
    (unsigned as { principal: string }).principal = acct.addr.toString();
  }
  const signature = signMandate(unsigned, acct.sk);
  return { mandate: { ...unsigned, signature }, account: acct };
}

const ctx = {
  amount: "5.00",
  asset: "USDC",
  merchantId: "demo-merchant",
};

describe("evaluateMandate", () => {
  const prev = process.env.DEV_ALLOW_UNSIGNED;

  beforeEach(() => {
    process.env.DEV_ALLOW_UNSIGNED = "false";
  });

  afterEach(() => {
    if (prev === undefined) delete process.env.DEV_ALLOW_UNSIGNED;
    else process.env.DEV_ALLOW_UNSIGNED = prev;
  });

  it("allows a valid ed25519-signed mandate within amount and allowlist", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate(mandate, ctx);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.mandate.id).toBe("m-1");
  });

  it("rejects a non-address, non-did:key principal even with principalPubkey", async () => {
    const acct = algosdk.generateAccount();
    const pk = Buffer.from(algosdk.decodeAddress(acct.addr.toString()).publicKey).toString("base64");
    const { mandate } = signedMandate({ principal: "did:example:alice", principalPubkey: pk }, acct);
    const r = await evaluateMandate(mandate, ctx);
    expect(r.ok).toBe(false);
  });

  it("rejects a signer naming another Algorand principal (principalPubkey mismatch)", async () => {
    const victim = algosdk.generateAccount();
    const attacker = algosdk.generateAccount();
    const pk = Buffer.from(algosdk.decodeAddress(attacker.addr.toString()).publicKey).toString("base64");
    const { mandate } = signedMandate({ principal: victim.addr.toString(), principalPubkey: pk }, attacker);
    expect((await evaluateMandate(mandate, ctx)).ok).toBe(false);
    // without the hint the key comes from the address, and the attacker's signature fails
    const { principalPubkey: _p, ...noHint } = mandate;
    expect((await evaluateMandate(noHint as IntentMandate, ctx)).ok).toBe(false);
  });

  it("did:key principal: requires a matching principalPubkey", async () => {
    const acct = algosdk.generateAccount();
    const raw = algosdk.decodeAddress(acct.addr.toString()).publicKey;
    const did = didKeyFromEd25519(raw);
    expect(did.startsWith("did:key:z6Mk")).toBe(true);
    expect(Buffer.from(ed25519KeyFromDidKey(did)!).equals(Buffer.from(raw))).toBe(true);
    const pk = Buffer.from(raw).toString("base64");
    const { mandate } = signedMandate({ principal: did, principalPubkey: pk }, acct);
    expect((await evaluateMandate(mandate, ctx)).ok).toBe(true);
    const { principalPubkey: _p, ...noHint } = mandate;
    expect((await evaluateMandate(noHint as IntentMandate, ctx)).ok).toBe(false);
    const other = Buffer.from(algosdk.decodeAddress(algosdk.generateAccount().addr.toString()).publicKey).toString("base64");
    expect((await evaluateMandate({ ...mandate, principalPubkey: other }, ctx)).ok).toBe(false);
  });

  it("allows attaching principalPubkey after signing (bridge path)", async () => {
    // Bridge / phone returns publicKey after the intent body is signed; clients
    // attach it for key resolution. It must not change canonical signed bytes.
    const { mandate, account } = signedMandate();
    const pk = Buffer.from(account.sk.slice(32)).toString("base64");
    const withPk = { ...mandate, principalPubkey: pk };
    const r = await evaluateMandate(withPk, ctx);
    expect(r.ok).toBe(true);
  });

  it("rejects a tampered mandate (bad signature)", async () => {
    const { mandate } = signedMandate();
    const tampered = { ...mandate, maxAmount: "99.00" };
    const r = await evaluateMandate(tampered, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(["unsigned_not_allowed", "ac2_verification_failed"]).toContain(
        r.reason,
      );
    }
  });

  it("rejects revoked mandates", async () => {
    const { mandate } = signedMandate({ revoked: true });
    const r = await evaluateMandate(mandate, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("revoked");
  });

  it("rejects expired mandates", async () => {
    const past = new Date(Date.now() - 60_000).toISOString();
    const { mandate } = signedMandate({ expiresAt: past });
    const r = await evaluateMandate(mandate, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("expired");
  });

  it("rejects when amount exceeds maxAmount", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate(mandate, { ...ctx, amount: "10.01" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("amount_exceeded");
  });

  it("rejects merchant not on allowlist", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate(mandate, {
      ...ctx,
      merchantId: "other-shop",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("merchant_not_allowlisted");
  });

  it("rejects empty allowlist", async () => {
    const { mandate } = signedMandate({ allowlist: [] });
    const r = await evaluateMandate(mandate, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("merchant_not_allowlisted");
  });

  it("rejects unsigned when DEV_ALLOW_UNSIGNED is false", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate({ ...mandate, signature: null }, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(["unsigned_not_allowed", "ac2_verification_failed"]).toContain(
        r.reason,
      );
    }
  });

  it("allows unsigned when allowUnsigned is explicitly true", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate(
      { ...mandate, signature: null },
      { ...ctx, allowUnsigned: true },
    );
    expect(r.ok).toBe(true);
  });

  it("rejects asset mismatch", async () => {
    const { mandate } = signedMandate();
    const r = await evaluateMandate(mandate, { ...ctx, asset: "ALGO" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("asset_mismatch");
  });

  it("rejects invalid schema payloads", async () => {
    const r = await evaluateMandate({ not: "a mandate" }, ctx);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("invalid_schema");
  });
});
