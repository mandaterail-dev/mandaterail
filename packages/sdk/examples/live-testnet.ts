/**
 * Live TestNet smoke for @mandaterail/sdk. TestNet only, not audited.
 *
 *   pnpm --filter @mandaterail/sdk example:live
 *
 * Read-only by default: health, challenges, and the 401s an unauthenticated
 * caller gets. With OPERATOR_MNEMONIC set to an account on the hosts'
 * OPERATOR_ALLOWLIST, it also lists mandates and pending approvals with
 * signed-challenge evidence (format "algosdk"). Never use a funded or MainNet
 * key here.
 */
import {
  Ac2BridgeClient,
  ConsoleClient,
  DemoApiClient,
  MandateRailHttpError,
  encodeOperatorAttestation,
  type OperatorChallenge,
} from "../src/index.js";

const demo = DemoApiClient.testnet();
const bridge = Ac2BridgeClient.testnet();
const consoleApi = ConsoleClient.testnet();

async function expectStatus(p: Promise<unknown>, status: number): Promise<string> {
  try {
    await p;
    throw new Error(`expected HTTP ${status}, got success`);
  } catch (e) {
    if (e instanceof MandateRailHttpError && e.status === status) {
      return (e.body as { error?: string })?.error ?? String(status);
    }
    throw e;
  }
}

const health = await demo.health();
console.log("demo-api:", health.service, health.network, "asset", health.asset);

const ch = await consoleApi.challenge("mandate.list", "mandates");
console.log("console challenge:", ch.audience, ch.action, ch.subjectId, "expires", ch.expiresAt);
const bch = await bridge.challenge("list", "pending");
console.log("bridge challenge:", bch.audience, bch.action, bch.subjectId);

console.log("console list without attestation ->", await expectStatus(consoleApi.listMandates(), 401));
console.log("bridge pending without attestation ->", await expectStatus(bridge.pending(), 401));

const mnemonic = process.env.OPERATOR_MNEMONIC;
if (mnemonic) {
  const { default: algosdk } = await import("algosdk");
  const acct = algosdk.mnemonicToSecretKey(mnemonic);
  const sign = (c: OperatorChallenge) =>
    encodeOperatorAttestation({
      nonce: c.nonce,
      address: acct.addr.toString(),
      format: "algosdk",
      signature: Buffer.from(
        algosdk.signBytes(new TextEncoder().encode(c.message), acct.sk),
      ).toString("base64"),
    });
  const { items } = await consoleApi.listMandates({
    operatorAttestation: sign(await consoleApi.challenge("mandate.list", "mandates")),
  });
  console.log("signed console list:", items.length, "mandates");
  const { pending } = await bridge.pending({
    operatorAttestation: sign(await bridge.challenge("list", "pending")),
  });
  console.log("signed bridge pending:", pending.length);
} else {
  console.log("OPERATOR_MNEMONIC not set: skipped signed calls");
}
console.log("OK");
