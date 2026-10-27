# `@mandaterail/sdk`

TypeScript HTTP clients aligned to [`openapi/openapi.yaml`](../../openapi/openapi.yaml). Apache-2.0.

> **TestNet only. AI security reviewed. Use at your own risk.** No third-party audit. For the live TestNet demo hosts and local dev, not a production multi-tenant API client.

| Client | `.testnet()` (live) | `.localhost()` | Routes |
|--------|---------------------|----------------|--------|
| `DemoApiClient` | `https://mr-api.8-221-97-26.sslip.io` | `http://127.0.0.1:8787` | `health`, `listReceipts`, `getReceipt` |
| `Ac2BridgeClient` | `https://mr-bridge.8-221-97-26.sslip.io` | `http://127.0.0.1:8790` | `pairStatus`, `challenge`, `pending`, `sign`, `requestStatus`, `approve`, `reject` |
| `ConsoleClient` | `https://mr-console.8-221-97-26.sslip.io` | `http://127.0.0.1:8788` | `challenge`, `listMandates`, `getMandate`, `createMandate`, `revokeMandate` |

Exports: `TESTNET_DEMO_API_URL`, `TESTNET_AC2_BRIDGE_URL`, `TESTNET_CONSOLE_URL`, `TESTNET_SIGNDATA_DOMAIN` (`mandaterail.pages.dev`), `encodeOperatorAttestation`, `OPERATOR_ATTESTATION_HEADER`, `MandateRailHttpError` (`.status`, `.body.error`).

## Auth

- **Operator (signed-challenge, live hosts):** call `challenge(action, id)`, sign `message` with an account on `OPERATOR_ALLOWLIST`, and pass `encodeOperatorAttestation(...)` as `operatorAttestation`. Every nonce is single-use and bound to one action and one id, so you need a fresh challenge per call. Wallets use ARC-60 `signData` with domain `mandaterail.pages.dev`; scripts use `algosdk.signBytes`. Full flow and error codes: [`docs/wiki/05-developer-integration.md`](../../docs/wiki/05-developer-integration.md).
- **Requester (agents):** `sign()` returns a `requesterToken`; poll `requestStatus(id, token)`. Agents never see `/pending` or hold operator keys.
- **token-lab** (`operatorToken`, `X-MandateRail-Operator-Token`): local TestNet only. It's refused on MainNet and isn't available on the live hosts.
- **Merchant (planned):** `X-MandateRail-Key` via `apiKey`.

## Live TestNet example (works as written)

```ts
import algosdk from "algosdk";
import {
  Ac2BridgeClient, ConsoleClient, DemoApiClient,
  MandateRailHttpError, encodeOperatorAttestation, type OperatorChallenge,
} from "@mandaterail/sdk";

const demo = DemoApiClient.testnet();
const bridge = Ac2BridgeClient.testnet();
const consoleApi = ConsoleClient.testnet();

console.log(await demo.health()); // { ok, service, network, merchant, asset: "10458941" }

// Unauthenticated operator calls are refused:
try { await consoleApi.listMandates(); }
catch (e) { if (e instanceof MandateRailHttpError) console.log(e.status, (e.body as any).error); } // 401 attestation_required

// Signed-challenge (operator account must be on the host's OPERATOR_ALLOWLIST):
const op = algosdk.mnemonicToSecretKey(process.env.OPERATOR_MNEMONIC!); // TestNet-only key
const attest = (c: OperatorChallenge) => encodeOperatorAttestation({
  nonce: c.nonce,
  address: op.addr.toString(),
  format: "algosdk",
  signature: Buffer.from(algosdk.signBytes(new TextEncoder().encode(c.message), op.sk)).toString("base64"),
});

const { items } = await consoleApi.listMandates({
  operatorAttestation: attest(await consoleApi.challenge("mandate.list", "mandates")),
});
const { pending } = await bridge.pending({
  operatorAttestation: attest(await bridge.challenge("list", "pending")),
});
for (const p of pending) {
  if (!p.id) continue;
  await bridge.approve(p.id, {}, { operatorAttestation: attest(await bridge.challenge("approve", p.id)) });
}
```

A non-allowlisted signer gets `401 operator_not_allowlisted`.

Runnable version (read-only unless `OPERATOR_MNEMONIC` is set):

```bash
pnpm --filter @mandaterail/sdk example:live
OPERATOR_MNEMONIC="…" pnpm --filter @mandaterail/sdk example:live
```

## Signed mandate create

```ts
import { signMandate } from "@mandaterail/core";

const principal = algosdk.mnemonicToSecretKey(process.env.PRINCIPAL_MNEMONIC!);
const body = {
  id: "m-" + crypto.randomUUID(),
  principal: principal.addr.toString(),         // Algorand address (or Ed25519 did:key + principalPubkey)
  agent: "did:example:agent-1",
  maxAmount: "1.00", asset: "USDC", allowlist: ["demo-merchant"],
  expiresAt: new Date(Date.now() + 3600_000).toISOString(),
  revoked: false,
  nonce: crypto.randomUUID(),
  createdAt: new Date().toISOString(),          // required, signed, -15 min / +2 min skew
};
const mandate = { ...body, signature: signMandate(body, principal.sk) };
const created = await consoleApi.createMandate(mandate, {
  operatorAttestation: attest(await consoleApi.challenge("mandate.create", mandate.id)),
});
// created.authorization.status === "signature-verified"
```

The console stores the body exactly as signed. Create errors (400) are `invalid_json`, `invalid_id`, `id_required`, `already_revoked`, `invalid_mandate`, `signed_create_requires_createdAt`, `invalid_createdAt`, `signed_fields_changed` and `invalid_signature`. Other responses: 409 `create_failed`, 413 `payload_too_large`, 503 `store_full`.

## Localhost

```ts
const demo = DemoApiClient.localhost();
const bridge = Ac2BridgeClient.localhost({ operatorToken: process.env.AC2_OPERATOR_TOKEN }); // token-lab, TestNet loopback only
```

## Install / test

```bash
pnpm add @mandaterail/sdk --filter <your-package>
pnpm --filter @mandaterail/sdk test
```
