# MandateRail Architecture

## Placement

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────────┐     ┌─────────┐
│ AC2         │────▶│ MandateRail      │────▶│ GoPlausible        │────▶│ x402    │
│ identity /  │     │ policy engine +  │     │ facilitator        │     │ settle  │
│ authz       │     │ middleware       │     │ /verify /settle    │     │         │
└─────────────┘     └──────────────────┘     └────────────────────┘     └─────────┘
```

MandateRail is **not** a facilitator and **not** an identity provider. It is the policy gate for **delegated spend** (IntentMandate) between AC2 and x402.

## Packages

### `@mandaterail/schema`

Shared IntentMandate types (Zod) and exported JSON Schema for docs / OpenAPI.

### `@mandaterail/ac2-client`

Signing adapters (no OpenClaw required for unit tests):

- `Ac2Signer` — `signIntentMandate(unsigned) → { signature, publicKey, address? }`
- `LocalEd25519Signer` — headless Algorand/ed25519 (Phase-1)
- `HttpAc2BridgeSigner` — POST SigningRequest to `AC2_BRIDGE_URL` (OpenClaw / phone)

### `@mandaterail/core`

Pure policy functions:

- `evaluateMandate(mandate, context) → PolicyResult`
- Checks: amount, allowlist, expiry, revoked
- AC2 verification via ed25519 (`verifyAc2Signature`); pairing UX via `ac2-client` + `ac2-bridge`
- `DEV_ALLOW_UNSIGNED=false` by default

### `@mandaterail/facilitator-goplausible`

Thin `fetch` client:

- `verify(payment)` / `settle(payment)`
- TESTNET default base URL
- Fail closed; never returns a synthetic settle success

### `@mandaterail/middleware-hono`

1. On unpaid access → `402` with `payment` + `mandate` extras
2. On fulfill → load mandate → `evaluateMandate` → facilitator verify → settle → continue

### `@mandaterail/middleware-express`

Minimal port / re-export surface for Express apps.

## Apps

- **demo-api** — 402 + mandate extras, paid path, JSON receipt store
- **ac2-bridge** — pair/status + sign approval stub (auto-local or phone)
- **console** — CRUD-ish mandate store (JSON file) for local demos

## Trust boundaries

| Boundary | Trust |
|----------|-------|
| Client → Merchant | Untrusted; must present payment + mandate |
| Merchant → MandateRail | Local library; merchant configures allowlists |
| MandateRail → GoPlausible | Network call; fail closed |
| AC2 | Stubbed; production must verify signatures externally |

## Non-goals

- Implementing the GoPlausible facilitator itself
- Full AC2 stack (stub only)
- Custodial wallets
