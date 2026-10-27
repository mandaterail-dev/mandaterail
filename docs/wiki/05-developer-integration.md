# Developer integration

> **TestNet only. AI security reviewed. Use at your own risk.** No third-party audit firm has reviewed MandateRail. The internal review reports are in `docs/security/audits/` (eng hygiene / AI review). Don't describe it as audited by a third party, formally verified or MainNet-ready.

## Specs

- OpenAPI: [`openapi/openapi.yaml`](../../openapi/openapi.yaml) (live + local `servers`, every error code)
- Auth: [`docs/api/auth.md`](../api/auth.md)
- Security posture: [`docs/security/README.md`](../security/README.md), threat model [`00-threat-model.md`](../security/00-threat-model.md)
- SDK: [`packages/sdk/README.md`](../../packages/sdk/README.md)

## Endpoints

| Service | Live TestNet | Local |
| --- | --- | --- |
| demo-api (merchant demo, receipts, `/paid/resource`) | `https://mr-api.8-221-97-26.sslip.io` | `http://127.0.0.1:8787` |
| ac2-bridge (AC2 signing queue, operator approve/reject) | `https://mr-bridge.8-221-97-26.sslip.io` | `http://127.0.0.1:8790` |
| console (IntentMandate store) | `https://mr-console.8-221-97-26.sslip.io` | `http://127.0.0.1:8788` |
| Web console (SPA) | `https://mandaterail.pages.dev` | `http://localhost:5173` |

All three live hosts run on one TestNet ECS box behind Caddy (TLS, edge rate limiting). They run `OPERATOR_ATTESTATION_MODE=signed-challenge` with `OPERATOR_SIGNDATA_DOMAIN=mandaterail.pages.dev`. Network is Algorand TestNet; asset is USDC ASA `10458941`.

Quick check:

```bash
curl -s https://mr-api.8-221-97-26.sslip.io/health
curl -s https://mr-console.8-221-97-26.sslip.io/health   # operatorAttestationMode: signed-challenge
curl -s https://mr-bridge.8-221-97-26.sslip.io/health
```

## Signed-challenge operator flow

Operator routes need OperatorAuth:
- **Bridge:** `GET /pending`, `POST /approve/{id}`, `POST /reject/{id}`.
- **Console:** every `/mandates` route, including `POST /mandates/{id}/authorize-check`.

There's no shared secret or API key; an allowlisted Algorand account signs a single-use challenge.

1. **Challenge.** `GET {host}/operator/challenge?action=<action>&id=<subject>`

   | Host | action | id |
   | --- | --- | --- |
   | bridge (audience `mandaterail-ac2-bridge`) | `list` | `pending` |
   | | `approve`, `reject` | pending request id |
   | console (audience `mandaterail-console`) | `mandate.list` | `mandates` |
   | | `mandate.read` (GET and authorize-check), `mandate.revoke` | mandate id |
   | | `mandate.create` | the `id` in the create body |

   The response has `nonce`, `message`, `issuedAt` and `expiresAt` (default TTL 120 s). Challenges are rate-limited per client (429).
   The two audiences are separate, so a bridge challenge never works at the console, or the reverse.

2. **Sign `message`** with an account on the host's `OPERATOR_ALLOWLIST`:
   - **Wallet (ARC-60 `signData`, e.g. Lute).** Build a SIWA JSON payload:
     ```json
     { "domain": "mandaterail.pages.dev", "account_address": "<addr>",
       "uri": "https://mandaterail.pages.dev", "version": "1",
       "statement": "<challenge.message>", "nonce": "<challenge.nonce>",
       "issued-at": "<issuedAt>", "expiration-time": "<expiresAt>",
       "chain_id": "283", "type": "ed25519" }
     ```
     Pass it base64-encoded to `signData(data, { scope: AUTH, encoding: "base64" })`. The server checks:
     - the signature is Ed25519 over `sha256(data) || sha256(authenticatorData)`;
     - `statement`, `nonce` and `account_address` match the challenge;
     - `domain` equals `mandaterail.pages.dev`;
     - `authenticatorData` starts with `sha256("mandaterail.pages.dev")`.

     Wallet signing therefore only works from the `mandaterail.pages.dev` origin, or whatever `OPERATOR_SIGNDATA_DOMAIN` is on your own deployment.
   - **Offline / scripts:** `algosdk.signBytes(utf8(message), sk)` (algosdk adds the `MX` prefix, so it can't be replayed as a transaction).

3. **Header.** Send `X-MandateRail-Operator-Attestation: base64(JSON)` where JSON is
   `{nonce, address, format: "arc60" | "algosdk", signature, data?, authenticatorData?}` (all base64 fields).
   Every nonce is single-use and bound to one action and one id, so you need a fresh challenge for every call.

## Signed mandate create (console)

`POST /mandates` stores one of two kinds of record:

- **Unsigned draft.** With no signature (or a console stub), the server fills defaults and its own metadata. The record is never authorized for execute.
- **Signed mandate.** With a real AC2 Ed25519 signature, the body is stored **exactly as signed**. The signature covers `canonicalMandateBytes`: stable-key-order JSON of the mandate without `signature` and `principalPubkey`. Requirements:
  - **`createdAt`** is required: ISO 8601, at most 15 min in the past and 2 min in the future.
  - **Every field** you want stored must be in the signed body (the server adds nothing). `revoked` must be `false`.
  - **Principal binding.** The verify key comes from `principal`:
    - An **Algorand address**: the key is the address. A `principalPubkey`, if sent, must match it.
    - An **Ed25519 `did:key`**: `principalPubkey` (base64 32 bytes) is required and must equal the DID key.
    - **Anything else** (e.g. `did:example:*`) is rejected. An operator can't sign "for" another principal.
  - On success the console stores a server-side verified flag, and `authorization.status` is `signature-verified`.

`POST /mandates/{id}/authorize-check` (auth `mandate.read`) re-runs the full policy (signature, allowlist, amount, asset, expiry, revoked). It returns 200 `{ok: true}` only for a verified, unrevoked mandate within policy. Otherwise it returns 403 with `error` and `authorization`.

## Error codes

All errors are JSON `{error, message?}`. Responses on the operator surfaces are `Cache-Control: no-store`.

**401 OperatorAuth (bridge + console):**

| Code | Meaning |
| --- | --- |
| `attestation_required` | no attestation header |
| `attestation_malformed` | header isn't valid base64 JSON evidence |
| `unknown_nonce` | the challenge wasn't issued by this host; includes a bridge nonce used at the console |
| `expired_nonce` | the challenge has expired |
| `replayed_nonce` | the challenge was already used |
| `challenge_binding_mismatch` | wrong action or id, or an ARC-60 domain / `rpIdHash` mismatch |
| `invalid_signature` | the signature doesn't verify |
| `operator_not_allowlisted` | the signer isn't on `OPERATOR_ALLOWLIST` |
| `unauthorized` | local-only mode and the caller isn't direct loopback |

**Challenge:**
- `invalid_action` / `invalid_subject` (400)
- `rate_limited` (429, `Retry-After`)
- `signed_challenge_disabled` / `challenge_unavailable`: the host isn't in signed-challenge mode

**Console create (400):**

| Code | Meaning |
| --- | --- |
| `invalid_json` | the body isn't a JSON object |
| `invalid_id` | `id` doesn't match `^[A-Za-z0-9._:-]{1,128}$` |
| `id_required` | signed-challenge mode needs a client-chosen `id` |
| `already_revoked` | `revoked: true` on create |
| `invalid_mandate` | schema validation failed (`details`) |
| `signed_create_requires_createdAt` | a signed create has no `createdAt` |
| `invalid_createdAt` | not ISO 8601, or outside the skew window |
| `signed_fields_changed` | parsing would change the signed bytes |
| `invalid_signature` | the AC2 signature doesn't verify against the key bound to `principal` |

**Console, other:**

| Status | Code | Meaning |
| --- | --- | --- |
| 404 | `not_found` | |
| 409 | `create_failed` | generic; details are only logged on the server |
| 413 | `payload_too_large` | body over `CONSOLE_MAX_BODY_BYTES` |
| 429 | `rate_limited` | |
| 503 | `store_full` | store reached `CONSOLE_MAX_MANDATES` |
| 403 | `unsigned_or_unverified` | from authorize-check, or a policy reason |

**Bridge:**

| Status | Codes |
| --- | --- |
| 400 | `invalid_signing_request` |
| 401 | `requester_token_required` |
| 403 | `use_local_disabled`, `forbidden` |
| 404 | `not_found` |
| 409 | `not_pending` |
| 429 | `queue_full`, `client_pending_cap`, `rate_limited` |

## SDK

```bash
pnpm --filter @mandaterail/sdk example:live    # read-only smoke against the live TestNet hosts
```

See [`packages/sdk/README.md`](../../packages/sdk/README.md) for `DemoApiClient.testnet()`, `Ac2BridgeClient.testnet()`, `ConsoleClient.testnet()`, `challenge()` and `encodeOperatorAttestation()`.

## Rules

- TestNet only (USDC ASA `10458941`). MainNet isn't cleared; see [`docs/ops/phase-2-mainnet-dry-run.md`](../ops/phase-2-mainnet-dry-run.md).
- Agents never hold payer mnemonics or operator keys.
- Human AC2 approval remains the IntentMandate gate.
- Public wording: "TestNet" and "AI security reviewed. Use at your own risk." Never imply a third-party audit firm.
