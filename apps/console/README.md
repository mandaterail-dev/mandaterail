# @mandaterail/console

Local JSON file-store for IntentMandates (operator laptop / TestNet demos).

## Security warning

**This console must not bypass the AC2 human gate.**

| Record class | Meaning | Authorized for execute? |
|--------------|---------|---------------------------|
| `unsigned-draft` | Created without a real ed25519 signature | **No** |
| `stub-signature` | Legacy `sig_console_stub*` placeholder | **No** |
| `signature-invalid` | Bytes present but verify failed | **No** |
| `signature-verified` | Verified via `@mandaterail/core` | Policy may allow (still needs merchant settle) |

- `POST /mandates` no longer invents placeholder signatures; missing sig → `signature: null` + `unsigned-draft`.
- `POST /mandates/:id/authorize-check` refuses unsigned/stub/invalid mandates (403) and otherwise runs the same `evaluateMandate` policy path as merchant middleware (`allowUnsigned: false`).
- Prefer AC2 bridge `pending → approve` (OperatorAuth) to obtain real signatures before any paid path.
- Default bind is `127.0.0.1`. Do not expose this store as a public product API.

See `docs/security/01-qwen-threat-model-punchlist.md` (S2 / console gate) and `docs/api/auth.md`.

## Endpoints

- `GET /health`
- `GET /mandates` — list with `authorization` classification
- `POST /mandates` — create (draft or verified)
- `GET /mandates/:id`
- `POST /mandates/:id/revoke`
- `POST /mandates/:id/authorize-check` — policy gate; not settlement

## Run

```bash
pnpm --filter @mandaterail/console start
# → http://127.0.0.1:8788
```

## Console auth (TestNet hosting)

`apps/console` reuses the bridge's signed-challenge `OperatorAttestation` from core:

- `GET /operator/challenge?action=<mandate.create|mandate.revoke|mandate.read|mandate.list>&id=<id>` issues a one-time challenge bound to the action and id (`mandates` for list). The audience is `CONSOLE_CHALLENGE_AUDIENCE` (default `mandaterail-console`), which is separate from the bridge's, so bridge challenges can't be replayed at the console.
- `POST /mandates` (the client supplies `id`), `POST /mandates/:id/revoke`, `POST /mandates/:id/authorize-check` (action `mandate.read`), `GET /mandates` and `GET /mandates/:id` all require `X-MandateRail-Operator-Attestation` from a signer on `OPERATOR_ALLOWLIST`. `OPERATOR_SIGNDATA_DOMAIN` is required. Missing, forged, mis-bound or non-allowlisted attestations get 401.
- CORS comes from `CORS_ORIGINS`.
- Clamped limits:
  - `CONSOLE_RATE_PER_IP`: default 30, range 1–120 per minute
  - `CONSOLE_RATE_GLOBAL`: default 300, range 1–800
  - `CONSOLE_MAX_BODY_BYTES`: default 16384, range 1024–65536 (413 when exceeded)
  - `CONSOLE_MAX_MANDATES`: default 1000, range 1–10000 (503 `store_full` when reached)
- Startup refuses a non-loopback bind without signed-challenge, refuses trusted proxy hops > 0 in local-only mode, and refuses out-of-range limits. Local-only mode (not signed-challenge) serves only `isTrustedLocalRequest` callers, and in that mode any proxy forwarding header is denied. In signed-challenge mode forwarding headers are allowed; with `AC2_BRIDGE_TRUSTED_PROXY_HOPS=1` the rate-limit key is the X-Forwarded-For entry appended by the trusted proxy.
- Store: writes are atomic (temp file, fsync, rename) under an in-process write mutex that covers read-modify-write and the cap check. Single process only. In local-only mode a create without an id gets a server-generated UUID. `create_failed` returns a generic message, and the details are logged server-side only.
- `apps/web` signs console calls the same way it signs bridge calls (ARC-60 signData, with a manual-sign fallback).
- Residuals: the challenge store is in memory, and the JSON file store is single-process. TestNet only. Eng hygiene (internal AI review); no third-party audit.

- Signed create: when `POST /mandates` carries a real AC2 signature, the console stores the body byte-for-byte as signed (canonical bytes). It adds no defaults, `createdAt` or `metadata`. The body must include `createdAt`. A create is rejected with 400 if schema parsing would change the signed bytes (`signed_fields_changed`) or the signature does not verify (`invalid_signature`). Server-added fields are applied to unsigned drafts only.

- Principal binding (core `resolvePrincipalAddress`): the verify key is derived from `principal`. That's an Algorand address, or an Ed25519 `did:key` with a matching `principalPubkey`. A mismatched `principalPubkey` or any other principal form is rejected. Signed `createdAt` must be ISO 8601 within -15 min / +2 min. Creates with `revoked: true` are rejected. The "verified" status comes from a server-side flag stored beside the mandate, never from client metadata.
