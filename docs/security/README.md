# Security documentation

Index of MandateRail security engineering notes.

| Doc | Purpose | Status |
|-----|---------|--------|
| [00-threat-model.md](./00-threat-model.md) | STRIDE-oriented threat register | **DRAFT — internal AI review; not formally verified** |
| [01-qwen-threat-model-punchlist.md](./01-qwen-threat-model-punchlist.md) | Independent Qwen review punchlist (threat model) | **internal AI review — findings recorded, P0 tracked** |
| [02-remediation-status.md](./02-remediation-status.md) | P0 / P1 / P2 remediation tracker | Living status (not a hardening claim) |
| [03-qwen-openapi-punchlist.md](./03-qwen-openapi-punchlist.md) | Independent Qwen OpenAPI punchlist | **internal AI review — contract notes** |
| [04-qwen-p0-recheck.md](./04-qwen-p0-recheck.md) | internal reviewer P0 recheck scorecard (PASS + residuals) | **internal AI review — residual work recorded** |
| [05-operator-attestation-bindings.md](./05-operator-attestation-bindings.md) | OperatorAttestation bindings: `signed-challenge` implemented; device\|HSM\|vault stub | **signed-challenge implemented — internal AI review**; others stub |

## Public messaging rule

The **public wiki and marketing materials must not claim** that MandateRail is:

- security **audited**,
- **formally verified**, or
- production- / MainNet-**hardened**,

until remediations in the threat model are closed and an independent review is on record.

Demo apps use **localhost trust** and TestNet defaults. That is development scaffolding only. P0 remediations reduce accidental exposure of demo footguns; they do **not** equal production readiness.

For operator checklist language aimed at wiki readers, see [../wiki/06-security.md](../wiki/06-security.md). Prefer linking here for the authoritative draft threat register and punchlists.

## Audits (eng hygiene)

Dated internal review notes live under [audits/](./audits/). **Not public “audited” claims.** Latest: [2026-10-13 OperatorAttestation review 107bc4e..9ac1af0 + remediation](./audits/2026-10-13-operator-attestation.md) — P1-A and P2-A..F fixed in `6c70f99`, recheck findings OA-N1/OA-P2-G/OA-P2-H fixed in `29977dd`, round 3 (TestNet PASS, no P0/P1) OA-P3-K fixed in `d77e4ee`, OA-P2-I partial there and closed with OA-P2-M/OA-P2-N in `d502fda`, OA-P2-J accepted; run 9 OA-P1-O (localhost trust behind tunnels) and OA-P3-P fixed; run 10 OA-P2-Q/OA-P2-R fixed in `4d8cee8` (`OPERATOR_SIGNDATA_DOMAIN` now required for every signed-challenge deployment); MainNet signed-challenge requires `OPERATOR_SIGNDATA_DOMAIN` (also [2026-10-12 OperatorAttestation signed-challenge bindings](./audits/2026-10-12-operator-attestation-bindings.md), [2026-09-24 P0 insecure-dev MainNet gates](./audits/2026-09-24-p0-insecure-dev-mainnet.md), [2026-09-21 P1 residuals](./audits/2026-09-21-p1-security-residuals.md), [multi-wallet picker](./audits/2026-09-21-multi-wallet-picker.md)).


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
