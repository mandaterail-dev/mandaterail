# MandateRail API authentication

**Status: design sketch** aligned with `openapi/openapi.yaml`. Demo apps on localhost may still run with limited auth; that is **DEV ONLY** and is being tightened for AC2 operator routes.

## Production (merchant callers)

| Control | Requirement |
|---------|-------------|
| Credential | Merchant API key in header `X-MandateRail-Key` |
| Prefixes | **`mr_test_`** — TestNet / lab keys only; **`mr_live_`** — MainNet keys only. Runtime: `validateMerchantApiKeyPrefix` in `@mandaterail/core` (wired in `demo-api` when `X-MandateRail-Key` is present). Reject `mr_live_` unless MainNet is explicitly enabled (`ALLOW_MAINNET=1` + MainNet `NETWORK`). |
| Storage | **Hashed at rest** (never store plaintext keys) |
| Scope | Each key bound to a **merchant address** (receive-only payTo) |
| Network | Optional **IP allowlist** per key |
| Rotation | Support revoke/rotate without downtime |

Optional future: HTTP Message Signatures (`HttpSignature` security scheme) for service-to-service calls.

## Operator auth (AC2 bridge pending / approve / reject)

Separate from merchant `ApiKeyAuth`. Used for human / paired-device completion of pending signatures. Mode via `OPERATOR_ATTESTATION_MODE`.

| Control | `signed-challenge` (required on MainNet / `ALLOW_MAINNET`) | `token-lab` (TestNet lab only) |
|---------|-----------------------------------|------------------|
| Credential | `GET /operator/challenge?action=approve\|reject\|list&id=…` → sign `message` with an `OPERATOR_ALLOWLIST` Algorand account → header `X-MandateRail-Operator-Attestation` (base64 JSON evidence) | Header `X-MandateRail-Operator-Token` matching `AC2_OPERATOR_TOKEN`; if unset, loopback + `ALLOW_INSECURE_DEV=1` + TestNet only |
| Routes | `GET /pending` (`list`, id `pending`), `POST /approve/{id}`, `POST /reject/{id}` | same + manual `POST /sign` |
| Manual `POST /sign` | loopback-only queue (approval still needs operator signature) | token / lab |
| Nonce | single-use, TTL `OPERATOR_CHALLENGE_TTL_MS` (default 120 s), bound to action + id; burned on any presentation | n/a |
| Signature formats | `algosdk` (`signBytes`, "MX" prefix) or `arc60` (wallet `signData`; optional `OPERATOR_SIGNDATA_DOMAIN` binds SIWA domain + rpIdHash) | n/a |
| Startup | MainNet profile refuses `token-lab`; `signed-challenge` refuses empty allowlist | TestNet only |
| Bind | Default `AC2_BRIDGE_HOST=127.0.0.1` | same |

## Agent callers

- Agents **never receive `ALGORAND_MNEMONIC`** (or other payer signing material).
- Mandate signatures are obtained only via the AC2 bridge flow: `POST /sign` → `GET /pending` → human/device `POST /approve/{id}` (or reject) with OperatorAuth.
- `AC2_BRIDGE_AUTO_LOCAL` + host mnemonic is **CI / local operator** only — requires `ALLOW_INSECURE_DEV=1` and TestNet `NETWORK` or the process exits.

## Console / file-store (dev-only surface)

- Marked `x-mandaterail-surface: console-dev` in OpenAPI — **not** a public product API.
- Unsigned records are **`unsigned-draft` only**; execute/authorize-check refuses them.
- Does not replace AC2 human approval.

## TestNet vs MainNet

- TestNet API keys (`mr_test_…`), mnemonics, and merchant addresses must be **clearly labeled** in config and docs.
- Do not reuse TestNet keys as MainNet credentials (`mr_live_…`).
- Default facilitator and ASA constants in this repo target **TestNet**.

## Localhost trust (DEV ONLY)

Binding `demo-api`, `console`, and `ac2-bridge` to loopback without merchant `ApiKeyAuth` is acceptable for operator demos. It is **not** authentication. Production gateways must require `X-MandateRail-Key` (and/or HttpSignature) and must not treat network location as identity.

AC2 operator routes additionally require `OperatorAuth` (or explicit insecure loopback lab profile).

See:

- `docs/security/00-threat-model.md` (DRAFT — not remediated; internal AI review only)
- `docs/security/01-qwen-threat-model-punchlist.md`
- `docs/security/02-remediation-status.md`


## CORS (browser origins)

| Control | Requirement |
|---------|-------------|
| Env | `CORS_ORIGINS` — comma-separated exact origins |
| Default | **Empty** → **no** `Access-Control-*` headers (deny-by-default) |
| Local SPA | Must **proxy** to `demo-api` / `ac2-bridge` (or set an explicit allowlist for lab UI origins) |
| Implementation | `@mandaterail/core` `parseCorsOrigins` / `applyCorsHeaders`; wired in `demo-api` and `ac2-bridge` |

## Operator attestation

| Control | Status |
|---------|--------|
| Interface | `OperatorAttestationVerifier` (`signed-challenge` \| `device` \| `hsm` \| `vault`) |
| Bound | `SignedChallengeOperatorVerifier` (Ed25519 / Algorand account allowlist) — internal AI review (eng hygiene) |
| Stub | `UnimplementedOperatorAttestationVerifier` → HTTP 501 for device / hsm / vault |
| Lab shim | `InsecureDevOperatorAuth` (`token-lab`) — **not** a production binding, refused on MainNet |
