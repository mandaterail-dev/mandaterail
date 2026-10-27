# OperatorAttestation production bindings (design stub)

**Status:** `signed-challenge` binding **implemented** (2026-10-12, eng hygiene — internal AI review). device / hsm / vault remain stubs (501).  
**Interface:** `packages/core/src/operator-attestation.ts`  
**Tip context:** stub verifier landed in `125afb1` as `UnimplementedOperatorAttestationVerifier` (HTTP 501).

## Intent

Production OperatorAuth for AC2 approve / reject (and related gated routes) must verify an **operator attestation**, not a merchant API key and not a long-lived shared secret held by agents.

Planned binding kinds (already on the TypeScript interface):

| Kind | Rough evidence |
|------|----------------|
| `device` | Signed challenge + device / phone attestation (AC2-style) |
| `hsm` | HSM-backed key proof / quote bound to the pending subject |
| `vault` | Vault (or equivalent) short-lived session token bound to the operator |

## Implemented: `signed-challenge` (Ed25519 / Algorand account)

Code: `packages/core/src/operator-challenge.ts` (`OperatorChallengeStore`, `SignedChallengeOperatorVerifier`), wired in `apps/ac2-bridge` `requireOperator(action)`; console signer `apps/web/src/hooks/useOperatorSigner.ts`.

| Property | Behavior |
|----------|----------|
| Mode | `OPERATOR_ATTESTATION_MODE=signed-challenge\|token-lab`; default `signed-challenge` on MainNet profile, `token-lab` otherwise. MainNet / `ALLOW_MAINNET` refuses `token-lab` at startup |
| Allowlist | `OPERATOR_ALLOWLIST` (comma-separated Algorand addresses); empty → refuse start in signed-challenge |
| Challenge | `GET /operator/challenge?action=approve\|reject\|list&id=…` → nonce (24 random bytes), TTL `OPERATOR_CHALLENGE_TTL_MS` (120 s), canonical message incl. audience/action/subject/nonce/issued/expires |
| Single-use | nonce burned on first presentation (valid or not); replay → `replayed_nonce` |
| Binding | challenge action + subject must equal route action + pending id (`list`/`pending` for `GET /pending`) |
| Formats | `algosdk` (`verifyBytes`, "MX" prefix) · `arc60` (Ed25519 over sha256(data)\|\|sha256(authenticatorData); SIWA JSON `statement`=message, `nonce`, `account_address`; optional `OPERATOR_SIGNDATA_DOMAIN` checks domain + rpIdHash) |
| Header | `X-MandateRail-Operator-Attestation` = base64(JSON evidence) |

Wallet support (use-wallet 4.6.0): only **Lute** reports `canSignData`. Pera / Defly / Defly Web / Exodus / Kibisis do not; the console falls back to a paste-in offline `algosdk.signBytes` signature.

## Production path (target)

1. Client presents `OperatorAttestation` (`kind` + `evidence` / `sessionId` / optional `expiresAt`).
2. A concrete `OperatorAttestationVerifier` implementation verifies:
   - signed challenge response, **or**
   - device attestation, **or**
   - vault session binding  
   against the pending subject (`subjectId` / mandate / approval id) and optional `remoteAddress` context.
3. On success: allow the gated operator action. On failure: **401**. Unbound kind / missing production binding: **501** (current stub behavior).

## Non-negotiables

- **Agents never hold signing material** (no MAGIC/MNEMONIC in SPA or agent runtime for IntentMandate / operator approve).
- Merchant `ApiKeyAuth` (`X-MandateRail-Key`, `mr_test_` / `mr_live_`) is **not** OperatorAuth.
- Presence of the interface or stub class is **not** production readiness.

## TestNet / lab shim (documented, not production)

For local / CI TestNet demos only:

- Header: `X-MandateRail-Operator-Token` (`OPERATOR_TOKEN_HEADER` / `InsecureDevOperatorAuth`)
- Env: `AC2_OPERATOR_TOKEN` (preferred), or loopback + `ALLOW_INSECURE_DEV=1` when token unset
- Hard-fail outside lab: insecure flags require `ALLOW_INSECURE_DEV=1` **and** TestNet `NETWORK` or process exit

Do **not** treat the token shim as a device / HSM / vault binding. Replace `UnimplementedOperatorAttestationVerifier` before any non-dev OperatorAttestation claim.

## Out of scope for this stub

Implementation details (challenge formats, HSM vendor APIs, vault auth backends, key rotation) — TBD when bindings are designed and reviewed. This file only records the intended boundary.
