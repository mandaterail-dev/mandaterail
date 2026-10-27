# Eng hygiene review — OperatorAttestation signed-challenge bindings (2026-10-12)

**NOT a public audited claim.** Internal engineering hygiene only. Do not cite as "security audited," "formally verified," or MainNet-hardened.

## Scope

- **P1-1:** Replace the 501 stub path for AC2 operator routes with a real verifier: Ed25519 signed challenge from an allowlisted Algorand account (`SignedChallengeOperatorVerifier`).
- **P1-3 / T-BR-03:** `GET /pending` now requires OperatorAuth (`action=list`, subject `pending`) in both modes.
- MainNet / `ALLOW_MAINNET` profile requires `OPERATOR_ATTESTATION_MODE=signed-challenge` + non-empty `OPERATOR_ALLOWLIST`; `token-lab` refused at startup and in `authorizeOperator`.
- Console: Approve / Deny / load-pending fetch a challenge and sign with the connected wallet; `VITE_AC2_OPERATOR_TOKEN` no longer needed on Pages.

## Design

| Control | Implementation |
|---------|----------------|
| Challenge issue | `GET /operator/challenge?action=approve\|reject\|list&id=…`; 404 for unknown pending id; 24-byte random nonce; TTL 120 s (`OPERATOR_CHALLENGE_TTL_MS`); store capped at 10k entries |
| Message | `MandateRail operator attestation v1` + audience, action, subject, nonce, issued, expires (newline-separated) |
| Single-use | Nonce burned on first presentation (including failures and non-allowlisted signers) |
| Binding | Challenge action/subject must match route action and `:id` |
| Allowlist | `OPERATOR_ALLOWLIST` (invalid addresses dropped) |
| Signature | `algosdk`: `algosdk.verifyBytes` ("MX"-prefixed). `arc60`: Ed25519 (node:crypto) over sha256(data)\|\|sha256(authenticatorData); SIWA JSON must embed statement=message, nonce, account_address; optional `OPERATOR_SIGNDATA_DOMAIN` checks domain + authenticatorData rpIdHash |
| Pluggability | `OperatorAttestationVerifier` interface kept; device / hsm / vault still `UnimplementedOperatorAttestationVerifier` (501) |
| `/sign` queue (manual) | signed-challenge: loopback-only (queueing grants no approval). token-lab: unchanged |
| CORS | `X-MandateRail-Operator-Attestation` added to Allow-Headers |

## Tests run

- `pnpm --filter @mandaterail/core test` — 52/52 (new: valid sig, wrong signer, not allowlisted, expired nonce, replayed nonce, unknown nonce, action mismatch, id mismatch, malformed, ARC-60 accept + MX-prefixed reject, mode defaults, allowlist parse; gate: MainNet refuses token-lab, MainNet requires allowlist, unknown mode refused, `authorizeOperator` refuses token on MainNet)
- `tsc --noEmit`: core, demo-api, ac2-bridge, web — clean
- Bridge smoke (TestNet, signed-challenge, loopback): `/pending` 401 without header → 200 signed → 401 on replay; approve-challenge on `/reject` → 401 `challenge_binding_mismatch`; correct reject challenge → 200. MainNet + `token-lab` → refuses start (exit 1).

## Wallet signData findings (use-wallet 4.6.0)

- `canSignData = true` only for **Lute**. Pera, Defly, Defly Web, Exodus, Kibisis: `false` (signData throws).
- Console fallback for those wallets: prompt shows the challenge; operator signs offline with `algosdk.signBytes` (same allowlisted account) and pastes base64 signature. Clunky; acceptable for TestNet operators only.
- ARC-60 verification formula is implemented per spec and unit-tested with a synthetic signer; **not yet verified against a live Lute signature** — do that before relying on `arc60` evidence.

## Residual risks

1. Nonce store is in-memory, single process: restart drops challenges; multiple bridge replicas need a shared store (Redis/DB) with atomic consume.
2. `GET /operator/challenge` is unauthenticated (by design) — rate limiting not implemented; store cap (10k) can be exhausted → 503 DoS.
3. Allowlist is static env; no rotation / revocation API; compromise of an operator wallet = operator compromise until env change + restart.
4. ARC-60 path unverified against live wallets; domain binding off unless `OPERATOR_SIGNDATA_DOMAIN` set.
5. Manual `/sign` queue in signed-challenge mode trusts loopback (co-located agent assumption).
6. `/approve/{id}` still accepts the client-supplied mandate signature body; signer of that body is not cross-checked with the operator address.
7. device / hsm / vault bindings remain 501.
8. Independent Qwen recheck pending.
