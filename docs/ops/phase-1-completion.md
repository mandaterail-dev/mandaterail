# Phase 1 completion checklist

**Tip baseline:** post–P0-1 insecure-dev MainNet gates on `<public-repo>` `main` (see audits `2026-09-24-p0-insecure-dev-mainnet.md`). Prior: `a7e0f23` Phase 1 checklist; `125afb1` P1 residuals; `9e4282f` multi-wallet.  
**Internal AI review (internal reviewer, eng hygiene); no third-party audit. NOT MainNet-hardened.** TestNet-lab status only. Public copy: "AI security reviewed. Use at your own risk."

Last updated: 2026-10-13 (America/New_York).

## DONE (vs tip `125afb1`)

| Item | Evidence |
|------|----------|
| Multi-wallet picker (Pera, Defly, Lute, Exodus, Kibisis) | `9e4282f`; eng-hygiene note `docs/security/audits/2026-09-21-multi-wallet-picker.md` |
| Runtime merchant API key prefixes `mr_test_` / `mr_live_` | `@mandaterail/core` `validateMerchantApiKeyPrefix`; wired in `demo-api` when `X-MandateRail-Key` present (`125afb1`) |
| CORS deny-by-default allowlist | `CORS_ORIGINS` on `demo-api` + `ac2-bridge`; empty = no CORS headers (`125afb1`) |
| OperatorAttestation interface + stub | `UnimplementedOperatorAttestationVerifier` → 501; lab shim remains `InsecureDevOperatorAuth` (`125afb1`) |
| Eng-hygiene audits | `docs/security/audits/2026-09-21-p1-security-residuals.md`, `2026-09-21-multi-wallet-picker.md` |
| Pages with mocks | Cloudflare Pages SPA can run with Vite mocks (`VITE_USE_MOCKS` / `VITE_USE_API_MOCKS`); live API CORS / `VITE_*` still open below |
| P0-1 MainNet insecure-dev / operator token gates | `authorizeOperator` TestNet-only loopback bypass; `assertOperatorGateOrExit`; `ALLOW_INSECURE_DEV` needs TestNet; eng note `docs/security/audits/2026-09-24-p0-insecure-dev-mainnet.md` |
| P1-2 SPA OperatorAuth header | **Superseded by signed-challenge** (`3d8651a`): the console signs a single-use `GET /operator/challenge` nonce with an allowlisted wallet and sends `X-MandateRail-Operator-Attestation`; the SPA holds no secret. `VITE_AC2_OPERATOR_TOKEN` is token-lab only (TestNet, refused on MainNet) and must never ship to Pages. Agents poll `GET /requests/{id}/status` with a per-request requester token, not `/pending` (`29977dd`) |
| OperatorAttestation `signed-challenge` binding (2026-10-12) | `SignedChallengeOperatorVerifier` + `GET /operator/challenge` + `X-MandateRail-Operator-Attestation`; `OPERATOR_ATTESTATION_MODE`; MainNet refuses `token-lab`; console signs via wallet `signData` / offline fallback; eng note `docs/security/audits/2026-10-12-operator-attestation-bindings.md` (internal AI review) |
| OperatorAttestation run 11 verdict (2026-10-13) | **CLEAR for TestNet hosting** under the conditions below; **MainNet NOT cleared**. OA-P3-S docs fix (auto-local tunnel warning, local `OPERATOR_SIGNDATA_DOMAIN=localhost:5173` example). Internal AI review (eng hygiene) |
| OperatorAttestation hardening run 10 (2026-10-13, `4d8cee8`) | `OPERATOR_SIGNDATA_DOMAIN` required for every signed-challenge deployment, more forwarding headers (OA-P2-Q); auto-local refused with hops > 0 and 403 for non-local callers (OA-P2-R) (internal AI review) |
| OperatorAttestation hardening run 9 (2026-10-13) | Localhost trust never applies behind a tunnel/proxy (`isTrustedLocalRequest`; forwarding headers or hops > 0 → non-local); hops > 0 requires `OPERATOR_SIGNDATA_DOMAIN` and refuses tokenless token-lab (OA-P1-O); one shared loopback client key (OA-P3-P). **Never tunnel tokenless token-lab.** (internal AI review) |
| OperatorAttestation hardening run 8 (2026-10-13, `d502fda`) | `/sign` rate limit after the auth gate, per-client (10) < global (60) (OA-P2-M); uncollected results never evicted early + per-client pending cap 50 (OA-P2-N); closes OA-P2-I (internal AI review) |
| OperatorAttestation hardening round 3 (2026-10-13, `d77e4ee`) | Bounded ac2-bridge queue (`AC2_BRIDGE_MAX_PENDING`, pending TTL → `expired`, retention eviction of finalized items + token hashes), `POST /sign` rate limit (OA-P2-I); demo-api strict loopback (OA-P3-K); negative-auth + MainNet gate route tests. Round 3 recheck: TestNet PASS, no P0/P1 (internal AI review) |
| OperatorAttestation hardening round 2 (2026-10-13, `29977dd`) | Requester status endpoint + ac2-client polling fix (OA-N1); rolling challenge limiter, clamped `OPERATOR_CHALLENGE_RATE_*`, optional `AC2_BRIDGE_TRUSTED_PROXY_HOPS` (OA-P2-G); strict loopback check (OA-P2-H); ac2-bridge route tests (internal AI review) |
| OperatorAttestation hardening (2026-10-13, `6c70f99`) | Dual-model review of `107bc4e..9ac1af0` remediated: `OPERATOR_SIGNDATA_DOMAIN` required on MainNet / non-loopback (P1-A); challenge rate limit + no pending-id oracle (P2-A); TTL 10–600s (P2-B); approve/reject final → 409 (P2-C); `useLocal` lab-only (P2-D); `no-store` (P2-E); root typecheck + middleware-express build fixed (P2-F). Note `docs/security/audits/2026-10-13-operator-attestation.md` (internal AI review) |
| Live TestNet hosting (2026-10-13) | `https://mr-api.8-221-97-26.sslip.io`, `https://mr-bridge.8-221-97-26.sslip.io`, `https://mr-console.8-221-97-26.sslip.io` behind Caddy; all three are `signed-challenge` with `CORS_ORIGINS` = `https://mandaterail.pages.dev` (checked live 2026-10-13). The Pages SPA bundle points at all three hosts (closes OPEN 2) |
| Console hardened + reviewed (runs 12–15) | Signed-challenge on every `/mandates` route incl. authorize-check, CORS, clamped limits, startup gate, atomic locked store, signed create stored byte-for-byte, principal binding (CON-P2-8), createdAt/revoked checks, server-side verified flag; demo-api `/health` no longer exposes `receiptsPath`. Run 14 live E2E 15/15 on `01b9fde`; run 15: `d8f3095` no TestNet blockers. Report `docs/security/audits/2026-10-13-console-auth.md` (internal AI review) |
| Wiki / SDK polish (closes OPEN 3) | `docs/wiki/05-developer-integration.md` (live endpoints, signed-challenge + ARC-60 flow, signed create, error codes); `packages/sdk` `.testnet()` clients, bridge `challenge()`, `encodeOperatorAttestation`, `example:live` (run against live hosts); OpenAPI live `servers` + console create 400/409 codes; `.env.example` console/bridge limits |
| Internal recheck (closes OPEN 4) | internal reviewer (internal dual-model reviewer) runs 11–15 on the operator-attestation and console tips. internal reviewer is the security gate; there's no external audit firm. Never a public "audited" claim |
| P1-3 `GET /pending` auth | Operator-gated (`action=list`) in both modes |
| P1-4 demo-api localhost bind | Default `DEMO_API_HOST=127.0.0.1` + non-loopback warning |

## OPEN (Phase 1 residuals, carried into Phase 2)

Items 2–4 of the previous list are DONE (see above). Remaining residuals are tracked in [`phase-2-mainnet-dry-run.md`](phase-2-mainnet-dry-run.md):

- Device / HSM / vault OperatorAttestation bindings (501 stub). `signed-challenge` is the only bound mode.
- Persistent / multi-instance state: challenge store, limiters, bridge queue and console mandates are in-memory or a single-process JSON file (P2-T1).
- `token-lab` (`X-MandateRail-Operator-Token`) stays local-TestNet only and is refused on MainNet.

## TestNet hosting conditions (internal reviewer run 11, internal AI review)

Hosting conditions for TestNet (all required):
1. `OPERATOR_ATTESTATION_MODE=signed-challenge` with a non-empty `OPERATOR_ALLOWLIST` and `OPERATOR_SIGNDATA_DOMAIN` set.
2. `AC2_BRIDGE_TRUSTED_PROXY_HOPS` equal to the exact number of trusted proxies in front of the bridge.
3. No `AC2_BRIDGE_AUTO_LOCAL` and no tokenless token-lab behind any proxy or tunnel.
4. No header-less tunnels (`ssh -R`, socat, raw TCP forwarding) to the bridge.
5. Co-located agents use a separate loopback-only bridge (signed-challenge `POST /sign` is refused when hops > 0).
6. Public wording stays "TestNet" and "AI security reviewed. Use at your own risk." (wording policy updated 2026-10-15); never imply a third-party audit firm, and no MainNet-ready claims.

MainNet is **not** cleared.

## How to read this doc

- **DONE** means landed in the tip baseline above for TestNet / lab demos.
- **OPEN** means remaining work before any stronger Phase 1 “complete / live” claim.
- Public materials must not say security-audited, formally verified, or MainNet-hardened based on this checklist.

