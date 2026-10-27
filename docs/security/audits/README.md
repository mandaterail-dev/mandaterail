# Security audits (eng hygiene)

Dated internal review notes written after MandateRail development drops.

**These are engineering hygiene records — not public “security audited” claims.** Public messaging stays TestNet-first / not-audited until an independent external audit artifact exists and remediations clear a named gate.

| Report | Scope |
|--------|--------|
| [2026-09-21-multi-wallet-picker.md](./2026-09-21-multi-wallet-picker.md) | Multi-wallet Connect picker (Pera, Defly, Lute, Exodus, Kibisis) |
| [2026-09-21-p1-security-residuals.md](./2026-09-21-p1-security-residuals.md) | P1 residuals: API key prefix, CORS allowlist, attestation stub |
| [2026-09-24-p0-insecure-dev-mainnet.md](./2026-09-24-p0-insecure-dev-mainnet.md) | P0-1 MainNet insecure-dev gates; P1-2 SPA OperatorAuth header; P1-4 demo-api localhost |
| [2026-10-12-operator-attestation-bindings.md](./2026-10-12-operator-attestation-bindings.md) | P1-1 signed-challenge OperatorAttestation; P1-3 `GET /pending` auth; MainNet refuses token-lab |

See also [../README.md](../README.md) for the threat model index.
- [2026-10-13 console auth (runs 12–15)](2026-10-13-console-auth.md)
