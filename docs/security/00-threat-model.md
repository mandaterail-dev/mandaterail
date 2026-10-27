# MandateRail threat model

**Status: DRAFT — not remediated. Internal AI review only (eng hygiene); no third-party audit. NOT formally verified.**

Independent review punchlist: [01-qwen-threat-model-punchlist.md](./01-qwen-threat-model-punchlist.md). Remediation tracker: [02-remediation-status.md](./02-remediation-status.md).

This document is an engineering threat-model skeleton for MandateRail (IntentMandate policy layer between AC2 identity and x402 / GoPlausible settlement). It is **not** an audit report, penetration-test result, formal verification artifact, or claim of production readiness.

Public materials (wiki, README, diligence packs) **must not** describe MandateRail as audited, verified, or MainNet-hardened until remediations tracked here are closed and an independent review is recorded.

| Field | Value |
|-------|-------|
| Scope | Local demo apps (`demo-api`, `console`, `ac2-bridge`), middleware packages, planned third-party API auth |
| Network assumption (current demos) | Operator laptop / localhost; TestNet defaults |
| Classification | Internal engineering draft |
| Remediation | Open — see status column below |

---

## 1. Assets

| Asset | Why it matters |
|-------|----------------|
| Payer signing material (`ALGORAND_MNEMONIC`, device keys) | Direct fund loss if leaked or misused |
| IntentMandate integrity (canonical bytes + ed25519) | Forged or mutated mandates authorize spend the principal did not approve |
| Merchant allowlist + amount / expiry / revoke policy | Bypass ⇒ agent overspend or wrong payee |
| Settlement authenticity (facilitator verify/settle) | Fake settle ⇒ merchant releases goods without payment |
| Receipt records (`receiptId`, `txId`, payer/merchant metadata) | Tampering undermines audit / dispute / reconciliation |
| Merchant API keys (planned production) | Impersonation of merchant control plane |
| AC2 bridge pending queue | Spoofed approve/reject ⇒ unauthorized signatures |

## 2. Trust zones (current vs intended)

```
[Agent / third-party caller] ──untrusted──▶ [Merchant + MandateRail lib]
        │                                         │
        │                              fail-closed│
        ▼                                         ▼
[AC2 bridge localhost] ──DEV trust──▶ [Human / phone approver]
        │
        └── mnemonic only in CI auto-local (must never ship to agents)

[Merchant] ──TLS──▶ [GoPlausible facilitator] ──▶ [Algorand TestNet / MainNet]
```

| Zone | Current demo assumption | Production intent |
|------|-------------------------|-------------------|
| `127.0.0.1` bridge / console / demo-api | Trusted operator machine; **no multi-tenant auth** | Strong auth; no localhost-trust |
| Merchant process | Honest `loadMandate` + middleware config | Same + key-scoped APIs |
| Facilitator | External HTTPS; network errors deny | Pinning / allowlisted base URL |
| Agent callers | Untrusted; present mandate + payment only | **Never** receive `ALGORAND_MNEMONIC` |
| Receipt store | Local JSON file | Integrity-protected / append-only store |

**Localhost-trust is DEV ONLY.** Binding unsigned admin APIs to loopback is acceptable for TestNet demos; it is explicitly out of scope as a production control.

## 3. STRIDE-oriented threat register

Status key: **OPEN** = identified, not remediated for production; **PARTIAL** = demo mitigations only; **PLANNED** = design intent, unimplemented.

### 3.1 Mandate forgery (Spoofing / Tampering)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-MF-01 | Unsigned mandate accepted | Caller omits signature; merchant fulfills | `DEV_ALLOW_UNSIGNED=false` default; ed25519 verify in core | Operator may flip flag; console stubs may insert placeholder sigs | PARTIAL |
| T-MF-02 | Altered fields after sign | Flip `maxAmount` / allowlist / `payTo` extras | Canonical signed bytes + verify | Ensure all policy fields are in signed payload across versions | PARTIAL |
| T-MF-03 | Wrong principal attribution | Present foreign signature / pubkey | Address/pubkey binding in verify path | Cross-check principal vs payment payer end-to-end | OPEN |
| T-MF-04 | Store injection | `POST /demo/mandates` accepts arbitrary JSON into memory store | Demo-only in-memory store; R19: loopback-only (no proxied/public writes), off on MainNet, 200-entry cap, 1 h TTL, 8 KiB body | Production mandate create must require auth + verified signature | MITIGATED (demo) |

### 3.2 Replay (Elevation / Tampering)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-RP-01 | Reuse signed mandate | Replay same mandate across payments | `nonce`, `expiresAt`, `revoked` fields | No global nonce ledger / single-use enforcement across merchants | OPEN |
| T-RP-02 | Reuse payment / settle proof | Replay facilitator artifacts | Facilitator verify/settle (external) | MandateRail-side idempotency keys TBD | OPEN |
| T-RP-03 | Stale revoke | Revoke on console not observed by merchant | Per-process / file stores | Distributed revoke propagation | OPEN |

### 3.3 Payer ≠ merchant confusion (Spoofing / Elevation)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-PM-01 | Same key as payer and payTo | Operator reuses mnemonic for `MERCHANT_ADDRESS` | Docs + `.env.example` insist on distinct roles | No runtime assert that payTo ≠ payer | PARTIAL |
| T-PM-02 | 402 `payTo` swapped | Malicious or misconfigured merchant redirects funds | Merchant configures `payTo`; allowlist is merchant **id** not address | Bind allowlist entries to settlement addresses | OPEN |
| T-PM-03 | Agent confuses receive vs spend | Agent funded with merchant address mnemonic | Institutional docs; agents must not hold mnemonic | Training + API auth model (signing only via bridge) | PLANNED |

### 3.4 Mnemonic leak (Information disclosure)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-MN-01 | Mnemonic in agent runtime | Agent env includes `ALGORAND_MNEMONIC` | Preferred path: AC2 bridge pending → human approve | CI `AC2_BRIDGE_AUTO_LOCAL` still needs mnemonic on host | PARTIAL |
| T-MN-02 | Log / error leakage | Stack traces or health endpoints echo secrets | Health logs print `(set)` not value | Audit all log paths; redact receipt dumps | OPEN |
| T-MN-03 | `.env` commit / backup | Secrets enter git or shared disks | `.gitignore` for `.env` | Operator discipline; secret scanning CI | PARTIAL |
| T-MN-04 | Bridge host compromise | Process with mnemonic auto-signs any `/sign` | Loopback bind default `127.0.0.1` | Authn on bridge; hardware / phone-only prod | OPEN |

### 3.5 Bridge spoofing (Spoofing / Elevation)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-BR-01 | Fake bridge URL | Agent pointed at attacker `AC2_BRIDGE_URL` | Operator-configured URL | Mutual auth / pairing ceremony attestation | OPEN |
| T-BR-02 | Unauthenticated approve | Anyone who can hit `/approve/{id}` injects signature | OperatorAuth + loopback default (demo) | Paired-device attestation; no non-loopback without token | PARTIAL |
| T-BR-03 | Pending queue inspection | `GET /pending` leaks messages / hints | Local-only | Authz + minimize plaintext in list | OPEN |
| T-BR-04 | Mode confusion | `AC2_BRIDGE_AUTO_LOCAL` left on outside CI | Hard-fail unless `ALLOW_INSECURE_DEV=1` + TestNet NETWORK | Broader build profiles / CI attestation | PARTIAL |

### 3.6 CORS / browser origin issues (Spoofing / Information disclosure)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-CO-01 | Over-permissive CORS | Browser origin calls console / bridge / receipts | Demos typically no broad CORS config | Explicit deny-by-default CORS for prod APIs | OPEN |
| T-CO-02 | Credentialed cross-site | Malicious page triggers revoke / approve | Localhost demos | SameSite cookies / no cookie auth; prefer API keys | PLANNED |
| T-CO-03 | Web console XSS → API | Future `apps/web` XSS hits local APIs | Fixture / mock mode available | CSP, origin allowlists, separate ports + auth | OPEN |

### 3.7 Receipt tampering (Tampering / Repudiation)

| ID | Threat | Attack sketch | Current control | Gap | Status |
|----|--------|---------------|-----------------|-----|--------|
| T-RC-01 | Local JSON rewrite | Attacker edits `receipts.json` | File permissions on operator machine | Signed receipts / chain txId as source of truth | OPEN |
| T-RC-02 | Fake receipt without settle | Insert row without facilitator success | Written only after settle in happy path | Authenticated write path; verify tx on-chain | PARTIAL |
| T-RC-03 | IDOR on `GET /receipts/{id}` | Guess/list others’ receipts | Open demo endpoints | Merchant-scoped auth; no global list for third parties | OPEN |
| T-RC-04 | Mock facilitator in prod | `DEMO_MOCK_FACILITATOR=true` mints fake tx | Documented lab-only | Hard refuse mock outside explicit demo build | OPEN |

### 3.8 Additional STRIDE notes

| Category | Notes for MandateRail |
|----------|----------------------|
| Denial of service | Facilitator / bridge unavailability fails closed (good for safety, bad for availability) — document SLA expectations |
| Information disclosure | Health endpoints expose network, ASA id, merchant configured flags — keep non-sensitive |
| Elevation of privilege | Planned merchant API keys must be hashed at rest, scoped to merchant address, optional IP allowlist |

## 4. Auth model implications (production sketch)

These controls are **design intent** for third-party / merchant API callers; they are not fully implemented in demo apps.

1. **Merchant API keys** — header `X-MandateRail-Key`; store only hashes; scope each key to a merchant address; optional IP allowlist.
2. **Agent callers** — never receive `ALGORAND_MNEMONIC`; obtain signatures only via AC2 bridge `pending → approve` (human / paired device).
3. **TestNet keys** — clearly labeled; never interchangeable with MainNet credentials in config or docs.
4. **Optional future** — HTTP Message Signatures (`HttpSignature`) for service-to-service calls.
5. **Localhost-trust** — documented DEV ONLY; production must not rely on loopback as authentication.

## 5. Explicit non-claims

- Internal AI review only (no third-party audit); not formally verified.
- Not a custodial wallet service.
- TestNet demos ≠ MainNet risk posture.
- Fail-closed facilitator client is necessary but not sufficient for merchant safety.
- Presence of this document does **not** mean remediations are complete.

## 6. Remediation tracking

Authoritative living status: [02-remediation-status.md](./02-remediation-status.md).  
Punchlist source: [01-qwen-threat-model-punchlist.md](./01-qwen-threat-model-punchlist.md).

| Priority | Item | Status |
|----------|------|--------|
| P0 | AC2 OperatorAuth + loopback default (S2) | See remediation status |
| P0 | Console unsigned-draft / no human-gate bypass | See remediation status |
| P0 | Insecure flag hard-fail (`ALLOW_INSECURE_DEV` + TestNet) | See remediation status |
| P0 | Production merchant API keys + no mnemonic to agents | Open (contract sketched) |
| P1 | Replay / nonce ledger + revoke propagation | Open |
| P2 | Mock facilitator / MandateCreate tighten | Open |

Closing demo footguns ≠ production hardened.
