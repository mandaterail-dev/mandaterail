# @mandaterail/ac2-bridge

Minimal Hono stub that fronts AC2 Wallet / OpenClaw signing for MandateRail.

## Modes

| Mode | Env | Behavior |
|------|-----|----------|
| Auto-local (CI) | `AC2_BRIDGE_AUTO_LOCAL=true` + `ALGORAND_MNEMONIC` | `POST /sign` signs immediately with the local key |
| Manual / phone | unset auto-local | `POST /sign` returns `{ id, status: "pending" }`; complete via `POST /approve/:id` |

## Endpoints

- `POST /pair/status` → `{ paired, mode }`
- `GET /pair/status` → same
- `POST /sign` — SigningRequest body → signature or pending id
- `GET /pending` — list pending / completed approvals
- `POST /approve/:id` — `{ signature, publicKey?, address? }` or `{ useLocal: true }`
- `POST /reject/:id`

## Quick start (CI / headless)

```bash
export AC2_BRIDGE_AUTO_LOCAL=true
export ALGORAND_MNEMONIC="..."   # payer key — never commit
pnpm --filter @mandaterail/ac2-bridge start
# → http://127.0.0.1:8790
```

Point clients at the bridge:

```bash
export AC2_MODE=bridge
export AC2_BRIDGE_URL=http://127.0.0.1:8790
```

## OpenClaw + AC2 Wallet (phone)

See [docs/AC2_PAIRING.md](../../docs/AC2_PAIRING.md) for device pairing steps.

Summary:

1. Install **AC2 Wallet** on the phone.
2. Install an OpenClaw AC2 plugin:

   ```bash
   openclaw plugins install @algorandfoundation/ac2-open-claw-reference@next
   # OR
   openclaw plugins install @goplausible/ac2-plugin-openclaw
   ```

3. Pair:

   ```bash
   openclaw ac2 pair
   ```

4. Run this bridge (manual mode) and set `AC2_BRIDGE_URL` so MandateRail / agents POST SigningRequests here. OpenClaw’s `ac2_sign` tool (or a thin local forwarder) should complete `POST /approve/:id` after on-phone approval.

## SigningRequest shape

```json
{
  "type": "IntentMandate/v1",
  "sig_hint": "raw-ed25519",
  "display_hint": "json",
  "message": "{...canonical mandate JSON...}",
  "message_b64": "<base64>",
  "mandateId": "optional",
  "principal": "optional"
}
```

`sig_hint` may also be `message-algorand` depending on wallet capability.


## OperatorAuth (P0)

`POST /approve/:id`, `POST /reject/:id`, and **manual** `POST /sign` require:

| Mode | Rule |
|------|------|
| `AC2_OPERATOR_TOKEN` set | Header `X-MandateRail-Operator-Token` must match |
| Token unset | Only loopback + `ALLOW_INSECURE_DEV=1` + TestNet `NETWORK` (never `ALLOW_MAINNET` / MainNet) |

Default bind remains **`127.0.0.1`**. Do not expose beyond loopback without token + network controls.

Insecure flags (`AC2_BRIDGE_AUTO_LOCAL`, `DEV_ALLOW_UNSIGNED`, and `ALLOW_INSECURE_DEV` itself) hard-fail at startup unless `ALLOW_INSECURE_DEV=1` and `NETWORK` indicates Algorand TestNet. MainNet / `ALLOW_MAINNET=1` hard-fails unless `AC2_OPERATOR_TOKEN` is set.

See `docs/api/auth.md` and `docs/security/02-remediation-status.md`.

## OperatorAuth (approve / reject)

Production OperatorAuth is **attestation-based** (AC2 phone / signing device, HSM, or vault-backed session)—not a shared agent API key. The bridge verifies operator signatures/attestations. A static `X-MandateRail-Operator-Token` is only a TestNet `ALLOW_INSECURE_DEV` shim.

## Operator challenge rate limits and proxies (internal AI review)

| Env | Default | Range | Notes |
|---|---|---|---|
| `OPERATOR_CHALLENGE_RATE_PER_IP` | 30 | 1..120 | per client key, rolling 60 s |
| `OPERATOR_CHALLENGE_RATE_GLOBAL` | 600 | 1..800 (≥ per-IP) | all clients, rolling 60 s |
| `OPERATOR_CHALLENGE_TTL_MS` | 120000 | 10000..600000 | |
| `AC2_BRIDGE_TRUSTED_PROXY_HOPS` | 0 (off) | 0..5 | rate-limit key = `X-Forwarded-For` entry n from the right |

| `AC2_BRIDGE_MAX_PENDING` | 1000 | 1..10000 | queued + retained items; full → 503 |
| `AC2_BRIDGE_PENDING_TTL_MS` | 900000 | 60000..86400000 | pending → `expired` |
| `AC2_BRIDGE_RETENTION_MS` | 600000 | 60000..86400000 | finalized items + token hashes evicted; before that, only items the requester already collected can be evicted to make room |
| `AC2_BRIDGE_MAX_PENDING_PER_CLIENT` | 50 | 1..10000 (≤ max pending) | pending items per client → 429 `client_pending_cap` |
| `AC2_BRIDGE_SIGN_RATE_PER_MIN` | 60 | 1..600 | `POST /sign` global, counted only after the loopback/auth gate → 429 |
| `AC2_BRIDGE_SIGN_RATE_PER_CLIENT` | 10 | 1..600 (≤ global) | `POST /sign` per client → 429 |

Out-of-range values refuse start. At the maximum clamps the challenge store stays under its 10k cap (800 × 12 = 9,600 live entries).

Only set `AC2_BRIDGE_TRUSTED_PROXY_HOPS` when every request reaches the bridge through exactly that many trusted proxies that append to `X-Forwarded-For` (e.g. 1 for a single Cloudflare Tunnel / reverse proxy). Otherwise clients can spoof the header and pick any per-IP key, which defeats the per-IP limit (the global cap still holds).

### Tunnels, reverse proxies and localhost trust (OA-P1-O)

A tunnel or reverse proxy on the same host (e.g. `cloudflared`, nginx, Caddy) makes **all internet traffic arrive from 127.0.0.1**. The bridge therefore treats a request as local only if the peer is loopback **and** `AC2_BRIDGE_TRUSTED_PROXY_HOPS=0` **and** none of `X-Forwarded-For`, `Forwarded`, `CF-Connecting-IP`, `X-Real-IP` or `True-Client-IP` is present. This one rule (`isTrustedLocalRequest`) governs every localhost-trust decision: `POST /sign` queueing in signed-challenge mode, tokenless token-lab operator routes, and token-lab requester status without a token.

- `OPERATOR_SIGNDATA_DOMAIN` is required for every signed-challenge deployment. Forwarding headers checked: `X-Forwarded-For`, `Forwarded`, `CF-Connecting-IP`, `X-Real-IP`, `True-Client-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Via`, `X-Client-IP`, `Fastly-Client-IP`.
- With `AC2_BRIDGE_TRUSTED_PROXY_HOPS > 0` nothing is local: startup requires `OPERATOR_SIGNDATA_DOMAIN`, refuses `AC2_BRIDGE_AUTO_LOCAL`, and token-lab requires `AC2_OPERATOR_TOKEN`. Auto-local `POST /sign` returns 403 to any caller that is not a direct loopback request. In signed-challenge mode `POST /sign` is then refused, so co-located agents need a separate loopback-only bridge.
- **Never tunnel or proxy tokenless token-lab** (`ALLOW_INSECURE_DEV=1`, no `AC2_OPERATOR_TOKEN`) **or `AC2_BRIDGE_AUTO_LOCAL`**. A proxy that adds no forwarding header (raw TCP forwarding, `ssh -R`, socat) cannot be detected: it would grant everyone lab operator access, and with `AC2_BRIDGE_AUTO_LOCAL` it would let anyone get signatures from the bridge mnemonic.
- All loopback peers (127.0.0.0/8, `::1`, `::ffff:127.x`) share **one** per-client rate-limit and pending-cap key (`loopback`).

## Requester status (agents)

A queued `POST /sign` returns `202 { id, status, requesterToken, statusUrl }`. Poll `GET /requests/{id}/status` with `X-MandateRail-Requester-Token: <requesterToken>`. Agents must not poll `GET /pending`, which is operator-only. `@mandaterail/ac2-client` `HttpAc2BridgeSigner` does this automatically.
