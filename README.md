# MandateRail

**Delegated spend / IntentMandate policy layer** between [AC2](https://github.com/) identity and [x402](https://x402.org) payment rails.

MandateRail attaches IntentMandate requirements to HTTP `402 Payment Required` responses, evaluates policy (amount cap, merchant allowlist, expiry, revocation), then calls the **GoPlausible facilitator** (`/verify`, `/settle`). It never fakes settlement and does not vendor GoPlausible.

## Architecture (short)

```
Client / Agent
    │
    ▼
Merchant (Hono/Express + MandateRail middleware)
    │  402 + payment extras + mandate extras
    ▼
AC2 (LocalEd25519Signer | HttpAc2BridgeSigner / phone)
    │
    ▼
MandateRail policy engine
    │  amount · allowlist · expiry · revoked
    ▼
GoPlausible facilitator (TESTNET by default)
    │  /verify → /settle
    ▼
x402 settlement → receipt store
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), and [docs/AC2_PAIRING.md](docs/AC2_PAIRING.md). HTTP contract sketch: [openapi/openapi.yaml](openapi/openapi.yaml) (auth notes in [docs/api/auth.md](docs/api/auth.md); threat model draft in [docs/security/](docs/security/)).

## Monorepo

| Path | Package | Role |
|------|---------|------|
| `packages/schema` | `@mandaterail/schema` | IntentMandate Zod + JSON Schema |
| `packages/core` | `@mandaterail/core` | Policy engine + tests |
| `packages/ac2-client` | `@mandaterail/ac2-client` | `Ac2Signer`, local + HTTP bridge signers |
| `packages/middleware-hono` | `@mandaterail/middleware-hono` | 402 extras + policy → facilitator |
| `packages/middleware-express` | `@mandaterail/middleware-express` | Thin Express stub |
| `packages/facilitator-goplausible` | `@mandaterail/facilitator-goplausible` | Fetch client `/verify` `/settle` |
| `apps/demo-api` | `@mandaterail/demo-api` | Demo Hono server + receipt store |
| `apps/ac2-bridge` | `@mandaterail/ac2-bridge` | AC2 pairing / sign approval stub |
| `apps/console` | `@mandaterail/console` | Create / list / revoke mandates |

## Requirements

- Node.js **20+**
- [pnpm](https://pnpm.io) 9+ (recommended)

## Quick start

```bash
cd mandaterail
cp .env.example .env
pnpm install
pnpm test                 # core + ac2-client vitest (no OpenClaw required)
pnpm --filter @mandaterail/demo-api start
# → http://127.0.0.1:8787
```

Console (optional):

```bash
pnpm --filter @mandaterail/console start
# → http://127.0.0.1:8788
```

## Safety defaults

| Knob | Default | Meaning |
|------|---------|---------|
| `DEV_ALLOW_UNSIGNED` | `false` | Reject unsigned / unverified mandates |
| Facilitator network | **TESTNET** | `GOPLAUSIBLE_BASE_URL` points at testnet |
| Settle | **fail closed** | Network/API errors → deny; never fake settle |

Do not enable unsigned mode in production.

## Documentation

Developer wiki (index + architecture, protocol, console, integration stub, security):

- [docs/wiki/](docs/wiki/) — start at [docs/wiki/README.md](docs/wiki/README.md)

Also: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/PROTOCOL.md](docs/PROTOCOL.md), [docs/AC2_PAIRING.md](docs/AC2_PAIRING.md).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## A→Z Algorand TestNet paid path (merchant ≠ payer)

Real TestNet exact payment against GoPlausible (`https://facilitator.goplausible.xyz`) with cryptographic IntentMandate signatures (ed25519 / Algorand keys).

**Roles are distinct:**

| Env | Role |
|-----|------|
| `MERCHANT_ADDRESS` | Receive-only **payTo** (must be opted into USDC) |
| `ALGORAND_MNEMONIC` | **Payer** — signs mandate + funds the axfer |

### Network constants

| Item | Value |
|------|-------|
| CAIP-2 | `algorand:SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=` |
| USDC ASA | `10458941` (6 decimals) |
| Fee payer | `ZMFK2OI7ZBD2U27ISERZC4S6LKM6WMFJPZQ4MYNJDZ2VNBNMBA67RA22AA` |
| Facilitator | `https://facilitator.goplausible.xyz` |
| Explorer | `https://explore.algokit.io/testnet/transaction/{txId}` |

### Steps

```bash
cp .env.example .env
pnpm install
pnpm test

# 1) Create two TestNet wallets (payer + merchant)
pnpm create-wallet   # → ALGORAND_MNEMONIC (payer)
pnpm create-wallet   # → MERCHANT_ADDRESS only (receive-only; fund + USDC opt-in)
# Fund ALGO at https://bank.testnet.algorand.network/
# Opt both into USDC ASA 10458941

# 2) Configure distinct merchant vs payer
export MERCHANT_ADDRESS=<merchant-algorand-address>
export ALGORAND_MNEMONIC="<payer 25-word mnemonic>"

# 3) Start demo-api
pnpm demo
# → http://127.0.0.1:8787

# 4) Unpaid probe → 402 with PaymentRequirements (payTo = MERCHANT_ADDRESS)
curl -si http://127.0.0.1:8787/paid/resource | head

# 5) Paid e2e (signs mandate as payer, axfer to merchant, verify+settle)
pnpm e2e:paid
# Expect HTTP 200 with receiptId + explorerUrl

# 6) Receipts
curl -s http://127.0.0.1:8787/receipts | jq .
curl -s http://127.0.0.1:8787/receipts/<receiptId> | jq .
```

Safety defaults: `DEV_ALLOW_UNSIGNED=false`, never fake settle unless `DEMO_MOCK_FACILITATOR=true`.

### Receipts

After a successful settle, demo-api persists a receipt under `apps/demo-api/data/receipts.json` (override with `RECEIPTS_PATH`):

`receiptId`, `mandateId`, `txId`, `network`, `payer`, `merchant`, `amount`, `asset`, `createdAt`, `explorerUrl`

Paid `200` responses include `receiptId` + `explorerUrl`.

## Web console wallet (display identity)

The `apps/web` console Connect button opens a multi-wallet picker (`@txnlab/use-wallet-react` on TestNet): **Pera, Defly, Defly Web, Lute, Exodus, Kibisis**, plus optional WalletConnect when `VITE_WALLETCONNECT_PROJECT_ID` is set. Display identity only — IntentMandate signing remains on the AC2 bridge / OperatorAuth; the SPA never receives mnemonics. API demo mode is controlled by `VITE_USE_API_MOCKS` (with `VITE_USE_MOCKS` as a compatibility alias); wallet mocking is separate via `VITE_WALLET_MOCKS=true` (picker of six still shown; connect yields `DEMO_PRINCIPAL` / providerName `Mock`). Cloudflare Pages uses API mocks while keeping real wallet providers available.


## AC2 Wallet pairing path

Full OpenClaw + phone pairing cannot run unattended here. Use the integration layer:

```bash
# Headless bridge (CI): auto-sign with ALGORAND_MNEMONIC
export AC2_BRIDGE_AUTO_LOCAL=true
export ALGORAND_MNEMONIC="..."
pnpm ac2-bridge
# → http://127.0.0.1:8790

export AC2_MODE=bridge
export AC2_BRIDGE_URL=http://127.0.0.1:8790
pnpm e2e:ac2-local
```

Phone + OpenClaw steps: [docs/AC2_PAIRING.md](docs/AC2_PAIRING.md)

```bash
openclaw plugins install @algorandfoundation/ac2-open-claw-reference@next
# OR: openclaw plugins install @goplausible/ac2-plugin-openclaw
openclaw ac2 pair
# point AC2_BRIDGE_URL at apps/ac2-bridge (manual mode)
```

`Ac2Signer` implementations live in `@mandaterail/ac2-client` (`LocalEd25519Signer`, `HttpAc2BridgeSigner`).
