# AC2 Wallet pairing (device + OpenClaw)

Full OpenClaw ↔ phone pairing cannot run unattended in CI. This doc is the first-class path so MandateRail can use a paired AC2 Wallet for IntentMandate signatures.

## Prerequisites

- Node 20+, pnpm, MandateRail repo
- [OpenClaw](https://github.com/) CLI available on the Mac
- **AC2 Wallet** app installed on the phone
- Algorand TestNet account funded + opted into USDC ASA `10458941` (payer)

## 1. Install OpenClaw AC2 plugin

Prefer the Algorand Foundation reference plugin; GoPlausible’s plugin is an alternative:

```bash
openclaw plugins install @algorandfoundation/ac2-open-claw-reference@next
# OR
openclaw plugins install @goplausible/ac2-plugin-openclaw
```

## 2. Pair the phone

```bash
openclaw ac2 pair
```

Follow the QR / deep-link prompts in AC2 Wallet. Confirm the session shows as paired.

## 3. Start MandateRail ac2-bridge

On the Mac (same machine as OpenClaw):

```bash
cd mandaterail
cp -n .env.example .env

# Manual / phone mode — do NOT set AC2_BRIDGE_AUTO_LOCAL
unset AC2_BRIDGE_AUTO_LOCAL
# Optional: mark paired for status probes
export AC2_PAIRED=true

pnpm install
pnpm --filter @mandaterail/ac2-bridge start
# → http://127.0.0.1:8790
```

## 4. Point MandateRail at the bridge

```bash
export AC2_MODE=bridge
export AC2_BRIDGE_URL=http://127.0.0.1:8790
```

Also set merchant (receive-only) separately from the phone payer:

```bash
export MERCHANT_ADDRESS=<receive-only Algorand address>
# ALGORAND_MNEMONIC is NOT required when signing via phone bridge
```

## 5. Wire OpenClaw `ac2_sign` → bridge approve

When an agent calls `HttpAc2BridgeSigner.signIntentMandate`:

1. Client `POST /sign` with a SigningRequest (`sig_hint: raw-ed25519` or `message-algorand`, `display_hint: json`).
2. Bridge returns `{ id, status: "pending" }` (manual mode).
3. OpenClaw / a thin local forwarder should:
   - read `GET /pending`
   - invoke `ac2_sign` (or equivalent) so the phone shows the mandate JSON
   - `POST /approve/:id` with `{ signature, publicKey, address }`
4. Client polls `/pending` until the signature appears (handled inside `HttpAc2BridgeSigner`).

### Thin local forwarder sketch

A tiny script can poll `/pending` and call OpenClaw; keep secrets off disk:

```bash
# Pseudocode — adapt to your OpenClaw tool surface
while true; do
  curl -s "$AC2_BRIDGE_URL/pending" | jq .
  # for each pending id: openclaw ac2 sign --message-b64 ... → POST /approve/:id
  sleep 1
done
```

## 6. Headless fallback (no phone)

For CI / unattended Mac scripts:

```bash
export AC2_BRIDGE_AUTO_LOCAL=true
export ALGORAND_MNEMONIC="..."   # never commit
export AC2_MODE=bridge
export AC2_BRIDGE_URL=http://127.0.0.1:8790
pnpm --filter @mandaterail/ac2-bridge start
pnpm e2e:ac2-local
```

Or skip the bridge entirely:

```bash
export AC2_MODE=local
export ALGORAND_MNEMONIC="..."
pnpm e2e:paid
```

## Safety

- `DEV_ALLOW_UNSIGNED=false` (default) — never flip for production
- Do not commit `.env`, mnemonics, or `apps/demo-api/data/receipts.json` with real tx history if sensitive
- Merchant (`MERCHANT_ADDRESS`) is **receive-only**; the phone / mnemonic is the **payer**

## Packages

| Piece | Path |
|-------|------|
| `Ac2Signer` / `LocalEd25519Signer` / `HttpAc2BridgeSigner` | `packages/ac2-client` |
| Bridge stub | `apps/ac2-bridge` |
| Pairing e2e (auto-local) | `scripts/e2e-ac2-local.ts` |
