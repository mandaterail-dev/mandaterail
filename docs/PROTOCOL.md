# MandateRail Protocol

## IntentMandate

An **IntentMandate** authorizes an agent (or client) to spend up to a capped amount at allowlisted merchants, until expiry or revocation.

### Logical fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string (uuid) | Mandate identifier |
| `principal` | string | AC2 principal / DID / address that issued the mandate |
| `agent` | string | Agent identity allowed to spend under this mandate |
| `maxAmount` | string (decimal) | Maximum spend (inclusive), in `asset` units |
| `asset` | string | Asset ticker or CAIP-19 id (e.g. `USDC`) |
| `allowlist` | string[] | Merchant ids / origins permitted |
| `expiresAt` | string (ISO-8601) | Hard expiry |
| `revoked` | boolean | Soft revoke flag |
| `nonce` | string | Replay protection |
| `signature` | string \| null | AC2 / principal signature (optional when `DEV_ALLOW_UNSIGNED`) |
| `createdAt` | string (ISO-8601) | Creation time |
| `metadata` | object | Opaque extensions |

Canonical Zod + JSON Schema live in `@mandaterail/schema`.

## HTTP 402 extras

When payment is required, MandateRail middleware augments the `402` response:

```http
HTTP/1.1 402 Payment Required
Content-Type: application/json

{
  "error": "payment_required",
  "payment": {
    "scheme": "x402",
    "network": "testnet",
    "amount": "1.00",
    "asset": "USDC",
    "payTo": "0xMerchant..."
  },
  "mandate": {
    "required": true,
    "accept": ["IntentMandate/v1"],
    "hints": {
      "merchantId": "demo-merchant",
      "maxAmountSuggested": "1.00",
      "asset": "USDC"
    }
  }
}
```

### Fulfillment request

Client retries with payment proof **and** mandate attachment:

```http
POST /resource
X-PAYMENT: <x402 payment payload>
X-MANDATE-ID: <mandate id>
X-MANDATE: <base64url JSON IntentMandate or pointer>
```

## Policy evaluation order

1. Schema validate IntentMandate
2. Reject if `revoked === true`
3. Reject if `now > expiresAt`
4. Reject if request amount `> maxAmount`
5. Reject if merchant not in `allowlist` (empty allowlist = deny)
6. AC2 signature verify (stubbed — see TODOs)
7. Facilitator `/verify` then `/settle` (fail closed)

## Facilitator (GoPlausible)

- Default base URL: testnet facilitator
- Endpoints used: `POST /verify`, `POST /settle`
- Errors / non-2xx / invalid JSON → **deny** (never invent a settle receipt)
