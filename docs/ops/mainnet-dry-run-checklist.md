# MainNet dry run: rehearsal (T13) and run (T14) checklist

Caps (set on host 2026-10-19, R33): **0.01 USDC per payment, 0.05 USDC per day** (`SPEND_CAP_PER_PAYMENT_USDC=0.01`,
`SPEND_CAP_PER_DAY_USDC=0.05` in `$E/mainnet-common.env`; backup `mainnet-common.env.bak-20261020032438`; config load verified
with `resolveSpendCaps` from release 0957080 -> 0.010000 / 0.050000). Stack stopped + paused.

State refresh (2026-10-19 15:30 EDT, R33-P3-5): deployed release `/opt/mandaterail/releases/0957080`; all 5 mainnet units inactive;
`mainnet-PAUSE` present. Funding DONE: payer `SEKG…YR2M` 4.999 ALGO + **10.00 USDC**, merchant `VI23…MZ4I` 4.999 ALGO, both opted
into ASA 31566704. The payer holds more than the old 1 USDC at-risk ceiling: caps bound spend through MandateRail to 0.05/day,
but the payer key's full balance is at risk if the key leaks. DECISION for the owner: sweep payer down to ≤ 0.10 USDC before the run, or accept 10 USDC at risk.
Trust: host operator accepted as trusted for the dry run only (R25-P2-1, see phase-2 plan).

Conventions: `H` = `<workdir>/ecs.sh` (root on the host). `E=/etc/mandaterail`. MainNet hosts:
`API=https://mr-mainnet-api.8-221-97-26.sslip.io`, `BR=https://mr-mainnet-bridge.8-221-97-26.sslip.io`,
`CO=https://mr-mainnet-console.8-221-97-26.sslip.io`. Wallets: payer `SEKG…YR2M`, merchant `VI23…MZ4I`,
requester (agent key, no funds) `FEQ2…YGBQ`, operator `JXPW…GXP5R4` (the owner's wallet via Pages, ARC-60).
Mnemonics live only in `<workdir>/secrets/mainnet-*.mnemonic` (box, 0600) and the Mac `.secrets` dir. Never on the host, never in the SPA.

## Pause switch (P2-T10) and rollback — know these first

| Action | Command | Expected |
|---|---|---|
| PAUSE (no restart) | `H 'touch /etc/mandaterail/mainnet-PAUSE'` | `curl -s -o /dev/null -w '%{http_code}' $API/paid/resource` → **503**, body `{"error":"paused",...}`; bridge `POST /sign` → 503 |
| RESUME | `H 'rm -f /etc/mandaterail/mainnet-PAUSE'` | `/paid/resource` → 402 |
| STOP everything | `H 'systemctl stop mandaterail-mainnet-{demo-api,ac2-bridge,console}; systemctl disable --now mandaterail-mainnet-{monitor,reconcile}.timer'` | health 502 at Caddy |
| Operator kill | edit `$E/mainnet-ac2-bridge.env` + `$E/mainnet-console.env`: `OPERATOR_ALLOWLIST=` (empty) → services refuse to start | services stay down |
| Code rollback | `H 'ln -sfn /opt/mandaterail/releases/<prev> /opt/mandaterail/mainnet-current && systemctl restart mandaterail-mainnet-{demo-api,ac2-bridge,console}'` | /health 200, `gate` mainnet-dry-run |
| Funds | sweep merchant USDC + ALGO to the owner's cold address from the box (`scripts/mainnet-sweep` steps below) | indexer shows 0 |

Rollback of the whole MainNet stack (TestNet untouched): stop+disable the 5 mainnet units, `pg_dropcluster --stop 18 mainnet`
(after `pg_dump` to an age file), remove `mrm_*` lines from `/etc/redis-mr/redis.conf` (backup `.bak-pre-mainnet`), restart redis-mr,
remove the 3 Caddy vhosts and reload, `rm $E/mainnet-*`, then re-pin TestNet (`spend release-pin`) because the unit set changed.

## 0. Funding (the owner)
1. Send **ALGO**: payer **1.0 ALGO** (min 0.2 = 0.1 account + 0.1 USDC opt-in; rest buffer for opt-in/close fees), merchant **0.5 ALGO** (min 0.2).
   GoPlausible pays the payment-group fees (feePayer ZMFK…22AA on MainNet), so the payer needs no fee float.
2. We opt both into ASA 31566704 (box, signs locally, 0.001 ALGO fee each):
   `node scripts/mainnet-optin.mjs payer && node scripts/mainnet-optin.mjs merchant` (see "Box helpers").
3. Check: `curl -s https://mainnet-api.algonode.cloud/v2/accounts/<addr>/assets/31566704` → 200, amount 0, for both.
4. Send **USDC**: payer (done: 10.00 USDC received; ≤ 0.10 needed for this run). Merchant gets nothing.
   Steps 0.1-0.3 are DONE (verified on algod 2026-10-19).

## 1. Preflight (T13 rehearsal starts here)
- [ ] `H 'pg_lsclusters; sudo -u postgres psql -X -p 5434 -d mandaterail_mainnet -Atc "select count(*) from pg_db_role_setting where setrole=0"'` → cluster online, **0**
- [ ] `H 'sudo -u postgres psql -X -p 5434 -d mandaterail_mainnet -Atc "select network from mr_network"'` → `mainnet`
- [ ] Pause file present: `H 'ls -l /etc/mandaterail/mainnet-PAUSE'`
- [ ] Start apps paused: `H 'systemctl start mandaterail-mainnet-demo-api mandaterail-mainnet-ac2-bridge mandaterail-mainnet-console; sleep 5; journalctl -u "mandaterail-mainnet-*" -n 30 --no-pager | grep -i "refus\|error\|STATE_BACKEND"'`
  → no refusals; demo-api passes the algod genesis/asset check and the merchant opt-in check (fails until step 0.2).
- [ ] `for u in $API $BR $CO; do curl -s $u/health; echo; done` → 200, no secrets.
  GAP (2026-10-15 smoke start): `/health` does not yet report `network` / `asset` / `gate` (plan C), and demo-api started
  without checking the merchant's USDC opt-in. Until those land, check manually: `journalctl -u mandaterail-mainnet-demo-api | grep -i "network\|asset"`
  and the merchant opt-in curl in step 0.3.
- [ ] `curl -s -o /dev/null -w '%{http_code}\n' $API/paid/resource` → **503 paused**.
- [ ] Mnemonic scan on the host: `H 'grep -rIlE "([a-z]{3,8} ){24}[a-z]{3,8}" /etc/mandaterail /opt/mandaterail/mainnet-current/ --exclude-dir=node_modules 2>/dev/null | head'` → empty; `H 'systemctl show -p Environment "mandaterail-mainnet-*" | grep -ci mnemonic'` → 0.
- [ ] Enable MainNet monitor + reconcile timers: `H 'systemctl enable --now mandaterail-mainnet-monitor.timer mandaterail-mainnet-reconcile.timer; systemctl start mandaterail-mainnet-monitor; journalctl -u mandaterail-mainnet-monitor -n 3 -o cat'` → ok, pinOk true; pager configured.

## 2. Negative checks (still paused for 2a, resumed for the rest)
- [ ] 2a `/paid/resource` 503 while paused; `POST $BR/sign` 503 while paused.
- [ ] Resume: `H 'rm -f /etc/mandaterail/mainnet-PAUSE'`; `/paid/resource` → 402 with `accepts[0].asset` = `31566704` and network `algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=`.
- [ ] `GET $BR/pending` and `POST $BR/approve/x` without attestation → 401; `GET $CO/mandates` → 401.
- [ ] `POST $BR/sign` without `X-MandateRail-Requester-Auth` → 401 `requester_auth_failed`; with a non-allowlisted key → same 401.
- [ ] Over-cap payment: a 0.02 USDC price/payment → refused by the 0.01 per-payment cap; over-cap mandate (`maxAmount` 1.01 USDC, above hard max) at `POST $CO/mandates` → refused.
- [ ] A bridge nonce presented to the console → 401.

## 3. Happy path (T14), 3 × 0.01 USDC
1. Signed IntentMandate (principal = payer, `maxAmount` 0.10 USDC, 1 h expiry, merchant `VI23…MZ4I`) via the Pages console against `$CO` (operator `JXPW…` signs with ARC-60). Authorize-check → 200.
2. Agent (box) requests `$API/paid/resource` → 402; sends the AC2 sign request to `$BR/sign` signed with the requester key.
3. the owner approves on device (operator challenge via Pages). Payment settles via GoPlausible.
4. Verify: receipt returned; `curl -s "https://mainnet-idx.algonode.cloud/v2/accounts/VI23U6FMZK3ZXRPJZFAXAWU6VOY7JZVQXZO6ABFDBAO6K5IVZWERE2MZ4I/transactions?asset-id=31566704"` shows exactly 10000 micro-USDC per payment; monitor/reconcile clean (`stale.pending 0`).
5. Repeat 2–4 twice more (total 0.03 USDC). Then revoke the mandate; the next payment → refused.

## 4. Cap, pause and restart drills
- [ ] Daily cap (already 0.05 on host, no edit needed): after the 3 happy-path payments, pay 0.01 twice more (total 0.05); the 6th → refused. Do NOT raise the caps afterwards; any raise needs the owner's approval + internal reviewer.
- [ ] Pause mid-flow: `touch` the pause file between 402 and settle → 503; `rm` → resumes.
- [ ] Restart persistence: `systemctl restart mandaterail-mainnet-*` mid-flow; queue, mandates and nonces survive; a used nonce is still rejected.

## Success criteria
All checkboxes pass; ≤ 0.05 USDC spent; every on-chain transfer has a receipt and vice versa; no ALERT except the deliberate ones; no 5xx other than the deliberate 503s; payer balance never above its funded amount (see the funding decision above).

## Abort / rollback triggers
Any payment > 0.01 USDC, any transfer without a receipt, any unexpected ALERT, any 5xx burst → **PAUSE first**, then stop the services, then sweep.

## Close-out
1. `touch` pause file; stop + disable the 3 app services and the 2 timers.
2. Sweep: merchant USDC → the owner's cold address, then close out the payer's remaining USDC/ALGO (box helper, signed locally).
3. Report to `docs/ops/runs/<date>-mainnet-dry-run.md` (amounts, tx ids, timings) and send it to internal reviewer (gate I.7).

## Box helpers
Wallet mnemonics are read from `<workdir>/secrets/mainnet-<name>.mnemonic` by short node scripts run on the box only; they sign locally and submit to `https://mainnet-api.algonode.cloud`. They are not part of the repo and not deployed.
