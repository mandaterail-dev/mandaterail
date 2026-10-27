# Escrow app + timelocked upgrade + automatic circuit breaker (design, option A)

Status: DESIGN ONLY, for internal reviewer review. No contract code, no deploys, no transactions yet. TestNet first.
Revision 2 (after internal reviewer run 68): kind-tagged, length-prefixed proposal hashes with a `p_kind` assert in every
execute arm (R68-P2-1); `AuthAddr(admin) == zero` on every admin arm (P2-2); release identity excludes `not_after`,
seq is strictly increasing with gaps allowed (P2-3); `config_epoch` bound into `M`, out-of-bounds evidence limited to
unreleased or in-ring seqs, release ring and evidence dedupe split (P2-4); proposal clearing on update, execution
expiry, exhaustive CONFIG record, `count` in `b:hours`, one-shot `bootstrap()`, self op-up, corrected old-key
rationale (P3-1..4); §1/§6 updated for the software verifier key (no AWS); §5.4 lists x402 options (a)–(e) as an open
decision.
Revision 3 also records the owner's x402 decision: §5.4 option (b), self-settle, anyone may submit, txid = receipt.
Revision 3 (after internal reviewer run 69, R69-P3-3): per-seq abandonment is terminal (`signed → landed | abandoned`, recorded
by both signers before `seq + 1`; the DB ledger row is marked abandoned); the verifier's per-seq store is durable
(fsync + B2 anchor, fail closed if lost); `signed_at` is bound into `M` with `not_after ≤ signed_at + 600` enforced
on-chain; the seq jump is bounded (`seq ≤ last_seq + K`, `K = 64`).
Revision 4 (after internal reviewer run 70): co-signed on-chain `abandon(seq_to)` that consumes dead seqs, plus a sign-side
K guard and a breaker/simulate preflight, all paged (R70-P2-1); `mandate_hash` commits to the merchant's own 402
challenge, which the merchant recomputes and marks used once (R70-P2-2); §5.4 pins genesis hash and asset id and
declares the `mandaterail-escrow-v1` scheme with its `X-PAYMENT` format (R70-P3-3); the evidence hash covers the
release identity tuple, not the full `M` (R70-P3-4).
Revision 5 (after internal reviewer run 71): `A` is now `MR-ESCROW-ABANDON-v2` (108 bytes) and binds `expected_last_seq` and
`not_after`; an abandon is re-issued only after the pending one landed or expired, and signers refuse every release
seq ≤ a pending `seq_to` or ≤ an abandoned seq (R71-P2-1). §5.4 merchant acceptance is one explicit conjunction,
with challenge expiry judged against signing and landing and acceptance bound to the session that received `C`
(R71-P3-3). `bootstrapped == 1` is required by `abandon`; `simulate` is bound to the submitted group id (R71-P3-4).
Revision 6 (after internal reviewer run 73): a pending `A` is judged from **every** provider's view: it expires only when
the minimum chain time across providers is past `not_after` or all providers read `last_seq > expected_last_seq`; a
lagging read or a disagreement keeps it pending (R73-P3-2). §5.4: `not_after ≤ C.expires − 30 s`, and a nonce whose
landing timestamp is unknown stays `issued` until it is resolved (R73-P3-3).
Revision 7 (after internal reviewer run 74): pending-`A` judgment needs views from **at least 2 distinct pinned
providers** (distinct operators; one provider answering twice is not agreement, R74-P3-1); a provider whose chain
time trails the signer clock by more than 60 s (or leads it by more than 30 s) is stale, paged, and dropped, and with
fewer than 2 fresh providers releases stop (R74-P3-2, §6 item 11). Implemented: `packages/signer/src/escrow-release.ts`
(runtime, one snapshot feeds the guard and `M`), `escrow-guard.ts`, and the §5.4 rules in `packages/core/src/escrow-x402.ts`.
The verifier key stays the Alibaba software key (`aliyun-softkey`), reconfirmed by the owner on Oct 22, 2026.
Decision (the owner, Oct 21, 2026, relayed by internal reviewer): the black-swan stop is **option A**: a timelocked public
upgrade plus automatic pause only. There is **no guardian, no human pause, no override key**. This doc follows the
DB design in `attested-release-signer.md` §23 (automatic rate pauses, tamper pauses with cooldown plus a 2-of-2
resume, DB caps 0.01 / 0.05 USDC) and moves the same rules on-chain.

Wording rule: this system runs on accounts the owner controls (GCP, Alibaba, Algorand keys; no AWS). Docs and public copy
describe what it does ("automatic pause", "timelocked upgrades", "capped losses"), never absolute claims.
The approved audit line stays: "AI security reviewed. Use at your own risk."

## 0. Summary

| Piece | Today | Option A |
|---|---|---|
| Who holds USDC (ASA `31566704`) | plain single-key account `SEKG…YR2M` | stateful app account (the "escrow app") |
| Who authorizes a release | payer key signs an axfer after the DB / signer gates | escrow app checks 2 Ed25519 sigs (Cloud KMS signer + verifier) and sends an inner axfer |
| Caps | DB only (0.01 per release, 0.05 per day) | DB **and** on-chain, same numbers |
| Pause | DB pause tables, automatic | DB pauses **and** an on-chain breaker, automatic only |
| Changes to code / keys / caps | redeploy | 2-of-3 multisig, public on-chain announcement, ≥72 h timelock, no bypass |

## 1. Escrow app and how the signers authorize releases

### 1.1 Accounts and keys (all pinned in global state, changeable only through §2)
- `K_SIGNER`: Ed25519 pubkey of the GCP Cloud KMS signer key (`EC_SIGN_ED25519`, HSM protection level on MainNet).
- `K_VERIFIER`: Ed25519 pubkey of the verifier's **software key file** on its Alibaba host (platform `aliyun-softkey`,
  rev 24 §24.8): generated on the host at first boot, `root:root 0600`, delivered to the verifier by systemd
  `LoadCredential`. There is **no AWS** account or key and no hardware protection. These are the same two keys the DB
  v12/v16 quorum already pins. A compromise of the verifier host can forge `K_VERIFIER` signatures; the on-chain caps
  (§4) are the bound (§6.4).
- `ADMIN`: the 2-of-3 multisig address (§2). It has **no** power over funds or pause state except through a timelocked
  upgrade. Every admin-gated arm also requires `AcctParams AuthAddr(ADMIN) == zero` (§2.3, R68-P2-2).
- `FEE_PAYER`: no special role. Anyone can submit a correctly signed release group and pay its fees. Authority comes
  only from the two signatures, never from the sender.

### 1.2 On-chain release message
JSON/JCS parsing on the AVM is too expensive, so the signers sign a second, fixed-layout binary message alongside the
existing `MR-RELEASE-ATTEST-v1` JCS attestation. Both are produced from the same DB row. The signer and verifier each
refuse to sign unless both encodings describe the same release (same nonce, receiver, amount, mandate hash).

```
M = "MR-ESCROW-RELEASE-v1"     (20 bytes, domain prefix; v1 layout below is rev 3, nothing deployed yet)
 || genesis_hash               (32)  must equal Global GenesisHash (TestNet vs MainNet)
 || app_id                     (8)   must equal Global CurrentApplicationID
 || key_epoch                  (8)   must equal global key_epoch (bumped on every key rotation)
 || config_epoch               (8)   must equal global config_epoch (bumped on every executed CONFIG; R68-P2-4)
 || seq                        (8)   last_seq < seq ≤ last_seq + K, K = 64 (gaps allowed, R68-P2-3; bounded, R69-P3-3d)
 || receiver                   (32)  merchant address
 || amount                     (8)   micro-USDC, 1 ≤ amount ≤ per_release_cap
 || signed_at                  (8)   unix seconds the signers built M; signed_at ≤ now + 30 (block-time skew)
 || not_after                  (8)   unix seconds; now ≤ not_after ≤ signed_at + 600 and not_after ≤ now + 600 (R69-P3-3c)
 || mandate_hash               (32)  SHA-512/256 of the JCS attestation (links to the DB ledger row)
```
Total 172 bytes (20+32+8+8+8+8+32+8+8+8+32). The app call passes `M`, `sig_signer`, `sig_verifier` as arguments.

**Release identity vs. validity window (R68-P2-3).** The *release identity* of `M` is
`(seq, key_epoch, config_epoch, receiver, amount, mandate_hash)`. `signed_at` and `not_after` are **not** part of it:
they are only the validity window. Because `not_after ≤ signed_at + 600` is checked on-chain, a signer can't hand out a
message that stays valid far into the future: every signed `M` dies at most 10 min after it was built, so a held-back
message is useless after that (R69-P3-3c). Retrying an unlanded release (expired window, fee cap, congestion, a verifier refusal after the signer
signed) re-signs the **same identity** with a new `not_after`, which is never equivocation (§3.1).
**Per-seq state machine (R69-P3-3a, terminal abandonment).** Each signer keeps, per seq, a record
`(identity_hash, state, last_not_after)` with `state ∈ {signed, landed, abandoned}`:
- `signed`: the identity is fixed. A retry re-signs the **same identity** with new `signed_at` / `not_after`; a
  different identity for that seq is refused (and is equivocation evidence, §3.1).
- `signed → landed`: the `REL` log for the seq is confirmed on-chain (or `last_seq ≥ seq` with the identity in `b:rel`).
- `signed → abandoned`: only after the latest `not_after` signed for that seq has passed **by chain time** (block
  `LatestTimestamp`) and the seq is not landed. Abandonment is **terminal**: an abandoned seq is never re-signed, not
  even with the same identity. The release itself, if still wanted, is re-issued as a new DB ledger row at a new seq.
- **Ordering rule:** a signer signs `seq + 1` (or any higher seq) only after **its own** record for every lower seq it
  signed is `landed` or `abandoned`, **and** it has received the peer's matching terminal record for that seq (the
  signer and verifier exchange signed `(seq, identity_hash, state)` acks over the existing attestation channel). So
  there are never two live messages for different seqs at once: the R69 race (re-signing N after N+1 was signed, then
  N+1 landing first and killing N while its ledger row stays "pending") cannot happen.
- **DB side:** when both records say `abandoned`, the signer marks the `mr_release_ledger` row `abandoned` (an
  append-only status row in a new `mr_release_ledger_status` table, owned by `mr_pause_writer`, v18 or later). The row
  **stays counted** against the DB per-release and 24 h caps (conservative), and the monitor's REL-vs-ledger check
  treats `abandoned` rows as expected-absent on-chain, so no false alarm. A `REL` log for a seq whose ledger row is
  `abandoned` is a page (it should be impossible).
- Because `release` accepts any `last_seq < seq ≤ last_seq + K`, an abandoned seq never wedges releases, and once a
  higher seq lands every lower seq is dead (`seq ≤ last_seq` fails).

**Durable verifier store (R69-P3-3b).** The verifier's per-seq records are not just host-local files:
- Written with write-temp + fsync + rename + dir fsync under `/var/lib/mr-verifier/seq/`, **before** the signature is
  released, and appended to the verifier's own B2 Object Lock chain (prefix `mr-verifier/<network>/`, its own
  write+list+read-only key, same check-then-put sink and manifest-pinned `minSeq` as the signer and the monitor).
- At start, the verifier reconciles: it reads the B2 chain head and refuses to sign anything (fail closed, pages) if
  the local store is missing, older than the B2 head, or disagrees with it. A wiped or restored-from-old-image host
  therefore can't forget what it signed and can't equivocate.
- The on-chain `last_seq` and `b:rel` are a third cross-check: the verifier refuses to sign a seq `≤ last_seq`.

**Bounded seq jump (R69-P3-3d).** `seq ≤ last_seq + K` with `K = 64` (a program constant). Even a compromised key
pair can't sign `seq = 2^64 - 1` and wedge the app forever; at most it burns 64 seqs per landed release (all still
under the caps). Honest operation stays far below K because of the ordering rule (at most one live seq).

**K-window stall and `abandon(seq_to)` (R70-P2-1).** `last_seq` used to move only when a release landed, so 64
consecutive abandoned seqs (a long breaker pause, an app freeze, a fee spike: about 11 h at one seq per 10 min) would
push every new seq past `last_seq + K` and stall the app until a 72 h UPDATE. Three layers fix this:
1. **On-chain `abandon(A, sig_s, sig_v)`**, co-signed by **both** release keys over a fixed 108-byte message
   (rev 5, R71-P2-1)
   ```
   A = "MR-ESCROW-ABANDON-v2"  (20)
    || genesis_hash            (32)  = Global GenesisHash
    || app_id                  (8)   = Global CurrentApplicationID
    || key_epoch               (8)   = global key_epoch
    || config_epoch            (8)   = global config_epoch
    || expected_last_seq       (8)   == last_seq (exact; A is void once last_seq moves)
    || seq_to                  (8)   expected_last_seq < seq_to ≤ expected_last_seq + K
    || not_before              (8)   now ≥ not_before
    || not_after               (8)   now ≤ not_after; not_before < not_after ≤ not_before + 3600
   ```
   The program asserts `bootstrapped == 1`, `last_seq == expected_last_seq`, `seq_to ≤ last_seq + K` and
   `not_before ≤ LatestTimestamp ≤ not_after`.
   Effect: `last_seq = seq_to`, so every seq in `(last_seq, seq_to]` is consumed and can never land; logs
   `("ABN", old_last_seq, seq_to)`. It moves no funds, writes no `b:rel` slot and touches no cap counter, so it is
   accepted in **both** breaker states (it is the way out of a stall after a long tamper pause). Anyone may submit it;
   authority is only the two signatures. Replays fail `seq_to > last_seq`. Bare `ed25519verify_bare` as in §1.3; same
   group, fee and `RekeyTo` rules as `release` (§1.3 items 6–7).
   **Signer rule:** a key signs `A` only when, for every seq in `(last_seq, seq_to]`, its own record is `abandoned`
   or it never signed that seq, the peer's matching terminal ack is in hand, and `not_before` is strictly greater
   than the largest `not_after` either signer ever signed for those seqs. So by chain time every release message
   for those seqs is already expired when `abandon` can land: an `abandon` and a release for the same seq can't both
   take effect, and abandoning never kills a live message. `seq_to` is the highest abandoned seq, so a single call
   clears the whole backlog. The DB marks the ledger rows `abandoned` as in the state machine above (still counted
   against the DB caps).
   **Pending-abandon interlock (rev 5, R71-P2-1).** Without an expiry and an exact `last_seq`, a co-signed `A` whose
   broadcast failed or was delayed could land later, after releases had been re-issued above the old `last_seq`, and
   consume releases signed **after** `A`. Now:
   - each signer records an issued `A` as **pending** `(expected_last_seq, seq_to, not_before, not_after)` before
     releasing its signature; it is **landed** when **every** provider reads `last_seq ≥ seq_to`, and **expired**
     when the **minimum** `LatestTimestamp` across providers is past `not_after`, or **every** provider reads
     `last_seq > expected_last_seq` (then `A` can never pass). A read with `last_seq < expected_last_seq` is a lagging
     provider, not expiry; a disagreement between providers, no provider answer, or fewer than 2 **distinct pinned**
     providers keeps `A` pending (rev 6, R73-P3-2: fail closed, the chain time input is required; rev 7, R74-P3-1);
   - while an `A` is pending, the signer refuses every release seq `≤ seq_to` (page `escrow preflight refused: seq N
     <= pending abandon seq_to M`) and signs no second `A`; a new `A` is issued only after the pending one landed or
     expired, always with `expected_last_seq` = the `last_seq` it just read;
   - a release seq `≤` the highest abandoned seq is refused (re-signing it would give that seq a second identity,
     which is equivocation evidence);
   - so any `A` that can still land was signed against the current `last_seq`, and every seq it consumes was either
     abandoned before it or refused while it was pending: it can't consume a release signed after it.
2. **Sign-side K guard.** Each signer reads `last_seq` (two providers, its own set) before signing a release and
   computes `gap = seq - last_seq`. `gap ≥ K_WARN = 32`: page `escrow seq window filling (gap N/64)`.
   `gap > K_GUARD = 48`: refuse to sign the release, page `escrow seq window: release refused`, and run
   `abandon` first (automatic, both keys, no human step). The release is then re-issued at `last_seq + 1`. Honest
   operation never gets near 48, so the guard only acts after a long outage.
3. **Breaker / simulate preflight.** Before building `M`, each signer reads the app state and refuses to sign
   (no seq is burned) when `breaker_state ≠ RUNNING`, `bootstrapped ≠ 1`, `key_epoch` or `config_epoch` differ from its
   pinned values, or the release would exceed `per_release_cap`, the 24 h headroom or `max_per_hour` (computed from
   `b:hours`). After both signatures exist, the broadcaster runs algod `simulate` on the complete signed group
   (real signatures, real fees) and submits only if it passes and the simulated group id equals the group id it
   submits (rev 5, R71-P3-4). A refused preflight or a failed simulate pages
   (`escrow preflight refused: <reason>` / `escrow simulate failed: <reason>`); a failed simulate leaves the seq to
   expire and be abandoned through (1).
Together: preflight keeps abandoned seqs rare, the K guard turns a backlog into one `abandon` call before the window
fills, and `abandon` clears a backlog even when the app was paused for days. A stall now needs **both** keys to stop
signing `abandon`, which already halts releases (§6 items 5 and 11).

### 1.3 `release` method checks (all must pass, or the whole group fails)
1. `bootstrapped == 1` and `breaker_state == RUNNING` (§3).
2. Layout and length exact (172 bytes); every field check above (including `config_epoch`, `last_seq < seq ≤
   last_seq + K`, `signed_at ≤ now + 30`, `now ≤ not_after ≤ signed_at + 600`).
3. `ed25519verify_bare(M, sig_signer, K_SIGNER)` and `ed25519verify_bare(M, sig_verifier, K_VERIFIER)`.
   Bare (RFC 8032 pure) verify, no `ProgData` prefix, so it matches what Cloud KMS and the verifier's software key
   (Node `crypto.sign(null, …)`, Ed25519 pure) produce over raw bytes.
4. Caps and rate (§4): per-release, rolling 24 h, releases per hour. The boxes `b:hours` and `b:rel` must exist; a
   missing box fails the call (fail closed, never "treat as empty").
5. Effects: `last_seq = seq`; add `amount` and 1 to the current hour slot; write the release identity hash into
   `b:rel[seq mod 16]` (with its seq); one inner `axfer` of the pinned USDC asset, `amount`, to `receiver`, with
   `Fee = 0` (outer fee pooling), and `RekeyTo`, `AssetCloseTo`, `CloseRemainderTo` explicitly set to the zero
   address; log `("REL", seq, receiver, amount, mandate_hash)`.
6. The outer transaction must have `RekeyTo == zero`, `OnCompletion == NoOp`, and the group must contain only the
   release call plus budget calls (§7.3); `GroupSize` and each sibling's `ApplicationID` / `OnCompletion` /
   `RekeyTo` are checked.
   **Fee floor (R69-P3-4):** the release txn's own `Fee ≥ 2 × Global MinTxnFee` (its own fee plus the one inner
   axfer, whose `Fee = 0` relies on pooling), and the group's total fee must cover every txn plus the inner one
   (each `opup` sibling may carry `Fee = 0` only if the release txn's fee covers it: the release asserts
   `Txn.Fee ≥ (1 + 1 + n_opup) × MinTxnFee` when the siblings carry zero fee). An underfunded group fails up front
   with a clear error instead of failing inside the inner submit.
7. Invariant on every call: `AcctParams AuthAddr(CurrentApplicationAddress) == zero` (the app account is not rekeyed).

### 1.4 Signer / verifier flow
1. DB inserts the ledger row (`mr_release_ledger`) through the v16 wrapper as today; DB caps and pauses run first.
2. mr-signer (GCP) re-checks the row, builds `M`, signs it with Cloud KMS. The verifier (Alibaba host, software key
   file, rev 24) independently re-derives the row from its own providers (dRPC only, disjoint from the signer's set)
   and signs `M`. Both apply the per-seq state machine in §1.2 (terminal abandonment, durable store, peer acks) and
   pin `app_id` and `config_epoch` in their config.
3. Our broadcaster assembles the group, pays fees from a low-balance ALGO fee account, and submits; anyone else may
   submit the same signed bundle (§5.4, option (b)).
4. The monitor cross-checks the on-chain `REL` logs against the ledger and nonce table and adds them to the B2 anchor chain.
So a release needs: DB gates, both keys (GCP Cloud KMS and the Alibaba host key), and the on-chain gates. Losing any
one of the three only stops releases.

## 2. Upgrades: 2-of-3 multisig, public ~72 h timelock, no bypass

### 2.1 Constants (in the program bytes, not in state)
- `TIMELOCK = 259200` seconds (72 h). Not stored in state, so no state write can shorten it. Changing it needs an
  upgrade, which itself waits 72 h under the old program.
- `EXEC_WINDOW = 604800` seconds (7 d). A proposal can be executed only in `[p_eta, p_eta + EXEC_WINDOW]`; after that
  it is dead and anyone may clear it with `expire()` (R68-P3-1). A stale approved change can't be sprung months later.
- `MAX_PENDING = 1`. A new proposal (of any kind) is refused while one is pending (cancel or expire first).
- `USDC_ASSET`: chosen by genesis hash in code (`31566704` MainNet, `10458941` TestNet); any other genesis rejects.

### 2.2 Global state
| Key | Type | Meaning |
|---|---|---|
| `admin` | bytes32 | 2-of-3 multisig address |
| `k_signer`, `k_verifier` | bytes32 | pinned pubkeys |
| `key_epoch` | uint | bumps on key rotation |
| `config_epoch` | uint | bumps on every executed CONFIG (R68-P2-4); bound into `M` |
| `last_seq` | uint | highest released seq |
| `per_release_cap`, `daily_cap` | uint | micro-USDC; MainNet: 10000 and 50000 |
| `max_per_hour` | uint | release count limit per hour |
| `breaker_state` | uint | 0 RUNNING, 1 TAMPER_PAUSED |
| `pause_epoch`, `paused_at`, `resume_after`, `trip_count`, `last_clean_at` | uint | §3 |
| `bootstrapped` | uint | 0 until the one-shot `bootstrap()` ran (§2.3), then 1 forever |
| `p_kind` | uint | 0 none, 1 UPDATE, 2 CONFIG, 3 DELETE |
| `p_hash` | bytes32 | kind-tagged proposal hash (§2.3) |
| `p_eta` | uint | earliest execution time = propose time + TIMELOCK (latest = `p_eta + EXEC_WINDOW`) |

Boxes (R68-P2-4: release bodies and evidence are **separate**):
- `b:hours`: the 24 h ring, 25 slots of `(hour_index, sum, count)` (§4.2).
- `b:rel`: the last 16 release identities, 16 slots of `(seq uint64, identity_hash bytes32)` = 640 bytes, written
  by `release` at `seq mod 16`. Used only to check out-of-bounds evidence for in-ring seqs (§3.1).
- `e:<evidence_hash>`: one empty box per accepted tamper evidence (dedupe that can't be evicted, §3.2). The submitter
  pays its MBR in the same group (a payment to the app ≥ the box MBR), so evidence boxes never drain the app's ALGO.
The app keeps no other box per release. Schema is fixed at creation; reserve 4 spare uints and 2 spare byte slices.

### 2.3 Methods
**Proposal hash (R68-P2-1, P3-1).** Every proposal is hashed with its kind and app id, and variable parts are
length-prefixed, so no body of one kind can be presented as another:
```
p_hash = SHA512_256("MR-ESCROW-PROP-v1" || kind (1 byte) || app_id (8) || body)
  UPDATE: body = n (1) || for each approval page: len (2) || page || m (1) || for each clear page: len (2) || page
  CONFIG: body = the canonical CONFIG record below (fixed length)
  DELETE: body = empty
```
Every execute arm asserts `p_kind` first (`execute_config` asserts `p_kind == CONFIG`, the UpdateApplication arm
`p_kind == UPDATE`, the DeleteApplication arm `p_kind == DELETE`) and recomputes the hash with its own kind byte.

**Create arm (R69-P3-4).** `ApplicationID == 0` (creation) is the only time state is set without a timelock:
- Args: `admin (32) || k_signer (32) || k_verifier (32) || per_release_cap (8) || daily_cap (8) || max_per_hour (8)`,
  i.e. exactly the 120-byte CONFIG record layout, validated with the **same** rules as `execute_config` (non-zero
  distinct keys, caps within the code bounds for the genesis, `max_per_hour ∈ [1, 60]`); the genesis hash must be a
  known network (it selects `USDC_ASSET` and the MainNet bounds).
- Initial state: `key_epoch = 1`, `config_epoch = 1`, `last_seq = 0`, `breaker_state = RUNNING`, `pause_epoch = 0`,
  `paused_at = resume_after = trip_count = 0`, `last_clean_at = now`, `bootstrapped = 0`, `p_kind = 0`,
  `p_hash = zero`, `p_eta = 0`.
- `OnCompletion == NoOp`, `RekeyTo == zero`, no inner transactions, no boxes (those come from `bootstrap()`), the
  global/local schema exactly as §2.2 (local schema 0), `ExtraProgramPages` as built. The creator gets no role: it is
  not stored, and nothing later checks it.
- The published deploy record (§5.2) lists the create args, so anyone can recompute the initial state.

**Admin checks (R68-P2-2).** `Txn.Sender == admin` alone does not detect a rekeyed admin (the 2-of-3 could rekey to a
single key and keep proposing and cancelling). So `propose`, `cancel`, the UpdateApplication arm and the
DeleteApplication arm all also require `AcctParams AuthAddr(A) == zero` where **the operand `A` is the state-held
`App.globalGet("admin")`** (R69-P3-4), never `Txn.Sender` or an argument, together with `Txn.Sender == A`. (Using
`Txn.Sender` as the operand would be equivalent only after the sender check; pinning the state value removes any
ordering mistake.) The multisig address still signs as itself. Rejected alternative: pin the 3 cosigner pubkeys in the program and verify the multisig on-chain (3 extra
ed25519 verifies per admin call); the AuthAddr check gives the same guarantee for far less budget.

- `propose(kind, hash)`: admin checks above, `kind ∈ {1, 2, 3}` (R69-P3-4: 0 or anything else is rejected, so a
  proposal can't be stored under a kind no execute arm accepts), `hash` exactly 32 bytes, no pending proposal (`p_kind == 0`). Sets `p_kind`, `p_hash`,
  `p_eta = now + TIMELOCK`. Logs `("PROPOSE", kind, hash, p_eta)`. The monitor pages ntfy and writes it to the B2
  chain; a public status page shows the pending proposal and its countdown, and the full proposal body (program pages
  or the CONFIG record) is published at proposal time so anyone can recompute the hash.
- `cancel()`: admin checks; clears `p_kind`, `p_hash`, `p_eta`; logs `CANCEL`. Cancel can only stop a change; it
  cannot touch funds or the breaker.
- `expire()`: anyone, once `now > p_eta + EXEC_WINDOW`; clears the proposal; logs `EXPIRE`.
- `execute_config(record)`: `len(record) == 120` exactly (R69-P3-4); anyone may call when `p_kind == CONFIG`, `p_eta ≤ now ≤ p_eta + EXEC_WINDOW` and the
  kind-tagged hash of `record` equals `p_hash`. The **CONFIG record is exhaustive and canonical**: a fixed 32+32+32+
  8+8+8 = 120-byte layout `admin || k_signer || k_verifier || per_release_cap || daily_cap || max_per_hour`; every field
  is always written (an unchanged field carries its current value), there are no optional or extra fields.
  Validation: each key is exactly 32 bytes and non-zero, `k_signer ≠ k_verifier`, `admin` non-zero; caps ≥ 1 and
  within the code bounds (MainNet `per_release_cap ≤ 10000`, `daily_cap ≤ 50000`, `per_release_cap ≤ daily_cap`);
  `max_per_hour` in `[1, 60]`. If either key differs from its current value, `key_epoch += 1`. Always
  `config_epoch += 1`. Clears the proposal, logs `EXEC`. Raising caps past the code bounds needs an UPDATE.
- **UpdateApplication** arm: `p_kind == UPDATE`, admin checks, `p_eta ≤ now ≤ p_eta + EXEC_WINDOW`, and the
  kind-tagged hash of `Txn.ApprovalProgramPages[0..n]` and `Txn.ClearStateProgramPages[0..m]` (length-prefixed as
  above) equals `p_hash`. The arm **clears `p_kind`, `p_hash`, `p_eta`** before approving, so the new program starts
  with no pending proposal (and the old proposal can't be re-used). Otherwise reject.
- **DeleteApplication** arm: `p_kind == DELETE`, admin checks, inside the execution window, **and** the app holds no
  USDC holding at all (opted out) and 0 ALGO beyond MBR. Since every inner close field is forced to zero, the current
  program can **never** opt out of USDC itself; so DELETE is only reachable after a timelocked UPDATE that adds an
  opt-out path (R68-P3-3). That is intended: funds leave only through `release` or a published, 72 h-delayed UPDATE.
- `bootstrap()` (R68-P3-3): callable exactly once, by anyone, while `bootstrapped == 0`. It asserts the genesis hash
  is a known network, does one inner asset opt-in (0-amount `axfer` to itself) of the `USDC_ASSET` pinned for that
  genesis, creates `b:hours` and `b:rel` (zeroed), then sets `bootstrapped = 1`. No later call can run it again, and
  no other method can opt in to anything. `release` and `report_tamper` refuse while `bootstrapped == 0`.
- `opup()`: a no-op method of **this** app, used only as budget filler (§7.3).
- **ClearState**: the app uses no local state, so the clear program is `return 1` and nothing depends on it.
- Opt-in, CloseOut: rejected.

"Lowering" changes (smaller caps, a pause) are **also** timelocked. An instant lower path would be a human pause,
which option A excludes.

### 2.4 What the timelock does and does not do
- Holders of 2 of 3 admin keys can replace the program, but only after a public 72 h notice. During those 72 h the
  old rules, caps and breaker stay in force.
- Nobody can make an emergency fix faster than 72 h. A bug is handled by the automatic breaker and the caps, then a
  timelocked fix.

## 3. Automatic circuit breaker (no human can trigger it)

### 3.1 Two kinds of stops, same as DB v16
- **Rate / cap stops** are not a state: a release that would exceed a cap or the hourly count simply fails. AVM
  failures revert all state, so nothing "trips"; the stop clears on its own as the window rolls. This matches the
  DB rule that rate pauses clear on their own.
- **Tamper pause** is a stored state (`breaker_state = TAMPER_PAUSED`). Since a failed call cannot write state, a trip
  needs a successful `report_tamper` call carrying **evidence the contract can verify on its own**. Anyone may
  submit it (including the monitor); the evidence, not the sender, decides. Honest traffic (retries, abandoned seqs,
  old releases, releases signed before a cap change) must never be valid evidence. Accepted evidence:
  1. **Equivocation (R68-P2-3):** two messages with the same `seq`, `key_epoch` and `config_epoch` whose **release
     identities differ** (`receiver`, `amount` or `mandate_hash`), each with a valid sig from the same key. Messages
     that differ only in `not_after` are the same identity (a retry) and are **not** evidence.
  2. **Out-of-bounds signature (R68-P2-4):** one validly signed `M` (by either key) with the current `key_epoch` and
     `config_epoch`, accepted only in these cases:
     - `seq > last_seq` (not yet released) and it breaks a hard rule under the caps it was signed under: wrong
       `genesis_hash` or `app_id`, `amount = 0` or `amount > per_release_cap`. (`not_after` is not checked here:
       an expired window is honest.) Because `config_epoch` must equal the current one, the caps it is compared with
       are the caps in force when it was signed: a genuine message signed before a timelocked cap decrease carries
       an old `config_epoch` and is never evidence.
     - `seq ≤ last_seq` **and** `b:rel` holds that seq (one of the last 16 releases) **and** its identity hash
       differs from the logged one. A seq outside the ring, or a skipped seq that never landed, is not checkable
       and is **never** treated as differing, so replaying old public release bodies can't trip the breaker.
  3. **Signed tamper alert:** `MR-ESCROW-TAMPER-v1 || genesis || app_id || key_epoch || pause_epoch || reason_code`
     signed by **either** automated key. The signer and verifier send it on their own when their checks detect
     tampering (DB integrity manifest mismatch, ledger vs nonce mismatch, provider disagreement). These keys are held
     by automated services (Cloud KMS; the verifier's host key file), not by a person, so this is still not a human
     pause. Residual: whoever can drive one of those keys can pause (a stop only, bounded by the cooldown; see §6).
  The admin multisig is **not** accepted as evidence.

### 3.2 Auto-resume (matches the DB v16 rule)
- On trip: `pause_epoch += 1`, `paused_at = now`, `trip_count += 1`,
  `resume_after = now + max(FLOOR, FLOOR × 2^(trip_count-1))`, capped at 7 days. `FLOOR = 21600` (6 h) on MainNet,
  a code constant; TestNet build may use 300 s, and the MainNet build refuses `FLOOR < 21600` (checked against the genesis hash).
- `trip_count` decays: if `now - last_clean_at ≥ 7 days` at resume time, it resets to 0. Same backoff as the DB.
- `resume(sig_s, sig_v)`: anyone may submit once `now ≥ resume_after`, with **both** keys signing
  `MR-ESCROW-RESUME-v1 || genesis || app_id || key_epoch || pause_epoch`. A new trip bumps `pause_epoch`, so an old
  resume attestation never matches (same "later anomaly supersedes the pending resume" rule as the verifier).
- **Canonical evidence hash (R69-P3-4, R70-P3-4).** `evidence_hash = SHA512_256("MR-ESCROW-EV-v1" || type (1) ||
  parts)`, each part length-prefixed (2 bytes). The parts cover the **release identity tuple**
  `I(M) = genesis_hash || app_id || key_epoch || config_epoch || seq || receiver || amount || mandate_hash`, never the
  full `M`: `signed_at` and `not_after` are left out, so retry variants of one identity (new validity window, same
  identity) give **one** box and can't extend the pause several times. Type 1 (equivocation) parts are the two
  identities **sorted bytewise ascending** plus `key_id`: `I_lo || I_hi || key_id` (equal identities are rejected:
  that is a retry, not equivocation), so `(M1, M2)` and `(M2, M1)` give one box. Type 2 parts: `I(M) || key_id`.
  The signatures are verified, not hashed, so a second signature over the same identity is the same box. Type 3
  parts: the alert message (it has no validity window).
- Every accepted evidence creates the box `e:<evidence_hash>`; a `report_tamper` whose box already exists is
  rejected. Boxes are never deleted or evicted (R68-P2-4: the old 16-entry `b:ev` dedupe could be evicted and then
  replayed), so the same evidence cannot be replayed to hold the app paused forever. Further new evidence while
  paused extends `resume_after`. The submitter funds the box MBR in the same group.
- The DB and the chain are independent: either one paused blocks releases. The monitor pages if they disagree for
  more than 10 min ("breaker mismatch").

## 4. On-chain caps that mirror the DB

### 4.1 Values
MainNet: `per_release_cap = 10000` (0.01 USDC), `daily_cap = 50000` (0.05 USDC), both also capped by code constants
(§2.3). TestNet uses the same numbers with TestNet USDC `10458941` (build checks asset id by genesis hash).

### 4.2 Rolling 24 h window
- Box `b:hours`: a ring of 25 entries, each `(hour_index uint64, sum uint64, count uint64)` = 24 bytes, 600 bytes in
  total (R68-P3-2). `hour_index = now / 3600`. Created by `bootstrap()`; if it is missing, `release` fails (fail
  closed).
- On `release`: slot `h mod 25`; if its stored `hour_index ≠ h`, reset it to `(h, 0, 0)`. Sum every slot whose
  `hour_index` is in `[h-24, h]` and require `sum + amount ≤ daily_cap`.
- Using 25 slots (current hour plus the 24 before) is conservative: any real 24 h interval lies inside 25 hour
  buckets, so no real 24 h span can exceed `daily_cap`. The cost is that capacity frees up to 1 h later than an
  exact sliding window. The DB uses an exact window over `mr_release_ledger`; the stricter of the two wins.
- Hourly count: the slot's own `count` field; require `count + 1 ≤ max_per_hour` (default 10), then store `count + 1`.
- Time comes from `Global LatestTimestamp` (block time). Block proposers can skew it by a few seconds, which moves
  bucket edges by seconds, not the bound. `not_after` stops old signed messages being held back for later.

## 5. Migration from the plain account `SEKG…YR2M` (TestNet first)

### 5.1 TestNet
1. Deploy the escrow app with TestNet constants; fund ~0.6 ALGO; call the one-shot `bootstrap()` (inner opt-in to
   USDC `10458941`, chosen by genesis in code; creates `b:hours` and `b:rel`). A second `bootstrap()` must fail.
2. Pin TestNet keys: Cloud KMS signer key and the verifier key (TestNet key ids, never MainNet).
3. Run the test matrix: valid release; bad sig from each key; replayed / skipped seq; wrong genesis / app id;
   over per-release cap; over daily cap over a simulated day; hourly count; each tamper evidence type; resume before
   and after cooldown; stale resume after a second trip; propose / cancel / execute before and after 72 h (TestNet
   build keeps 72 h; use a dedicated short-timelock build only in a local sandbox, never on a public net);
   update with wrong program hash; delete with funds; rekey / close fields set on outer txn. R68 cases: CONFIG
   record presented to the UPDATE arm and program pages to `execute_config` (kind tag); admin rekeyed to a single
   key (AuthAddr check); a retry that differs only in `not_after` submitted as equivocation (must be rejected); an
   abandoned seq followed by `seq + 1`; an old in-ring and an out-of-ring release body replayed as evidence; a
   pre-cap-decrease message as evidence; the same evidence twice; execute after `EXEC_WINDOW`; `expire()`.
4. internal reviewer run on the TEAL/PyTeal (or Puya) source and the test log before anything moves on MainNet.

### 5.2 MainNet (each step needs the owner's go)
1. Deploy, verify the deployed program hash matches the reviewed build, fund ALGO, call `bootstrap()` (opt-in to
   `31566704`, pinned for the MainNet genesis in code).
2. Publish app id, program hash, admin multisig address and keys in the docs and status page.
3. Move a small tranche (e.g. 0.10 USDC) from `SEKG…YR2M` to the app; run the dry run against the app.
4. Switch the release path to the app; DB stops issuing payer-key signatures (the payer key backend refuses).
5. Drain the plain account: final axfer of USDC with `AssetCloseTo = app` (closes the opt-in and returns its 0.1 ALGO
   MBR), then close ALGO to the fee account with `CloseRemainderTo`. After that the old key controls nothing. Do not
   rekey it to the app: a rekeyed empty account keeps an extra attack surface and a closed one does not.
6. Record the closing txids (USDC close-to and ALGO close) in the docs and the B2 chain, and add the old address to
   the monitor's watch list (page on any transaction touching it). The earlier rationale "keep the old key in case
   funds arrive by mistake" was wrong (R68-P3-4): a closed account has no USDC opt-in, so USDC can't arrive, and an
   ALGO payment would re-create the account under the old key. So the old key gives no recovery value and is a
   liability: destroy it after the close is confirmed and recorded (a short delay only to confirm finality).

### 5.3 ALGO minimum balance (MBR)
- App account: 0.1 ALGO base + 0.1 ALGO USDC opt-in + boxes (2500 + 400 × (key + value) microALGO each):
  `b:hours` (7 + 600 B) ≈ 0.245 ALGO, `b:rel` (5 + 640 B) ≈ 0.261 ALGO. About **0.71 ALGO** locked, plus a buffer.
  Each evidence box `e:<hash>` (34 B name, empty) costs 0.0161 ALGO and is paid by its submitter in the same group.
  Inner axfer fees are pooled from the outer txn so the app balance does not drain.
- Creator account: global schema MBR (0.1 base per app + 0.0285 per uint + 0.05 per byte slice) ≈ 0.9 ALGO for the
  schema above with spares.
- Fee account: ~0.01 ALGO per release (§7.3); keep a few ALGO, monitor low balance.

### 5.4 x402 settlement: DECIDED, option (b) self-settle (the owner, Oct 21, 2026)
Decision (the owner, in his own words, Oct 21, 2026): **option (b)**. Settlement is ours: the escrow `release` call is the
settlement, **anyone may submit** a correctly signed release group, and the **confirmed txid is the receipt**. the owner
picked it as the option with the fewest gatekeepers: no facilitator or single submitter can block or censor a release.
(Public copy still describes this concretely, e.g. "anyone can submit a signed release", never with absolute words.)

**Scheme and network binding (R70-P3-3).** Escrow payments use a distinct x402 scheme id,
**`mandaterail-escrow-v1`**, never the x402 `exact` scheme. The merchant pins, per network, the triple
`(genesis_hash, app_id, asset_id)`: MainNet `wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=` + the published app id +
USDC `31566704`; TestNet `SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=` + its app id + USDC `10458941`. A receipt is
refused unless the transaction's genesis hash, the app id and the inner axfer's asset id all match that triple
(app id alone is not enough: the same id can exist on another network).

**402 challenge (R70-P2-2).** `REL` logs are public, so a bare txid proves that *a* payment happened, not that it
paid for *this* request: a third party could present another payer's txid first. The fix is that the payment commits
to the merchant's own challenge:
- The `402` body (scheme `mandaterail-escrow-v1`) carries a challenge
  `C = {v: 1, scheme, network: genesis_hash, app_id, asset_id, receiver, amount, resource, nonce, client, expires}`.
  `nonce` is 16+ random bytes from the merchant, `resource` is the method + canonical URL, `client` is the caller
  identity the merchant already knows (API key id or wallet address; empty string if anonymous), `expires` ≤ 10 min.
  The merchant stores `nonce` as `issued` with `expires`.
- `challenge_hash = SHA-256(JCS(C))`. The client passes `C` with the spend request; the JCS release attestation
  includes `challenge_hash` (and the DB ledger row stores it), so **`mandate_hash` (SHA-512/256 of that attestation)
  commits to the challenge**. Signers refuse to sign if `C.receiver`, `C.amount`, `C.network`, `C.app_id` or
  `C.asset_id` differ from the release row, or `C.expires` has passed.
- **Challenge expiry vs landing (rev 5, R71-P3-3a).** Signers set `not_after ≤ C.expires − 30 s` (rev 6, R73-P3-3; in
  addition to `not_after ≤ signed_at + 600`), a margin for block-timestamp drift between signer and chain, so a release can only land while its challenge is valid. The merchant judges
  expiry at the **landing round's** block timestamp (`ts(round) ≤ C.expires`), not at the time it sees the payment,
  and keeps the nonce `issued` for `C.expires + 120 s` (confirmation grace). A payer whose release landed in time is
  never refused for a slow confirmation. **Timestamp unknown** (the landing round's block, or the tx itself, can't
  yet be read from the merchant's providers, or they disagree) means the nonce stays `issued` (neither served nor
  refused-and-burned) until the timestamp is resolved; the grace window never moves an unknown to `used` or to
  expired (rev 6, R73-P3-3). Rev 7: both rules are code (`escrowNotAfter`, `resolveEscrowNonce` in
  `packages/core/src/escrow-x402.ts`); a window under 20 s is refused before `M` is built.
- **Session binding (rev 5, R71-P3-3b).** The merchant stores, with the nonce, the session that received `C` (API key
  id, wallet address, or for anonymous callers a random session id it set on the `402` response). The `402` carries
  `Cache-Control: no-store`. Only that session can redeem the challenge, so with `client = ""` a party that learns
  `C` and the attestation can't race the payer.
- **Acceptance predicate (rev 5, R71-P3-3c).** The merchant serves the resource iff **all** of the following hold,
  evaluated in **one** database transaction:
  ```
  accept ⇔ C_presented == C_stored(nonce)                       -- byte-equal after JCS
         ∧ session(request) == C_stored.session                 -- R71-P3-3b
         ∧ attestation.challenge_hash == SHA-256(JCS(C_stored))
         ∧ SHA-512/256(attestation) == REL.mandate_hash         -- REL from the confirmed tx, pinned triple (§ above)
         ∧ REL.receiver == C_stored.receiver ∧ REL.amount ≥ C_stored.amount
         ∧ ts(landing round) ≤ C_stored.expires                 -- R71-P3-3a
         ∧ UPDATE nonce SET state='used' WHERE nonce=… AND state='issued' affects exactly 1 row
         ∧ INSERT (genesis_hash, txid) INTO used_txids succeeds (unique)
  ```
  Any false conjunct rolls the transaction back and refuses (a second use, an unknown nonce, an expired or
  other-session challenge, or a reused txid). A stolen txid carries someone else's challenge, which this merchant
  either never issued, bound to another session, or already marked used, so it buys nothing.

**`X-PAYMENT` format (scheme `mandaterail-escrow-v1`).** Base64 of the JSON
`{x402Version: 1, scheme: "mandaterail-escrow-v1", network: <genesis_hash b64>, payload: {txid, app_id, seq,
challenge: C, attestation: <the JCS release attestation, string>}}`. `X-PAYMENT-RESPONSE` is base64 JSON
`{success, txid, network, round}`. The txid alone is never sufficient.

**Settlement flow (b):**
1. The client calls a paid endpoint; the merchant answers `402` with the `mandaterail-escrow-v1` requirements and the
   challenge `C` (amount ≤ 0.01 USDC, receiver, nonce, resource, client, expiry).
2. The DB path runs as today plus `challenge_hash`: mandate checks, DB caps and pauses, `mr_release_ledger` row with
   its seq and `challenge_hash` (§1.4).
3. The signer and verifier sign `M` (§1.2). The API returns to the client a **release bundle**: `M`, both signatures,
   `app_id`, the unsigned group template (release call + `opup` siblings, box refs, fee floor per §1.3) and the seq.
4. **Anyone may submit.** Our broadcaster submits by default and pays fees from the fee account, but the
   client, the merchant or any third party may submit the same bundle with their own fee payer: authority is only in
   the two signatures (§1.1). Duplicate submissions are harmless (the second fails `seq > last_seq`). If nobody lands
   it before `not_after` (≤ `C.expires`), the seq is abandoned (§1.2) and a new release is issued at a new seq.
5. **Receipt = the confirmed txid** of the outer `release` app call (and its inner axfer). The receipt record
   (existing receipts endpoint/storage) stores: `txid`, confirmed round, `app_id`, `seq`, receiver, amount,
   `mandate_hash`, and the explorer link. It is written only after confirmation is seen from **two** providers (the
   signer's set and the verifier's dRPC set), never on submit.
6. **Verification by the merchant (no trust in us):** the merchant (or our middleware on its behalf) checks, from its
   own indexer/algod: the txid is confirmed on the pinned genesis hash; it is an app call to the pinned `app_id`; it
   carries a `REL` log with `(seq, receiver = merchant, amount ≥ price, mandate_hash)`; the inner axfer of the pinned
   asset id to the merchant matches; and the acceptance predicate above (R71-P3-3c) holds as one transaction. Then it
   serves the resource.
7. **Single use:** the challenge nonce goes `issued → used` atomically on acceptance, and each `(genesis_hash, txid)`
   is also stored as used, so neither a txid nor a challenge can pay twice (on-chain, a seq can't land twice).
8. The monitor cross-checks every `REL` log against the ledger and receipts and anchors it to B2 (§1.4).

**Rejected options:**
- **(a) facilitator verifies our confirmed group** — rejected: depends on GoPlausible adding app-escrow
  verification (unconfirmed), and puts a third party in the verification path; (b) gives merchants the same proof
  straight from the chain.
- **(c) pre-signed group handed to the facilitator to submit** — rejected: the facilitator controls timing and
  fees and can withhold submission (burns seqs, delays releases); (b) lets anyone submit, so no single submitter can
  stall a release.
- **(d) logic-sig delegated payer** — rejected: adds a second authorization program (lsig) with its own attack
  surface and rekey/close-field pitfalls, for no gain over the app's inner axfer.
- **(e) hot payer topped up by the app** — stays rejected: it brings back a single-key account with a balance.

Consequences: MandateRail does not use the x402 "exact" scheme on Algorand for escrow payments; the SDK and
middleware gain a "verify release txid" path (code later, TestNet first). Residual: a merchant that skips step 6 and
trusts our receipt endpoint trusts our servers; docs tell merchants to verify on-chain.

## 6. Residuals

1. **Loss window during the timelock.** If both release keys are compromised, the attacker can drain at most
   `daily_cap` per 24 h (0.05 USDC) at ≤ 0.01 per release, until a tamper trip or a key rotation (72 h). Worst case
   over a 72 h timelock: about 0.15–0.20 USDC (4 overlapping windows), plus whatever is in the app if a malicious
   UPDATE is executed. Keep only a few days of float in the app.
2. **Malicious upgrade.** 2 of 3 admin keys can replace the program after 72 h public notice (as designed). Nothing
   in the contract stops a published bad upgrade; protection is the notice (monitor pages, status page; the on-chain
   `PROPOSE` log is the source of truth) and a low balance, so a merchant or the owner can react (e.g. stop sending
   funds to the app). Users must be told this plainly.
3. **Upgrade key custody.** 3 keys, 3 places, no 2 in the same cloud account or device:
   e.g. key 1 YubiKey/hardware wallet with the owner, key 2 hardware wallet in a separate physical location, key 3 a
   KMS-held key in a cloud account different from the signer's. Losing 2 keys freezes upgrades and config forever
   (releases continue under the current rules). Never store a mnemonic for these on the box or in chat.
4. **Cloud dependence and the software verifier key.** Releases need GCP (signer, Cloud KMS) **and** the Alibaba host
   (verifier, software key file, rev 24). There is no AWS anywhere in the path. The verifier key has **no hardware
   protection**: a compromise of the verifier host forges `K_VERIFIER` signatures, so the second check can be forged
   and the on-chain caps (and the DB caps) are the bound; a full drain additionally needs the GCP signer. Root
   accounts on each cloud are trust roots (on Alibaba, root can rewrite key and RAM policies; the KMS test showed deny
   statements do not bind root). The contract limits what a cloud compromise can do to the caps; it does not stop an
   outage or account suspension, which halts releases. This system runs on accounts the owner controls and is not beyond
   anyone's control.
5. **One key pauses, both resume.** Either automated key alone can pause (by design). Bounded by cooldown and backoff
   (max 7 days per trip); a compromised key can keep the app paused by re-signing tamper alerts with new epochs.
   Losing or disabling one release key halts releases until a 72 h key rotation. If 2 admin keys are also lost, there
   is no remedy.
6. **No fix under 72 h** (as designed): a bug is handled by the automatic breaker and the caps, then a timelocked fix.
7. **Circle freeze / clawback** on USDC (§7.2), outside contract control.
8. **Public notice depends on the monitor and status page**; the on-chain `PROPOSE` log is authoritative.
9. **Block time.** Bucket edges rely on block timestamps (seconds of skew).
10. **Seq burn (R69-P3-3d).** A compromised key pair can burn up to K = 64 seqs per landed release; nothing is
    released by it and caps still apply. A lost verifier store fails closed (no signing) until reconciled with B2.
11. **Abandon (R70-P2-1).** Both keys together can `abandon` live seqs early only by signing a `not_before` that
    the signer rule forbids; a key pair that breaks the rule can at most kill unlanded releases (a stop, no funds
    move). If either key stops signing `abandon`, a backlog stalls releases, which losing that key does anyway.
    Rev 5 (R71-P2-1): a stale or delayed `A` is void once `last_seq` moves or `not_after` passes; while one is pending,
    releases at or below its `seq_to` wait at most `not_after - not_before ≤ 1 h` **while at least 2 distinct pinned
    providers are fresh** (chain time within 60 s behind / 30 s ahead of the signer clock). Under a provider stall
    that bound does not hold and is not claimed: a stale provider is paged (`escrow provider stale`) and dropped, and
    with fewer than 2 fresh providers the signer refuses **every** release (not only seqs ≤ `seq_to`) and pages
    until providers recover (rev 7, R74-P3-2: fail closed, a stop, no funds move).
    Two-provider disagreement on `last_seq` (R71-P3-4): the signer uses the **higher** value for refusals and the K
    guard (the fail-closed direction there), but a pending `A` expires only when **both** providers read
    `last_seq > expected_last_seq` or the **minimum** chain time is past `not_after` (rev 6, R73-P3-2); it signs no `A` while its providers disagree, and pages `escrow last_seq disagreement`. Implemented (rev 7): `EscrowRuntime.prepareRelease` in
    `packages/signer/src/escrow-release.ts` reads one snapshot from the pinned algod providers and runs
    `pendingAbandonStatus` + `escrowPreflight` on the same read that builds `M`.
12. **Merchant checks (R70-P2-2).** The challenge binding protects only merchants that keep their own nonce store and
    run step 6; a merchant that accepts a bare txid can be paid with someone else's receipt.

## 7. Algorand-specific risks

### 7.1 Rekey
- App accounts cannot be rekeyed by an outside transaction. The only way is an inner txn with `RekeyTo`; the
  program sets every inner `RekeyTo` / close field to zero and the review must check there is no generic inner-txn path.
- Outer txns in the group are checked for `RekeyTo == zero` so a fee account cannot be rekeyed by a crafted group.
- The app account's own `AuthAddr` is asserted zero on every call (§1.3); the admin's `AuthAddr` is asserted zero in
  every admin-gated arm (§2.3, R68-P2-2), so a rekeyed multisig loses its powers instead of passing them to one key.
- The old plain account is closed, not rekeyed (§5.2).

### 7.2 Circle controls on USDC
- ASA `31566704` has freeze and clawback addresses held by Circle (record their values from algod `asset params` at
  deploy and alert if they change). Circle can freeze the app's holding or claw back its USDC at any time; the
  contract cannot prevent it. A frozen app account makes every release fail (all-or-nothing group), which the monitor
  pages as "asset frozen", not a tamper trip.
- Merchants can also be frozen; a failed axfer to a frozen receiver reverts the release.

### 7.3 Opcode budget and fees
- `ed25519verify_bare` costs 1900 each; two cost 3800, over one app call's 700. Budget is pooled across the group:
  the release call plus ~6 sibling calls give 4900+, enough for sigs, the 25-slot sum and box I/O. **Op-up pinning
  (R68-P3-3):** the siblings must be calls to this app's own `opup()` method (`ApplicationID ==
  CurrentApplicationID`, `OnCompletion == NoOp`, `RekeyTo == zero`, selector `opup`), so there is no external op-up
  app id to pin or trust; its code changes only through the timelocked UPDATE. If an external op-up app is ever used
  instead, its id must be a program constant and the review must confirm its approval program rejects
  Update/Delete (immutable). The release method checks the siblings so the group cannot carry other actions.
- Fees: ~8 txns × 0.001 ALGO + 1 inner axfer = about **0.009 ALGO per release**, paid by the fee account via fee
  pooling. Under congestion the min fee rises; the broadcaster caps the fee it will pay and retries.
- Box references: `b:hours` and `b:rel` (and `e:<hash>` for `report_tamper`) must be in the call's box refs (each ref
  covers 1 KB of I/O budget).
- AVM version ≥ 8 (box ops, `ed25519verify_bare`, program pages in `txn`).

### 7.4 Other
- `Global GenesisHash` and asset id checks stop a TestNet build being reused on MainNet and vice versa.
- Max 16 txns per group and 256 inner txns: one inner axfer per release, no loops over unbounded data.
- Round / time windows: `not_after ≤ signed_at + 600` and `not_after ≤ now + 600` limit how long a signed message
  stays valid; `signed_at ≤ now + 30` stops future-dated messages.

## 8. Next steps (none started)
Note (R69-P3-4): the CONFIG record length was re-checked: 32 + 32 + 32 + 8 + 8 + 8 = 120 bytes (admin, k_signer,
k_verifier at offsets 0/32/64; caps and `max_per_hour` at 96/104/112); the create arm uses the same 120 bytes.
1. internal reviewer reviews this design (separate run).
2. x402 integration decided: option (b), §5.4 (SDK/middleware txid verification is code work, TestNet first).
3. Choose the admin key holders and devices (§6.3); priced options to the owner for any hardware purchase.
4. Then contract code + TestNet tests, then another audit run, then MainNet steps with the owner's go.
