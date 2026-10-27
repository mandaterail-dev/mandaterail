# Manual spend release: two-person procedure (R23-P2-1)

Internal AI review (eng hygiene). Not a third-party audit.

A manual release frees a payer's daily-cap capacity. If the payment could
still confirm, the payer could overspend, so a release is gated three ways:

0. **Two observations (schema v8, R24-P2-1).** The release tool asks two
   different providers (`INDEXER_URL` plus `PROOF2_URL` / `PROOF2_KIND`, at
   least one an indexer). Each one is genesis-checked and must show the txId
   not found and a round past `lastValid + margin`. The DB re-checks both
   (different hosts, kind, 404, genesis = marker, round) and stores them in
   `proof_provider/kind/...` and `proof2_*`. Custody options:
   `docs/ops/release-custody.md`.
1. **The database checks the proof** (schema v7, `mr_spend_release`):
   - the row must have a pinned, non-null `tx_id` and `last_valid`, and the
     proof must be for exactly that txId and lastValid;
   - `margin >= 0` and `round_checked > last_valid + margin`;
   - the indexer status for the txId must be `404`;
   - the proof's genesis hash must equal the write-once `mr_network` marker
     (set by `migrate` from `NETWORK`);
   - the proof is stored in typed columns of `mr_spend_audit`
     (`proof_tx_id`, `proof_genesis_hash`, `proof_round_checked`,
     `proof_last_valid`, `proof_margin`, `proof_indexer_status`), with the DB
     clock and `session_user`.
   - `manual-release-forced` (no proof) is refused by the DB when the marker
     is `mainnet`. On TestNet the CLI needs `--force` with an explicit
     `NETWORK=testnet` and prints a warning.
   The DB cannot observe the chain itself: `round_checked` and the 404 are
   what the release tool saw on the indexer. That is why 2 and 3 exist.
2. **The credential is not on the host.** The `mr_release` password is kept
   only off-host (TestNet today: the agent box, `<workdir>/secrets/mr_release.pw`,
   0600). `/etc/mandaterail/state-release.env` on the host has a password-less
   `DATABASE_URL`. Someone with root on the host still cannot release without
   the second party supplying the password.
3. **Two people.** Every release needs:
   - **Requester** (on the host or with host access): identifies the row
     (`spend release` refuses rows without proof), records why in `--reason`.
   - **Approver** (holds the `mr_release` credential): independently checks
     the txId on an indexer/explorer for the right network, confirms the
     current round is past `lastValid + margin`, then supplies the password
     at runtime:

     ```
     ssh <host> 'cd /opt/mandaterail/current && sudo -u mandaterail env STATE_ENV_FILE=/etc/mandaterail/state-release.env \
       pnpm --filter @mandaterail/storage spend -- release --id <id> --operator "<requester>+<approver>" \
       --reason "<why, 8+ chars>" --password-stdin' < <workdir>/secrets/mr_release.pw
     ```

     The password travels on stdin only (never argv, env files or logs). The
     CLI refuses `--password-stdin` when the URL already has a password.
   - Afterwards both check `mr_spend_audit` for the row (action, proof columns,
     `session_user`) and note the release in the ops log.

For MainNet: the approver role must be a human (the owner), and the credential
moves to a device the host operator cannot read. Rotate the `mr_release`
password after any suspected exposure (role SQL with `-v rel_pw=...`).
