# mr_release credential custody (R24-P2-1)

Internal AI review (eng hygiene). Not a third-party audit. **Status: options only.
Nothing has been moved.** Moving the credential is the owner's step.

## Why

Since schema v8 the database checks two chain observations for every manual
release (`mr_spend_release`): two different provider hosts, at least one an
indexer, each genesis-checked against the write-once `mr_network` marker, each
reporting the txId not found and a current round past `lastValid + margin`.
Both are stored in typed `mr_spend_audit` columns (`proof_*`, `proof2_*`).

The database still cannot see the chain. Whoever holds the `mr_release`
password can call the function with made-up observations. The observations
make an honest mistake much less likely and leave a record. They do not stop
a dishonest credential holder. So the credential has to sit with a person who
is not the host operator: the owner.

Today (TestNet) the password is on the shared agent box at
`<workdir>/secrets/mr_release.pw` (0600). Every agent on the box can read
it, so the "two-person" procedure is really one party (internal reviewer, run 24).

## Options

### A. 1Password (recommended)
- Store the password as a 1Password item in the owner's private vault, e.g.
  `MandateRail / mr_release (TestNet)`, and later a separate MainNet item.
- Release from the owner's Mac. The password is piped in and never written to disk:
  ```
  op read "op://Private/mr_release (TestNet)/password" | \
    ssh <host> 'cd /opt/mandaterail/current && sudo -u mandaterail env STATE_ENV_FILE=/etc/mandaterail/state-release.env \
      pnpm --filter @mandaterail/storage spend -- release --id <id> --operator "<requester>+david" \
      --reason "<why, 8+ chars>" --password-stdin'
  ```
- With 1Password's Touch ID unlock, every release needs the owner's approval.
- Pro: biometric gate, audit log in 1Password, easy to rotate. Con: needs the `op` CLI on the Mac.

### B. File on the owner's Mac (Keychain or 0600 file)
- `security add-generic-password -s mandaterail-mr_release -a mr_release -w` (Keychain), or a 0600 file
  outside any synced folder.
- Release: `security find-generic-password -s mandaterail-mr_release -w | ssh <host> '... --password-stdin'`.
- Pro: no extra tools. Con: weaker approval prompt than 1Password, and easier to copy by accident.

### C. Run the release CLI on the owner's Mac over an SSH tunnel
- `ssh -N -L 15433:127.0.0.1:5433 <host>`, then on the Mac run
  `DATABASE_URL=postgres://mr_release@127.0.0.1:15433/mandaterail NETWORK=... INDEXER_URL=... PROOF2_URL=... PROOF2_KIND=... \
   pnpm --filter @mandaterail/storage spend -- release ... --password-stdin` with the password from A or B.
- The chain observations then come from the owner's own network path, not the host's,
  so the host can't fake them.
- pg_hba must allow `mr_release` from 127.0.0.1 only (it does today); the tunnel ends on the host's loopback.
- Pro: strongest separation. Con: needs a repo checkout and Node/pnpm on the Mac.

A or B combined with C is the target for MainNet.

## Cut-over steps (when the owner chooses)
1. Rotate: run the role SQL with `-v rel_pw=<new>`. Read the new password from 1Password or the Keychain
   so it never appears on the box.
2. Store it per the chosen option. Never in git, chat, env files or shell history.
3. Delete `<workdir>/secrets/mr_release.pw` from the agent box (`shred -u`).
4. Do a TestNet dry run: release a seeded expired row, then check `mr_spend_audit` (both observations, `session_user = mr_release`).
5. Update `docs/ops/release-two-person.md` and the host notes. After that, agents can prepare releases but not run them.

## Still open
- Both public TestNet providers (algonode, Nodely) are run by the same company. For MainNet the second
  observation should come from a different operator or from a node we run ourselves.
- A signed attestation (e.g. the observer signs `(txId, round, genesis)` with a key held by the owner) would make
  the observations checkable in the DB. Not implemented.

## Provider allowlist (R25-P2-1, partial; schema v9)

Run 25 showed that "different providers" was just a comparison of host strings: `127.0.0.1` + `localhost`,
a host + the same host `:443`, and `x.invalid` + `y.invalid` all released an unexpired row.

Now:
- Each network profile (`@mandaterail/core` `TESTNET_PROVIDER_ALLOWLIST` / `MAINNET_PROVIDER_ALLOWLIST`, exposed as
  `profile.providerAllowlist`) lists the hosts a proof may come from, each with an **operator id**.
- The migration seeds the same list into `mr_network_provider (network, host, operator_id)`. The table is
  owned by the owner, and nobody else can write it. A CHECK refuses loopback, localhost, `*.localhost`,
  `*.invalid` and IP literals.
- `mr_spend_release` (the DB) strips the port and looks up each observation host on the marker network's list.
  It refuses loopback, localhost, .invalid and IP literals, and hosts that aren't on the list. It requires the
  two observations to have **different operator ids**, and stores both operator ids in the audit row
  (`proof_operator`, `proof2_operator`).
- The release CLI (`twoProviderNoConfirmProof`) applies the same rules before it makes any network call.

Still open: the observations are self-reported by whoever holds the mr_release credential. There are no signed
attestations (out of scope for this change). The real fix is still credential custody, or signed attestations.

**TestNet today has ONE operator.** algonode.cloud and nodely.dev are both Nodely (`operator_id = nodely`), so a
proof-based `manual-release` on TestNet is currently **refused by the DB**. To release on TestNet you need one of:
1. **A second operator (preferred, and needed for MainNet anyway).** Run your own node or pick a provider from
   another company. Add it to the profile allowlist in `packages/core/src/network.ts` and add a migration that
   inserts it into `mr_network_provider` (for example `('testnet', 'idx.own-node.example.com', 'own-node')`).
   Then point `INDEXER_URL` or `PROOF2_URL` at it.
2. **A TestNet-only override.** Not implemented. If you build one, it must be refused by the DB when the
   marker is mainnet, as `manual-release-forced` already is. Today the forced release
   (`--force`, `manual-release-forced`, TestNet only, refused on mainnet by the CLI and the DB) is the only way
   to free a stuck TestNet row, and it is audited as FORCED with no proof.
