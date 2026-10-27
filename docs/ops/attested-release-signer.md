# Attested release signer (design; closes R25-P2-1)

Status: rev 26 (Oct 22, 2026, 19:31 ET, the owner): MainNet signer = GCP Cloud KMS (`active.signer = "gcp"`; reported 2026-10-23: key version 1 ENABLED, one key-level signerVerifier binding for mr-signer@; signer VM not created yet (Compute Engine API disabled); see docs/ops/kms-key-order.md); aliyun-softkey = the only active co-signer; AWS KMS = backup, locked. (rev 25, R75-P2-1, had GCP as a locked backup.) Earlier sections naming AWS as the verifier or `awskms`/`aliyun-aws-kms` as a MainNet co-signer are superseded; the verifier refuses them on MainNet.
Rev 24 (Oct 21, 2026, CHANGE FROM DAVID: option C dropped; **correction: no AWS account exists and no AWS KMS key was ever created**; the verifier co-signs with a software Ed25519 key file generated on its Alibaba host, MainNet refused unless a manifest-pinned flag is set; see §24.8).
Rev 22 (Oct 21, 2026, CHANGE FROM DAVID: mr-verifier moves from AWS to its own Alibaba Cloud ECS instance; internal reviewer run 62 fixes: no GUC-gated pause writes, v13 renumbered to v16 after getblock v13-v15, monitor pause checks, verifier pause lifts only after the observed resume; see §24).
Rev 21 (Oct 21, 2026, CHANGE FROM DAVID: fully automatic signing, no human unlock / pause / kill switch, automatic rate-pause clearing, tamper pauses resume only after a cooldown with a fresh 2-of-2 quorum verified by DB v16, DB-enforced caps, R53 P3s; see §23, which supersedes every unlock / manual-pause step in §9 and §13–§22).
Rev 20 (Oct 19, 2026, internal reviewer run 52: atomic allowlist refresh, signature-first unlock limit, OnFailure pager, shared front-end IPs; see §22). Rev 19 (run 51: verifier HTTPS egress allowlist, EIP/KMS-key prevent_destroy, corrected §20.2 credential-theft note, held P3s; see §21). Rev 18: §20.
Rev 17 (Oct 19, 2026, internal reviewer run 49: KMS sign reconcile + static-IP/VPC match, forwarder dead-man, AWS verifier terraform, held P3s; see §19).
Rev 16 (Oct 19, 2026, internal reviewer run 48: AWS KMS verifier backend, trust domains in v12, GCP alerts to ntfy, signed unlock; see §18).
Rev 15 (Oct 19, 2026, CHANGE FROM DAVID: the automated signer runs in a Google Cloud VM with a Cloud KMS key, not on a home machine with a YubiKey; see §17, which supersedes the YubiKey/home-host parts of §13–§16).
Rev 14 (after internal reviewer run 46: R46-P2-1 audit mutex, operator count, verifier trust domains, held P3s, A7 with our own payment; see §16).
Rev 13 (after internal reviewer run 45: v12 2-of-2 quorum, second verifier, ykcs11 backend, host configs, rehearsal A7; see §15).
Rev 12 (after internal reviewer run 44: mr-signer main wired, reconcile of stuck rows, rehearsal A1–A6 run on TestNet, see §14.2).
Rev 11 (after internal reviewer run 43 on 65eb15c; R43-P2-1..4 and the held P3s fixed, see §14).
Rev 10 (after run 42 on rev 9 d2df94d): **Software implemented** (TestNet/dev
only; see §14 for the commits); nothing provisioned, nothing applied to any ECS database. Rev 10: the signer is
**automated** (the owner, Oct 19) and §13 adds a layered defense-in-depth design with a threat/layer/cost table; R42-P3-1
fixes: "independent vantage point" wording, the caps line, the used.db DB-export procedure, chrony skew refusal, refuse
if any provider shows the txn present, keyId length (32 hex), gating of IMA policy updates, snapshot staleness.
Rev 9: (a) the CLI verifies the returned msg and signature before `mr_spend_release`; (b) a
rewritten §6.2b trust statement (the signer host is the absence oracle); (c) the CLI checks absence independently
before submitting. Held P3s: used.db backup and recovery, the 3-miss lock as a DoS lever, and helper/mr-signer binary
integrity.
Earlier: rev 8 = read-only /tmp, §6.2b, AuthorizedKeysFile/PidFile, disk-full exemptions, Z1 row; Earlier: rev 7 = sandboxed mr-confirm sshd, watcher as backup, nsenter check, bind race, dedicated machine primary,
break-glass log rotation; rev 6 = lifetime socket watch, private /tmp, mid-session forward test, held P3s; rev 5 = R37 1-3 plus the kind
CHECK, upgrade cutoff, xpayment txId, helper checks, WireGuard, console auth; rev 4 = R36 1-7 plus the fee caps, `from=`,
lv_est, home-IP, deterministic build; rev 3 = R35-P1-1, R35-P2-1..5; rev 2 = R34-P1-1..4 and the R34 P2s. Section 12 lists the
P3s parked for later.

the owner's decision (Oct 19): the signing secret lives in a separate, isolated,
encrypted vault container run by a dedicated signing agent whose only role is
signing. Broadcast happens in a different environment.

## 0. Problem recap

R25-P2-1: `mr_spend_release` frees an ambiguous (submitted, unconfirmed) spend
on the word of whoever holds the `mr_release` credential, and that party in turn
trusts whatever the configured providers report. A compromised host, CLI or
provider can release a spend whose transaction later lands, which lets it spend
twice inside the cap.
Goal: a release is accepted only with a signature from a key that (a) never
exists on the agent box, the owner's daily-use Mac or the DB host, (b) is used only
after the signer has decoded the real signed transaction and seen, from two
pinned independent operators, that it can no longer confirm, and (c) is used only
after a human confirms on the signer itself.

## 1. Components and trust zones (R34-P1-1)

| Zone | Runs | Holds | Never holds |
|---|---|---|---|
| Z1 Signer host: dedicated VPS/machine, **separate cloud account** (not the Alibaba account of the DB) | `mr-signer` container only (no other code or agents) | the Ed25519 attestation key **on the YubiKey (non-exportable PIV, §6.1)**; an age-encrypted key file exists only in the §6.3 fallback for pre-5.7 firmware. Also provider API keys and request-auth public keys | payer key, DB creds, broadcast code |
| Z2 Broadcast env (ECS app) | existing submit path | payer spend key (existing custody) | signer key |
| Z3 DB host (ECS, Alibaba account A) | Postgres + v11 verifier | pinned signer **public** key, operators, margin, nonce table | signer private key |
| Z4 Operator (release CLI) | `mandaterail spend release --attest` | request-auth key (ed25519 SSH/FIDO2) | signer key |
| Agent box / Mac | dev, build, docs | nothing for MainNet signing | any signer key or identity |

Rev 1's Mac-local OrbStack/Docker option is **dropped**. A container on the owner's
daily Mac shares a kernel/VM, a user session and iCloud with everything else.

Signer account isolation: a new provider account with its own email alias,
hardware-key 2FA and its own billing. No API tokens for it live on the agent box,
and nobody who holds Alibaba account A credentials can reach it.

### 1.1 Request authentication and on-signer confirmation

**Transport and SSH hardening (R35-P2-5).** The signer has no public port except sshd (non-22 port, provider firewall
plus nftables allowlisted to the operator's egress, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`,
`PermitRootLogin no`, `AllowUsers mr-req mr-confirm`, `PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com`,
`AuthenticationMethods publickey`, global `AllowTcpForwarding no`, `AllowStreamLocalForwarding no`,
`AllowAgentForwarding no`, `X11Forwarding no`, `PermitTunnel no`, `MaxAuthTries 2`, `LoginGraceTime 20`). Egress is
443 to the pinned provider IPs only. The only forwarding exception is per user (R36-3):

```
Match User mr-confirm
    AllowStreamLocalForwarding remote
    StreamLocalBindMask 0177
    StreamLocalBindUnlink yes
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```
`mr-req` stays under the global `no` for all forwarding. The **dedicated-machine option (YubiKey plugged into the
signer) needs no forwarding at all**, so the `Match` block is omitted there and the whole forwarding risk disappears.
- `mr-req` `authorized_keys`: `restrict,command="/usr/local/bin/mr-signer request",from="10.77.0.2/32",verify-required sk-ssh-ed25519@openssh.com AAAA... req-david-2026`.
  `restrict` disables pty and every forwarding option. `verify-required` is set too, so the PIN is needed as well as the touch.
- `mr-confirm` `authorized_keys` (R37-1):
  `restrict,port-forwarding,pty,command="/usr/local/bin/mr-signer confirm",from="10.77.0.2/32",verify-required sk-ssh-ed25519@openssh.com AAAA... confirm-david-2026`.
  This is a different FIDO2 credential from the request key. `permitlisten` is **not** used, because it only accepts
  host:port and cannot name a unix-socket path. `restrict` disables everything, and `port-forwarding` re-enables
  forwarding for this key only. sshd then limits it to remote stream-local forwarding through the `Match` block
  (`AllowTcpForwarding no`, `AllowStreamLocalForwarding remote`), so TCP `-L`, `-R` and `-D` and local stream-local
  forwarding are all refused by sshd.
  **The forced command enforces the socket path:** at start, `mr-signer confirm` lists the unix sockets bound by its
  own sshd session process (`ss -xlp`, filtered on the session's sshd pid). It requires **exactly one**, at
  `/run/mr-signer/confirm/piv.sock`, owned by `mr-confirm` with mode 0600 (`StreamLocalBindMask 0177`). The directory
  `/run/mr-signer/confirm` is 0700 `mr-confirm`, and `mr-confirm` can write nowhere else under /run. Any other or extra
  bound socket means it prints a refusal and exits, which ends the session. The helper is reached only through that
  path.
- **Socket watch for the whole session (R36-P2-3.1).** A start-time check isn't enough, because a client can add a
  forward later (`ssh -O forward`, or the `~C` escape). So:
  - `mr-signer confirm` starts a watcher thread that polls the session sshd pid's bound unix sockets every 250 ms, and
    also subscribes to inotify `IN_CREATE` on `/run/mr-signer/confirm` and on every directory `mr-confirm` can write.
  - It **re-checks synchronously right before each PIV sign request** is written to the socket: exactly one socket,
    the expected path, owner and mode.
  - On any extra or changed socket (or a TCP listener, if sshd were ever misconfigured), it kills the whole session:
    `kill -TERM` the session's sshd child, then `-KILL` after 1 s. It purges that session's pending confirmation, logs
    it, and pages through ntfy. A sign already in flight has its response discarded and is never released.
- **Applies only to the VPS alternative.** The primary dedicated-machine option (§7) has no forwarding, so it needs
  none of the sockets, sandbox or watcher below.
- **Dedicated sandboxed sshd for `mr-confirm` (R39-P2-1).** `mr-confirm` doesn't log in through the main sshd. It has its
  own instance, `mr-confirm-sshd.service`, with its own `sshd_config` (`ListenAddress 10.77.0.1:2222`, `AllowUsers
  mr-confirm`, the `Match` settings above as global settings, its own host key, also pinned,
  `AuthorizedKeysFile /etc/ssh/mr-confirm/authorized_keys/%u` (root:root 0644, directory 0755 root, outside `/home`, so
  `ProtectHome=yes` can't hide it and the user can't edit it), `PidFile /run/mr-confirm-sshd/sshd.pid`, inside the
  unit's `RuntimeDirectory`). The main sshd uses `AuthorizedKeysFile /etc/ssh/authorized_keys/%u` too, so `mr-signer
  admin add-key` writes under `/etc/ssh/…/authorized_keys/` only, and has `DenyUsers mr-confirm`. Unit hardening:
  ```
  [Unit]
  After=wg-quick@wg0.service
  BindsTo=wg-quick@wg0.service
  [Service]
  ExecStart=/usr/sbin/sshd -D -f /etc/ssh/mr-confirm/sshd_config
  ProtectSystem=strict
  ProtectHome=yes
  TemporaryFileSystem=/tmp:ro
  PrivateDevices=yes
  InaccessiblePaths=-/dev/shm -/dev/mqueue -/var/tmp
  ReadWritePaths=/run/mr-signer/confirm
  RuntimeDirectory=mr-confirm-sshd
  NoNewPrivileges=no            # sshd must drop to the user; privsep needs it
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectControlGroups=yes
  RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
  LockPersonality=yes
  AppArmorProfile=-mr-confirm-sshd   # optional, see below
  ```
  `/run/mr-signer/confirm` is created by `tmpfiles.d` as `d 0700 mr-confirm mr-confirm`. Because the session's sshd
  child (which performs the `-R` bind as `mr-confirm`) inherits the unit's mount namespace, **every path outside
  `/run/mr-signer/confirm` is read-only, and bind(2) fails with EROFS/EACCES in the kernel**, before any socket exists.
  **`/tmp` is an empty read-only tmpfs** (`TemporaryFileSystem=/tmp:ro`, rev 8, replacing `PrivateTmp=yes`), so a
  `/tmp` bind fails the same way on every host, with or without AppArmor. sshd's remote stream-local forwarding only
  creates filesystem sockets, never abstract ones. sshd itself needs no writable `/tmp` (privsep uses
  `/run/mr-confirm-sshd`, the `RuntimeDirectory`). The optional AppArmor profile is defence in depth:
  `/run/mr-signer/confirm/piv.sock rw`, `deny /tmp/** w` for unix binds, `deny unix (bind) type=stream addr=@*`
  (abstract), and `deny network inet stream bind` for the session child.
- **Forced command (R39-P2-1.2):** the rev 6 `unshare` re-exec is **dropped**; the unit sandbox replaces it. The
  `pam_namespace` polyinstantiation is also dropped (the read-only `/tmp` covers it). The rev 6 **socket watcher stays as a
  backup layer** (250 ms poll, inotify, synchronous re-check before each sign, kill on anything extra).
- **Rehearsal proof (TestNet, before any MainNet key exists):** with the TestNet signer and keys, record in
  `docs/ops/runs/<date>-signer-ssh-proof.md`:
  1. `ssh -R /run/mr-signer/confirm/piv.sock:<local>` works and the confirm prompt appears;
  2. `-R /tmp/x.sock:…`, `-R /run/mr-signer/confirm/other.sock:…`, and two `-R` sockets → the forced command refuses;
  3. `-R 9000:localhost:22`, `-L 9000:localhost:22`, `-D 1080` and `-W host:port` → sshd refuses the forwarding;
  4. the `mr-req` key with any `-R`, `-L` or `-D` → refused, and with no pty;
  5. a connection from outside the WireGuard address → no TCP answer on the public IP;
  6. `sshd -T -C user=mr-confirm,addr=10.77.0.2` and `sshd -T -C user=mr-req,addr=10.77.0.2` output is attached;
  7. **mid-session forward (R36-P2-3.3):** with a confirm session open and a request pending, add a forward with
     `ssh -O forward -R /tmp/y.sock:<local>` (ControlMaster) and, separately, with the `~C` escape
     (`-R /run/mr-signer/confirm/z.sock:<local>`) → the session is killed within 1 s, the pending request is purged, an
     ntfy page arrives, and a sign attempted right after is never produced. The same test runs with a forward added
     between the code entry and the sign;
  8. **wg0 down at boot:** reboot the signer with `wg-quick@wg0` disabled (or its config renamed). `sshd` must **not**
     start (`systemctl is-active sshd` → inactive, because of `BindsTo`), `ss -ltn` shows no TCP listener on any address,
     and the public IP answers nothing on TCP. Then re-enable wg0 and confirm sshd comes up on 10.77.0.1 only. Recovery
     during the test is through the provider console as `mr-break`;
  9. **writable-paths check via `nsenter` (R39-P2-1.3):** `P=$(systemctl show -p MainPID --value mr-confirm-sshd)`,
     then `nsenter -t $P -m -- setpriv --reuid=mr-confirm --regid=mr-confirm --clear-groups find / -xdev -writable
     2>/dev/null` (plus the same without `-xdev` for the tmpfs mounts). The result must equal `ops/signer/writable-dirs`
     (**only** `/run/mr-signer/confirm`; `/tmp` must show as `ro`), and `nsenter -t $P -m findmnt -o TARGET,OPTIONS` is attached;
  10. **bind-and-connect race (R39-P2-1.4):** in an open confirm session, add `~C -R /var/lib/x.sock:<local>` (and, as
     separate cases, `/home/mr-confirm/x.sock`, `/dev/shm/x.sock`, `/run/x.sock`), while a local script tries to
     `connect()` to that path every 5 ms for 50 ms. Expected: sshd logs a **bind failure** (`unix_listener: cannot bind …
     Read-only file system` / `Permission denied`), the connect attempts all get ENOENT, and no socket file ever exists.
     The `/tmp/x.sock` and `/var/tmp/x.sock` cases must **also fail at bind on every host**, with and without
     AppArmor (the read-only tmpfs). The rehearsal runs this step once with the AppArmor profile disabled to prove it.
  internal reviewer reviews that file before the MainNet key ceremony.
- **The dedicated-machine option avoids all of this:** the YubiKey is plugged into the signer, so `mr-confirm` gets no
  `port-forwarding`, the `Match` block is omitted, and steps 1-3 reduce to "all forwarding refused".
- **Home IP changes.** On the VPS option, both keys use `from="10.77.0.2/32"` (the operator's WireGuard address) and sshd
  listens only on `10.77.0.1`. The WireGuard UDP port is open to any source, because WG peers are authenticated by key and
  roam, so **a home IP change needs no change on the signer**. If the operator's WG key is lost, or the WG port must be
  narrowed, recovery goes through the provider console as `mr-break` (below). On the dedicated-machine option, the signer
  sits on the home LAN, `from=` is the operator machine's LAN /32 (DHCP reservation), and a change of the public home IP
  doesn't matter.
- **WireGuard custody and sshd binding:**
  - The signer's WG private key is generated on the signer (`wg genkey`) into `/etc/wireguard/wg0.key`, root 0600. It
    never leaves the host. Only its public key is recorded (repo `ops/signer/wg.pub`, plus the audit run).
  - The operator's WG private key is generated on the operator's machine and kept in that machine's WireGuard app or
    keychain as a **non-syncing** item (no iCloud Keychain, no Drive, no bundle). Losing it means generating a new
    one and updating the signer's peer key from the console (below).
  - A WG key is only a network credential. It never replaces the FIDO2 keys, which are still required for every
    session.
  - sshd: `ListenAddress 10.77.0.1` only. `sshd.service` gets `After=` and `BindsTo=wg-quick@wg0.service` so it can't
    start with a fallback bind. nftables accepts only UDP on the WG port on the public interface and drops all TCP;
    SSH is accepted only on `wg0` from `10.77.0.2`. The rehearsal proves this (step 5 above).
  - WG keys are rotated yearly or on loss (§9.1 table).
- **Console login authentication (break-glass):**
  - The provider account login needs a password from 1Password plus a **hardware security key (WebAuthn)** only. No
    SMS or TOTP fallback, and recovery codes are printed and kept offline.
  - The provider's web/serial console logs in as the local user `mr-break`, with a random 32-character password
    stored in 1Password (its own item, separate from admin and signer secrets). `pam_access` allows `mr-break` only on
    `ttyS0`/`tty1`, and it is not in sshd's `AllowUsers`.
  - `mr-break` may only use `sudo` for a fixed allowlist: `mr-signer admin`, `mr-signer queue purge`, and
    `systemctl restart sshd wg-quick@wg0`. It does **not** get raw `nft` or an editor on `authorized_keys`.
  - **Restricted key edits:** `mr-signer admin add-key --role req|confirm --pubkey <sk-ssh-ed25519 …> --comment <c>` and
    `admin remove-key <comment>` are the only ways to change `authorized_keys`. `add-key` **builds the line itself** from a
    fixed template per role (the options in §1.1 exactly, including `from="10.77.0.2/32"` and `verify-required`). It
    accepts only `sk-ssh-ed25519@openssh.com` keys, refuses any caller-supplied options, and writes atomically
    (temp file + rename, 0600). It prints the resulting line and its sha256, which go into the signer log and the next
    audit run. `admin set-wg-peer <pubkey>` replaces only the single WG peer key, and `admin set-wg-port <port>` changes
    only the WG UDP port rule.
  - **Break-glass logging:** every `mr-break` login and every `mr-signer admin` call is logged **locally**, to the
    journal (`SyslogIdentifier=mr-break`, journald `Storage=persistent`, `ForwardToSyslog=no`) **and** to an append-only
    file `/var/log/mr-signer/break-glass.log` (`chattr +a`, root 0600). It is also paged through ntfy. The local log is
    included in every audit run, so an ntfy outage doesn't hide a login.
  - **Rotation and disk-full for the append-only log (P3):**
    - `/var/log/mr-signer` is its own small filesystem (a 256 MB loop or LV, `noexec,nosuid,nodev`), so a full log
      can't fill `/`.
    - Rotation is monthly, by a root-only `mr-signer log-rotate` (not logrotate's copytruncate, which would fail on
      `+a`). It takes the rotation lock, runs `chattr -a`, renames the file to `break-glass.log.YYYYMM`, hashes it,
      sets `chattr +i` on the archive, creates a new file with `chattr +a`, and logs the archive sha256 in the new
      file and the journal. internal reviewer records the archive hashes. Archives older than 12 months move off-host (to
      the Recovery bundle) and are deleted only after their hash is confirmed there.
    - **Disk-full handling, fail-closed:** before every `mr-signer admin` or `confirm` action, the tool checks that
      the log can be written (free space ≥ 16 MB, and a test append succeeds). If not, the action is **refused**
      (signing and admin both stop).
    - **Exempt from the disk-full check (so recovery is always possible):** the **console `mr-break` login** itself
      (best-effort log write; on failure it prints `BREAK-GLASS LOG UNWRITABLE` on the console and the PAM hook still
      lets the login through, since the console is already authenticated by the provider's hardware-key login and the
      local password), and **`mr-signer log-rotate --emergency`**, which archives and starts a new file. Both still
      write to the journal (whose own `SystemKeepFree` reserve is separate) and page through ntfy. Every other
      `mr-break` sudo command refuses until the log is writable again. Journald keeps
      `SystemMaxUse=200M` and `SystemKeepFree=500M` on `/`.
    - **Disk-space page:** a 5-min timer pages through ntfy (`[MAINNET signer] disk`) when `/` or
      `/var/log/mr-signer` is at 80% or more, and again at 95%. The free percentages are included in every audit run.
- **Pinned host key:** the signer's ed25519 host key fingerprint is recorded in the repo
  (`ops/signer/known_hosts`, also in the manifest notes and every audit run). The CLI uses
  `StrictHostKeyChecking yes` with `UserKnownHostsFile` set to that file only, so trust-on-first-use is never possible.

**Request authentication.** The request is the JCS object `{network, spendId, signedTxnB64, requestedAt, reqNonce}`.
It is signed with the requester's Ed25519 request-auth key, which is pinned in the signer config. The signer verifies
that signature before anything else and drops unauthenticated requests.

**Candidate message echo (R36-2).** After its checks (§2), the signer builds the exact candidate attestation `msg`
(including its own nonce and expiry) and **returns it over the same `mr-req` channel** (the forced command's stdout)
before any confirmation. The CLI then:
1. re-parses `msg` with the same strict JCS profile and requires `spendId`, `txId`, `sender` and `network` to equal the
   values in **its own** request (txId and sender computed by the CLI from the same `signedTxnB64`);
2. checks `keyId` = the pinned key and `expiry - now <= 15 min`;
3. computes and shows **its own** `SHA-256(msg)` together with the confirm code.
The signer shows its hash of the same `msg` in the confirm session, and the YubiKey helper shows it a third time (§6.2).
A mismatch at any step means abort.

**Return verification before release (R41-a).** When the signer returns `{msg, sig}` after confirmation, the CLI calls
`mr_spend_release` only if:
1. `msg` is **byte-identical** to the echoed candidate it verified and hashed (constant-time compare of the bytes, and
   `SHA-256(msg)` equal to the stored `msgHash`). A different message is refused even if it is validly signed and
   passes every field check;
2. `Ed25519.verify(msg, sig, pinnedPubkey)` passes with the pinned key for this network (libsodium, same key as the
   `mr_signer_key` row). The CLI pins the pubkey itself and doesn't read it from the signer.
Otherwise the CLI aborts, purges its state file, pages (`[MAINNET signer] return mismatch`) and leaves the spend
untouched. The DB verifier still checks everything again. This step only ensures the CLI never forwards anything other
than what the operator saw.

**Independent absence check by the CLI (R41-c).** Before sending the request **and again before calling
`mr_spend_release`**, the CLI queries at least one pinned provider itself, from **an independent vantage point**: the CLI's own host,
network path, DNS pinning and provider endpoint, none of which the signer controls. Where possible the provider is
also run by an operator the signer's observations don't use (the CLI's pinned list is ordered to prefer one); if only
the same operators are available, it uses a different endpoint of them and records that (R42-P3-1):
- the genesis must equal the per-network pin;
- `last-round >= lastValid + MARGIN`;
- absence must be shown by `idx404` (with `idxRound >= lastValid + MARGIN`) or by `blockscan` over fv..lv, for the
  payment txId and every group txId.
If any check fails, or the provider is unreachable, the CLI refuses (no request, or no release) and pages. The CLI's own
observation is printed next to the signer's, and is logged with the release, but it is not part of the signed message.
This independent check is what limits the signer-as-oracle risk described in §6.2b.

**Confirm code (R35-P1-1).**
- The **CLI** derives `code = base32(SHA-256("MR-CONFIRM-v1" || signedRequestBytes))[0:10]`: 10 characters,
  50 bits, at least 8 characters as required. It shows the code to the operator on their own screen.
  The signer computes the same value internally but **never displays it or sends it back**.
- `mr-signer confirm` asks the human to type the code. A matching code selects and confirms exactly that pending
  request. An unknown code is logged and refused, and 3 misses lock the queue for 10 min.
- **Collision refusal:** a new request whose code matches any pending or recently used (24 h) code is refused,
  and the CLI must re-sign it with a new `reqNonce`.
- Before asking for the code, the signer shows the decoded fields (sender, receiver, asset, amount, fv, lv,
  txId, group id, the observations) and the **final attestation message hash** (`SHA-256(msg)` hex). The CLI
  computes and shows the same hash from the same inputs, and the human compares the two on different screens.
- Pending requests expire after 10 min. There is no auto-confirm.
- **Control model, stated honestly:** this is **single-person control**. the owner holds both the request key and the
  confirm key, so the confirm step protects against a remote attacker who has only the request key (or only the CLI
  host). It does not protect against the owner's own devices being fully compromised together. It becomes two-person
  control only when a second operator holds their own confirm key and the signer requires their confirmation.
  This is tracked with the second-operator blocker.

## 2. Signer protocol

### 2.1 Raw transaction binding

(R34-P1-2, R35-P2-1, R36-5..7.) The caller never supplies txId, fv, lv or group.

**Which bytes are stored (R36-6).** `mr_spend.signed_txn` holds the **signed group exactly as submitted to the network
after settle**: the msgpack concatenation of every `SignedTxn` in group order, including the fee-payer's signature,
captured from the facilitator settle response or from the app's own submit. If the app only ever has the X-PAYMENT
payload (payer-signed payment member, **unsigned** fee-payer member) because settle was ambiguous, it stores that
payload instead and sets `signed_txn_kind = 'xpayment'`. For that kind, signature verification (step 2 below) covers
**only the payer member**. The fee-payer member is checked structurally (step 5) and its txId is still computed and
bound, but it is not required to carry a signature.

**Who derives the fields (R36-7).** The **app** (the reserve/settle path in `PgSpendStore`, same pinned algosdk decoder)
decodes `signed_txn` and derives `tx_id`, `first_valid`, `last_valid`, `group_id` and `sender`, and writes them in the
same transaction as the bytes. The database does **not** parse msgpack. It enforces that the columns are written together
(all non-null or all null, NOT NULL once `status <> 'pending'`), and the verifier compares the attestation against them.
The signer re-derives every field independently from the same bytes, so an app that wrote wrong derived fields produces
a signer/DB mismatch and the release is refused.

**Which txId is attested for `xpayment` rows.** A transaction's txId is computed over the unsigned `txn` body, so it does
not depend on signatures. For `xpayment` rows, the attested `txId` is the **payer's payment member** (the `axfer`),
exactly as it would appear on chain. The attested `groupId` is computed from all members' txIds, including the
unsigned fee-payer member. The blockscan and idx404 absence checks cover the payment member's txId **and** the
fee-payer member's txId.

**Constraints and immutability (R36-5, R37-3).**
- `CHECK (signed_txn_kind IN ('group','xpayment'))`. `signed_txn_kind` is NOT NULL whenever `signed_txn` is non-null.
- `CHECK (submit_round IS NULL OR last_valid IS NULL OR submit_round <= last_valid)` and
  `CHECK (first_valid < last_valid AND last_valid <= first_valid + 1000)` once set.
- A `BEFORE UPDATE` trigger on `mr_spend` raises if any of `signed_txn`, `signed_txn_kind`, `tx_id`, `first_valid`,
  `last_valid`, `group_id`, `sender`, **`submit_round` or `submit_at`** changes once non-null. A `BEFORE DELETE` trigger
  forbids deleting any row with a non-null `signed_txn`.
- The one exception is an `xpayment` → `group` upgrade, done once, when the same group's fully signed bytes arrive.
  It requires every derived field (including `submit_round` and `submit_at`) to be identical, **and is refused if the
  row already has `attestation_msg` or a `mr_release_nonce` row exists for the spend**. After an attestation exists,
  the stored bytes are final.
- The trigger function, constraints and their definitions are in the manifest.

The CLI fetches `signed_txn` from the DB, and the signer then does the following.
1. It msgpack-decodes the bytes itself (algosdk, pinned version, vendored in the image). Unknown fields, trailing
   bytes and non-canonical msgpack (re-encode and compare bytes) are all refused.
2. It **verifies the sender's signature** on every group member (for `kind='xpayment'`, the payer member only; see
   above): Ed25519 over `"TX" || txn` with the `snd` key, or
   the logicsig/msig path if one is pinned (none is today, so lsig and msig are refused).
3. It computes each member's `txId = base32(SHA-512/256("TX" || txn))` and the group id
   (`SHA-512/256("TG" || msgpack(txids))`), and requires the group id to equal every member's `grp`.
4. The **payment member** must have: `type=axfer`, `xaid=31566704`, `aamt <= 10000`, `arcv` = the pinned merchant,
   `snd` = the **pinned payer** (`SEKG…YR2M`), `gh` and `gen` = the MainNet pins, and **no** `aclose`, `asnd`
   (clawback/revoke), `rekey` or `lx` (lease). `lv - fv <= 1000` and `fv < lv`.
   **Fee caps:** the payer member's `fee` must be **0** (fees are pooled onto the fee-payer). A non-zero payer fee is
   refused, because it would drain payer ALGO outside the USDC caps.
5. **Other group members:** only the pinned GoPlausible fee-payer pattern is allowed: a `pay` from the pinned
   fee-payer `ZMFK…22AA`, amount 0, receiver = itself, `fee <= 2000` µALGO (pinned; covers a 2-member group at min
   fee), with no close, rekey or lease. Any other member, an extra
   member, or a group of the wrong size means refusal.
6. It binds `txId`, `firstValid`, `lastValid`, `groupId` and `sender` into the attestation.
The DB verifier then requires those to equal the DB-derived columns.

### 2.2 Observations

All of these must pass, else the signer refuses.
1. It queries **two providers from different pinned operators** (Nodely and algonode.cloud are ONE operator), with
   the CLI's allowlist, DNS pinning and private/6to4/Teredo refusal.
2. Each provider's genesis = the **per-network pin** for the request's network.
   **Per-network genesis pins:** one table `{mainnet: "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=", testnet:
   "SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI="}` is pinned in the signer config, the helper config and the CLI, and is
   tied to the DB's `mr_network` row (`mr_network.genesis_hash`, write-once). Each signer instance serves exactly one
   network, set at key creation. A request, observation, transaction (`gh`) or message whose genesis doesn't equal the
   pin for that instance's network is refused. No code path falls back from one network's pin to the other.
3. Each provider's `last-round >= lastValid + MARGIN` (pinned at 10 in the signer config and in the DB key row).
4. **Absence is proven per observation by one of two named methods (R35-P2-3)**, recorded in the field `method`:
   - `"idx404"`: indexer `GET /v2/transactions/{txId}` → 404, with the indexer health round ≥ lastValid + MARGIN
     (`idxRound`).
   - `"blockscan"`: algod blocks fv..lv fetched and checked for the txId and every group txId; the provider must
     still serve round fv (archival, or within ~1,300 rounds). For this method `idxRound` is the **last block
     scanned**, which must equal `lv` exactly (no indexer is involved).
   **Round rule by method (R36-1):** every observation needs `round >= lv + MARGIN` (provider head). Additionally,
   `idx404` needs `idxRound >= lv + MARGIN`, and `blockscan` needs `idxRound = lv` (all of fv..lv scanned). Without the
   split, a blockscan observation could never pass a blanket `idxRound >= lv + margin` rule.
   Every observation also records `at` (the signer's UTC time of the observation).
5. One issuance per spendId.

### 2.3 Signed payload

Canonical encoding: RFC 8785 (JCS) restricted profile. Only objects, arrays,
strings and non-negative integers < 2^53 are allowed. Strings are restricted to printable
ASCII with no `\` or `"` inside values, so no escapes ever appear. Keys are sorted, there is no whitespace
and no floats, booleans or nulls. A domain prefix comes first:

```
msg = "MR-RELEASE-ATTEST-v1\n" || JCS({
  "expiry":"2026-10-19T19:40:00Z", "firstValid":<int>, "genesisHash":"wGHE2...",
  "groupId":"<b64 or empty>", "keyId":"<32 hex = first 128 bits of sha256(pubkey)>", "lastValid":<int>,
  "network":"mainnet", "nonce":"<43-char b64url, 32 bytes>",
  "observations":[{"at":"2026-10-19T19:39:12Z","idxRound":<int>,"method":"idx404"|"blockscan",
                   "operator":"<id>","provider":"<host>","round":<int>}, ...],   // sorted by operator
  "round":<min observed round>, "sender":"<58 base32>", "spendId":"<uuid>",
  "txId":"<52 base32>", "v":1})
sig = Ed25519(sk, msg)   // RFC 8032 pure Ed25519
```

## 3. v11 database (R34-P1-3, R34-P1-4)

```
mr_signer_key(key_id text pk, pubkey bytea check(length=32), network text not null
              references mr_network, margin_rounds int not null check(>=10),
              created_at, revoked_at timestamptz null, revoke_reason text)
   -- trigger: INSERT only by migration owner; UPDATE allowed only revoked_at
   --          NULL -> ts (one-way); no DELETE.  Pinned in the manifest.
mr_signer_operator(operator text pk, network text)   -- write-once, manifest-pinned
mr_release_nonce(nonce bytea pk, spend_id uuid unique, key_id, used_at)
mr_spend: + signed_txn bytea, first_valid int, attestation_msg bytea, attestation_sig bytea
```

`mr_spend_release(spend_id, msg bytea, sig bytea)` (SECURITY DEFINER, fixed
search_path; existing locks and caps unchanged):
1. If the network is mainnet and there's no msg/sig, it raises. TestNet stays unsigned behind an explicit flag.
2. **Strict canonical JSON:** strip the prefix, require printable ASCII only, parse
   as jsonb, and require `convert_to(mr_jcs(parsed),'UTF8') = body` byte for byte.
   `mr_jcs` is a small immutable PL/pgSQL serializer for the restricted profile, so
   duplicate keys, whitespace, floats, reordering or escapes all fail.
   It requires exactly the expected key set and types.
3. Picks the key by `keyId`, which must be non-revoked and have **key.network = mr_network.network =
   msg.network**. It requires `mr_ed25519_verify(msg, sig, pubkey)`.
4. Genesis = pinned. spendId = arg. txId/firstValid/lastValid = the row's
   values. `expiry > now()` and `expiry - now() <= 15 min`.
5. `round >= lastValid + key.margin_rounds`, and every observation's `round >= lastValid + key.margin_rounds`.
   `idxRound` per method: `idx404` → `idxRound >= lastValid + key.margin_rounds`; `blockscan` → `idxRound = lastValid`. **Formats and order (R35-P2-3):** `fv < lv <= fv + 1000`
   (from the DB-derived columns, re-checked); `txId` matches `^[A-Z2-7]{52}$`; `sender` is 58 base32 characters and
   equals `mr_spend.sender`; `groupId` is empty or 44-character base64 and equals the DB-derived group; `nonce` is
   43-character base64url; `method` is in {`idx404`,`blockscan`}; every `at` and `expiry` matches
   `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`. Every observation's `at` must be after the spend's `last_valid`
   wall-clock estimate `lv_est` (defined below), ≤ `now()+60 s`, and ≥ `now()-15 min`, and must be ≤ `expiry`. The observations array holds
   2 to 4 entries.
   **Definition of `lv_est`:** at submit the app records `submit_round` (the algod `last-round` it used for the
   suggested params) and `submit_at` (DB `now()`), next to the derived fields and immutable with them. Then
   `lv_est = submit_at + (last_valid - submit_round) * 2.5 s`. 2.5 s is a conservative **lower** bound on the
   MainNet block time (currently about 2.8 s), so `lv_est` is the earliest wall-clock time round lv could plausibly
   have been reached. An observation claiming lv+margin before that is rejected as impossible. If `submit_round` is
   null (legacy rows), the release is refused.
6. Observations come from **>= 2 distinct operators that are all in `mr_signer_operator`**
   for that network. Unknown operators, or duplicates of one operator, fail.
7. Inserts the nonce. The primary key plus the unique spend_id reject replays.
8. Releases, and stores msg/sig on the row.

**Revoke:** `mr_signer_revoke(key_id text, reason text)` is SECURITY DEFINER, executable
by `mr_admin` only. It works only inside an `mr-admin-window` session, sets `revoked_at = now()`
(one-way) and raises a NOTICE, and the monitor pages on any revoked key. Unrevoking is
impossible: a new key needs a migration, a manifest update and an audit.
The manifest pins key rows, operators, margin, trigger and function definitions, and
the verifier extension version plus the `.so` sha256.

### 3.1 Ed25519 verifier options (pgcrypto has no Ed25519)

| Option | Verdict |
|---|---|
| **A'. Minimal C extension `mr_ed25519`** (one function: `mr_ed25519_verify(bytea,bytea,bytea) returns bool IMMUTABLE STRICT PARALLEL SAFE`, about 40 lines calling libsodium `crypto_sign_verify_detached`, length checks, in repo, built reproducibly, `.so` + libsodium sha256 in manifest) | **Chosen (R34-P2).** Tiny, auditable, constant-time libsodium, no key-management surface. Cost: a build step per PG major, and the `.so` is part of the trust base (root on the DB host can swap it; it's detected by the hash). |
| A. pgsodium | Rejected. Large surface (server key, TCE, event triggers), deprecated for new use by Supabase. |
| B. plpython3u + nacl | Rejected. An untrusted language means OS code runs as postgres. |
| C. plv8 + tweetnacl | Fallback only if A' can't be built. Heavy, and lags PG majors. |
| D. Pure PL/pgSQL Ed25519 | Rejected. Slow and unreviewed. |
| E. CLI-only verify | Pre-check only. It doesn't close R25-P2-1. |

**Build specification (R35-P2-4).**
- Source: `ops/pg/mr_ed25519/` (`mr_ed25519.c`, `mr_ed25519.control`, `mr_ed25519--1.0.sql`, `Makefile`).
- C contract: `PG_FUNCTION_INFO_V1`; arguments read with `PG_GETARG_BYTEA_PP` and sizes with `VARSIZE_ANY_EXHDR`.
  It requires **exactly 64 bytes** for the signature and **exactly 32 bytes** for the public key, and errors otherwise
  (not false). The message has no length limit other than a 4 KB cap. It calls `sodium_init()` once in `_PG_init`,
  and then `crypto_sign_verify_detached`. The function is `IMMUTABLE STRICT PARALLEL SAFE`.
- Build: in a pinned container image (`postgres:<exact major>.<minor>-bookworm@sha256:<digest>`, same major as the
  ECS cluster). libsodium is pinned by Debian package version plus sha256 of the `.deb`, or statically linked from a
  pinned source tarball (sha256 recorded). Static linking is preferred, so the host libsodium is not in the TCB.
- **Deterministic build flags:** `SOURCE_DATE_EPOCH` = the commit time; `CFLAGS="-O2 -fPIC -fstack-protector-strong
  -D_FORTIFY_SOURCE=2 -ffile-prefix-map=$PWD=. -fdebug-prefix-map=$PWD=. -frandom-seed=mr_ed25519 -g0"`;
  `LDFLAGS="-Wl,--build-id=sha1 -Wl,-z,relro,-z,now"`; libsodium is built with `--disable-shared --enable-static
  --with-pic` and the same prefix maps, then `strip --strip-unneeded` with the pinned binutils from the image.
  `LC_ALL=C TZ=UTC`, fixed build path `/build`. Reproducibility gate: two clean builds (CI plus internal reviewer's off-host
  rebuild) must give byte-identical `.so` sha256 before it is pinned.
- Install: the `.so` goes in `$(pg_config --pkglibdir)`, root:root 0644, and the control and SQL files in
  `$(pg_config --sharedir)/extension`, also root:root 0644. **No `LD_LIBRARY_PATH`** or `rpath` (checked with
  `readelf -d`); `ldd` must show only libc. The SQL file creates the function in schema `mr_crypto`,
  `REVOKE EXECUTE ... FROM PUBLIC` and `GRANT EXECUTE` only to the owner of `mr_spend_release`.
- Hashes: sha256 of the `.so`, the control file, the SQL file and the libsodium tarball or `.deb` are recorded in
  `ops/pg/mr_ed25519/SHA256SUMS` and in the manifest. The monitor re-hashes the installed files. **internal reviewer
  recomputes the `.so` hash from a clean rebuild off the host and records the live `.so` hash in every audit run.**

**Golden test vectors (R35-P2-3)** live in `test/vectors/release-attest/`:
- RFC 8032 test 1-3.
- A valid TestNet attestation (msg bytes, sig, pk, DB row).
- One negative file per rule: wrong network key, revoked key, a single operator, an unpinned operator,
  round < margin, `fv >= lv`, `lv > fv+1000`, a bad `at` format, `at` in the future, `at` after expiry, an unknown
  method, a missing method, non-canonical JSON (space, reordered keys, duplicate key, `1.0`, `\u0041`), a nonce
  replay, a wrong sender, `aclose` set, rekey set, a lease set, an extra group member, and a bad sender signature.
The same vectors are run by the signer's tests, the CLI and the DB verifier.

Tests: RFC 8032 vectors, our fixtures, single-byte mutations of msg, sig and pk, wrong
network key, revoked key, a single operator, an unpinned operator, round < margin,
non-canonical JSON variants (space, reordered keys, duplicate key, `1.0`, `\u0041`),
and nonce replay. They run in `pnpm test` and in migrate preflight.

## 4. Broadcast separation

Broadcast stays on the ECS app. The signer has no payer key and no broadcast code, its egress is the pinned
provider IPs only, and its algod client has no POST. The broadcaster never contacts the signer.
**Corrected wording (R35-P2-1):** the broadcaster holds the **payer key**, so a compromised broadcaster is **not**
limited to the MandateRail caps: it can sign and send any transfer the payer account can make, up to the payer's
whole balance (currently 10.00 USDC + ~5 ALGO). The caps bind only spends that go through MandateRail. What the
signer design guarantees is narrower: a compromised broadcaster or DB host **cannot forge a release attestation**, so
it cannot get an ambiguous spend un-counted. Payer-balance exposure is bounded only by keeping the payer underfunded
(open decision) and by payer-key custody.

## 5. Admin and superuser custody, and the trust boundary

- The `mr_admin` and postgres superuser passwords stay in their own custody (§6.4), separate
  from the signer identity, never on the agent box, and are used only inside `mr-admin-window`.
- **Trust boundary:** root on the ECS DB host stays fully trusted. Root or superuser can
  replace the verifier, the `.so`, the pinned key or the rows. v11 makes that
  detectable (manifest, monitor, pins recorded off-host in every audit run), not
  impossible. Root on the signer VPS, and the signer's cloud provider, are trusted for key
  confidentiality only while the key is unsealed (§6 keeps that window to seconds).
  An independent vantage point (§13 "Independent checks": an M-of-N second verifier in a separate trust domain) is
  still required to go further.

## 6. Key storage and unlock (R34-P2)

(R34-P2, R35-P2-2.)

### 6.1 Preferred: the Ed25519 attestation key generated and used on the YubiKey

YubiKey 5 series with **firmware 5.7+** supports Ed25519 in the PIV applet. The attestation key is generated
**on the YubiKey** (`ykman piv keys generate -a ED25519 --pin-policy ALWAYS --touch-policy ALWAYS 9c`), with the
PIV attestation certificate proving on-device generation. It is never exportable, so there is no key file and no
decryption step at all. The pubkey and the PIV attestation certificate are pinned in the DB and the manifest.
The YubiKey must be **plugged into the signer host** (the dedicated-machine option), or forwarded to it (§6.2).
Backup: there is none by design. Losing the key means revoke and enroll a new key (§9). That is safe: ambiguous
spends stay stuck until the new key is pinned.

### 6.2 YubiKey forwarding (needed only when the signer is a VPS)

- The PIV signing operation is forwarded, never the key. Pure Ed25519 needs the full message (no prehash),
  so the forwarded operation is "sign msg" over a stream-local socket
  (`ssh -R /run/mr-signer/piv.sock:/run/user/<uid>/mr-piv.sock`, only on the `mr-confirm` session). On the
  confirmer's computer, a pinned helper (`mr-piv-sign`) handles each request. **Before asking the YubiKey to sign
  (R36-4)** it:
  1. parses the message with the strict JCS profile and the `MR-RELEASE-ATTEST-v1\n` prefix;
  2. requires `network` = the pinned network and `keyId` = the pinned key id;
  3. requires `sender` = the pinned payer (`SEKG…YR2M`);
  4. requires `spendId` and `txId` to equal the CLI's own pending request, read from the CLI's state file
     (rules below), **and refuses unless `SHA-256(msg) == msgHash` from that file** (R37-2);
  5. requires `expiry` to be in the future and `expiry - now <= 15 min`;
  5a. requires `genesisHash` = the genesis pinned **for `msg.network`** in the helper config (see "Per-network genesis
      pins" in §2.2);
  5b. requires `round >= lastValid + MARGIN` (MARGIN pinned in the helper config, 10), and for every observation
      `round >= lastValid + MARGIN`, plus the per-method `idxRound` rule (`idx404`: `>= lastValid + MARGIN`;
      `blockscan`: `= lastValid`);
  5c. requires 2 to 4 observations from **at least 2 distinct operators, all in the helper's pinned operator list**;
  6. shows the decoded fields (spendId, txId, sender, lv, round, operators and methods, expiry) and `SHA-256(msg)`.
  Only then does it call the PIV sign, and the YubiKey requires PIN and touch. Any failure means refusal and a logged
  reason.
- **State file rules (R37-2):**
  - The CLI writes `~/.mandaterail/signer-pending/<spendId>.json` (0600, directory 0700, `O_CREAT|O_EXCL|O_NOFOLLOW`)
    **only after** it has verified the echoed candidate message (§1.1 "Candidate message echo"). It contains
    `{spendId, txId, msgHash, createdAt, expiresAt}`, where `expiresAt = min(msg.expiry, createdAt + 15 min)`.
  - **Single use:** the helper opens it with `O_NOFOLLOW` and checks the owner, mode and `expiresAt`. It atomically
    renames it to `<spendId>.used` before calling the PIV sign. A second sign for the same file is refused, and so is a
    file that is missing, expired, or not 0600 and owned by the user.
  - **Cleanup:** on every run, and from a `launchd` job every 15 min, the CLI removes `*.used` files older than 24 h and
    any pending file past `expiresAt`. It refuses symlinks and files not owned by the user, and logs what it removed. The
    helper itself deletes its `.used` file after a successful sign and the response has been returned to the signer.
    Leftover files are never accepted for signing anyway (single-use plus expiry). The state file is a local integrity
    check only and holds no secret.
- **Forbidden:** decrypting or holding any signer key material on the confirmer's computer; exporting the key;
  any helper mode that signs arbitrary bytes. The helper refuses anything that isn't an attestation message
  matching the hash the signer showed.
- Honest tradeoff: with forwarding, the confirmer's computer is in the signing path (it could be tricked into
  signing a malicious attestation if both it and the signer host are compromised). The dedicated physical machine
  with the YubiKey plugged in avoids that, and is preferred if hardware is acceptable.

### 6.2b Dedicated-machine signing path (PRIMARY; R40-P2-1)

On the dedicated machine the YubiKey is plugged into the signer, so there is no forwarding. The confirm session runs on
the machine's own console or over the hardened `mr-confirm` SSH session with no forwarding at all. The signing path is:
- **Helper:** a pinned `mr-piv-sign` binary (same source as §6.2, built reproducibly, sha256 in the manifest) runs as its
  own uid `mr-piv` in `mr-piv-sign.service`. A udev rule gives `mr-piv` **sole access** to the YubiKey: `pcscd` runs with
  polkit rules allowing only `mr-piv` (`org.debian.pcsc-lite.access_card` / `access_pcsc`), and the hidraw/usb device node
  is `0600 mr-piv`. No other uid, including `mr-signer` and `mr-confirm`, can talk to the card.
- **Reachability:** the helper listens on `/run/mr-piv/sign.sock`, `0600 mr-piv`, in a `0710 mr-piv:mr-signer` directory.
  It checks `SO_PEERCRED` and accepts only the `mr-signer` uid (the confirm process). There is no network listener
  (`RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`). The unit also has `ProtectSystem=strict`, `ProtectHome=yes`,
  `PrivateTmp=yes`, `NoNewPrivileges=yes` and `DeviceAllow=` for the YubiKey only.
- **Checks:** the helper runs checks **1-5c** from §6.2 itself (strict JCS and prefix, network/keyId pins, pinned sender,
  spendId/txId matching the pending request plus `SHA-256(msg) == msgHash`, expiry ≤ 15 min, per-network genesis pin,
  round/margin and per-method idxRound rules, 2-4 observations from ≥ 2 pinned operators). Here the "pending request"
  record is the signer's own record of the authenticated request (the `msgHash` the CLI sent back after verifying the
  echo).
- **Operator hash entry:** before the PIV sign, the helper shows the decoded fields and asks the operator to type the
  **first 16 hex characters of the msgHash that their own CLI computed from the echo** (§1.1 "Candidate message echo",
  shown on the operator's computer, not on the signer). A mismatch refuses; 3 misses lock the helper for 10 min. Only
  after that does the YubiKey require PIN and touch. The 16 hex characters (64 bits) bind the operator's independent
  view of the message to this exact signature.
- **Single use and expiry:** the helper keeps a `spendId → used` table (`/var/lib/mr-piv/used.db`, `0600 mr-piv`). A
  second sign for the same spendId is refused, even with a new nonce, until that key is revoked and a new key is pinned.
  Requests are valid until `min(msg.expiry, received + 15 min)`.
- **Trust that remains in the signer host (honest statement, rev 9, R41-b):** root on the signer machine, or a
  compromised `mr-signer` process, **is the absence oracle**. It queries the providers, builds the observations and the
  echoed candidate message, and controls the path to the helper, the PIN prompt and the card. It can therefore fabricate
  "absent" observations for a transaction that actually confirmed, and get a **false-absence attestation with one
  ordinary confirm**. The operator sees a consistent message, its hash matches the CLI's view of the echo, and PIN and
  touch proceed normally. The 16-hex match only stops **bait-and-switch** (signing a different message than the one the
  operator's CLI verified). It does not prove that the observations are true. Root also can't export the key, but it can
  deny service, swap binaries (detected at the next audit, below) and lie in the display.
  **Gates that remain against a false-absence attestation:**
  1. **The CLI's independent absence check** (§1.1, R41-c) against a pinned provider, preferably from another operator.
     A lying signer must also defeat that provider, or the operator's CLI host.
  2. **The DB verifier's rules:** the network, key, margin and per-method round rules, the `lv_est` timing, formats,
     at least 2 pinned operators, txId/fv/lv/sender/group equal to the app-derived columns, nonce and replay rules, and
     expiry. These bound *what* can be attested and *when*, but they can't detect fabricated observations.
  3. **The caps:** 0.01 USDC per payment and 0.05 USDC per day. Each false release frees at most one payment's
     reservation, so it costs **at most 0.01 USDC per false release, and each one needs its own confirm** (an
     authenticated confirm of that exact msgHash; automated mode: a requester-signed confirm issued only after the
     CLI's independent checks pass, §13). The daily cap bounds the total at 0.05 USDC (R42-P3-1).
  4. Reconcile and monitor after the fact: a released spend whose txId later shows up on chain pages, as an incident
     (§9 step 4).
  **Accepted for the capped dry run:** with the caps above, a single operator and gate 1 in place, this residual is
  accepted for the MainNet dry run only. Before launch, it needs either an independent vantage point that confirms
  from its own host and providers (the §13 M-of-N second verifier), or provider-signed responses (none exist for
  Algorand today, §13).
- **used.db backup and recovery (P3):** `used.db` is SQLite (WAL, `synchronous=FULL`). After every sign, the helper
  appends `{spendId, msgHash, at}` to an append-only journal (`/var/lib/mr-piv/used.log`, `chattr +a`). A nightly job
  copies an age-encrypted snapshot of both files to the Recovery bundle. **Recovery:** if `used.db` is lost or corrupt,
  the helper refuses to start (fail-closed) until it is rebuilt from `used.log`, from the last snapshot plus the log,
  and from the DB's `mr_release_nonce` and `attestation_msg` rows (the authoritative list of spends already attested).
  **DB export procedure (R42-P3-1):** on the DB host, as `mr_release` (SELECT only on these tables), run
  `exportAttestedSpends` (`packages/signer/src/cli/release.ts`): `SELECT store||'/'||spend_id FROM mr_release_nonce
  UNION SELECT store||'/'||id FROM mr_spend WHERE attestation_msg IS NOT NULL ORDER BY 1`. Write it to a file, record
  its sha256 and line count in the break-glass log, carry it to the signer on the break-glass admin path (never the
  request API), and feed it to `UsedStore.rebuild(file, [log copy, snapshot], dbList)`. The rebuild refuses unless the
  result is a superset of the DB list.
  The rebuilt set must be a superset of the DB list, otherwise the helper stays down. Even with `used.db` lost, the
  DB's nonce and `spend_id` uniqueness still prevents a second release, so the loss is only a defence-in-depth gap.
- **3-miss lock as a DoS lever (P3):** anyone who can reach the helper's prompt (root, or a compromised `mr-signer`)
  can trip the 3-miss lock repeatedly and block releases. That is accepted: it's fail-closed, and ambiguous spends just
  stay counted. Mitigations:
  - every lock pages (`[MAINNET signer] confirm lockout`, with the count);
  - more than 2 lockouts in 1 h escalate the lock to a **hard lock**, which the timer doesn't clear;
  - **recovery path:** the operator at the machine's console runs `mr-piv-sign unlock`, which requires YubiKey PIN and
    touch (proving physical presence) and logs to the break-glass log. After an unexplained lockout, the next audit run
    reviews it before more signs.
- **Binary integrity for the helper and mr-signer (P3):**
  - The dedicated machine boots a **read-only root** (squashfs image, built reproducibly), protected by **dm-verity**
    with the root hash in the signed kernel command line (Secure Boot with our own enrolled key, or UKI + measured boot).
    `/var/lib/mr-piv`, `/var/lib/mr-signer` and `/var/log/mr-signer` are the only writable mounts, all
    `noexec,nosuid,nodev`.
  - Where dm-verity isn't available (VPS fallback): **IMA appraisal** (`ima_appraise=enforce`) with signed hashes for
    `/usr/local/bin/mr-signer`, `mr-piv-sign` and their libraries, and IMA measurement into the TPM, or the IMA log on
    hosts without a TPM.
  - **Gating of IMA policy updates (R42-P3-1):** the IMA policy is loaded once at boot from the signed image; the
    kernel is built without runtime policy writes (`CONFIG_IMA_WRITE_POLICY=n`), or the policy file must itself be
    signed (`CONFIG_IMA_APPRAISE_SIGNED_INIT`), so `/sys/kernel/security/ima/policy` can't be rewritten at runtime. The
    IMA signing key stays offline (Recovery bundle), never on the host. A policy or binary update is a new signed image,
    built reproducibly, recorded in the manifest, and applied only through break-glass with a page. Every audit compares
    the loaded policy hash with the pinned one.
  - **Audit:** every audit run records the dm-verity root hash (or the IMA measurement list digests) and the sha256 of
    `mr-signer`, `mr-piv-sign`, `mr-confirm-sshd`'s config and the units. internal reviewer compares them with a clean off-host
    rebuild.
- **TestNet rehearsal, automated mode (rev 11; this list replaces the human steps 1, 2 and 11 below):**
  - A1. a happy-path sign: the CLI verifies the echo, runs its independent check and sends the signed confirm; the
    helper verifies that confirm itself; PIN unsealed from the TPM, no touch; the DB accepts the attestation;
  - A2. a confirm signed by an unpinned key, a replayed confirm nonce, a stale confirm, or a confirm for another
    spend or msgHash → the helper refuses, and 3 misses lock it;
  - A3. a direct connection to `sign.sock` from root-as-another-uid and from `mr-signer` with a forged confirm →
    refused (gate exit 77 / helper refusal);
  - A4. restoring an old `policy.json` → mr-signer refuses to boot (off-host counters); the 6th attested release in
    24 h → the DB refuses;
  - A5. ntfy down during a sign → the signer pauses and the signature is withheld; the heartbeat stops pinging;
  - A6. 3 lockouts in 1 h → hard lock; `mr-piv-sign unlock` with the console presence proof (PIV PIN verify) clears it.
  The §1.1 confirm-code and `mr-confirm` SSH flows apply only to the non-automated fallback (a human operator).
- **TestNet rehearsal, manual fallback** (recorded in `docs/ops/runs/<date>-signer-dedicated-proof.md`):
  1. a happy-path sign with the TestNet key: the hash entry matches, then PIN and touch, then a valid attestation that
     the DB accepts;
  2. a wrong 16-hex entry → refused, and 3 misses → locked;
  3. a second sign for the same spendId → refused;
  4. an expired request → refused;
  5. `mr-confirm`, `mr-signer` and root-but-not-`mr-piv` processes running `ykman piv info` / `pcsc_scan` → access
     denied (root via `sudo -u` other uids; real root is documented as able to);
  6. a connection to `sign.sock` from a uid other than `mr-signer` → refused (`SO_PEERCRED`);
  7. tampered messages for each of checks 1-5c → refused, using the golden vectors;
  8. **return swap (R41-a):** a test hook makes the signer return a *different*, validly signed `msg` (for example the
     same spend with a changed `round`, signed by the real TestNet key) → the CLI refuses before `mr_spend_release`
     because the bytes differ from the verified echo, and pages. A `msg` with a bad signature → refused;
  9. **CLI absence check (R41-c):** (i) a spend whose TestNet transaction **did** confirm, with the signer's provider
     responses faked to 404 through a test hook → the CLI's own provider shows it present, so the CLI refuses and pages;
     (ii) the CLI's provider unreachable → refused; (iii) the CLI's provider round < lv+MARGIN → refused;
  10. used.db deleted → the helper refuses to start, is rebuilt from the log, snapshot and DB, and a second sign for an
      already-released spend is still refused;
  11. 3 lockouts within 1 h → hard lock, page, `mr-piv-sign unlock` with PIN and touch restores it.

### 6.3 Fallback (YubiKey firmware older than 5.7): age-encrypted file key

Only if 5.7+ hardware isn't available. The key file `signer.key.age` is encrypted to a **dedicated
`age-plugin-yubikey` identity** (PIN and touch "always") used for nothing else. It is decrypted per signature into
`tmpfs` **on the signer host** (`/run/mr-signer/k`, 0700, `noexec,nosuid,nodev`, size 64k, swap off, core dumps
off, `mlockall`), used once, then overwritten and unlinked. There is no iCloud, Keychain, 1Password, Drive or
Time Machine copy of the identity.

### 6.4 Separation from admin secrets (R35-P2-2)

The signer identity (YubiKey PIV slot or age identity) is **not** used to encrypt anything else. The `mr_admin` and
postgres superuser passwords stay in the existing recovery custody (their own age identity, 1Password/locked file,
Drive bundle), entirely separate. A leak of one does not unlock the other.

## 7. Hosting options under a separate account (prices fetched Oct 19, 2026)

| Option | Monthly | Spec | Source | Note |
|---|---|---|---|---|
| **Vultr Regular Performance, IPv4** | **$3.50** ($2.50 IPv6-only) | 1 vCPU / 0.5 GB / 10 GB | vultr.com/pricing | Recommended. Cheapest with IPv4; providers need IPv4 egress |
| Alibaba Simple Application Server, **second account** | $3.50 (1 GB: $4.50) | 1 vCPU / 0.5 GB / 20 GB | alibabacloud.com/en/product/swas/pricing | Same vendor as the DB. A separate account helps, but Alibaba remains a single point of compromise for both |
| DigitalOcean Basic Droplet | $4.00 | 1 vCPU / 512 MiB / 10 GiB | digitalocean.com/pricing/droplets | Good alternative |
| Hetzner CX23 | €5.99 ≈ $7.09 incl. IPv4 (cheapest orderable often CPX02 €6.49 ≈ $8.09) | 2 vCPU / 4 GB / 40 GB | pikkly.dev/vps/hetzner (checked Oct 19) | CX23 often sold out; EU only |
| **Dedicated physical machine (PRIMARY)**: a small fanless PC or Pi on the owner's network, YubiKey plugged in | ~$0/mo after a one-time hardware cost (not price-checked) | — | — | Recommended (rev 7). No forwarding, no cloud root, no VPS provider in the trust base; availability depends on home power and network |

Nothing is over $15/month. **Recommendation (rev 7): the dedicated physical machine is primary.** With the YubiKey
plugged into the signer there is no SSH socket forwarding, so the whole R36-P2-3 / R39-P2-1 item (sandboxed
mr-confirm sshd, socket watcher, rehearsal steps 7, 9 and 10) **does not apply**. Its SSH needs only "all forwarding
refused". It also removes the cloud provider and the forwarding helper's computer from the signing path.
**Alternative: Vultr $3.50 IPv4 in a new account** (DigitalOcean $4 second), with WireGuard, the sandboxed
`mr-confirm-sshd` unit and the full rehearsal. Use it only if a home machine isn't acceptable (power, network, physical
security).

## 8. Second independent MainNet provider (unchanged from rev 1)

| Candidate | Free tier | Paid | URL |
|---|---|---|---|
| Nodely / algonode (operator 1) | 6M req/mo, no key | $256/mo unlimited | https://nodely.io/api |
| **GetBlock (operator 2, recommended)** | 40,000 req/day | from $29; $499/mo; dedicated from $1,000/mo | https://getblock.io/nodes/algo/ |
| Blockdaemon | generic 3M CU/mo; Algorand "coming soon" | self-serve | https://www.blockdaemon.com/protocols/algorand |
| Allnodes | Algorand not listed | from $320/mo | https://www.allnodes.com/pricing |
| Own non-archival node | — | 8 vCPU/8+ GB/100 GB NVMe; Hetzner CX43 €16.49 (8/16/160) or Vultr/DO ~$40-48; **over $15** | https://dev.algorand.co/nodes/overview/ |

GetBlock must be checked for indexer or archival access before it is pinned.

## 9. Emergency runbook (R34-P1-4)

Triggers: suspected signer or request-key compromise, an unexpected attestation in
the signer log or DB, a monitor page on `mr_release_nonce` growth without an operator
action, a lost YubiKey, or a provider account compromise.
1. **PAUSE MainNet:** `touch /etc/mandaterail/mainnet-PAUSE` (503 on /paid and /sign).
2. **Revoke in the DB:** open an `mr-admin-window` and run
   `select mr_signer_revoke('<keyId>','<reason>')`. After that, every attestation under that key
   fails. Verify with `select revoked_at from mr_signer_key` and a monitor run (it should page "revoked").
3. **Kill the signer:** power off the VPS from the separate account console, rotate that
   account's password and 2FA, and remove all `authorized_keys`.
4. **Audit:** list every `mr_release_nonce` row and every spend released under that key.
   Check each txId on both operators. Any released spend whose transaction landed counts as a
   double-count incident: record it, sweep, and report to internal reviewer.
5. **Rotate:** set up a new host, generate a new key, write a v11.x migration (new key row; the old
   one stays revoked) and a manifest update, and get an internal reviewer run before RESUME.
6. While no key is valid, ambiguous spends stay stuck. That is fail-closed and cap-safe.
Lost YubiKey without compromise: revoke anyway (step 2), then enroll a new on-device key (§6.1).

### 9.1 Key rotation runbook (R35-P2-5)

| Key | Where pinned | Rotate when | Steps |
|---|---|---|---|
| Request key (`req-*`, FIDO2) | signer `mr-req` `authorized_keys` + signer config request-auth pubkey | yearly, device loss, or suspicion | 1. **Purge the queue** (`mr-signer queue purge --all`, logged). 2. Remove the old line and config key. 3. Enroll the new key (in person or over the confirm session). 4. Test request → confirm on TestNet. |
| Confirm key (`confirm-*`, FIDO2) | signer `mr-confirm` `authorized_keys` | same | Same as above. While no confirm key is valid, nothing can be signed (fail-closed). |
| Attestation key (YubiKey PIV) | DB `mr_signer_key` + manifest | compromise, loss, or yearly | §9 steps 2 and 5 (revoke, then a migration for the new key). |
| Provider API keys (GetBlock, etc.) | signer env file 0400 | 90 days or a leak | Rotate at the provider. Update the env file, restart the signer, run a test observation, then revoke the old key at the provider. |
| WireGuard keys (signer `wg0.key`, operator peer key) | signer `/etc/wireguard`, repo `ops/signer/wg.pub` | yearly or on loss | Generate the new key on the side that owns it. Update the peer public key through the console (`mr-break`). Commit the new `wg.pub` and re-run rehearsal step 5. |
| Signer SSH host key | repo `ops/signer/known_hosts` + manifest | rebuild or suspicion | Generate the new host key. Commit the new fingerprint via a reviewed PR before first use, and internal reviewer records it. |

**Queue purge** is mandatory on any rotation or suspicion. Pending requests signed by an old key are never
confirmable after rotation.
**Named deputy:** a deputy who can PAUSE MainNet and run `mr_signer_revoke` must be named (an open decision). They
hold their own pause access and `mr_admin` window procedure, but **no** signer request or confirm key, so they can
stop and revoke but never sign. Until the deputy is named, only the owner can act.

## 10. Open decisions for the owner

1. Signer host: a dedicated home machine (**primary**, no SSH forwarding), or the alternative Vultr $3.50 / DO $4 / Alibaba SAS on a 2nd account.
2. Buy 2 YubiKey 5 series with firmware 5.7+ (on-device Ed25519); price not checked here.
3. Who confirms on the signer: the owner alone for now (single-person control), with a second operator later.
4. GetBlock free account (sign-up and API key in the owner's name) as operator 2.
5. Approve the minimal C extension build on the ECS PG.
6. WireGuard to the signer vs a plain `from=` /32 with console updates when the home IP changes.
7. Name a deputy (can pause and revoke, cannot sign).
8. Payer balance: reduce from 10.00 USDC (§4 exposure).
9. Approve the §13 automated-signer layers, and the second-verifier VPS ($3.50–7/mo, separate account) plus v12 before launch.
10. Buy the dedicated TPM 2.0 machine for the signer (one-time; not priced here).

## 11. Rollout

The v11 migration plus the `mr_ed25519` build ships on TestNet with a TestNet key on a throwaway
VPS, then an internal reviewer run, then a MainNet key ceremony on the chosen host, then the MainNet
migration, then a release rehearsal with an ambiguous TestNet spend.

## 12. Parked P3s (fix later, tracked)

- **ntfy split:** separate topic and title prefix per network (`[MAINNET]` vs
  `[testnet]`), so a TestNet alert can't be mistaken for a MainNet one, or the reverse.
- **MainNet release pin:** its own `/etc/mandaterail/mainnet-release-pin`
  (commit, tree hash, manifest hash), separate from TestNet's, checked by the MainNet monitor.
- **Redis ACL passwords:** out of plaintext `redis.conf` and into hashed ACL entries (`#<sha256>`)
  or an ACL file at 0600 root with env-file references.
- **optin.py:** move it into the repo (`scripts/`), and add a genesis-hash check against the pinned
  MainNet genesis and a fee cap (refuse fee > 0.001 ALGO) before signing.
- **YubiKey PKCS#11 backend:** `YubikeyPivBackend` is a stub that refuses to construct until it can be built and tested
  on a 5.7+ card (PKCS#11 via ykcs11; `yubico-piv-tool` is ruled out because it only takes the PIN on argv).
- **SO_PEERCRED on `sign.sock`:** Node has no peer-credential API. The socket relies on 0600/0710 permissions plus
  systemd; the production helper adds the peer-uid check in a small socket-activation wrapper.
- **v12 (2-of-N in the DB):** see §13.6. The DB requires the second verifier's co-signature only after v12.

## 13. Automated signer: defense in depth (rev 10)

the owner's direction (Oct 19, 6:50 PM): the signer **must be automated**, and the signing machine must be extremely robust,
with dedicated IP checks and other policies against unauthorized access. In automated mode no person confirms each
release, so the human gates in §1.1 and §6.2b change:
- The operator's **16-hex entry** becomes the **requester-signed confirm**. The CLI (requester) verifies the echoed
  message byte for byte, runs its own independent absence check (§1.1, R41-c), and only then sends
  `confirm{msgHash}`, signed with its pinned Ed25519 key. mr-signer **forwards that signed confirm unchanged** to the
  helper, which verifies it **itself**: the requester's pubkey is pinned in the helper's own config, the helper keeps
  its own nonce store and its own ±30 s window, and the confirm's store/spendId and msgHash must equal the message.
  The helper signs only a message whose SHA-256 equals a confirm it verified this way (check 4, R43-P2-4). mr-signer
  can't mint a confirm, because it never holds the requester key.
- **PIV PIN policy ONCE, touch policy NEVER.** Touch would block automation. The PIN is sealed to the TPM
  (`systemd-creds encrypt --with-key=tpm2`, bound to a signed PCR 11 policy / pcrlock; the literal PCR 7 default was
  dropped in systemd v258), so it unseals only on the measured, unmodified boot of this machine.
- **Honest consequence:** with nobody looking at each message, the residual from §6.2b ("the signer is the absence
  oracle") gets bigger. What bounds it is the policy engine, the independent checks and the caps (at most 0.01 USDC per
  false release, at most 0.05 USDC per day). The layers below are designed so that no single compromise (network, the
  requester, one provider, the signer process) can release funds beyond those bounds, and every attempt pages.

### 13.1 Layers

Status: **code** = implemented and tested in this repo (TestNet/dev); **host** = host configuration, written as a
spec and applied at provisioning; **hw** = blocked on hardware; **design** = later work.

1. **Network** (host + code)
   - WireGuard is the only way in. The signer API binds only to the WireGuard address. nftables policy is `drop` on
     input and forward. The only inbound rule allows UDP to the WG port from the requester's /32 (and the second
     verifier's).
   - A **source-IP allowlist** at two levels: the WG peer `AllowedIPs` (one /32 per peer) and the app check in
     `server.ts`, which closes connections from any other source address (**code**).
   - **Default-deny egress:** nftables output allows only (a) the pinned provider hosts on 443, resolved at boot and
     re-resolved by a pinned resolver into an nft set (DNS pinning is at host level; the app code does not pin DNS, R43-P3), (b) NTS/NTP to the pinned chrony sources, (c) the WG endpoint,
     (d) the off-host log and heartbeat endpoints. Everything else is dropped and logged. The app refuses forbidden
     hosts (loopback, private, 6to4/Teredo; **code**, `HttpProbe`), disables redirects, and times out after 10 s.
   - No inbound except the request channel. No listening sshd (see Host).
2. **Request authentication** (code)
   - Every request is signed with the pinned requester key: Ed25519 over `MR-SIGNER-REQ-v1\n` || JCS(body). mTLS is
     not needed on top of WireGuard plus signed requests. It can be added, but it moves no trust boundary.
   - Request timestamp within ±30 s. **Single-use request nonces**, persisted before the signer acts on the request.
     Then **per-requester rate limits** (default 30 requests per hour) and the network bound into every request.
   - The **two-phase protocol** (candidate → echo → confirm): a signature exists only for a msgHash the requester
     confirmed after its own checks.
3. **Host** (host; hw where noted)
   - **dm-verity read-only root** (reproducible squashfs, root hash in a signed UKI). The only writable mounts are
     `/var/lib/mr-signer`, `/var/lib/mr-piv` and `/var/log/mr-signer`, all `noexec,nosuid,nodev` (§6.2b).
   - **Secure Boot with our own enrolled key, plus measured boot.** The PIV PIN credential is TPM-sealed to the
     signed PCR policy (**hw**: TPM 2.0 machine).
   - **IMA** appraisal and measurement where dm-verity doesn't cover a file. Policy updates are gated (§6.2b,
     R42-P3-1).
   - **Minimal OS**: no compilers, no package manager at runtime, no interpreters beyond the pinned Node runtime in the
     image.
   - **No SSH except break-glass.** sshd is not installed in the running image. Break-glass is the physical console,
     or a separate signed image that boots with sshd on the WG address, which logs and pages on boot.
   - **Auto-updates policy:** no unattended in-place upgrades (they would break dm-verity and IMA). Security updates
     ship as a new reproducible signed image: built weekly, or within 72 h of a relevant CVE, verified against an
     off-host rebuild, then applied by break-glass reboot. A machine running an image more than 30 days old pages.
   - **Physical tamper and USB lockdown:** `usbguard` with `ImplicitPolicyTarget=block` and a single allow rule for
     the YubiKey (vendor/product, serial, interface hash, port). Other USB ports are disabled in firmware. Tamper-evident
     seals on the case and the YubiKey port are photographed at every audit. The BIOS password is in the Recovery
     bundle. Full-disk encryption of the writable partitions (TPM plus PIN at boot).
4. **Process isolation** (host + code)
   - `mr-piv-sign` runs as its own uid and has **sole access to the card**: pcscd polkit rules, a 0600 device node,
     and `DeviceAllow=` only for that card. The signer reaches it only through `sign.sock` (**code**: `piv/socket.ts`,
     0600, 0710 dir).
   - **systemd sandboxing** for both units: `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
     `NoNewPrivileges=yes`, `PrivateDevices=yes` (signer), `RestrictAddressFamilies=AF_UNIX` (helper),
     `IPAddressDeny=any` (helper), `IPAddressAllow=` the WG and egress sets (signer), `CapabilityBoundingSet=`,
     `MemoryDenyWriteExecute=no` (Node JIT; documented), `LockPersonality=yes`, `ProtectKernel*=yes`.
   - **seccomp:** `SystemCallFilter=@system-service` minus `@privileged @resources @mount @debug`, and
     `SystemCallArchitectures=native`.
   - **Separate uids:** `mr-signer` (API and orchestration), `mr-piv` (card), `mr-log` (log shipper). No uid has a
     login shell.
5. **Policy engine** (code: `policy.ts`, persisted with fsync, monotonic counter)
   - Caps: at most 0.01 USDC per released spend (also enforced on the decoded transaction), at most 3 releases per
     hour, at most 5 and at most 0.05 USDC released in any **rolling 24 h** (config validation rejects higher values).
     A spend is released once per signer.
   - **Three independent cap counters (R43-P2-1/P2-4):** (a) mr-signer's policy state; (b) the helper's own counter
     (at most 3 signs per hour and 5 per 24 h, in its own state file, uid `mr-piv`); (c) **the DB**:
     `mr_spend_release_attested` refuses a 6th attested release in any rolling 24 h, counted over `mr_release_nonce`
     for all keys, under a table lock. (c) doesn't depend on the signer host at all.
   - **Rollback and wipe detection (R43-P2-1):** a local state file must exist (created only by an explicit init), and
     every write must increase its counter. Every off-host log event records the policy and request-nonce counters.
     At boot the signer loads the last event from the off-host chain and **refuses to start if either local counter
     is behind it**. So restoring an older `policy.json` or `requests.json` (which would also reopen request nonces),
     or deleting one and re-running init, refuses. Remaining gap: a rollback *between* two logged events can't happen,
     because every state change is followed by an event; a crash between the write and the event leaves local ahead,
     which is allowed. A TPM NV counter mirror is **hw**.
   - **Pinned merchant, sender and asset:** the payment must be an axfer of the pinned USDC ASA to the pinned
     merchant from the pinned payer. Any other group member must be the pinned fee-payer pattern. Close, clawback,
     rekey and lease are refused. The signature is verified, and canonical msgpack is required (**code**:
     `txcheck.ts`).
   - **Time-window rules:** signing only inside a configured UTC window. The request timestamp must be within ±30 s.
     The `lv_est` gate requires that lastValid has passed by the submit-time estimate. The attestation expiry is at
     most 15 minutes away (5 minutes by default).
   - **Anomaly auto-pause:** any provider showing the txn present, an echo mismatch (wrong app-derived fields), a
     confirm-hash mismatch, a genesis mismatch, a provider head spread above the bound, or 6 refusals within an hour
     pauses the signer. Only a break-glass unpause clears it.
   - **Clock (R42-P3-1):** chrony with at least 2 NTS sources. The signer refuses to sign when chrony is unsynchronised
     or `|offset| > 5 s` (checked at both candidate and confirm).
   - **Snapshot staleness (R42-P3-1):** the DB snapshot in the request (the row plus the DB `clock_timestamp()`) must
     be no more than 60 s old. Provider heads must agree within 20 rounds. Observations are taken during the request,
     the DB refuses observations older than 15 minutes, and the attestation expires within 15 minutes.
   - **Refuse if any provider shows the txn present (R42-P3-1):** every pinned provider is queried, not just two. A
     single "present", for the payment or any group member, refuses and pauses. Absence must be proven by at least 2
     distinct operators.
6. **Independent checks** (code for the CLI; design for M-of-N)
   - **CLI independent vantage point:** implemented. The CLI's own provider probe refuses on present, unreachable,
     wrong genesis or a round below lastValid + MARGIN, before confirm.
   - **M-of-N second verifier in a separate trust domain** (design; v12): a second small VPS under a different
     account, provider and operator. It has its own pinned providers and its own Ed25519 key, re-runs §2.1 and §2.2
     independently, and co-signs the same msgHash. The signer asks the helper to sign only with the co-signature
     (2-of-2). v12 then makes `mr_spend_release_attested` require a valid co-signature from a pinned `verifier` key,
     so a compromised signer host alone can't release anything. Cost: one VPS at $3.50 to $7 per month (§7).
   - **Provider-signed responses:** no Algorand API provider we found (Nodely, GetBlock, algonode) signs its API
     responses. Algorand **State Proofs** attest block headers. They help prove *inclusion*. Absence over fv..lv would
     need light-client verification of every block's transaction commitment, which is a possible future option but not
     available as a provider feature today.
7. **Monitoring** (code + host)
   - **Fail-closed alerting:** every candidate, sign, refusal and pause is appended to an **off-host, append-only,
     hash-chained log** (`audit.ts`). If the sink is unavailable, the signer refuses (**code**). The sink is a
     Backblaze B2 bucket with Object Lock in compliance mode (no extra charge for Object Lock; the first 10 GB are
     free, then $6.95 per TB per month). The signer's B2 key can write but not delete.
   - **Heartbeat canary and dead-man switch:** the signer pings Healthchecks.io (free Hobbyist tier, 20 checks) every
     5 minutes, only after its self-checks pass: clock, state files, used journal, helper reachable, policy not paused,
     image age (`heartbeat()`, **code**). A missed ping pages the owner and the deputy. A canary TestNet spend is released
     weekly to prove the end-to-end path.
   - Pages go out over ntfy with network-prefixed titles (§12).
8. **Response**
   - **Remote kill switch:** an authenticated `pause` request from the requester or the deputy key pauses the signer
     and drops pending candidates. It can never unpause (**code**). The off-host fallback is to drop the WG peer.
   - **Deputy pause and revoke:** the deputy holds a pause-capable requester key and can run `mr_signer_revoke` in an
     admin window (§9). The deputy can't sign or unpause.
   - **Key rotation:** §9.1 (revoke the old key in the DB, pin the new key id, rebuild `used.db` from the DB export).

### 13.2 Threats → layers → remaining risk → cost

Costs are monthly unless marked one-time. **⚑ = over $15/month** (not recommended).

| # | Threat | Layers (13.1) | Remaining risk | Cost |
|---|---|---|---|---|
| T1 | Network attacker reaches the signer | 1 (WG only, IP allowlist, no inbound), 2 | A stolen WG key **and** requester key, from the requester host | $0 |
| T2 | Requester (ECS CLI host) compromised | 2 (rate limits), 5 (caps, limits, window), 6 (CLI check is on the same host, so M-of-N needed), 7 | Up to 0.05 USDC/day in false releases, paged, until pause; bounded to 0 with v12 M-of-N | $0; verifier VPS $3.50–7 |
| T3 | Replay of a request or attestation | 2 (request nonces), 5, DB `mr_release_nonce`, `used.db` | None known | $0 |
| T4 | One lying or compromised provider | 5 (any-present refusal, ≥ 2 operators, head spread), 6 | All queried providers colluding or compromised together | $0 (GetBlock / Nodely free) |
| T5 | RCE in the `mr-signer` process | 4 (helper sole card access via the 0660 socket + SO_PEERCRED gate, seccomp, uids), helper checks 1–5c **and its own verification of the requester-signed confirm**, helper caps, DB limit | Without the requester key it gets **no** signature. With a compromised requester too, it can fabricate observations; then bounded by the helper caps and the DB limit (5 per 24 h, 0.01 each); zero with v12 | $0 |
| T6 | Root or persistent malware on the signer | 3 (dm-verity, secure/measured boot, TPM-sealed PIN, IMA, no SSH) | Root **bypasses the helper** (it can unseal the PIN and talk to the card), so the helper checks and caps don't bind it. Only the **DB verifier rules and the DB limit** bound it (≤ 5 false releases per rolling 24 h, ≤ 0.01 each), until reboot, revoke or detection; the key can't be exported | $0 (+ hw) |
| T7 | Physical theft or tamper | 3 (TPM+PIN FDE, sealed PIN, seals, usbguard), 7 (dead-man), 8 (revoke) | An attacker with the machine powered and unlocked; revoke stops it | one-time hardware (not priced here) |
| T8 | Malicious USB (BadUSB/HID) | 3 (usbguard default block, single allow rule, ports off) | A device spoofing the allowed YubiKey's descriptors on the allowed port | $0 |
| T9 | Supply chain or malicious update | reproducible builds, manifest pins, 3 (updates policy, IMA policy gating) | A compromised build host and off-host rebuild together | $0 |
| T10 | Clock spoofing (to pass lv_est/expiry) | 5 (chrony NTS ×2, > 5 s refuses), DB uses its own clock | Skew under 5 s, which the margins absorb | $0 |
| T11 | Stale snapshot or provider | 5 (≤ 60 s snapshot, head spread ≤ 20 rounds, lv_est), DB re-checks | Low | $0 |
| T12 | Silent outage or tampered monitoring | 7 (fail-closed audit, heartbeat, dead-man, weekly canary) | Detection delayed up to one heartbeat period | $0 (HC Hobbyist; ⚑ Business $20 not needed) |
| T13 | Key compromise (signing access to the card) | 8 (revoke, rotation, kill switch), DB pins, **DB limit** | Up to 5 false releases per rolling 24 h (≤ 0.01 USDC each) until the revoke lands; the signer and helper caps don't apply to someone using the card directly | $0 |
| T14 | DoS (lockout trips, rate limits, pause) | fail-closed by design | Releases wait; ambiguous spends stay counted (accepted) | $0 |
| T15 | Off-host log tampering | 7 (B2 Object Lock compliance, write-only key, hash chain) | B2 account takeover can't delete locked objects | $0 under 10 GB |

Layers that cost money:
- second-verifier VPS (Vultr $3.50, DO $4, Hetzner CX23 €5.99);
- B2 ($0 at our volume);
- Healthchecks (free).
- ⚑ **Over $15/month and not recommended:** own Algorand node, Hetzner CPX41 ≈ €121; Healthchecks Business $20;
  Alibaba KMS $500.
- One-time: YubiKeys and the TPM machine (§10).

### 13.3 Recommendations

1. Run the automated signer on the dedicated TPM machine with dm-verity, sealed PIN, usbguard and no sshd. Keep the
   policy defaults (0.01 per release, 3 per hour, 5 per day, 0.05 per day).
2. Before MainNet launch (beyond the capped dry run), add the **M-of-N second verifier** on a $3.50–7 VPS in another
   account, and ship v12 so the DB requires its co-signature. This is the one layer that closes T2 and T5.
3. Use B2 Object Lock for the off-host log and Healthchecks Hobbyist for the dead-man switch, both free at our volume.
4. Keep GetBlock or Nodely free tiers as the second operator. Don't buy an own node yet (⚑).

## 14. Implementation (rev 10, TestNet/dev only)

- Piece 1, `a981ec8`: `ops/pg/mr_ed25519`, a verify-only C extension.
  - Built with static libsodium 1.0.20 in a pinned PG 18 container.
  - Two builds are byte-identical: `.so` sha256 `40bc9651…`.
  - RFC 8032 golden vectors and negatives.
- Piece 2, `98a031c`: the v11 migration (`packages/storage/src/v11-attested.ts`).
  - Code: the app-derived `signed_txn` decoder, the attestation codec, role grants, and the manifest re-pinned.
  - Tested on a local PG 18 with the extension.
- Piece 3, `7b7e7ef`: `packages/signer`, the automated `mr-signer` (§13.1 layers 1, 2, 5, 7, 8 in code).
- Piece 4, `b26c87c`: the `mr-piv-sign` helper behind `SignBackend`, with checks 1–5c, the used journal and the
  lockout.
  - `SoftwareEd25519Backend` is **TESTNET-ONLY**: it refuses mainnet and requires `MR_SIGNER_SOFTWARE_KEY=TESTNET-ONLY`.
  - The YubiKey backend is a refusing stub (hardware-blocked).
- Piece 5, `d952a0e`: the CLI attested release path (`packages/signer/src/cli/release.ts`), with end-to-end tests
  on PG 18.
  - It runs echo A and echo B, the independent absence check, return byte identity and signature verification, then
    the attested release.
  - It also provides the DB export for a `used.db` rebuild.
- `used.db` deviation: an append-only, fsync'd, hash-checked JSONL journal instead of SQLite (Node 20 has no built-in
  SQLite), with the same fail-closed rebuild rule.
- Not done yet:
  - the middleware-hono call site that stores `signed_txn` after settle;
  - v12 (M-of-N in the DB);
  - the systemd units and the nftables/usbguard files.

### 14.1 Rev 11 fixes (internal reviewer run 43)

- `2f75f7f` (v11 amended before any database applied it): the DB limit of 5 attested releases per rolling 24 h, and
  `FOR SHARE` on the key row.
- `0d4aecb`: `build.sh` works outside git, the toolchain is pinned, and the `.so` is unchanged (`40bc9651…`).
- `1629a74` (mr-signer):
  - rollback and wipe detection against the off-host chain, with the chain head loaded from the sink;
  - a failed page pauses the signer and withholds the signature;
  - the heartbeat checks the page path;
  - limits are over rolling 24 h windows, with bounded config and fee caps;
  - refusals no longer return their reasons to the peer.
- `b91d696` (mr-piv-sign):
  - every sign re-checks TestNet;
  - the software backend is excluded from the MainNet image;
  - the helper verifies the requester's confirm itself and keeps its own caps;
  - the `.socket` unit plus the SO_PEERCRED gate (`ops/signer/peercred-gate.c`);
  - the lockout is persisted, and unlock needs a presence proof.
- `5f6f71d` (CLI): the pubkey is pinned in the CLI, and the independent check is repeated right before the DB call.

### 14.2 Rev 12 (internal reviewer run 44)

- **mr-signer main** (`packages/signer/src/main.ts`): config → audit chain → boot gate → HTTP server → heartbeat
  timer (self-check incl. a real ntfy test publish, then the dead-man ping). Secrets only from the environment file.
- **Sinks**: `B2ObjectLockSink` (S3 API, hand-written SigV4, one object per event with COMPLIANCE retention,
  Content-MD5, `If-None-Match: *`, inverted-seq keys so a 1-key list returns the head). **Blocked on a B2 account in
  the owner's name** (free tier covers this volume). TestNet rehearsal used `LocalAppendStandInSink`, which refuses to
  construct unless network = testnet and it carries the label `TESTNET-ONLY STAND-IN (not off-host, not Object Lock)`.
- **Empty bucket**: every event has a `seq`; config `audit.minSeq` pins the lower bound (record the head seq at
  install and at each review). An empty bucket with `minSeq > 0`, or a lower head, refuses to boot. Missing local
  state with a non-empty log refuses too (wipe, not a fresh install).
- **Helper state anchoring**: the helper's sign reply carries its state counter; mr-signer logs it off-host (also on
  every boot line) and pauses, withholding the signature, if a later reply does not advance. A restored helper.json
  is therefore caught on the next sign.
- **Reconcile**: `mr_spend_pending_signed_to_ambiguous(store, timeout_ms)` (definer, mr_reconcile only, timeout ≥
  60 s, audited `stuck-pending-ambiguous`): pending rows with stored signed bytes and no settle outcome move to
  ambiguous after the timeout (default 15 min), never to released. Called at the start of `reconcileSpendPg`.
- **Probes**: Nodely's indexer `/health` has no genesis hash; the probe reads it from the head block header.
- **Unit hardening**: `DeviceAllow=/dev/mr-yubikey` (udev rule pinned by serial) instead of all USB; `serveOnce`
  read timeout (10 s) so an idle peer can't hold the single connection slot; attach errors keep their context.
- **lv_est with a future firstValid**: the middleware sets `submit_round = firstValid`; a payment whose firstValid is
  ahead of the head at submit makes lv_est later than the real expiry, i.e. conservative (late, never early).
- **Budget surge**: a burst of ambiguous spends can consume the 5/24 h DB budget; later legitimate releases wait.
  This is the intended trade (bounded loss); the pager shows each release, and the deputy can pause.
- **Rehearsal**: `docs/ops/runs/2026-10-19-signer-rehearsal-A1-A6.md`, all six pass; stand-ins listed there.
- Still open (accounts, all free tier): B2 (Object Lock bucket), Healthchecks.io, a second chain operator (GetBlock).

## 15. Rev 13 (internal reviewer run 45): hardware-free launch blockers

### 15.1 v12: two attestations (M-of-N, 2-of-2)
- `mr_release_quorum`: MainNet fixed at 2 (CHECK), TestNet 1 (dev) and only raisable. `mr_cosigner_key`: the
  second verifier's pinned keys, write-once, never equal to any signer key or pubkey (trigger).
- Entry point `mr_spend_release_attested(store, id, msg, sig, cmsg, csig, label, reason)` (mr_release only). The
  co-signature `MR-RELEASE-COSIGN-v1\n` + restricted JCS {attestHash = sha256(msg), store, spendId, txId, lastValid,
  round, nonce, expiry ≤ 15 min, observations, keyId, network, genesisHash, v} is verified with mr_ed25519; its
  observations must come from pinned operators **not used by the signer's observations**. Then the unchanged v11
  checks run (`mr_spend_release_attested_v11`, now internal). `mr_release_cosign` keeps one row per release.
  The 6-argument form remains and is refused wherever the quorum is 2.
- Tests: `packages/storage/src/v12-cosign.test.ts` (every defect refused, good pair releases once, guards).

### 15.2 Second verifier (`packages/signer/src/verifier/`, unit `deploy/verifier/mr-verifier.service`)
Own key (YubiKey via ykcs11; TestNet software key), own requester nonces, own caps (3/h, 5/24 h), own pause on
anomaly, own pager topic. It verifies the primary attestation against the pinned key, re-derives the stored signed
bytes, checks lv_est, runs its own absence check on providers whose operator the signer did not use, then co-signs.
**Run it on a different host and cloud account** from mr-signer. The CLI verifies the co-signature binding and
signature before the DB call. End-to-end test with quorum 2: `packages/signer/test/verifier.test.ts`.
Still needed for MainNet: **three pinned, mutually independent provider operators in total**: the two that v11
requires for the signer's observations, plus at least one more that the signer's observations did not use, for the
co-signer (v12 refuses co-sign observations from the signer's operators). Nodely and algonode.cloud count as ONE.
And the verifier's own YubiKey.

**What the verifier does NOT make independent (trust domains).** Its absence check is independent (its own chain
queries through an operator the signer did not use, its own key). Its *inputs* are not:
- **Requester key:** it trusts the SAME requester key(s) as the signer (`sc.requesters`, shared signer config), so
  a stolen requester key reaches both services.
- **DB inputs:** the signed bytes and the row (`submitAt`, `submitRound`, used for lv_est) come from the CLI, read
  from the same DB. The verifier re-derives txId/fv/lv/group/sender from the bytes, but it cannot tell whether the
  row's submit fields are true.
- **Codebase:** the same code (txcheck, providers, requests), so a bug there affects both (common mode).
- **Human operator:** the same person (the owner) runs both.
The DB enforces distinct keys and disjoint chain operators. It cannot enforce distinct hosts, cloud accounts or
people: there is no trust-domain attribute on the keys, and one DB owner pins both. Keeping them apart is
operational: different host, cloud account and YubiKey. That holds as long as the chain probe is the real check.

### 15.3 YubiKey backend (`piv/ykcs11.ts`)
PKCS#11 through ykcs11 (binding injected, `pkcs11js` in the image): token pinned by serial, slot 9c (CKA_ID 2),
CKK_EC_EDWARDS, the card's CKA_EC_POINT must equal the pinned pubkey; PIN from the systemd credential (0600,
6–8 chars, zeroed), one C_Login, never retried after a failure; CKM_EDDSA; messages must be an attestation or
co-signature of the backend's network; every signature is verified before return. Mock-token tests only.

### 15.4 Host (`deploy/signer/host/README.md`)
Units, nftables (default drop, per-uid egress), usbguard + udev serial pin, NTS chrony, dm-verity/UKI/TPM/IMA notes.
`systemd-analyze verify` found `StartLimit*` in `[Service]` (fixed: `[Unit]`); `nft -c` parses the ruleset.

### 15.5 R45-P3-1
Stand-in sink + `rehearsal/` excluded from the MainNet image and loaded only on TestNet; `open()` checks the head
links to seq − 1; **B2 does not implement If-None-Match (501)**, so the sink does check-then-put (a re-append of
identical bytes after a lost ack is a no-op, different bytes are refused) and refuses a head key with two
distinct versions; `BindsTo=` the YubiKey device unit; proof JSON carries the attestation.

### 15.6 Rehearsal A7
A real confirmed TestNet payment, stored as the app would, is detected (refused + auto-pause), see
`docs/ops/runs/2026-10-19-signer-rehearsal-r45.md`. Our own in-flight submit needs a funded TestNet account.

## 16. Rev 14 (internal reviewer run 46)

### 16.1 R46-P2-1: audit log serialized
`ChainedAudit.log()` runs behind a promise-chain mutex (`audit.ts`). Before, two concurrent requests could take the
same seq and prev: on B2 that gives two versions of one key, so the chain forks, and boot is bricked if that key is
the head. Test `packages/signer/test/r46.test.ts`: 40 concurrent `log()` calls against a sink with random latency
give seqs 1..40, each prev equal to the previous line's hash, and a clean re-open. A failed append consumes no seq
and does not stall the queue. Both tests fail on the old code.

### 16.2 Held P3s from run 46, fixed
- **B2 versions:** `at(seq)` (so seq − 1 at open) refuses a key with more than one distinct version, like the head.
  Keys older than seq − 1 are not re-listed at boot. Their hashes are chained, so a forged *newer version* of an
  old key breaks the next line's `prev` check only if someone re-reads it (an offline full-chain verify does).
- **ykcs11:**
  - a failed `open()` after `C_Initialize` now calls `C_Finalize`;
  - a sign that fails with DEVICE_REMOVED / TOKEN_NOT_PRESENT / SESSION_* drops the session, so the next request
    re-opens and logs in again (the failing request is not retried);
  - "zeroed" now says only the PIN Buffer is zeroed: pkcs11js takes a JS string, and that copy can't be zeroed.
  - **Needs YubiKey firmware 5.7+** (Ed25519 in PIV).
- **Verifier heartbeat:** healthy now also needs a synced clock within `maxClockSkewS`, not just "not paused".
  Still open (no account/infra): the verifier has no off-host audit chain or rollback anchor for
  `verifier.json` / `requests.json`, and lv_est uses the CLI-supplied row (§15.2).
- **Host:**
  - wg0 egress is per-uid (`meta skuid "mr-signer"` / `"mr-verifier"`) instead of open to every uid;
  - the verifier host has its own `deploy/verifier/nftables.conf`;
  - the units say the chronyd pid file means only that chronyd is running (sync is checked at runtime);
  - the verifier unit no longer mentions B2.
- **Proof:** standIns says "migrations through v12, TestNet quorum 1 (the 2-of-2 path runs only in
  test/verifier.test.ts)"; the A7 audit chain is in the proof (`auditLogA7`).

### 16.3 A7-own: our own payment
From the TestNet `pnpm e2e:paid` payer (FLJXFD7…) to its merchant (SK7X44D…), 0.001 USDC, with the payer paying its
own fee. Order: the row is stored with the real submit round; we submit (algod 200); it confirms; the row is
marked ambiguous (lost ack). We then wait for real time to pass lv + margin, with no lv − 1 shortcut. Result: the
release is refused with 403, the signer pauses on "anomaly … present", and the row stays ambiguous. Proof:
`docs/ops/runs/2026-10-19-signer-rehearsal-r46.{json,md}`. Only the confirmed case runs: public TestNet confirms
a valid submitted txn within a round or two, so "submitted then expired" can't be forced honestly (the
never-submitted expiry is A1).

## 17. Rev 15: hosting on Google Cloud (CHANGE FROM DAVID, Oct 19, 2026)
The automated signer runs in a **Google Cloud VM**. Its attestation key is a **Cloud KMS** key version, not a YubiKey on
a home machine, and signing stays fully automated. Nothing is provisioned: the owner must approve the GCP project and
the costs (§17.6). Research done Oct 19, 2026 from Google's current docs (links inline).

### 17.1 Findings
- **Ed25519 in Cloud KMS:** `EC_SIGN_ED25519` (PureEdDSA, raw data in, so the attestation bytes are signed as-is)
  is available at **SOFTWARE protection level only**. The HSM, single-tenant HSM, EXTERNAL and EXTERNAL_VPC
  levels list only `EC_SIGN_P256_SHA256` / `EC_SIGN_P384_SHA384` / `EC_SIGN_SECP256K1_SHA256`.
  <https://cloud.google.com/kms/docs/algorithms>
- **KMS prices** <https://cloud.google.com/kms/pricing>:
  - SOFTWARE key version $0.000082192/h ≈ **$0.06/month**;
  - HSM EC key version $0.003424658/h ≈ **$2.50/month** (first 2,000);
  - crypto operations **$0.03 per 10,000** ($0.15/10k for some HSM ops). At ≤ 5 releases/day that is under $0.01/month;
  - single-tenant HSM is $4.79/h ≈ $3,500/month (not an option).
- **Asymmetric signing API:** `POST https://cloudkms.googleapis.com/v1/{version}:asymmetricSign` with
  `{data, dataCrc32c}`. The response carries `signature`, `signatureCrc32c`, `verifiedDataCrc32c`, `name` and `protectionLevel`.
  <https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign>,
  <https://cloud.google.com/kms/docs/create-validate-signatures>
- **Token:** the VM's attached SA token comes from
  `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`, called with
  `Metadata-Flavor: Google`. No key file.
  <https://cloud.google.com/compute/docs/access/authenticate-workloads>
- **Audit:** `AsymmetricSign` is a **Data Access (DATA_READ)** audit log, which is **off by default** and must be enabled for
  `cloudkms.googleapis.com`. <https://cloud.google.com/kms/docs/audit-logging>,
  <https://cloud.google.com/logging/docs/audit/configure-data-access>
- **VMs** (us-central1, 730 h; Google's prices via <https://cloud.google.com/products/compute/pricing>, figures
  from economize.cloud, Oct 19, 2026):
  - **e2-micro** (2 shared vCPU, 1 GB) $0.0084/h ≈ **$6.11/month**, or **free**: the Free Tier gives one
    e2-micro per billing account per month in us-west1 / us-central1 / us-east1, plus 30 GB standard PD and 1 GB
    egress (<https://cloud.google.com/free/docs/compute-getting-started>);
  - **e2-small** (2 GB) $0.0168/h ≈ **$12.23/month**.
  E2 supports **Shielded VM** (Secure Boot, vTPM, integrity monitoring), at no extra cost.
- **Confidential VM** (AMD SEV / SEV-SNP / Intel TDX) is **not available on E2**: only N2D, C2D, C3D, C4D and
  C3/C4 machine types qualify (<https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations>).
  The smallest is n2d-standard-2 at $0.0845/h, plus the SEV surcharge of $0.005479/vCPU-h + $0.0007342/GiB-h
  (<https://cloud.google.com/confidential-computing/confidential-vm/pricing>): ≈ $0.1013/h ≈ **$74/month (FLAG > $15)**.
- **Cloud NAT** (<https://cloud.google.com/nat/pricing>):
  - $0.0014 per VM-hour ≈ $1.02/month;
  - $0.005/h per NAT IP ≈ $3.65/month;
  - $0.045/GiB processed (our traffic is well under 1 GiB).
- **FQDN egress rules** need **Cloud NGFW Standard**, $0.0193/GiB evaluated (north-south only), so cents per month.
  IP/port rules (Essentials) are free. <https://cloud.google.com/firewall/pricing>
- **IAP TCP forwarding** (admin SSH, CLI tunnel): no charge.
- **VPC Service Controls and org policies** need a Google Cloud **organization**, i.e. a free Cloud Identity org on
  a domain. A plain Gmail account has none, so without one: the IAM condition plus attached SA only, enforced by hand and audited.
- **Verifier key elsewhere:** AWS KMS has supported Ed25519 (`ECC_NIST_EDWARDS25519`, HSM-backed) since Nov 2025,
  at $1/key/month (<https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/>,
  <https://aws.amazon.com/kms/pricing/>). Vultr Regular Cloud Compute 1 vCPU/1 GB is **$5.00/month**
  (<https://www.vultr.com/pricing/>) but has no KMS/HSM or vTPM.

### 17.2 Decision: Ed25519 at SOFTWARE level (no schema change)
- **Option A (recommended): `EC_SIGN_ED25519`, SOFTWARE.** v11/v12, `mr_ed25519` (libsodium) and the attestation
  format stay unchanged; only the backend changes ($0.06/month). The key is non-exportable through the API in
  both levels. The real threat is **using** the key through IAM, and IAM gates SOFTWARE and HSM keys identically.
  What HSM adds is FIPS 140-2 Level 3 protection against key extraction *inside Google*. That risk is already in
  the trust base (§17.4) and is limited by the second verifier.
- **Option B: HSM with ECDSA P-256** ($2.50/month). This needs:
  - a new PG extension `mr_p256`: libsodium has no P-256; use OpenSSL `EVP_DigestVerify` with a pinned DER SPKI;
  - KMS returns **DER** ECDSA signatures, so normalize to low-S and check the form;
  - a v13 migration with an `alg` column on `mr_signer_key` / `mr_cosigner_key`;
  - a P-256 path in the CLI/helper verify code, a rebuilt integrity manifest, and a new audit.
  Roughly one run of work, plus re-auditing gate 1 (the extension). Do it later if the owner wants FIPS L3 for the key.

### 17.3 Architecture on GCP (files: `deploy/gcp/`, backend `packages/signer/src/piv/cloudkms.ts`)
- **Project:** a separate project used only for the signer (`mr-signer-prod`), with a budget alert at $15.
- **VM:**
  - e2-micro, Shielded VM (Secure Boot + vTPM + integrity monitoring), Debian 13;
  - **no external IP**; OS Login + 2FA;
  - admin and the CLI tunnel go **only through IAP** (`35.235.240.0/20`); the WireGuard path is dropped on GCP.
- **Signer service account:** dedicated `mr-signer@…`, **attached** to the VM, with **no SA keys**
  (`iam.disableServiceAccountKeyCreation` if there's an org). Its custom role has only `useToSign` + `viewPublicKey`, granted
  on the **one key**, with an IAM condition pinning **version 1**. Plus secretAccessor on its 3 secrets, logWriter
  and metricWriter. Not the default compute SA.
- **Network:**
  - custom VPC; Private Google Access (`private.googleapis.com` 199.36.153.8/30) for KMS / Secret Manager;
  - Cloud NAT for the providers, ntfy, hc-ping and B2;
  - NGFW policy: IAP ingress only; egress to PGA plus FQDN objects for the pinned hosts; deny the rest.
- **In-VM `deploy/gcp/nftables.conf`:**
  - only **mr-piv** (the helper) and root can reach the metadata token endpoint and PGA, so a compromised mr-signer
    process **can't** get the SA token;
  - mr-signer gets HTTPS to the allowlist only.
- **Units:** `gcp/mr-piv-sign@.service` drops USB, the PIN credential and PrivateNetwork, and allows only the resolver,
  MDS and PGA (`IPAddressAllow=`). `gcp/mr-signer.service` drops WireGuard.
- **Logging:** Data Access logs (DATA_READ) on for Cloud KMS → a locked-retention bucket, with alerts on every
  `AsymmetricSign` beyond the signer's own count and on any IAM / key-version change. The off-host ChainedAudit
  stays on **B2**, outside Google.
- **Backend `CloudKmsBackend` (implemented, mock-tested):**
  - token from the metadata server only, with `Metadata-Flavor` checked both ways, cached until 60 s before expiry and never logged;
  - **pinned**: full key-version name, 32-byte public key, protection level, and SA email (MainNet);
  - `open()` checks `getPublicKey` (algorithm `EC_SIGN_ED25519`, protection level, PEM == pin);
  - `sign()` accepts attestation / co-sign messages for its network only; it sends `dataCrc32c` and requires
    `verifiedDataCrc32c`, a matching `signatureCrc32c` and the pinned version name, and **verifies every signature
    against the pinned key** before returning it.
  Tests: `packages/signer/test/cloudkms.test.ts`.
- **Verifier:** see §17.5.
- **What's gone with the YubiKey:**
  - the presence proof (touch), which unlocked a hard-locked helper (A6), needs a replacement. Replaced in rev 16 by the
    signed unlock (§18.3). There is no IAP reset path;
  - usbguard/udev don't apply on GCP;
  - the dm-verity/UKI notes apply only with a custom image and custom Secure Boot keys.

### 17.4 Trust statement (rev 15)
The trust base now includes **Google** and **the GCP project's IAM admins**:
- Google runs the KMS, the hypervisor, the metadata server and IAM, and can in principle use the key;
  Shielded VM does not protect against Google, and Confidential VM ($74/month) would cover only VM memory, not KMS;
- any principal with `setIamPolicy` on the project or key, or `useToSign`, or the ability to attach the signer SA
  to another VM (`iam.serviceAccounts.actAs`), or root on the VM, can produce attestations.
What still bounds them:
- the DB checks every attestation (v11 caps, nonce, provider observations, lv_est), and at quorum 2 it requires the
  **verifier's co-signature from a different trust domain** with its own absence check;
- KMS Data Access logs + alerts, and the off-host B2 audit chain, make use visible;
- the policy caps: 5 releases/24 h and amount caps.
**Decision for the owner:** with Google in the signer's trust base, the verifier must **not** also depend on Google.

### 17.5 Where the verifier goes
- **Recommended: not GCP.** A different provider and account, so one cloud admin, compromise or legal order can't
  reach both keys.
  - **Vultr** ($5.00/month, 1 vCPU/1 GB) has no KMS, HSM or vTPM, so the verifier key would be a software key on disk
    (0600). Theft of that key alone still can't release funds (the primary attestation is also required), but it is
    the weaker option.
  - **Better, if the owner accepts a third account:** the verifier on AWS (Lightsail/EC2) with **AWS KMS Ed25519**
    (HSM-backed, $1/month). It needs an `AwsKmsBackend`, which isn't built: same shape as CloudKmsBackend, with
    SigV4 and instance-role credentials.
- A **separate GCP project in a separate Google account** is possible, but Google stays a common trust base for
  both keys. Its e2-micro free tier is per billing account, so a second account would get it, at the price of a
  weaker separation.

### 17.6 Monthly cost (USD, us-central1; anything over $15 is flagged)
| Item | Price | Recommended setup |
|---|---|---|
| Signer VM e2-micro, Shielded | $6.11 (free under Free Tier) | **$0–6.11** |
| 10 GB pd-standard | $0.40 (free under Free Tier, 30 GB) | $0–0.40 |
| Cloud KMS Ed25519 SOFTWARE, 1 version + ~150 signs | $0.06 + <$0.01 | **$0.07** |
| Cloud NAT (1 VM + 1 IP + <1 GiB) | $1.02 + $3.65 + ~$0.05 | **$4.72** |
| NGFW Standard FQDN egress (<1 GiB) | $0.0193/GiB | ~$0.02 |
| Secret Manager (3 secrets), Logging (<50 GiB), IAP | free tier / free | $0 |
| Log bucket (MBs, locked retention) | ~$0.02/GB | ~$0.01 |
| **Signer total** | | **≈ $4.85 (Free Tier) / ≈ $11.35** |
| Verifier on Vultr Regular 1 GB | $5.00 | $5.00 |
| (option) verifier key in AWS KMS Ed25519 | $1.00 + AWS VM (not priced) | — |
| (option) e2-small instead of e2-micro | $12.23 | signer ≈ $17.40 **FLAG > $15** |
| (option) HSM P-256 key (Option B) | $2.50 + schema work | +$2.50 |
| (option) Confidential VM n2d-standard-2 + SEV | ≈ $74 | **FLAG > $15** |
| B2 (audit sink), Healthchecks, ntfy | as before (free tiers) | $0 |
**Recommended: superseded by §20.2 (A: $14.02 with the AWS verifier).** Rev 15 estimate: ≈ $10/month (signer on GCP Free Tier + verifier on Vultr). Nothing above $15 is in the
recommended setup.

### 17.7 What the owner must set up (after approving the project and costs)
1. A GCP account with billing, a new project `mr-signer-prod`, and a budget alert at $15. Optionally a Cloud
   Identity org on his domain, for org policies + VPC-SC.
2. Run `deploy/gcp/README.md` §2–§6 (key, SA + custom role + condition, VM, network, audit logs). Then send the
   public key and version name so they can be pinned in the DB (v11 key row) and in `cloudkms.json`.
3. Store the 3 secrets in Secret Manager: ntfy topic, Healthchecks URL, B2 app key (B2 and Healthchecks accounts
   are still needed).
4. The verifier: a Vultr account ($5) or an AWS account (KMS Ed25519); plus a third independent chain operator (§15.2).
5. Generate the Ed25519 unlock key off the VM (§18.3) and send its public key for pinning.
6. Optionally (recommended, §18.2) a free Cloud Identity org on his own domain.


## 18. Rev 16 (internal reviewer run 48)

### 18.1 R48-P2-1: verifier on AWS KMS, trust domains pinned

> **Superseded (rev 25, Oct 22, 2026, R75-P2-1):** AWS is not the verifier. The only active MainNet co-signer is `aliyun-softkey`; the AWS KMS key (`alias/mandaterail-verifier`) and the GCP key are locked backups that the loaders refuse (see docs/ops/kms-key-order.md). (rev 26: the GCP key is now the active MainNet signer; AWS stays a locked backup.)
- `packages/signer/src/piv/awskms.ts`: `AwsKmsBackend` (kind `awskms`). Key spec `ECC_NIST_EDWARDS25519`, algorithm
  `ED25519_SHA_512`, `MessageType RAW` (≤ 4096 bytes). Credentials come from **IMDSv2** (PUT token, then the pinned
  role name), cached until 5 min before expiry; requests are SigV4 (`service=kms`) JSON 1.1 `TrentService.Sign` /
  `GetPublicKey`. Pinned: region, full key ARN (aliases refused), public key, role. Every signature is verified
  against the pinned key. Mock-tested in `test/awskms.test.ts`. Cost: $1/key/month + requests (free tier).
- `verifier.ts` refuses `cloudkms` (and anything but `yubikey-piv` / `awskms`) on MainNet: the co-signer must not
  share Google with the signer.
- v12 (amended in place; v12 is not applied anywhere): `mr_signer_key.trust_domain` and
  `mr_cosigner_key.trust_domain` (`provider:account`, e.g. `gcp:mr-signer-prod`, `aws:123456789012`) are required
  and write-once, and the co-signed release function refuses when the co-signer's provider equals the signer's.
  The integrity-manifest pin was regenerated.

### 18.2 R48-P2-2: GCP alerts page outside Google
`deploy/gcp/alerts/` (terraform, not applied) replaces the chain-count metric: log-match alert policies to an ntfy
webhook channel plus an independent Pub/Sub sink → forwarder → ntfy, with a daily heartbeat. Events: every
`AsymmetricSign`; signs not by the signer SA from the VM; actAs / token minting / SA attach / SA keys; key-version
destroy, restore, disable, update, create; auditConfig, IAM, sink and alert-policy changes; IAP and OS Login admin
grants. DATA_READ audit logs are enabled for Cloud KMS and IAM Credentials. **Recommendation: a free Cloud Identity
organization on the owner's domain**, so org policies, an org-level sink and org audit config sit above the project.

### 18.3 R48-P2-3: signed unlock (replaces the YubiKey touch and the IAP reset)
- the owner holds an Ed25519 **unlock key off the VM** (offline laptop / password manager, never on GCP). Its public key
  is pinned in the helper config (`unlockPubkeyB64`); the helper has no other unlock path.
- Message: `MR-HELPER-UNLOCK-v1\n` + JCS `{v, network, genesisHash, keyId, unlockKeyId, counter, nonce, issuedAt,
  expiry, reason}`. The helper requires: the pinned network/genesis/key, `issuedAt` within ±60 s, validity ≤ 10 min,
  `counter` equal to its current counter, an unused nonce (stored in helper state).
- Fits the counter anchor: an unlock **increments** the helper counter (never lowers it). mr-signer logs
  `unlock-requested`, then `unlock` or `unlock-refused` to the off-host chain (all paged) and checks the new counter
  against the anchor (`assertHelperAdvanced`). Routes: `POST /v1/unlock`, `/v1/helper-status`. Rehearsal A6 uses it.

### 18.4 P3s
- R48-P3-1: `protectionLevel` and `name` are required in Cloud KMS responses (fixed).
- R47-P3-1: audit pages run outside the append mutex; an ambiguous append is resolved via `at(seq)` (adopt our line,
  reuse an empty slot, refuse a foreign line as a fork); YKCS11 closes the session on any sign error; nftables output
  rule is `udp sport $WG_PORT`; rehearsal A7 limits text corrected. Verifier rollback and `lv_est` are accepted as-is.
- B2 write key (P3, documented): the VM's B2 key is restricted to the audit bucket/prefix with `writeFiles` only,
  Object Lock compliance mode; the verifier alerts on objects that are not chained or not from the VM. A VM compromise
  can append junk, not rewrite history. Alternative: keep the B2 key off Google entirely (the verifier pulls).

## 19. Rev 17 (internal reviewer run 49)

### 19.1 R49-P2-1: "from the VM" means the reserved IP + VPC, and every sign is reconciled
- `deploy/gcp/alerts/main.tf`: the signer VM gets a reserved static internal IP (`google_compute_address`,
  INTERNAL). The "sign not by the signer VM" alert fires unless principal = signer SA **and** callerIp = that IP
  **and** callerNetwork = `//compute.googleapis.com/projects/<p>/global/networks/<vpc>`. `gce-internal-ip` (shown
  for any VM in any project) is no longer accepted.
- `packages/signer/src/verifier/reconcile.ts` (`Reconciler`, run by mr-verifier on AWS): reads Cloud KMS
  `AsymmetricSign` audit entries for the pinned key version (Cloud Logging `entries:list`, read-only viewer via
  Workload Identity Federation, no key file) and the signer's off-host chain (read-only B2 key, hash links
  checked). Each AsymmetricSign must match exactly one `signed` event within ±2 min, and vice versa; the SA, IP
  and VPC are checked too. Any mismatch, broken link or source error pages `[verifier] ANOMALY KMS/chain
  mismatch`; the cursor does not advance past a bad window (it re-pages until handled). 10-min lag for log delay.

### 19.2 R49-P2-2: forwarder heartbeat dead-man
Cloud Scheduler publishes a daily heartbeat; the forwarder posts it to ntfy (tag `heartbeat`) and pings a
Healthchecks check (period 1 d, grace 2 h). The verifier polls the forwarder topic and pages once when the newest
heartbeat is older than 26 h or unreadable, and once on recovery (`checkForwarderHeartbeat`). Healthchecks pages
independently.

### 19.3 AWS verifier (`deploy/aws/`, terraform, not applied)

> **Superseded (rev 25, Oct 22, 2026, R75-P2-1):** AWS is not the verifier. The only active MainNet co-signer is `aliyun-softkey`; the AWS KMS key (`alias/mandaterail-verifier`) and the GCP key are locked backups that the loaders refuse (see docs/ops/kms-key-order.md). (rev 26: the GCP key is now the active MainNet signer; AWS stays a locked backup.)
IMDSv2 required, hop limit 1; key policy: admin (MFA) cannot sign, `kms:Sign` only by the instance role via the KMS
VPC endpoint (explicit Denies otherwise), endpoint policy repeats it; PassRole only to EC2 and only onto the
`mr-role=verifier` instance; CloudTrail → EventBridge (every `Sign` + key/role/IMDS/endpoint/trail changes) →
Lambda → ntfy (URL in Secrets Manager). Verifier nftables: only the `mr-verifier` uid reaches
`169.254.169.254:80` and the endpoint ENIs. Cost ≈ $11.40/mo with the endpoint (README). To verify at setup:
EventBridge delivery of the read-only `Sign` event.

### 19.4 Held P3s
- trust_domain is bound to the key resource id: v12 `key_resource` (write-once, both tables) must match the
  domain (`gcp:<project>` ↔ `projects/<project>/…/cryptoKeyVersions/<n>`, `aws:<12 digits>` ↔
  `arn:aws:kms:<r>:<acct>:key/<uuid>`, `yubikey:<serial>` ↔ `piv:<serial>:9x`). Manifest pin regenerated.
- `/v1/unlock` rate limit: 3 per 10 min (any outcome) before the body is read.
- The ntfy URL is in Secret Manager / Secrets Manager only; the GCP Monitoring channel is now Pub/Sub (no URL label).
- Forwarder `package-lock.json` pinned (functions-framework 3.4.2).
- Unlock-key custody: `docs/ops/unlock-key-custody.md` (YubiKey preferred, else offline + age, never on GCP/AWS).

## 20. Rev 18 (internal reviewer run 50)

### 20.1 Fixes
- `aws_cloudwatch_event_rule.kms_sign` has `state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"` (read-only
  `Sign` events are delivered). The key policy is a separate `aws_kms_key_policy`; the endpoint policy a separate
  `aws_vpc_endpoint_policy`: no cycle. OpenTofu 1.13.1 installed on the box; `tofu validate` and `tofu fmt -check`
  pass for `deploy/aws` and `deploy/gcp/alerts` (provider lock files committed).
- GCP token for reconcile: `deploy/gcp/alerts/wif.tf` (pool + AWS provider limited to
  `assumed-role/mr-verifier/i-*`, reader SA with `roles/logging.privateLogViewer` only, impersonation only by that
  principal set), `packages/signer/src/verifier/gcp-token.ts` (IMDSv2 → signed GetCallerIdentity → Google STS →
  generateAccessToken, scope logging.read, 0600 atomic file), `deploy/verifier/mr-gcp-token.{service,timer}`
  (every 20 min, token 60 min). The GCP actAs alert ignores only the reader SA's WIF GenerateAccessToken.
- P3s: `mr_v12_domain_matches` ELSE → false, yubikey serial must be digits before use in the pattern; every
  backend takes `keyResource` (the DB pin) and refuses at `open()` unless it names its configured key (required on
  MainNet); AWS alerts for Lambda, Secrets Manager and IAM user/key/MFA changes, no fake PassRole event (policy
  instead), AWS heartbeat → ntfy + Healthchecks, Object Lock default retention (COMPLIANCE 400 d),
  `ec2:SourceInstanceARN` in the key policy, PassRole/profile conditions fixed (MFA; `ec2:InstanceProfile`);
  reconciler mismatches are acknowledged with a requester-signed `reconcile-ack` naming the exact problem hash and
  a reason (paged, kept in state; `/v1/reconcile-status`, `/v1/reconcile-ack`); `/v1/unlock` is limited per caller
  (3/10 min) and globally (6/10 min); KMS endpoint IPs come from `tofu output nft_kms_define` (documented template
  in the verifier nftables).

### 20.2 Cost: the owner's limit is $15/month total
Prices fetched Oct 19, 2026 (AWS: kms, privatelink, vpc, secrets-manager, cloudtrail, eventbridge pages and
instances.vantage.sh; GCP: cloud.google.com/kms/pricing, /nat/pricing, Free Tier page). EBS, Lambda free tier, SSM
Parameter Store and GCP e2-micro / external-IP list prices were not re-fetched.

GCP signer, common to all: e2-micro on the Free Tier (us-east1/us-central1/us-west1) $0, 10 GB pd-standard $0
(30 GB free), Cloud KMS Ed25519 SOFTWARE 1 version $0.06 + ops < $0.01, Secret Manager ≤ 6 versions $0, Logging
< 50 GiB $0, Pub/Sub / Cloud Run functions / Scheduler within free tiers $0, NGFW FQDN egress ~$0.02.

| | **A. Recommended** | **B. Cheapest** | **C. Endpoint (over budget)** |
|---|---|---|---|
| GCP egress | Cloud NAT: $1.02 gateway + $3.65 IP + ~$0.05 | VM external IP, all ingress denied: $3.65 | Cloud NAT $4.72 |
| GCP signer subtotal | **$4.85** | **$3.73** | $4.85 |
| AWS instance | t4g.nano $3.07 + 8 GB gp3 $0.64 | t4g.nano $3.71 | t4g.nano $3.71 |
| AWS public IPv4 (EIP) | $3.65 | $3.65 | $3.65 |
| AWS KMS key + signs | $1.00 | $1.00 | $1.00 |
| KMS VPC endpoint | none (`aws:SourceIp` = EIP + `ec2:SourceInstanceARN`) | none | $7.30 |
| Secrets for ntfy / HC URLs | Secrets Manager 2 × $0.40 = $0.80 | SSM Parameter Store SecureString (standard, free) $0 (forwarder change needed, not built) | $0.80 |
| CloudTrail / EventBridge / Lambda / S3 | ~$0.01 | ~$0.01 | ~$0.01 |
| AWS verifier subtotal | **$9.17** | **$8.37** | $16.47 |
| **Total** | **$14.02** | **$12.10** | **$21.32 FLAG > $15** |

What each loses (compared with C, the most locked-down):
- **A**: KMS is reached over the public KMS endpoint, not a private one. Sign is pinned to the role, the instance
  ARN and the EIP. Rev 19 (R51-P3-2) correction: `ec2:SourceInstanceARN` does NOT stop stolen credentials. It is
  derived from the instance-role session, so role credentials copied off the instance still carry it. Only the
  `aws:SourceIp` = EIP pin (the `NotIpAddress` Deny) refuses a Sign made off the instance. Anyone who controls the
  instance (or that EIP) can sign, exactly as in C, and traffic to KMS crosses the internet (TLS). No endpoint
  policy layer. The EIP and the key are `prevent_destroy` (§21). Margin under $15 is $0.98: a second EIP, a larger
  disk or t4g.micro (+$3.06) breaks the budget, and sales tax (not in these list prices) may push $14.02 over $15.
- **B**: as A, plus: (1) the GCP signer VM has its own external IP instead of Cloud NAT. Ingress stays denied by
  the VPC firewall and nftables, and IAP remains the only admin path, but a firewall mistake now exposes the VM
  directly, and the reserved-IP alert/reconcile must pin the internal IP (unchanged) while egress leaves from the
  VM's own address. (2) URLs in SSM Parameter Store instead of Secrets Manager: no resource policies, no per-secret
  rotation; access still IAM-limited to the forwarder role and encrypted with the AWS-managed key.
- **C** keeps everything but costs $21.32. Not recommended within the $15 limit.
- Not fitting at all: t4g.micro instead of nano (A = $17.08), e2-small for the signer, an HSM key, Confidential VM.
- Free-tier caveat: the GCP e2-micro is free for one VM per billing account; AWS new-account credits are ignored
  here (they expire within 12 months).

## 21. Rev 19 (internal reviewer run 51)
Code review only, not an audit. R25-P2-1 stays open.

### 21.1 Launch items (R51-P3-1, R51-P3-2)
- **Verifier HTTPS allowlist** (budget mode has no VPC endpoint, so the verifier has to reach KMS by name):
  `deploy/verifier/egress-hosts.conf` lists kms.us-east-1.amazonaws.com, sts.us-east-1.amazonaws.com,
  sts.googleapis.com, iamcredentials.googleapis.com, logging.googleapis.com, ntfy.sh, hc-ping.com and the B2
  endpoint `s3.<b2-region>.backblazeb2.com`, which has to be filled in at install; the script refuses an unfilled
  placeholder. `mr-egress-refresh.sh` with its `.service` and a 30 min `.timer` resolves those hosts through the
  local resolver and adds their A/AAAA records to `@https_allowed4/6`, with a 2 h timeout. It never flushes the
  sets. It exits non-zero if a host doesn't resolve. `mr-verifier.service` and `mr-gcp-token.service` are ordered
  after it. In the verifier nftables, any other 443 traffic, from any uid, is dropped and logged as
  `mr-https-deny`. Caveat: AWS and Google front ends rotate addresses. A new address only becomes reachable at the
  next refresh, so a short burst of TLS failures can page as a reconcile ERROR. That fails closed.
- **AWS**: `ReleaseAddress` is added to the `mr-aws-admin` alert. `aws_eip.verifier` and `aws_kms_key.cosign`
  carry `lifecycle { prevent_destroy = true }`. §20.2 is corrected: `ec2:SourceInstanceARN` travels with stolen
  role credentials. Only the EIP pin refuses use off the instance, so the EIP must never be released or
  re-associated without an alert.

### 21.2 Held P3s and R50-P3-5
- WIF: the principal set gets `roles/iam.workloadIdentityUser` only. `serviceAccountTokenCreator` is dropped.
- The GCP actAs/token alert's exemption is now anchored:
  `^projects/-/serviceAccounts/mr-reconcile-reader@<project>\.iam\.gserviceaccount\.com$`. It no longer matches
  substrings such as `xmr-reconcile-reader@...`.
- Reconcile ack: `problemsHash(windowFrom, problems)`. The moving window end is no longer in the hash, so an ack
  built from `/v1/reconcile-status` stays valid while the window grows. Any new problem still changes the hash.
  `status()` now returns every problem plus `problemCount`, not just the first 50.
- `/v1/unlock` (R50-P3-5): behind IAP every caller has the IAP proxy's address, so the per-IP budget was really one
  shared bucket that anyone could exhaust to lock the owner out. The limit now counts only FAILED unlocks (refused
  signature or counter, bad JSON, oversize), from any source: 3 failures per 10 min locks unlock for the window.
  All attempts, whatever the outcome, are still capped globally at 6 per 10 min. A valid the owner-signed unlock never
  uses up the failure budget. Keying the limit on the request's signer would give the same single bucket, because
  there is one unlock key.
- Cost: the $14.02 total sits $0.98 under the $15 cap. Sales tax is not included and may push it over (§20.2).

### 21.3 Still open
- R50-P3-4 needs a Cloud Identity organization.
- Live gate 7 checks, still to run on real accounts: EventBridge delivery; the token timer and reconcile; KMS
  through the allowlist; a Sign from outside the EIP being refused; a real log entry showing the reserved IP and
  VPC; the quorum-2 rehearsal plus A6.

## 22. Rev 20 (internal reviewer run 52)
Code review only, not an audit. R25-P2-1 stays open.

- **R52-P2-1 (allowlist expiry)**: `nft add element` on an existing element does not reset its timeout, so every
  address used to expire 2 h after it was first added, leaving up to 30 min of blocked 443 every 2 h.
  `mr-egress-refresh.sh` now loads one `nft -f -` batch per run. For each family it does `add element`,
  `destroy element`, then `add element` with the de-duplicated addresses. The first `add` is needed because
  interval sets refuse to `destroy` a missing element; that was found while testing on nftables 1.1.3. The batch
  is one transaction: the addresses are never missing, their 2 h timeout restarts, and other elements are kept.
  A test checks the batch text. A live test in a private network namespace (sudo nft) shows a 5 s element reset
  to 2 h with an unrelated element kept.
- **R50-P3-5 (unlock lockout)**: `/v1/unlock` reads the body (64 KiB cap) and checks the Ed25519 signature
  against the pinned unlock key (`unlockPubkeyB64`, required on MainNet) before any rate accounting.
  - Anything not validly signed gets 403 and never reaches the helper. That covers junk, foreign keys, bad JSON
    and oversize bodies. These requests are capped globally (6 per 10 min, then 429).
  - Validly signed unlocks skip that cap and the junk count. They have their own cap (6 per 10 min) that only
    the holder of the owner's key can use, so junk POSTs cannot lock the owner out.
  - The helper still checks the body, counter, nonce and expiry. Its refusals are logged and paged as before.
  - Pre-filtered junk is not logged off-host, which keeps a flood from turning into a pager flood.
- **R52-P3-1**: `mr-egress-refresh.service` and `mr-gcp-token.service` have
  `OnFailure=mr-verifier-page@%n.service`, which posts the unit name to the verifier's ntfy topic as
  mr-verifier. If the allowlist itself is broken, ntfy may be unreachable; the Healthchecks dead-man is the
  backstop.
- **R52-P3-2**: the script runs under `set -euf` (no globbing of resolved or configured words) and also refuses
  `?` and `[`. The DNSSEC claim is withdrawn. The refresh trusts the local systemd-resolved stub, which does not
  enforce DNSSEC by default, and AWS and Google API names are not DNSSEC-signed in any case. A spoofed answer can
  add an address to the allowlist, but every connection is still TLS with system CA verification to the pinned
  host name, so it can't impersonate KMS, STS or Google. The cost is reachability: the verifier could reach a
  wrong address on 443.
- **R52-P3-3 (shared front-end IPs)**: the allowlist is by IP, and kms/sts.us-east-1.amazonaws.com and the
  *.googleapis.com names resolve to large shared front-end pools (CloudFront/AWS edge, Google Front End). Those
  same addresses serve many other AWS and Google services and customer endpoints, including attacker-controlled
  ones such as any googleapis.com or S3/API Gateway host behind the same front end. So the allowlist limits
  which networks the verifier can reach, not which services. A process running as mr-verifier could still
  exfiltrate through an allowed front end by sending a different SNI/Host. What actually binds the traffic is
  the app's pinned host names plus TLS verification, together with the uid match (only mr-verifier may use
  443). Closing this fully needs a TLS-aware (SNI-checking) egress proxy or the KMS VPC endpoint (option C,
  over budget). For the capped dry run this is accepted and documented; it is not fixed.
- Still open: R25-P2-1; R50-P3-4 (Cloud Identity org); the B2 region in `egress-hosts.conf`; the live gate 7
  checks.

## 23. Rev 21: fully automatic signing (CHANGE FROM DAVID, Oct 21, 2026)

Supersedes every human unlock, manual pause, YubiKey-presence and "the owner signs X" step in §9 and §13–§22.
The product is use-at-your-own-risk. Nothing here is applied to any ECS database or the MainNet stack. v16 is
written and tested on Postgres 18 only.

### 23.1 What changed
- **Removed:** `/v1/unlock`, `/v1/pause`, `/v1/helper-status`, `unlockPubkeyB64`, `src/piv/unlock.ts`, the unlock
  rate limiter (R49/R50/R52), `MrSigner.pause/unlock`, and `PolicyEngine.pause/unpause`. There is no owner override key,
  no FREEZE or UNFREEZE, no override CLI and no human kill switch. **No human-controlled runtime path can pause, unpause
  or change caps.** The signer HTTP API serves only `candidate`, `confirm`, `status`, `resume-candidate`,
  `resume-confirm` and `resume-apply`. The verifier also serves `resume-cosign`. A test asserts that every other route
  returns 404.
- **Config changes happen only by redeploy.** Each boot writes `config sha256 <hex>` into the B2 chain (`boot`
  event). The DB side is covered by `deploy/integrity-manifest.json` (schemaVersion 13) and the append-only
  `mr_config_audit`.
- **Rate pauses** (refusal bursts, and the 5/24 h and hourly caps) are `kind: "rate"`. Each has an `until` that is
  the oldest counted refusal + 1 h. They clear by themselves when the window rolls. Each clear is logged
  (`auto-resume-rate`) and paged.
- **Tamper / integrity pauses** cover audit-chain mismatch or rollback, manifest drift, disjointness or provider
  drift, an unexpected KMS Sign alert, and a dead pager. They are `kind: "tamper"`, logged as `pause-tamper` and
  paged. A tamper pause lifts only when **both** of these hold:
  1. **Cooldown:** `base * 2^(n-1)`, with n = the tamper count in the current 30-day period and the exponent capped
     at 6. The default base is 6 h, configurable (`tamperBaseCooldownS`). **MainNet refuses a base below 6 h** in
     both the signer and the verifier config, and DB v16 enforces the same with a CHECK. The count is **persisted in
     the DB** (`mr_pause_state.tamper_count`) and locally. A resume never lowers it. It resets to 1 only when the
     previous pause was more than 30 days earlier.
  2. **A fresh 2-of-2 quorum.** The signer re-runs its own checks (clock, rollback, and a re-read of the B2 head
     with `checkHead()`). It then gets its key (via the helper) to sign `MR-RESUME-ATTEST-v1`, which binds the
     network, genesis, keyId, DB pause_seq and tamper_count, the chain seq and head, a nonce, and issuedAt/expiry.
     mr-verifier re-checks the chain itself (`verifyChainHead`: that seq holds exactly that head and links back) and
     confirms there is no open reconcile mismatch. It then signs `MR-RESUME-COSIGN-v1` over the attestation hash.
     DB v16 `mr_tamper_resume` checks:
     - the cooldown;
     - both keys pinned, in different trust domains (the v12 separation);
     - the attestHash binding;
     - the current pause_seq and tamper_count;
     - that the chain heads match;
     - issuedAt within ±60 s and expiry ≤ 15 min;
     - single-use nonces (`mr_resume_nonce`).
     Only then does the signer accept the co-signature, checked against the pinned `cosignerPubkeyB64` (required on
     MainNet, and it must differ from the attestation key).
- **Every resume bumps the helper's state counter** and writes the new value into the chain, so the counter anchor
  is kept. Every pause and every automatic resume goes to the B2 chain and to ntfy.
- **The helper's hard lock is now an automatic long lock** of `6 h * 2^(n-1)`, which clears by itself (rehearsal A6
  was rewritten for this).
- **DB-enforced caps (v16 `mr_release_caps`)** are now **the only loss bound**. Every release goes through the 8-arg
  wrapper, which refuses while the DB is paused and enforces the per-release cap and the rolling 24 h sum. MainNet is
  seeded at 0.01 USDC per release and 0.05 USDC per rolling 24 h, matching the signer caps. TestNet is seeded at
  10 / 50 USDC. The caps can change only by migration (redeploy), and any change is recorded in `mr_config_audit`.
- `autoResumeOnce` (`packages/signer/src/cli/resume.ts`) is the driver. It is meant to run from a timer on the signer VM; that systemd timer is not written yet (open item). It returns
  `running | rate-paused | waiting | resumed`. A failed step leaves the pause in place.

### 23.2 Tradeoff (stated plainly)
An attacker who gets access (to the VM, the KMS key, or the requester key) can **wait out a pause**. Nothing a human
does is required, or able, to stop the next resume once the cooldown has passed and both sides' checks are clean.
The backoff only slows repeated tamper events (6 h, 12 h, 24 h, ... up to 16 days). **The per-release and daily caps
in the DB are therefore the real loss bound**: at most 0.05 USDC per rolling 24 h on MainNet, even with both keys
compromised. That bound holds only as long as the DB owner role itself is not compromised.

### 23.3 GCP project without an organization
The GCP project belongs to an individual Google account and has no Cloud Identity / Workspace organization. That
means no org policies, folders or org-level IAM deny. Project-level controls are used instead:
- No service-account key creation. Use the project-level `iam.disableServiceAccountKeyCreation` constraint where the
  project can set it. Where it can't, use IAM: no principal holds `iam.serviceAccountKeys.create`. A log alert on
  SA key creation is still to be added to deploy/gcp/alerts (open item).
- Restricted IAM: the owner binding is the human account only; the VM SA has `cloudkms.signerVerifier` on the one key
  version and nothing else; no primitive Editor roles; no `iam.serviceAccountTokenCreator` on the signer SA.
- Data Access audit logs are on for Cloud KMS and IAM. The unexpected-KMS-Sign alert (§20) depends on them.
- This is configured by hand on the console or with gcloud, outside the repo. It must be checked before any MainNet
  use (open item).

### 23.4 Not unstoppable
The system runs on the owner's GCP and AWS accounts, its DB on his host, and B2 and ntfy accounts. the owner or any of those
providers can shut it down (by suspending the account, deleting the project or revoking a key), so it is not
literally unstoppable. **Public copy must not use the words "permissionless" or "unstoppable".** Describe it as
"automatic, with DB-enforced spending caps".

### 23.5 R53 P3s
- P3-1 (unlock freshness) is moot: unlock is gone. The only remaining signed control messages are the resume
  attestation and co-signature. Both carry issuedAt (±60 s), expiry (≤ 15 min), a single-use nonce (checked by the
  helper, the verifier and the DB), the pause_seq and the chain head.
- P3-2: the server.ts comment now says the 429 comes after the body is read.
- P3-3: `mr-verifier-page@.service` builds the ntfy URL with the shell builtin `printf` (`$$`-escaped so systemd does
  not expand it) and pipes it into `curl -K -`. The topic is in no process's argv. There is a host-config test for this.

### 23.6 Run 62 fixes (rev 22)
- **R62-P2-1:** the guard no longer trusts a session setting. `mr_tamper_pause` and `mr_tamper_resume` are owned by
  the NOLOGIN role `mr_pause_writer` (deploy/sql/t11). Nobody is a member of it, and it has no login, no inherit and
  connection limit 0. The guard allows writes to pause state, `mr_pause_log` and `mr_resume_nonce` only when
  `current_user = mr_pause_writer`, which is true only inside those two functions. The table owner's session can
  neither `SET ROLE` to it nor `CREATE OR REPLACE` the functions. A regression test reproduces the old
  `SET LOCAL mr.v16_fn = 'on'` unpause and shows it is now refused. The guard also refuses a pause_seq that goes down
  or a tamper_count changed without a new pause.
  - **Monitor alerts** (`pauseReasons`):
    - an unpause without exactly 2 `mr_resume_nonce` rows for that pause_seq;
    - a pause_seq below the highest seq in `mr_pause_log` or `mr_resume_nonce`;
    - a tamper_count that differs from the logged or signed one;
    - a pause_seq with no log row.
  - The v16 guard triggers are in `EXPECTED_MR_TRIGGERS`, so a trigger left disabled pages (`tgenabled`). **Correction
    (R64-P2-1):** `tgenabled` only catches a trigger that is *still* disabled when the monitor runs. `DISABLE TRIGGER`,
    write, `ENABLE TRIGGER` in one transaction leaves no trace there. So the protection is ownership plus the event
    trigger, not the page (below and §24.6).
  - Limit: a superuser can still edit rows (`session_replication_role`, or the t11 window). For pause/resume rows the
    signature re-verification pages it; for caps the manifest comparison does; an audit wipe by a superuser is not
    detected.
- **R62-MIG-1:** r51's v13 is now **v16** "automatic-resume-and-db-caps", after getblock v13–v15. v16 renames the
  v15-patched 8-arg body to `mr_spend_release_attested_v12` and wraps it. The SQL objects are now `mr_v16_*`. The t11
  grants and the manifest (schemaVersion 16) are updated. No box dev DB had r51 v13. Nothing was applied to ECS.
- **R62-P3-1:** `mr_spend_release_attested` refuses anything other than READ COMMITTED. Under REPEATABLE READ or
  SERIALIZABLE, the rolling 24 h sum could miss a concurrent release.
- **R62-P3-2:** co-signing a resume no longer lifts the verifier's own pause. The verifier lifts it in
  `resumeObserved` (`/v1/resume-observed`), only after the signer's off-host chain, past the attested head, holds
  `auto-resume-tamper` for exactly the attestation hash it co-signed. The signer writes that event only after the
  DB's `mr_tamper_resume` and its co-signature check succeed. A pending marker expires after 15 min.
- **R62-P3-3:** deploy/gcp/README.md no longer describes the unlock.
- **R62-P3-4:** storage tsc is green.
- **R62-P3-5:** r51 was rebuilt on getblock-provider (6b82ff7) as small commits that each pass tsc.

## 24. Rev 22: mr-verifier on Alibaba Cloud (CHANGE FROM DAVID, Oct 21, 2026)

The signer stays on Google Cloud, and the co-signer moves from AWS to Alibaba Cloud. **Nothing was created or bought,
and the existing ECS was not changed** (only read-only metadata was read). deploy/aliyun is written and validated, not
applied.

### 24.1 Facts
- The existing ECS (8.221.97.26) is in **US (Virginia), us-east-1**, zone us-east-1a. It is an ecs.c9i.large
  (2 vCPU, 3.5 GiB) with no RAM role attached. It runs the TestNet stack and the stopped MainNet stack.
- **KMS Ed25519.** The KMS key-spec page lists **Ed25519 (EdDSA, sign only) for software-protected keys**. Hardware
  keys support only RSA, EC_P256 and EC_P256K. The create-key and instance-selection pages still list only RSA and EC,
  so the docs disagree; check in the console before relying on it.
  - https://www.alibabacloud.com/help/en/kms/key-management-service/user-guide/key-types-and-specifications
  - https://www.alibabacloud.com/help/en/kms/key-management-service/user-guide/manage-keys-2
  - https://www.alibabacloud.com/help/en/kms/key-management-service/product-overview/service-selection
- **Any asymmetric key, and any app-side encrypt/decrypt, needs a paid KMS instance.** Default keys are free but only
  for server-side encryption by Alibaba services. A software KMS instance costs **USD 500/month** (subscription), or
  pay-as-you-go **USD 4.50/day for the instance + USD 0.03/day per key version + USD 0.50/day per QPS**, about
  USD 150/month.
  - https://www.alibabacloud.com/help/en/kms/key-management-service/product-overview/kms-billing
  - https://www.alibabacloud.com/help/en/kms/key-management-service/pay-as-you-go
- **Pinning.**
  - An ECS instance RAM role gives keyless credentials from the metadata service:
    https://www.alibabacloud.com/help/en/kms/key-management-service/use-cases/access-kms-from-an-ecs-instance-in-a-secure-manner
  - KMS supports `acs:SourceIp` and `acs:SourceVpc` in RAM policies and key policies. `acs:SourceVpc` is supported in
    US (Virginia) and is present only on VPC-endpoint requests:
    https://www.alibabacloud.com/help/en/kms/key-management-service/security-and-compliance/condition-key
- **Audit.** ActionTrail records KMS `AsymmetricSign` events. A trail can deliver them to SLS, where an alert rule can
  send a webhook. ActionTrail itself is free; SLS storage and writes are billed.
  - https://www.alibabacloud.com/help/en/actiontrail/product-overview/audit-events-of-kms
  - https://www.alibabacloud.com/help/en/actiontrail/user-guide/enable-and-configure-alerts
  - https://www.alibabacloud.com/help/en/actiontrail/product-overview/billing-1
  - Caveat: calls through a KMS instance's dedicated (instance) endpoint are logged by the instance's own log
    analysis, which costs extra. Use the OpenAPI VPC endpoint `kms-vpc.us-east-1.aliyuncs.com` so every Sign is an
    ActionTrail event.

### 24.2 Key options (security vs cost)
| Option | Security | Monthly cost | DB / code change |
| --- | --- | --- | --- |
| A. Alibaba KMS software key, Ed25519 | Non-exportable key, every Sign in ActionTrail, pinned to the VPC + EIP | ~USD 150 (PAYG) or 500 | None: v12/v16 verify Ed25519. Needs an `aliyunkms` backend in the verifier (MainNet currently allows only awskms/yubikey) |
| B. Alibaba KMS EC_P256 / P256K | Same as A | Same as A | DB must verify ECDSA (a P-256 verify in mr_crypto plus an alg column), new message signing path. No gain over A if Ed25519 works |
| C. Alibaba host + keep the AWS KMS Ed25519 key | Non-exportable key, CloudTrail per Sign. The Alibaba host needs an AWS credential: IAM Roles Anywhere (an X.509 cert on the host) or an access key (bad) | ~USD 1 (AWS key) | Small: AwsKmsBackend already exists; credential source changes. The key's trust domain stays AWS, not Alibaba |
| D. KMS-wrapped software key on Alibaba | Not possible cheaply: wrapping also needs a KMS instance (same price as A, weaker than A) | ~USD 150 | — |
| E. Plain software Ed25519 key on the dedicated instance | Weakest: the key can be copied from the host, no per-Sign cloud audit. Bounded by 2-of-2 + DB caps (0.05 USDC/day MainNet) | 0 | Verifier MainNet guard would have to allow it (not done) |

**Recommendation:**
- For MainNet, use **A** if the owner approves the KMS instance. It is the only option that keeps a non-exportable key in
  the Alibaba trust domain.
- Within the $15/mo budget, use **C**. It is cheap, the key stays non-exportable and logged, and the verifier host is
  on Alibaba, but the key's trust domain is still AWS.
- **E** is acceptable only for TestNet.
- **B** is not worth the DB change.

**R63-P3d, option A is unproven.** Nobody has checked yet that Alibaba KMS signs a *raw* Ed25519 message:
`AsymmetricSign` with `MessageType=RAW` and pure Ed25519 (RFC 8032, not a pre-hashed digest), producing 64-byte
signatures that mr_crypto / v12 / v16 verify byte for byte. Before any purchase of a KMS instance (subscription), run
a **1-day pay-as-you-go test**: create the instance and key, sign a fixed vector, check it with
`verifyAttestation`, then release the instance the same day. the owner must approve it first, since it is a new paid
resource above $15/mo even for one day. If the test fails, A is off the table: choose C, or B with the DB change.

### 24.3 Isolation: a separate instance
The verifier must **not** run on the app ECS. That host runs the public app stack, the DB and the MainNet stack. A
compromise of any of those would also give the co-signer key's RAM role (one role per instance, shared metadata
service), and the 2-of-2 would collapse to "app host + signer". deploy/aliyun creates its own VPC, security group
(WireGuard only), instance, RAM role and EIP. The two hosts share only the Alibaba account, so the account is the
remaining shared trust root: use a RAM user with MFA for admin, keep the root account unused, and have the admin alerts
in §24.4 page.

### 24.4 Alerts outside Alibaba
ActionTrail (read + write events) feeds SLS, and SLS alerts send webhooks to **ntfy.sh** and **Healthchecks**, both
outside Alibaba:
- every `AsymmetricSign`;
- KMS, RAM, ECS role/metadata, Cloud Assistant (RunCommand/InvokeCommand), EIP, security group, trail, SLS and alert
  changes;
- a daily heartbeat to Healthchecks (grace 2 h), so a stopped trail or alert pages.

The URLs are capabilities: they exist only as `TF_VAR_*` and in encrypted state (OpenTofu state/plan encryption,
enforced). Still open:
- the verifier reconciling each AsymmetricSign against its own chain, as it does for GCP (code not written);
- GCP log reads from Alibaba need X.509 workload identity federation, because GCP has no Alibaba RAM provider.

### 24.5 Prices (US Virginia, on demand; to confirm in the console)
| Item | USD / month |
| --- | --- |
| GCP (signer) subtotal | 4.85 |
| ecs.t6-c2m1.large (2 vCPU burstable, 1 GiB), USD 0.009/h | 6.57 |
| (or ecs.t6-c4m1.large, 0.5 GiB, USD 0.005/h) | (3.65) |
| 20 GiB ESSD Entry system disk | ~1 (estimate) |
| EIP, pay-by-traffic (holding fee + <1 GB) | ~1–4 (estimate, confirm) |
| ActionTrail (free) + SLS storage/writes | <0.50 |
| **Total without KMS (option C adds ~USD 1 at AWS)** | **~13.9–17** (t6-c2m1) / **~11–14** (t6-c4m1) |
| KMS software instance (option A) | +150 PAYG / +500 subscription |

Instance prices are Spare Cores' Alibaba on-demand data for us-east-1 (keeper.sparecores.net). **Any of these needs
the owner's approval:** the instance is a new paid resource, the total is at or over the $15/mo line, and option A is
about 10× the budget.

### 24.6 Rev 23 (run 63) status
- R63-P2-1: `mr_pause_writer` owns the pause tables and the guard/parse/cooldown/jcs functions. Event triggers
  `mr_v16_ddl_guard` / `mr_v16_ddl_guard_drop` refuse DDL on them unless the session is superuser with
  `mr.ddl_window='open'`. `mr_resume_nonce` stores key_id+msg+sig, and the monitor re-verifies every resume pair, so a
  forged superuser row pages. It also pages if an event trigger is disabled or ownership drifts.
- R64-P2-1 (rev 23.1): the run-63 note "paged via `tgenabled`" was wrong, because a one-transaction DISABLE / UPDATE /
  ENABLE leaves `tgenabled = O`. Now `mr_release_caps`, `mr_config_audit`, `mr_release_cosign`, the caps-enforcing
  8-arg `mr_spend_release_attested`, `_v12` and the audit helper `mr_v16_audit` are also owned by `mr_pause_writer`
  and covered by the event-trigger pattern. So the app owner gets "must be owner" and a superuser without the window
  gets `mr_v16_ddl_guard ... refused` (regression probe for both). Caps values are pinned in
  `deploy/integrity-manifest.json` (`releaseCaps`) and compared by the monitor. `mr_release_caps_mainnet_max` CHECKs
  MainNet at <= 0.01 USDC per release and 0.05 per 24 h. A caps change is a superuser migration run as
  `SET ROLE mr_pause_writer` plus a manifest update. (Superseded by rev 23.2 below: `mr_v16_audit` now only works
  from inside the guard trigger, and superuser wipes are caught by the anchor.)
- R63-P2-2: verifier tamper pauses are mirrored into the DB (`mr_tamper_pause`, reason `verifier: ...`) if the
  verifier has no pending resume marker or the marker is older than 15 min. `resumeObserved` is retried on every tick
  and no longer expires (`/v1/status`).
- R63-P3: deploy/aliyun alert names (ScheduleKeyDeletion plus instance/keystore/version/rotation events), heartbeat
  `n > 0`, `acs:VpcSourceIp` instance /32 (verify live). Per-platform verifier egress via
  `deploy/verifier/render-platform.sh aws|aliyun|aliyun-aws-kms`.
- Rev 23.2 (run 65):
  - **R65-P2-1:** the rolling-24 h cap no longer counts `mr_release_nonce` (an app-owner table). The wrapper keeps its
    own append-only ledger `mr_release_ledger`, owned by `mr_pause_writer`. Each counted release adds a row (store,
    spend, network, amount, at) before `_v12` runs, and a refused release rolls it back. A trigger on
    `mr_release_nonce` (`mr_v16_nonce_ledger`) refuses a nonce row with no ledger row. So a `_v11` granted to
    `mr_release` by the owner can't release anything. The DDL guard now also covers `mr_release_nonce`, `_v11`,
    `mr_signer_tables_guard`, the ledger and its trigger, so the owner's DISABLE TRIGGER / TRUNCATE / ENABLE is
    refused. The monitor cross-checks the ledger and pages on any of these:
    - a nonce with no ledger row;
    - a released, ledgered spend with no nonce;
    - a 24 h ledger sum above the cap;
    - a 24 h nonce sum above the ledger's.

    Choice: the ledger, instead of re-owning `_v11` and `mr_release_nonce`. `_v11` writes `mr_spend`, `mr_spend_audit`
    and the nonce table under app-owner guards, so re-owning them would have spread `mr_pause_writer` rights over
    the whole spend path. Known side effect: a counted release that `_v12` returns as `ok = false` (not raised) stays
    counted, which is conservative. (Fixed in rev 23.3: the row is rolled back.)
  - **R65-P3-3:** the 6-arg TestNet entry was owned by the app owner, which on a host (non-superuser) has no EXECUTE
    on the writer-owned 8-arg wrapper, so it failed with permission denied. Tests ran as a superuser and missed it.
    It is now owned by `mr_pause_writer` (test: it reaches the wrapper's quorum check).
  - **R65-P3-1:** `mr_v16_audit` refuses unless `pg_trigger_depth() > 0`, for `mr_pause_state` / `mr_release_caps`
    INSERT/UPDATE only. Residual: an owner-created trigger could still call it, so this is a narrower door, not a
    closed one.
  - **R65-P3-2:**
    - a verifier anomaly after a co-signed resume supersedes it: a new pause, later than the marker.
    - the resume driver mirrors a verifier pause newer than the marker at once.
    - the "observation stuck" page needs an unpaused DB and carries the verifier's reason.
    - `resumeObserved` no longer lifts a newer pause on an older resume: it clears the marker, keeps the pause and
      pages.
  - **R65-P3-4:** every monitor tick anchors `mr_config_audit`, `mr_pause_log`, `mr_resume_nonce` and
    `mr_release_nonce` to an off-host chain. For each table it records the count, the max seq, a hash of all rows,
    and the count + hash of rows older than 10 min. The chain is B2 Object Lock (`MONITOR_ANCHOR_B2_*`, the same sink
    as the signer's; TestNet may use `MONITOR_ANCHOR_FILE`). The next tick re-hashes the old prefix. Fewer rows, a
    lower seq or a changed old row pages, and the bad state is not anchored over, so the page repeats. MainNet
    without the anchor configured pages. Pin `MONITOR_ANCHOR_MIN_SEQ` after install, as with the signer chain. Needs
    a B2 bucket and key for the monitor (not created: no purchase). Limit: a superuser who also controls the B2 key
    could still hide it; the bucket key should be write + list + read only.
- Rev 23.3 (run 66, all P3s; no P0-P2 were found):
  - **R66-P3-4:** v16 is now frozen. A test pins the sha256 of `v16Sql()`. Earlier review rounds had edited v16 in
    place, so **v17** (`v16-converge-and-ledger-backfill`) converges a database that applied any reviewed v16 text.
    It adds the R63 nonce columns, the MainNet caps CHECK, the ledger and its index, and the reviewed guard and wrapper
    bodies. It also backfills one ledger row per existing `mr_release_nonce` row and re-creates every guard trigger. A
    pre-R62 v16 is refused with a "rebuild" error. The ledger refuses UPDATE, DELETE and TRUNCATE (test). On a
    database where t11 has run, v17 must be applied by a superuser inside the deploy window, followed by a t11 re-run.
    It has not been applied anywhere, including ECS.
  - **R66-P3-1:**
    - The app owner has no EXECUTE on `mr_v16_audit`, no UPDATE on `mr_pause_state` and no TEMPORARY on the database.
    - The cooldown base changes only through `mr_set_tamper_cooldown_base(seconds)`. That function is owned by
      `mr_pause_writer` and only the owner can EXECUTE it. The change must be the only one in the row, is refused
      while paused, and is audited.
    - A direct UPDATE by anyone except the table owner (`mr_pause_writer`) is refused, superusers included.
  - **R66-P3-2:** the verifier re-reads its state after every await (clock, probes, chain check, observation) and
    writes with a compare-and-set on the counter. A supersede clears `pendingResume` and does not increment
    `tamperCount` a second time.
  - **R66-P3-3:** anchor lines are signed by a key that is not on the DB host. On MainNet this is a Cloud KMS
    `EC_SIGN_ED25519` version (`MONITOR_ANCHOR_KMS_KEY`, metadata token, sign-only); TestNet may use a software key.
    - Each signature covers `MR-ANCHOR-SIG-v1`, the network, the seq and the line hash, so a signed line can't be
      replayed at another seq.
    - The head and head-1 are both verified, and head-1 → head must not regress.
    - The prefix, minimum seq, retention floor (>= 365 d) and anchor pubkey are pinned in the manifest (`anchor`).
    - MainNet refuses to anchor unsigned and pages until the key exists and its pubkey is pinned. The key has not
      been created (no purchase).
    - **R67-P3-2 (key binding):** the B2 sink's `last()` and `at(seq)` require the object key to be
      `seqKey(prefix, line.seq)`. A genuine old line replayed under a key that sorts first (a partial rollback) or a
      junk object now refuses with `SinkBindingError` and pages `anchor: head key … does not match its line's seq`.
      **Repair path (documented, not automatic):** Object Lock keeps a planted object for the retention period, so the
      chain would stay wedged. After an operator confirms the object is planted or junk (and an internal reviewer run), its
      exact key is added to the sink config (superseded by R69-P3-1 below).
    - **R69-P3-1 (manifest-pinned skips):** `skipMisboundKeys` is gone. Skips are `(key, sha256 of the stored
      object bytes)` entries in the sha256-pinned integrity manifest (`anchor.<network>.skip`, default `[]`), so a
      change needs a manifest regeneration + `INTEGRITY_MANIFEST_SHA256` bump and an internal reviewer run. `last()` steps
      past a listed object only if it is bad: misbound, OR bound but failing parse / signature
      (`anchorLineAcceptable`). A listed object that is valid is returned (no rollback through the list); a
      pre-listed future key can't match unknown bytes. The monitor (spend-cli) passes the list, and pages
      `anchor: skipped manifest-pinned bad object <key>` on every tick a skip happens. `minSeq` stays pinned.
    - **R70-P3-1 (step over, signatures required):** a pinned junk object at `seqKey(head+1)` no longer stalls
      the chain for the retention period. The pinned skip keys map back to seqs (`anchorSkipSeqs`); append writes
      the next free seq above them with `prev` = the current head's hash, and the head-1 check steps down over pinned
      seqs to the line that `head.prev` links to (a pinned seq that holds the genuine predecessor still links
      normally; an unpinned gap is still refused). The manifest pin gains `requireSigned` (MainNet must be `true`,
      checked when the manifest is parsed): with it, `anchorLineAcceptable` refuses merely self-hashed lines and
      `anchorHead`/`anchorTick` refuse to run without a pinned pubkey and signer. MainNet fails closed even if the
      flag were false. TestNet stays `false` until its anchor key exists.
  - **Optional items (both done):**
    - A release that `_v12` returns as `ok = false` now leaves no ledger row (the rollback goes to a savepoint; the
      ledger is never deleted from). This replaces the "stays counted" side effect noted for R65.
    - The DDL guard refuses GRANT on protected objects, and any schema-wide GRANT, outside the window.

### 24.7 Option C chosen as the fallback (Oct 21, 2026): Alibaba host, AWS KMS key through IAM Roles Anywhere
**Alibaba KMS Ed25519 test (one day, TestNet only, instance released the same day; full results in the test
report):**
- `CreateKey --KeySpec Ed25519` returned **InternalFailure (HTTP 500) on all 6 attempts**, so the raw-Ed25519
  check could not be run. An EC_P256 control key in the same instance was created without problems.
- Ed25519 exists only as a SOFTWARE key, and only through the instance-API `Sign` (ClientKey auth, not RAM).
- `acs:SourceVpc` Deny was **not enforced**. `acs:SourceIp` Deny (the VpcSourceIp pattern) was enforced.
- The Alibaba **root** account could `SetKeyPolicy` from outside the VPC even with the Deny in place.
- Conclusion: option A is off the table for now.

**What option C is (deploy/aws-rolesanywhere + deploy/aliyun with `kms_instance_id = ""`; NOT APPLIED, no paid
resource created):**
1. **Roles Anywhere scope:**
   - The trust anchor is a single-purpose CA, made offline. It signs exactly one certificate (the verifier ECS's,
     CN `mr-verifier-aliyun-1`), and then its key is destroyed.
   - The role trusts only `rolesanywhere.amazonaws.com` via that anchor (`aws:SourceArn`), for that subject and
     issuer CN.
   - Profile sessions last 900 s (the minimum). The session policy allows only Sign and GetPublicKey on the key,
     from the EIP.
   - On the host, `aws_signing_helper serve` (deploy/verifier/mr-aws-rolesanywhere.service) serves the session on
     127.0.0.1:9911. `AwsKmsBackend` uses `credentialSource: "rolesanywhere-serve"`. No access keys exist.
2. **Key policy:**
   - `kms:Sign` is allowed only for that role and only on that key.
   - The `aws:SourceIp` condition is the Alibaba EIP /32.
   - Explicit Denies refuse Sign from any other IP, any other principal, or a session without the host-cert CN tag.
   - The admin role (MFA) can manage the key but not sign.
> **Superseded (rev 25, Oct 22, 2026, R75-P2-1):** AWS is not the verifier. The only active MainNet co-signer is `aliyun-softkey`; the AWS KMS key (`alias/mandaterail-verifier`) and the GCP key are locked backups that the loaders refuse (see docs/ops/kms-key-order.md). (rev 26: the GCP key is now the active MainNet signer; AWS stays a locked backup.)

3. **Providers:** `platform: "aliyun-aws-kms"` makes the verifier refuse to start unless it uses awskms through Roles
   Anywhere. On MainNet its providers must be dRPC only, with no operator shared with the signer. The verifier egress
   allowlist no longer lists GetBlock or Blockdaemon, on any platform.
4. **Residuals (must stay in the docs):**
   - **Root accounts on both clouds can rewrite policies.** The key-policy Deny does not bind root. This was seen
     live on Alibaba (root `SetKeyPolicy` from outside the VPC). On AWS, root can regain control of a key whose policy
     excludes it, through account recovery or AWS Support. The AWS and Alibaba root logins are therefore trust roots.
     Keep them unused with hardware MFA. Every policy change pages (CloudTrail / ActionTrail → ntfy).
   - **The clouds are not fully independent.** The verifier host is on Alibaba but signs through AWS. Anyone who
     holds the AWS account (or the host certificate's key while it is still on the EIP) holds the co-signing key's
     use. The 2-of-2 is "Google signer + AWS key used from an Alibaba host", not three independent clouds.
   - Any process on the verifier host can query the loopback credential endpoint. The EIP condition still applies.
   - To verify live before MainNet: Roles Anywhere session tags (`x509Subject/CN`) are visible in the KMS request
     context; `aws_signing_helper serve` returns the role under the pinned role name; there is no extra Roles
     Anywhere charge.
   - Software protection does not apply here: the AWS KMS key is HSM-backed. Option A's software-only residual goes
     away with C.
5. **Monthly cost estimate (USD, us-east-1 / Alibaba US Virginia, list prices to confirm):**

| Item | USD / month |
| --- | --- |
| GCP signer (unchanged) | 4.85 |
| Alibaba ECS t6-c2m1.large (or t6-c4m1.large) | 6.57 (3.65) |
| Alibaba 20 GiB ESSD Entry disk + EIP (pay-by-traffic) + SLS | ~2.5–5 |
| AWS KMS key (1) + Sign calls | 1.00 + <0.01 |
| AWS IAM Roles Anywhere (no Private CA: own offline CA) | 0 (AWS lists no charge; confirm) |
| AWS CloudTrail first trail + S3 Object Lock bucket | ~0.01 |
| AWS Secrets Manager (2 alert URLs) + Lambda forwarder | 0.80 + 0 |
| **Total (t6-c2m1)** | **~15.7–18.2** |
| **Total (t6-c4m1)** | **~12.8–15.3** |

    The t6-c4m1 size stays at about the $15/mo line. The t6-c2m1 size is over it. Either way the instance is a new
    paid resource and needs the owner's approval. Nothing has been applied.

### 24.8 Rev 24: software key file on the Alibaba host (CHANGE FROM DAVID, Oct 21, 2026)

**Correction.** Earlier text in §24.7, in deploy/aws-rolesanywhere and in status messages called it "the existing AWS
KMS key". That was wrong. **No AWS account exists and no AWS KMS key was ever created.** Option C was code and tofu
only. the owner also wants no card signups or new paid tools, so he dropped option C on Oct 21. deploy/aws-rolesanywhere,
mr-aws-rolesanywhere.service and the `aliyun-aws-kms` render stay in the tree, marked **UNUSED / OPTIONAL**. Nothing
there is applied.

**Design (platform `aliyun-softkey`; NOT APPLIED, nothing created):**
1. **Generated on the host.** `mr-verifier-keygen.service` runs at every boot, with `PrivateNetwork=yes`. On first
   boot `mr-verifier-keygen.sh` uses `openssl genpkey -algorithm ed25519` to write
   `/var/lib/mr-verifier-key/cosign.key`: PKCS#8 PEM, mode 0600, **owned by root:root** in a root 0700 directory
   (R67-P3-5: `mr-gcp-token` and `mr-verifier-page@` also run as `mr-verifier`, so a `mr-verifier`-owned key was
   readable by them; LoadCredential reads the file as root). The script never overwrites an existing key, never
   prints or copies the private key, and re-exports `cosign.pub` if a crash left it missing (R67 nit).
   **Fail closed (R67-P3-6):** every run, and `ExecStartPre=+… --check` in the verifier drop-in, refuses (and pages via
   `OnFailure=`) unless the directory is a real root 0700 directory and the key a regular, non-symlink, single-link
   root 0600 file. Every other `mr-verifier`-uid unit (`mr-gcp-token`, `mr-verifier-page@`, `mr-aws-rolesanywhere`)
   sets `InaccessiblePaths=-/var/lib/mr-verifier-key`.
2. **Pubkey export.** `cosign.pub` holds the base64 of the raw 32-byte public key (`cosignerPubkeyB64`). It is also
   printed to the journal so it can be pinned in the DB (v12 cosigner key) and in config.json.
3. **Delivery.** The drop-in `mr-verifier.service.d/softkey.conf` sets
   `LoadCredential=cosign.key:/var/lib/mr-verifier-key/cosign.key`, so systemd exposes the key read-only at
   `$CREDENTIALS_DIRECTORY/cosign.key`. `InaccessiblePaths=` hides the key directory from the verifier process.
   config.json has `"platform": "aliyun-softkey", "softkey": {}` and no path.
4. **Backend** (`SoftkeyFileEd25519Backend`, packages/signer/src/piv/softkey-file.ts). It reads only the credential.
   The derived public key must equal `cosignerPubkeyB64`, or the verifier refuses to start. Every sign() decodes the
   message (attestation, co-sign or resume) and requires the backend's own network and genesis pin. Error messages
   never contain key bytes.
5. **MainNet gate.** The verifier refuses MainNet in softkey mode unless **both** of these hold:
   (a) the integrity manifest says `verifierSoftkey.mainnet = true`. The manifest is sha256-pinned in code, so flipping
   this needs a manifest change, a new `INTEGRITY_MANIFEST_SHA256` and an internal reviewer run, never a host edit.
   (b) the host config sets `softkey.allowMainnet: true`.
   The manifest now pins `mainnet: false, testnet: true` (manifest sha256 `86fec581…` after R73-P3-4; `b298370d…` after R71-P3-2; `ee222b67…` after R70-P3-2; `91dfcdd4…` after R70-P3-1; `17b2700e…` after R69-P3-2; `05581486…` after R69-P3-1; `a1b0a02e…` after R67-P3-1; `aa9603da…` at rev 24). The SecondVerifier MainNet
   check accepts a softkey backend only if its gate passed for mainnet.
6. **Egress.** The `aliyun-softkey` render adds no key-service host, so the allowlist is the common set: dRPC as the
   only MainNet chain provider (disjoint from the signer's nodely and getblock), plus ntfy, Healthchecks, B2 and the GCP
   log read. It has no AWS and no Alibaba KMS endpoint, and `KMS_VPCE` matches nothing. The nft add/destroy/add batch
   refresh is unchanged. `assertPlatformConfig` enforces dRPC-only on MainNet and refuses awskms or ykcs11 alongside
   softkey.
7. **Caps unchanged.** 0.01 USDC per release and 0.05 USDC per day on MainNet (DB CHECK + manifest `releaseCaps`).

**Residuals (recorded):**
- **Host compromise exposes the key.** Root on the verifier host, or an exploit that reads the credential, can co-sign
  anything the attacker can also get the primary signer to sign. Losses are bounded by the DB caps (0.01 per release /
  0.05 per day) and by the tamper pause plus cooldown. This is weaker than v12's original goal of two non-exportable
  keys.
- **No hardware protection.** The key is a plain file. There is no HSM, KMS or TPM sealing (Alibaba KMS cannot create
  Ed25519 keys, §24.7). Disk snapshots contain it (the system disk is encrypted with the account's key, so anyone with
  snapshot access in the Alibaba account can read it).
- **Root on Alibaba.** The Alibaba root account (and any RAM admin) can reach the instance through Cloud Assistant,
  snapshots or a console reset, and so can read the key. The ActionTrail alerts (§24.4) page on these, but they cannot
  prevent them.
- **Not literally unstoppable.** The system runs on the owner's GCP and Alibaba accounts (§23).
- MainNet stays refused in this mode until the manifest flag is flipped under a separate internal reviewer run.

**Cost (Alibaba instance only; US Virginia list prices, to confirm in the console):**
| Item | USD / month |
| --- | --- |
| ecs.t6-c2m1.large (2 vCPU burstable, 1 GiB), USD 0.009/h | 6.57 |
| 20 GiB ESSD Entry system disk | ~1 |
| EIP, pay-by-traffic | ~1–4 |
| ActionTrail (free) + SLS | <0.50 |
| KMS | 0 (no KMS instance) |
| AWS | 0 (no account) |
| **Alibaba subtotal** | **~9–12** (or **~6–9** with ecs.t6-c4m1.large at USD 0.005/h) |

With the GCP signer (~4.85) the total is ~14–17 per month (t6-c2m1) or ~11–14 (t6-c4m1). Creating the instance
still needs the owner's approval.

