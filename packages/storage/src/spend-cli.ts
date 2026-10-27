/**
 * Cron-ready spend operations (T11 schedules `reconcile`).
 *   pnpm --filter @mandaterail/storage spend -- reconcile [--store demo-api] [--pending-older-than-ms 900000] [--limit 500] [--dry-run]
 *   pnpm --filter @mandaterail/storage spend -- release --id <reservationId> --operator <name> --reason "<why>" [--store demo-api] [--margin-rounds 10] [--force]
 * release (R19-P2-1) needs proof the txn can no longer confirm: INDEXER_URL
 * returns 404 for the row's txId AND the indexer round > lastValid + margin.
 * Without that proof it refuses unless --force is given; --force records the
 * reason as the force justification. Proof or force is written to
 * mr_spend_audit. Releasing an already-released row exits 0 with
 * "alreadyReleased": true (R19-P3-3, idempotent).
 * --operator is an UNTRUSTED free-text label, not an authenticated identity:
 * anyone with the DB credentials in the env file can write any name. The
 * real access control is who can read the env file. R22-P3-1: release runs
 * as mr_release (STATE_ENV_FILE default /etc/mandaterail/state-release.env);
 * reconcile runs as mr_reconcile and can only settle or mark ambiguous.
 * Env (STATE_ENV_FILE, default /etc/mandaterail/state-reconcile.env):
 *   DATABASE_URL (+ PG_SSL_CA_FILE for non-loopback TLS), NETWORK, INDEXER_URL, INDEXER_TOKEN (optional).
 * --force is refused on MainNet and needs an explicit NETWORK=testnet (R20-P3-1).
 *   pnpm --filter @mandaterail/storage spend -- monitor [--store demo-api] [--older-than-min 30]
 *     (T11) GETs MONITOR_HEALTH_URLS (comma list) and counts pending/ambiguous rows
 *     older than N minutes, keyed by URL. ok -> stdout, exit 0; otherwise
 *     "ALERT {...}" on stderr, exit 2 (health failure OR stale rows), and a
 *     POST to MONITOR_PAGER_WEBHOOK_URL if set (MONITOR_PAGER_FORMAT json|slack|ntfy).
 *     An empty MONITOR_HEALTH_URLS is a config error (exit 1). R21-P3-1.
 *     Runs as the read-only mr_monitor role (state-monitor.env).
 * reconcile/release refuse to run as a role that owns mr_spend_audit (R20-P3-4).
 * Prints one JSON line; exit 0 on success (including "skipped: locked"), 1 on error.
 *     R23-P3-4: also alerts when a needsRelease row was flagged more than
 *     MONITOR_NEEDS_RELEASE_MAX_MIN minutes ago (default 60).
 * R23: release needs the mr_release credential supplied AT RUNTIME (it is not
 * kept on the host): STATE_ENV_FILE=/dev/null DATABASE_URL=... from the
 * operator's side, per docs/ops/release-two-person.md.
 * Never prints URLs or tokens.
 */
import { indexerTxCheck, MAINNET_PROFILE, networkProfile, TESTNET_PROFILE, twoProviderNoConfirmProof, requireProviderKey } from "@mandaterail/core";
import { loadStateEnvFile, pgPoolConfig, redactSecrets } from "./backend.js";
import pg from "pg";
import path from "node:path";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { formatReleasePin, releaseDepsHash, releasePinReasons, releaseTreeHash, systemdState } from "./release-pin.js";
import { DEFAULT_MANIFEST_PATH, expectedProvidersHash, INTEGRITY_MANIFEST_SHA256, loadIntegrityManifest, MonitorConfigError, monitorSelfFailure, needsReleaseMaxMin, runMonitor } from "./monitor.js";
import { ANCHOR_PINS, AnchorFileStandIn, anchorLineAcceptable, anchorRequiresSig, anchorTick, GcpKmsAnchorSigner, SoftwareAnchorSigner, type AnchorPin, type AnchorSigner } from "./anchor.js";
import { readFileSync as readAnchorKey } from "node:fs";
import { B2ObjectLockSink, type AuditSink as LineSink } from "./b2-sink.js";
import { auditOwnerRisk, EXPECTED_MR_TRIGGERS, integrityStatus, reconcileSpendPg, releaseSpendManually, staleSpendCounts } from "./spend-ops.js";

const [cmd, ...rest] = process.argv.slice(2).filter((a) => a !== "--");
const arg = (n: string) => {
  const i = rest.indexOf(n);
  return i >= 0 ? rest[i + 1] : undefined;
};

async function main() {
  if (cmd === "monitor") return mainMonitor();
  if (cmd === "deps-hash") {
    // R30-P3-2: run on the deploying machine over a clean `pnpm install --frozen-lockfile
    // --ignore-scripts` of the release at its host path; prints the deps sha256.
    const dir = arg("--dir");
    if (!dir) throw new Error("usage: spend deps-hash --dir <release dir>");
    const d = releaseDepsHash(dir);
    process.stdout.write(`deps_sha256=${d.hash}\nentries=${d.files}\n`);
    return;
  }
  if (cmd === "release-pin") {
    // R28-P3-1 / R29-P3-1: run on the HOST as root over the installed, root-owned release
    // (after pnpm install + chown -R root:root + chmod -R go-w). --tree-sha256 is the tree
    // hash the deploying machine computed from `git archive <commit>`; it must match.
    // Prints the pin; the deploy writes it to /etc/mandaterail/release-pin (root:root 0644).
    // R30-P3-2: --deps-sha256 is the deps hash of a clean --ignore-scripts install of the
    // lockfile on the deploying machine; the host's install must match it.
    const dir = arg("--dir"), commit = arg("--commit") ?? "", wantTree = arg("--tree-sha256"), wantDeps = arg("--deps-sha256");
    if (!dir || !/^[0-9a-f]{40}$/.test(commit)) throw new Error("usage: spend release-pin --dir <release dir> --commit <40-hex sha> [--tree-sha256 <hash from git archive>] [--deps-sha256 <hash from an off-host clean install>]");
    const manifestSha256 = createHash("sha256").update(readFileSync(path.join(dir, "deploy/integrity-manifest.json"))).digest("hex");
    if (manifestSha256 !== INTEGRITY_MANIFEST_SHA256) throw new Error("release-pin: the release's manifest sha256 differs from INTEGRITY_MANIFEST_SHA256 in this checkout");
    const treeSha256 = releaseTreeHash(dir).hash;
    if (wantTree && wantTree !== treeSha256) throw new Error(`release-pin: tree hash ${treeSha256} differs from --tree-sha256 ${wantTree}`);
    const depsSha256 = releaseDepsHash(dir).hash;
    if (wantDeps && wantDeps !== depsSha256) throw new Error(`release-pin: installed dependencies hash ${depsSha256} differs from --deps-sha256 ${wantDeps}`);
    // R30-P3-3: refuse to pin a host whose units / drop-ins / env files break the rules.
    // --systemd-dir / --env-dir exist for tests only (fixture dirs; no expected units there).
    const sdDir = arg("--systemd-dir"), envDir = arg("--env-dir");
    const sd = systemdState(sdDir || envDir ? { unitDir: sdDir, envDir, expectedUnits: [], uid: process.getuid?.() ?? 0 } : {});
    if (sd.violations.length) throw new Error(`release-pin: systemd/env violations: ${sd.violations.join("; ")}`);
    process.stdout.write(formatReleasePin({ commit, treeSha256, depsSha256, manifestSha256, systemdSha256: sd.hash }));
    return;
  }
  loadStateEnvFile(cmd === "release" ? "release" : "reconcile", process.env, ["INDEXER_URL", "INDEXER_TOKEN", "PROOF2_URL", "PROOF2_KIND", "PROOF2_TOKEN", "NETWORK", "ALLOW_MAINNET", "USDC_ASA_ID", "MONITOR_HEALTH_URLS", "MONITOR_PAGER_WEBHOOK_URL", "MONITOR_PAGER_FORMAT", "MR_TEST_ALLOW_AUDIT_OWNER"]);
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is required");
  if (rest.includes("--password-stdin")) {
    // R23: the mr_release password is not stored on the host; it is piped in at
    // runtime (never argv, never printed). pg reads PGPASSWORD when the URL has none.
    if (new URL(url).password) throw new Error("--password-stdin: DATABASE_URL must not contain a password");
    const pw = (await readStdin()).replace(/\r?\n$/, "");
    if (!pw) throw new Error("--password-stdin: empty password on stdin");
    process.env.PGPASSWORD = pw;
  }
  const pool = new pg.Pool({ ...pgPoolConfig(url, process.env), max: 2 });
  pool.on("error", () => undefined);
  const store = arg("--store") ?? "demo-api";
  // R20-P3-2: the indexer must serve this profile's chain before a 404 counts.
  const profile = networkProfile(process.env);
  const explicitNetwork = (process.env.NETWORK ?? "").trim() !== "";
  try {
    if (cmd === "release" && rest.includes("--force") && profile.isMainnet) {
      throw new Error("--force is refused on MainNet; a release there needs a chain proof"); // R20-P3-1
    }
    if (cmd === "reconcile" || cmd === "release") {
      // R20-P3-4: refuse to write as a role that could DISABLE the audit trigger.
      const risk = await auditOwnerRisk(pool);
      if (risk) {
        const testOverride = process.env.MR_TEST_ALLOW_AUDIT_OWNER === "1" && !profile.isMainnet;
        if (!testOverride) throw new Error(`refusing to run as this DB role: ${risk}; use the non-owner mr_reconcile role`);
        console.error(`WARNING: ${risk} (allowed by MR_TEST_ALLOW_AUDIT_OWNER, tests only)`);
      }
    }
    if (cmd === "reconcile") {
      const idx = process.env.INDEXER_URL;
      if (!idx) throw new Error("INDEXER_URL is required");
      const r = await reconcileSpendPg(pool, {
        store,
        check: indexerTxCheck(idx, fetch, { profile, token: process.env.INDEXER_TOKEN }),
        pendingOlderThanMs: arg("--pending-older-than-ms") ? Number(arg("--pending-older-than-ms")) : undefined,
        limit: arg("--limit") ? Number(arg("--limit")) : undefined,
        dryRun: rest.includes("--dry-run"),
      });
      console.log(JSON.stringify({ cmd, store, ...r, at: new Date().toISOString() }));
    } else if (cmd === "release") {
      const id = arg("--id");
      if (!id) throw new Error("--id is required");
      const idx = process.env.INDEXER_URL;
      const margin = arg("--margin-rounds") ? Number(arg("--margin-rounds")) : 10;
      if (!/^\d+$/.test(arg("--margin-rounds") ?? "10")) throw new Error("--margin-rounds must be a non-negative integer");
      if (!rest.includes("--force")) {
        requireProviderKey(idx, process.env.INDEXER_TOKEN, "INDEXER_TOKEN");
        requireProviderKey(process.env.PROOF2_URL, process.env.PROOF2_TOKEN, "PROOF2_TOKEN");
      }
      const r = await releaseSpendManually(pool, {
        store, id, operator: arg("--operator") ?? "", reason: arg("--reason") ?? "",
        force: rest.includes("--force"),
        network: explicitNetwork ? profile.name : undefined,
        warn: (m) => console.error(m),
        // R24-P2-1: two independent providers (INDEXER_URL + PROOF2_URL, different hosts, both genesis-checked).
        // R26-P3-5: --force never builds (or validates) a proof, so a set PROOF2_URL can't break a TestNet forced release.
        prove: !rest.includes("--force") && idx && process.env.PROOF2_URL
          ? twoProviderNoConfirmProof(
            [
              { url: idx, kind: "indexer", token: process.env.INDEXER_TOKEN },
              { url: process.env.PROOF2_URL, kind: proof2Kind(process.env.PROOF2_KIND), token: process.env.PROOF2_TOKEN },
            ],
            fetch, { profile, marginRounds: margin }) // real fetch: DNS pinned per proof
          : undefined,
      });
      const note = r.alreadyReleased ? "already released; nothing changed" : undefined;
      console.log(JSON.stringify({ cmd, store, ...r, ...(note ? { note } : {}), operator: arg("--operator"), operatorTrusted: false, reason: arg("--reason"), at: new Date().toISOString() }));
    } else {
      throw new Error("usage: spend reconcile|release|monitor ...");
    }
  } finally {
    await pool.end();
  }
}
/**
 * R22-P3-3: the monitor never dies silently. Config errors exit 1; any other
 * failure (DB unreachable, env file unreadable, ...) pages and exits 2.
 */
async function mainMonitor() {
  const store = arg("--store") ?? "demo-api";
  let pool: pg.Pool | undefined;
  try {
    loadStateEnvFile("monitor", process.env, ["NETWORK", "MONITOR_HEALTH_URLS", "MONITOR_PAGER_WEBHOOK_URL", "MONITOR_PAGER_FORMAT", "MONITOR_NEEDS_RELEASE_MAX_MIN",
      "MONITOR_ANCHOR_B2_ENDPOINT", "MONITOR_ANCHOR_B2_REGION", "MONITOR_ANCHOR_B2_BUCKET", "MONITOR_ANCHOR_B2_PREFIX", "MONITOR_ANCHOR_B2_RETAIN_DAYS",
      "MONITOR_ANCHOR_B2_KEY_ID", "MONITOR_ANCHOR_B2_APP_KEY", "MONITOR_ANCHOR_FILE", "MONITOR_ANCHOR_MIN_SEQ",
      "MONITOR_ANCHOR_KMS_KEY", "MONITOR_ANCHOR_SIGNING_KEY_FILE", "MONITOR_ANCHOR_PUBKEY"]);
    const nrMin = needsReleaseMaxMin(process.env);
    const olderMin = Number(arg("--older-than-min") ?? "30");
    if (!Number.isInteger(olderMin) || olderMin <= 0) throw new MonitorConfigError("--older-than-min must be a positive integer");
    const url = process.env.DATABASE_URL;
    if (!url) throw new MonitorConfigError("DATABASE_URL is required");
    const p = new pg.Pool({ ...pgPoolConfig(url, process.env), max: 1, connectionTimeoutMillis: 10_000 });
    pool = p;
    p.on("error", () => undefined);
    // R21-P3-1: empty URL list = config error (exit 1); any alert, including a monitor self-failure, = exit 2.
    // R25-P3-1: triggers + marker are checked on every run against NETWORK's profile (NETWORK must be explicit).
    if (!(process.env.NETWORK ?? "").trim()) throw new MonitorConfigError("NETWORK is required (the monitor checks the network marker)");
    const prof = networkProfile(process.env);
    const r = await runMonitor({
      env: process.env, store, olderThanMin: olderMin,
      stale: () => staleSpendCounts(p, { store, olderThanMs: olderMin * 60_000, needsReleaseOlderThanMs: nrMin * 60_000 }),
      // R26-P3-2: drift vs deploy/integrity-manifest.json + the profiles' provider allowlists.
      integrity: {
        read: () => integrityStatus(p), want: { network: prof.name, genesisHash: prof.caip2.slice("algorand:".length) }, expectedTriggers: EXPECTED_MR_TRIGGERS,
        expected: {
          ...loadIntegrityManifest(process.env), // R27-P3-1: md5-pinned; missing / tampered / overridden on mainnet -> page + exit 2
          providersHash: expectedProvidersHash([{ network: "mainnet", allow: MAINNET_PROFILE.providerAllowlist }, { network: "testnet", allow: TESTNET_PROFILE.providerAllowlist }]),
        },
      },
      // R28-P3-1: /etc/mandaterail/release-pin (root-owned, written by the deploy) vs this release's tree + manifest + the code pin.
      anchor: monitorAnchor(p, prof.name),
      release: () => releasePinReasons({ env: process.env, root: path.resolve(path.dirname(DEFAULT_MANIFEST_PATH), ".."), manifestPath: DEFAULT_MANIFEST_PATH, pinnedSha256: INTEGRITY_MANIFEST_SHA256 }),
    });
    process.exitCode = r.exitCode;
  } catch (e) {
    if (e instanceof MonitorConfigError) {
      console.error(JSON.stringify({ cmd, error: redactSecrets(e.message, [process.env.DATABASE_URL, process.env.MONITOR_PAGER_WEBHOOK_URL, process.env.MONITOR_ANCHOR_B2_APP_KEY]) }));
      process.exitCode = 1;
    } else {
      process.exitCode = (await monitorSelfFailure({ env: process.env, store, error: e })).exitCode;
    }
  } finally {
    await pool?.end().catch(() => undefined);
  }
}

/**
 * R65-P3-4: the anchor chain. MainNet needs B2 (MONITOR_ANCHOR_B2_*; the key may write + list + read only, the
 * bucket has Object Lock); TestNet may use MONITOR_ANCHOR_FILE (stand-in). Unconfigured on MainNet = a page.
 */
function monitorAnchor(p: pg.Pool, network: string): () => Promise<{ reasons: string[]; seq: number; anchored: boolean }> {
  const e = process.env;
  // R66-P3-3: prefix, minimum sequence, retention floor and public key come from the sha256-pinned manifest
  let pin: AnchorPin = ANCHOR_PINS[network as "mainnet" | "testnet"];
  try { pin = loadIntegrityManifest(e).anchor?.[network] ?? pin; } catch { /* the integrity check pages a bad manifest */ }
  const envMin = Number(e.MONITOR_ANCHOR_MIN_SEQ ?? "0");
  if (!Number.isInteger(envMin) || envMin < 0) throw new MonitorConfigError("MONITOR_ANCHOR_MIN_SEQ must be a non-negative integer");
  const minSeq = Math.max(envMin, pin.minSeq);
  let pubB64 = pin.pubkey;
  if (!pubB64 && network !== "mainnet" && e.MONITOR_ANCHOR_PUBKEY) pubB64 = e.MONITOR_ANCHOR_PUBKEY; // TestNet only: MainNet uses the manifest pin
  const pubkey = pubB64 ? new Uint8Array(Buffer.from(pubB64, "base64")) : undefined;
  let signer: AnchorSigner | undefined;
  if (e.MONITOR_ANCHOR_KMS_KEY) signer = new GcpKmsAnchorSigner(e.MONITOR_ANCHOR_KMS_KEY);
  else if (e.MONITOR_ANCHOR_SIGNING_KEY_FILE) signer = new SoftwareAnchorSigner(readAnchorKey(e.MONITOR_ANCHOR_SIGNING_KEY_FILE, "utf8"), network); // throws off TestNet
  let sink: LineSink | null = null;
  let skipped: string[] = [];
  if (e.MONITOR_ANCHOR_B2_ENDPOINT) {
    const need = ["MONITOR_ANCHOR_B2_REGION", "MONITOR_ANCHOR_B2_BUCKET", "MONITOR_ANCHOR_B2_PREFIX", "MONITOR_ANCHOR_B2_KEY_ID", "MONITOR_ANCHOR_B2_APP_KEY"];
    for (const k of need) if (!e[k]) throw new MonitorConfigError(`${k} is required with MONITOR_ANCHOR_B2_ENDPOINT`);
    if (e.MONITOR_ANCHOR_B2_PREFIX !== pin.prefix) throw new MonitorConfigError(`MONITOR_ANCHOR_B2_PREFIX must be the pinned ${pin.prefix}`);
    const retainDays = Number(e.MONITOR_ANCHOR_B2_RETAIN_DAYS ?? "400");
    if (!Number.isInteger(retainDays) || retainDays < pin.retainDaysMin) throw new MonitorConfigError(`MONITOR_ANCHOR_B2_RETAIN_DAYS must be >= the pinned ${pin.retainDaysMin}`);
    // R69-P3-1: manifest-pinned (key, sha256) skips only; each skip is collected and paged by anchorTick
    sink = new B2ObjectLockSink({ endpoint: e.MONITOR_ANCHOR_B2_ENDPOINT, region: e.MONITOR_ANCHOR_B2_REGION!, bucket: e.MONITOR_ANCHOR_B2_BUCKET!, prefix: pin.prefix,
      retainDays, accessKeyId: e.MONITOR_ANCHOR_B2_KEY_ID!, secretAccessKey: e.MONITOR_ANCHOR_B2_APP_KEY!,
      skipPinned: pin.skip ?? [], accept: (l) => anchorLineAcceptable(l, pubkey, network, anchorRequiresSig(network, pin)), onSkip: (k) => skipped.push(k) });
  } else if (e.MONITOR_ANCHOR_FILE) {
    sink = new AnchorFileStandIn(e.MONITOR_ANCHOR_FILE, network); // throws off TestNet
  }
  if (!sink) {
    return async () => network === "mainnet" ? { reasons: ["anchor: not configured (MONITOR_ANCHOR_B2_*): superuser wipes of the append-only tables would go unseen"], seq: 0, anchored: false } : { reasons: [], seq: 0, anchored: false };
  }
  const s = sink;
  // R71-P3-1: the step-over set is resolved every tick from the pinned (key, sha256) against the stored objects
  return () => { skipped = []; return anchorTick({ pool: p, network, sink: s, minSeq, signer, pubkey, skipped: () => skipped, skipPins: pin, requireSigned: anchorRequiresSig(network, pin) }); };
}

function proof2Kind(v: string | undefined): "indexer" | "algod" {
  const k = (v ?? "indexer").trim().toLowerCase();
  if (k !== "indexer" && k !== "algod") throw new Error("PROOF2_KIND must be indexer or algod");
  return k;
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

main().catch((e) => {
  console.error(JSON.stringify({ cmd, error: redactSecrets(String(e?.message ?? e), [process.env.PGPASSWORD, process.env.DATABASE_URL, process.env.INDEXER_URL, process.env.INDEXER_TOKEN, process.env.PROOF2_URL, process.env.PROOF2_TOKEN, process.env.MONITOR_PAGER_WEBHOOK_URL]) }));
  process.exit(1);
});
