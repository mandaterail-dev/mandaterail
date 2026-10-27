/** R65-P3-4: the monitor anchors the append-only tables off-host every tick and pages on regression. */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import pg from "pg";
import { migratePostgres } from "./pg.js";
import { PG_URL, seedTestProviders } from "./test-helpers.js";
import { anchorLine, anchorSigMsg, AnchorFileStandIn, anchorTick, SoftwareAnchorSigner, type AnchorLine } from "./anchor.js";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { runMonitor } from "./monitor.js";

const run = promisify(execFile);
const SQL = path.resolve(__dirname, "../../../deploy/sql/t11-mr-reconcile-role.sql");
let own: pg.Pool, mon: pg.Pool, admin: pg.Pool, dbName = "";

describe.skipIf(!PG_URL)("R65-P3-4 monitor anchor chain [postgres]", () => {
  beforeAll(async () => {
    admin = new pg.Pool({ connectionString: PG_URL, max: 2 });
    dbName = `mr_anchor_${randomBytes(4).toString("hex")}`;
    await admin.query(`CREATE DATABASE ${dbName}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${dbName}`);
    own = new pg.Pool({ connectionString: url, max: 3 });
    await migratePostgres(own, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) });
    await seedTestProviders(own);
    await run("psql", ["-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", "pw=t-rec-pw", "-v", "mon_pw=t-mon-pw", "-v", "rel_pw=t-rel-pw", "-d", url, "-f", SQL]);
    const m = new URL(url); m.username = "mr_monitor"; m.password = "t-mon-pw";
    mon = new pg.Pool({ connectionString: m.toString(), max: 1 }); mon.on("error", () => undefined);
    // history: two tamper pauses + caps changes, back-dated past the 10 min settle window
    await own.query("SELECT * FROM mr_tamper_pause('test: a')"); // (idempotent while paused: one log row)
    const c = await own.connect();
    try {
      await c.query("BEGIN"); await c.query("SET LOCAL ROLE mr_pause_writer");
      for (const v of [20_000_000, 30_000_000]) await c.query("UPDATE mr_release_caps SET max_day_micro = $1 WHERE network = 'testnet'", [v]);
      await c.query("COMMIT");
      await c.query("SET session_replication_role = replica");
      await c.query("UPDATE mr_config_audit SET at = at - interval '1 hour'");
      await c.query("UPDATE mr_pause_log SET paused_at = paused_at - interval '1 hour'");
      await c.query("RESET session_replication_role");
    } finally { c.release(); }
  });
  afterAll(async () => { await mon?.end(); await own?.end(); if (dbName) await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`); await admin?.end(); });

  const replica = async (q: string) => {
    const c = await own.connect();
    try { await c.query("SET session_replication_role = replica"); await c.query(q); await c.query("RESET session_replication_role"); } finally { c.release(); }
  };

  it("anchors every tick (as mr_monitor), accepts appends, pages a superuser wipe / rewrite and keeps paging", async () => {
    const f = path.join(mkdtempSync(path.join(tmpdir(), "anchor-")), "anchor.jsonl");
    const sink = new AnchorFileStandIn(f, "testnet");
    const t1 = await anchorTick({ pool: mon, network: "testnet", sink });
    expect(t1).toEqual({ reasons: [], seq: 1, anchored: true });
    const l1 = JSON.parse(readFileSync(f, "utf8").split("\n")[0]!.split("\t")[0]!);
    expect(l1.tables.mr_config_audit.settled.count).toBeGreaterThanOrEqual(2);
    expect(l1.tables.mr_pause_log).toMatchObject({ count: 1, maxSeq: 1 });
    // appends are fine
    const c = await own.connect();
    try { await c.query("BEGIN"); await c.query("SET LOCAL ROLE mr_pause_writer"); await c.query("UPDATE mr_release_caps SET max_day_micro = 40000000 WHERE network = 'testnet'"); await c.query("COMMIT"); } finally { c.release(); }
    expect((await anchorTick({ pool: mon, network: "testnet", sink })).reasons).toEqual([]);
    // a superuser (replica mode skips every trigger) rewrites one old audit row and deletes a pause log row
    await replica("UPDATE mr_config_audit SET actor = 'someone-else' WHERE seq = (SELECT min(seq) FROM mr_config_audit)");
    await replica("DELETE FROM mr_pause_log WHERE pause_seq = 1");
    for (let i = 0; i < 2; i++) { // not anchored over: the page repeats
      const t = await anchorTick({ pool: mon, network: "testnet", sink });
      expect(t.anchored).toBe(false);
      expect(t.seq).toBe(2);
      expect(t.reasons).toEqual(expect.arrayContaining([
        expect.stringMatching(/anchor: mr_config_audit rows older than .* changed/),
        expect.stringMatching(/anchor: mr_pause_log has 0 rows, anchored 1 \(rows deleted\)/),
        expect.stringMatching(/anchor: mr_pause_log max seq 0 is below the anchored 1/),
      ]));
    }
    // runMonitor pages it (exit 2)
    const r = await runMonitor({ env: { MONITOR_HEALTH_URLS: "http://127.0.0.1:9/h" }, store: "s", olderThanMin: 30, stale: async () => ({ pending: 0, ambiguous: 0, oldestAgeMs: null }),
      anchor: () => anchorTick({ pool: mon, network: "testnet", sink }), fetchImpl: (async () => new Response("", { status: 200 })) as typeof fetch, log: () => undefined, err: () => undefined });
    expect(r.exitCode).toBe(2);
    expect(r.reasons.join("\n")).toMatch(/anchor: mr_pause_log has 0 rows/);
  });

  it("the chain itself: a wiped chain below the pinned minimum, a corrupt head, an unlinked head", async () => {
    const d = mkdtempSync(path.join(tmpdir(), "anchor-"));
    const f = path.join(d, "a.jsonl");
    const sink = new AnchorFileStandIn(f, "testnet");
    expect((await anchorTick({ pool: mon, network: "testnet", sink, minSeq: 3 })).reasons).toEqual([expect.stringMatching(/empty but the pinned minimum sequence is 3: wiped or swapped/)]);
    // fresh chain (the DB regression from the first test is anchored as the new baseline here)
    expect((await anchorTick({ pool: mon, network: "testnet", sink })).anchored).toBe(true);
    expect((await anchorTick({ pool: mon, network: "testnet", sink })).anchored).toBe(true);
    const lines = readFileSync(f, "utf8").split("\n").filter(Boolean);
    writeFileSync(f, [lines[0], lines[1]!.replace('"seq":2', '"seq":2 ')].join("\n") + "\n");
    expect((await anchorTick({ pool: mon, network: "testnet", sink })).reasons).toEqual(["anchor: anchor head line is corrupt"]);
    expect(() => new AnchorFileStandIn(f, "mainnet")).toThrow(/TESTNET-ONLY/);
  });

  it("R66-P3-3: lines are signed by the pinned off-host key, bound to their seq; head and head-1 verified; head-1 -> head monotone; MainNet refuses unsigned", async () => {
    const kp = () => { const { publicKey, privateKey } = generateKeyPairSync("ed25519");
      return { pub: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)), pem: privateKey.export({ format: "pem", type: "pkcs8" }).toString(), priv: privateKey }; };
    const k = kp(), other = kp();
    const signer = new SoftwareAnchorSigner(k.pem, "testnet");
    expect(() => new SoftwareAnchorSigner(k.pem, "mainnet")).toThrow(/TESTNET-ONLY/);
    const f = path.join(mkdtempSync(path.join(tmpdir(), "anchor-")), "s.jsonl");
    const sink = new AnchorFileStandIn(f, "testnet");
    const tick = () => anchorTick({ pool: mon, network: "testnet", sink, signer, pubkey: k.pub });
    expect((await tick()).anchored).toBe(true);
    await new Promise((r) => setTimeout(r, 5));
    expect((await tick()).anchored).toBe(true);
    const good = readFileSync(f, "utf8").split("\n").filter(Boolean);
    expect(good[1]!.split("\t")).toHaveLength(3);
    const parse = (l: string) => JSON.parse(l.split("\t")[0]!) as AnchorLine;
    const sha = (x: string) => createHash("sha256").update(x).digest("hex");
    // 1. a head appended by someone with sink access but without the key (unsigned / signed by another key)
    const forge = async (sg: { sign(m: Uint8Array): Promise<Uint8Array> } | undefined, mut: (l: AnchorLine) => AnchorLine = (l) => l) => {
      const h1 = parse(good[1]!), { v: _v, kind: _k, seq: _s, prev: _p, ...facts } = mut({ ...h1, at: new Date(Date.parse(h1.at) + 1000).toISOString() });
      return anchorLine(3, good[1]!.split("\t")[1]!, facts as never, sg);
    };
    for (const [line, re] of [
      [await forge(undefined), /head \(seq 3\) is not signed by the pinned anchor key/],
      [await forge({ sign: async (m) => new Uint8Array(edSign(null, m, other.priv)) }), /not signed by the pinned anchor key/],
    ] as const) {
      writeFileSync(f, [...good, line].join("\n") + "\n");
      expect((await tick()).reasons).toEqual([expect.stringMatching(re)]);
    }
    // 2. a validly signed line replayed at another seq: the signature is bound to (network, seq, hash)
    const l1 = parse(good[1]!);
    const replay = JSON.stringify({ ...l1, seq: 3, prev: good[1]!.split("\t")[1]! });
    writeFileSync(f, [...good, `${replay}\t${sha(replay)}\t${good[1]!.split("\t")[2]}`].join("\n") + "\n");
    expect((await tick()).reasons).toEqual([expect.stringMatching(/seq 3\) is not signed by the pinned anchor key/)]);
    void anchorSigMsg;
    // 3. even a correctly signed head may not roll facts back against head-1
    const rolled = await forge(signer, (l) => ({ ...l, tables: { ...l.tables, mr_config_audit: { ...l.tables.mr_config_audit!, count: 0, maxSeq: 0 } } }));
    writeFileSync(f, [...good, rolled].join("\n") + "\n");
    expect((await tick()).reasons).toEqual([expect.stringMatching(/regresses against seq 2 \(mr_config_audit\)/)]);
    // 4. the right key appends again after the junk is gone; a wrong configured key is caught before appending
    writeFileSync(f, good.join("\n") + "\n");
    expect((await tick()).anchored).toBe(true);
    const wrong = new SoftwareAnchorSigner(other.pem, "testnet");
    expect((await anchorTick({ pool: mon, network: "testnet", sink, signer: wrong, pubkey: k.pub })).reasons).toEqual(["anchor: the signing key does not match the pinned public key"]);
    // 5. MainNet: unsigned anchoring is refused (page)
    expect((await anchorTick({ pool: mon, network: "mainnet", sink })).reasons).toEqual([expect.stringMatching(/unsigned anchors are refused on MainNet/)]);
  });
});
