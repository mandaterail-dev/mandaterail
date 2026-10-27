import { afterAll, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { toMicro } from "@mandaterail/core";
import { openStateBackend, redactSecrets, resolveStateBackendKind, StateBackendError, type StateBackend } from "./backend.js";
import pg from "pg";
import { getPool, PG_URL, REDIS_URL, uid } from "./test-helpers.js";
import { loadStateEnvFile, pgPoolConfig, redisTlsOptions, SchemaNotReadyError } from "./backend.js";
import { redactTestOutput } from "./test-redact.js";
import { migratePostgres } from "./pg.js";

const opened: StateBackend[] = [];
afterAll(async () => { for (const b of opened) await b.close(); });

describe("T6 STATE_BACKEND switch", () => {
  it("kinds: default memory on TestNet; invalid refused; MainNet requires a shared backend", () => {
    expect(resolveStateBackendKind({}, false)).toBe("memory");
    expect(resolveStateBackendKind({ STATE_BACKEND: "postgres" }, false)).toBe("postgres");
    expect(resolveStateBackendKind({ STATE_BACKEND: "Redis+Postgres" }, true)).toBe("redis+postgres");
    expect(() => resolveStateBackendKind({ STATE_BACKEND: "sqlite" }, false)).toThrow(StateBackendError);
    expect(() => resolveStateBackendKind({}, true)).toThrow(/MainNet requires/);
    expect(() => resolveStateBackendKind({ STATE_BACKEND: "memory" }, true)).toThrow(/MainNet requires/);
    expect(() => resolveStateBackendKind({ NETWORK: "mainnet" })).toThrow(/MainNet requires/);
  });
  it("memory -> null; missing URLs refused", async () => {
    expect(await openStateBackend({}, { mainnet: false })).toBeNull();
    await expect(openStateBackend({ STATE_BACKEND: "postgres" }, { mainnet: false })).rejects.toThrow(/DATABASE_URL/);
    await expect(openStateBackend({ STATE_BACKEND: "redis+postgres", DATABASE_URL: "postgres://x@127.0.0.1:1/db" }, { mainnet: false })).rejects.toThrow(/REDIS_URL/);
  });
  it("redaction: URLs, user, password, host never appear", () => {
    const url = "postgres://admin:s3cr%21t@db.internal.example:5432/mr";
    const msg = `connect ECONNREFUSED db.internal.example: password authentication failed for admin:s3cr!t at ${url} (also redis://:hunter2@cache:6379)`;
    const r = redactSecrets(msg, [url]);
    for (const leak of ["s3cr", "hunter2", "db.internal.example", "admin:", url]) expect(r).not.toContain(leak);
  });
  it("unreachable database: StateBackendError with no credentials or host", async () => {
    const url = "postgres://mruser:TopSecretPw@127.0.0.1:1/mr";
    const log: string[] = [];
    const e = (await openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL: url }, { mainnet: false, log: (l) => log.push(l) }).catch((x) => x)) as Error;
    expect(e).toBeInstanceOf(StateBackendError);
    expect(e.message).not.toContain("TopSecretPw");
    expect(e.message).not.toContain("mruser");
    expect(log.join("\n")).not.toContain("TopSecretPw");
  });
  it("DATABASE_URL_FILE is read (mounted secret); unreadable file refused without path content", async () => {
    await expect(openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL_FILE: "/nonexistent/x" }, { mainnet: false })).rejects.toThrow(/not readable/);
  });

  for (const kind of ["postgres", "redis+postgres"] as const) {
    const skip = !PG_URL || (kind === "redis+postgres" && !REDIS_URL);
    it.skipIf(skip)(`[${kind}] opens, migrates and serves every store`, async () => {
      await getPool(); // migrated by the separate migrate step, as in prod
      const dir = mkdtempSync(path.join(tmpdir(), "mr-url-"));
      writeFileSync(path.join(dir, "db"), `${PG_URL}\n`);
      const b = (await openStateBackend(
        { STATE_BACKEND: kind, DATABASE_URL_FILE: path.join(dir, "db"), REDIS_URL },
        { mainnet: true },
      ))!;
      opened.push(b);
      expect(b.kind).toBe(kind);
      expect(Boolean(b.redis)).toBe(kind === "redis+postgres");
      const ch = await b.challengeStore({ audience: uid("aud") }).issue("approve", "x");
      expect(ch.nonce).toBeTruthy();
      expect(await b.rateLimiter({ name: uid("rl"), windowMs: 1000, perKey: 1, global: 5 }).take("k")).toBe(true);
      const sp = b.spend(uid("sp"));
      const r = await sp.reserve({ id: "r1", payer: "P", amountMicro: toMicro("1"), caps: { perPaymentMicro: toMicro("1"), perDayMicro: toMicro("5") }, nowMs: Date.now() });
      expect(r.ok).toBe(true);
      expect(await b.mandates(uid("m")).list()).toEqual([]);
      expect(await b.receipts(uid("r")).list(5)).toEqual([]);
    });
  }

  it("state env file: only state keys, existing env wins, default path optional", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-env-"));
    const f = path.join(dir, "state-bridge.env");
    writeFileSync(f, "# comment\nexport STATE_BACKEND=redis+postgres\nDATABASE_URL='postgres://a@h/db'\nREDIS_URL=redis://h:6379\nOPERATOR_ALLOWLIST=ignored\n");
    const env: Record<string, string | undefined> = { STATE_ENV_FILE: f, REDIS_URL: "redis://keep" };
    expect(loadStateEnvFile("bridge", env)).toBe(f);
    expect(env).toMatchObject({ STATE_BACKEND: "redis+postgres", DATABASE_URL: "postgres://a@h/db", REDIS_URL: "redis://keep" });
    expect(env.OPERATOR_ALLOWLIST).toBeUndefined();
    expect(loadStateEnvFile("nonexistent-service-xyz", {})).toBeNull();
    expect(() => loadStateEnvFile("bridge", { STATE_ENV_FILE: path.join(dir, "missing.env") })).toThrow(StateBackendError);
  });

  it.skipIf(!PG_URL)("apps never migrate: unmigrated / behind / ahead schema is refused; migrate step fixes it", async () => {
    const admin = await getPool();
    const db = `mr_mig_${uid("x").replace(/-/g, "_")}`;
    await admin.query(`CREATE DATABASE ${db}`);
    const url = PG_URL!.replace(/\/[^/]*$/, `/${db}`);
    try {
      await expect(openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL: url }, { mainnet: false })).rejects.toThrow(SchemaNotReadyError);
      const p = new pg.Pool({ connectionString: url, max: 2 });
      p.on("error", () => undefined);
      // legacy v1 database (as created by 1c513f3)
      await p.query("CREATE TABLE mr_schema (version integer PRIMARY KEY)");
      const { MIGRATIONS, schemaVersions } = await import("./pg.js");
      await p.query(MIGRATIONS[0]!.sql);
      await p.query("INSERT INTO mr_schema (version) VALUES (1)");
      await expect(openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL: url }, { mainnet: false })).rejects.toThrow(/v1 is behind/);
      // R23-P2-1: the first v7+ migrate needs NETWORK for the write-once marker
      await expect(migratePostgres(p, { network: "", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).rejects.toThrow(/NETWORK .* required/);
      expect(await migratePostgres(p, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).toEqual({ from: 1, to: MIGRATIONS.length, network: "testnet" });
      expect(await schemaVersions(p)).toEqual(MIGRATIONS.map((m) => m.version));
      expect(await migratePostgres(p, { network: "testnet", verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).toEqual({ from: MIGRATIONS.length, to: MIGRATIONS.length, network: "testnet" }); // idempotent
      await expect(migratePostgres(p, { network: "mainnet", allowMainnet: true, verifyNetwork: async (p) => ({ genesisHash: p.caip2.slice(9) }) })).rejects.toThrow(/marker is testnet/);
      const b = (await openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL: url }, { mainnet: false }))!;
      await b.close();
      await p.query("INSERT INTO mr_schema (version) VALUES (999)");
      await expect(migratePostgres(p)).rejects.toThrow(/newer/);
      await expect(openStateBackend({ STATE_BACKEND: "postgres", DATABASE_URL: url }, { mainnet: false })).rejects.toThrow(/newer/);
      await p.end();
    } finally {
      await admin.query(`DROP DATABASE IF EXISTS ${db} WITH (FORCE)`);
    }
  });

  it("R18-P3-3: TLS with verification for non-loopback Postgres; loopback/socket unchanged", () => {
    expect(pgPoolConfig("postgres://mr@127.0.0.1:5432/db").ssl).toBeUndefined();
    expect(pgPoolConfig("postgres://mr@localhost/db").ssl).toBeUndefined();
    expect(pgPoolConfig("postgres:///db?host=/var/run/postgresql").ssl).toBeUndefined();
    const c = pgPoolConfig("postgres://u:p@db.example.rds.amazonaws.com:5432/mr?sslmode=require");
    expect(c.ssl).toMatchObject({ rejectUnauthorized: true });
    expect(c.connectionString).not.toContain("sslmode");
    expect(pgPoolConfig("postgres://u@db.example/mr").ssl).toMatchObject({ rejectUnauthorized: true }); // TLS even without sslmode
    for (const m of ["disable", "allow", "prefer", "no-verify"]) {
      expect(() => pgPoolConfig(`postgres://u:pw@db.example/mr?sslmode=${m}`)).toThrow(/refused/);
    }
    const dir = mkdtempSync(path.join(tmpdir(), "mr-ca-"));
    writeFileSync(path.join(dir, "ca.pem"), "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n");
    expect((pgPoolConfig("postgres://u@db.example/mr", { PG_SSL_CA_FILE: path.join(dir, "ca.pem") }).ssl as { ca?: string }).ca).toContain("BEGIN CERTIFICATE");
    expect(() => pgPoolConfig("postgres://u@db.example/mr", { PG_SSL_CA_FILE: "/nope" })).toThrow(/not readable/);
  });
  it("R18-P3-3: non-loopback Redis must be rediss:// with verification", () => {
    expect(redisTlsOptions("redis://127.0.0.1:6379")).toEqual({});
    expect(() => redisTlsOptions("redis://cache.example:6379")).toThrow(/rediss/);
    expect(redisTlsOptions("rediss://user:pw@cache.example:6379")).toEqual({ tls: { rejectUnauthorized: true, ca: undefined } });
  });
  it("R18-P3-3: opening with a plaintext remote URL is refused before connecting, redacted", async () => {
    const e = (await openStateBackend({ STATE_BACKEND: "redis+postgres", DATABASE_URL: "postgres://u:Pw1@db.example/mr", REDIS_URL: "redis://:Pw2@cache.example:6379" }, { mainnet: false }).catch((x) => x)) as Error;
    expect(e).toBeInstanceOf(StateBackendError);
    expect(e.message).toMatch(/rediss/);
    expect(e.message).not.toMatch(/Pw1|Pw2/);
  });
  it("R18-P3-3: apps never take MIGRATE_DATABASE_URL from their env file; migrate opts in", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "mr-env-"));
    const f = path.join(dir, "state.env");
    writeFileSync(f, "MIGRATE_DATABASE_URL=postgres://owner:pw@h/db\nDATABASE_URL=postgres://svc@h/db\nPG_SSL_CA_FILE=/etc/ca.pem\n");
    const appEnv: Record<string, string | undefined> = { STATE_ENV_FILE: f };
    loadStateEnvFile("bridge", appEnv);
    expect(appEnv.MIGRATE_DATABASE_URL).toBeUndefined();
    expect(appEnv).toMatchObject({ DATABASE_URL: "postgres://svc@h/db", PG_SSL_CA_FILE: "/etc/ca.pem" });
    const migEnv: Record<string, string | undefined> = { STATE_ENV_FILE: f };
    loadStateEnvFile("migrate", migEnv, ["MIGRATE_DATABASE_URL"]);
    expect(migEnv.MIGRATE_DATABASE_URL).toBe("postgres://owner:pw@h/db");
  });
  it("R18-P3-1: test output redactor", () => {
    const r = redactTestOutput(`failed: postgres://a:b@h:5/db and rediss://:x@c:6 password=hunter2 ${PG_URL ?? ""}`);
    expect(r).not.toMatch(/a:b@|:x@|hunter2/);
    if (PG_URL) expect(r).not.toContain(PG_URL);
  });
});

describe("R19-P3-2: effective host (incl. ?host=) decides loopback vs TLS", () => {
  it("postgres: ?host= pointing off-box is not loopback -> TLS verified; sslmode=disable refused", async () => {
    const { createRequire } = await import("node:module");
    const fromPg = createRequire(createRequire(import.meta.url).resolve("pg"));
    const { parse } = fromPg("pg-connection-string") as { parse: (s: string) => { host?: string | null } };
    const tricky = "postgres://u:p@127.0.0.1/db?host=db.example.com";
    expect(parse(tricky).host).toBe("db.example.com"); // what the driver really dials
    expect(pgPoolConfig(tricky).ssl).toMatchObject({ rejectUnauthorized: true });
    expect(() => pgPoolConfig(`${tricky}&sslmode=disable`)).toThrow(/refused/);
    expect(pgPoolConfig("postgres://u@localhost/db?host=10.0.0.5").ssl).toMatchObject({ rejectUnauthorized: true });
    expect(pgPoolConfig("postgres://u@127.0.0.1/db?host=127.0.0.1").ssl).toBeUndefined();
    expect(pgPoolConfig("postgres://u@127.0.0.1/db?host=%2Ftmp").ssl).toBeUndefined();
  });
  it("redis: ?host= off-box needs rediss://; tls query override refused", () => {
    expect(() => redisTlsOptions("redis://127.0.0.1:6379/?host=cache.example")).toThrow(/rediss/);
    expect(() => redisTlsOptions("redis://127.0.0.1:6379/?tls=false")).toThrow(/tls/);
    expect(redisTlsOptions("redis://127.0.0.1:6379/?host=localhost")).toEqual({});
  });
});
