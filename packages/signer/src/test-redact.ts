/**
 * Vitest setup (R18-P3-1): redact connection strings / passwords from
 * anything tests print via console.* inside the workers. The runner output
 * is additionally piped through the redactor in with-state-services.sh.
 */
const lits = [process.env.MR_TEST_PG_URL, process.env.MR_TEST_REDIS_URL, process.env.DATABASE_URL, process.env.REDIS_URL].filter(
  (v): v is string => !!v,
);
export function redactTestOutput(s: string): string {
  let out = s;
  for (const v of lits) out = out.split(v).join("[redacted-url]");
  return out
    .replace(/\b(postgres(?:ql)?|rediss?):\/\/[^\s"'`<>]+/g, "$1://[redacted]")
    .replace(/(password|passwd|pwd)=[^\s&]+/gi, "$1=***");
}
for (const m of ["log", "info", "warn", "error", "debug"] as const) {
  const orig = console[m].bind(console);
  console[m] = (...args: unknown[]) =>
    orig(...args.map((a) => (typeof a === "string" ? redactTestOutput(a) : a instanceof Error ? redactTestOutput(a.stack ?? a.message) : a)));
}
