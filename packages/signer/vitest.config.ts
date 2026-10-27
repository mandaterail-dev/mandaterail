import { defineConfig } from "vitest/config";

// Files share real Postgres/Redis, and the restart test bounces them:
// run test files one at a time. test-redact.ts scrubs URLs from console output.
export default defineConfig({
  test: { fileParallelism: false, testTimeout: 60_000, setupFiles: ["./src/test-redact.ts"], include: ["test/**/*.test.ts"] },
});
