import { defineConfig } from "vitest/config";
// Opt-in rehearsal (not part of `pnpm test`): MR_REHEARSAL=1, see a1-a6.rehearsal.test.ts
export default defineConfig({ test: { root: __dirname, include: ["*.rehearsal.test.ts"], fileParallelism: false, testTimeout: 180_000, hookTimeout: 180_000, setupFiles: ["../src/test-redact.ts"] } });
