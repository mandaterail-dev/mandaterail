/** mr-piv-sign executable entry (R79-P3-2): `mr-piv-sign --stdio` only. Backend from MR_PIV_BACKEND / MR_KMS_CONFIG. */
import { mainStdio } from "./main-mainnet.js";

if (process.argv[2] !== "--stdio") { process.stderr.write("usage: mr-piv-sign --stdio\n"); process.exit(2); }
mainStdio().catch((e: unknown) => { process.stderr.write(`mr-piv-sign: ${(e as Error).message}\n`); process.exit(1); });
