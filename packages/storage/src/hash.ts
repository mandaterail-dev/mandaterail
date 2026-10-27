import { createHash } from "node:crypto";
/** R74-P3-3: the one sha256-hex helper for the anchor / B2 / monitor paths (bytes or UTF-8 string). */
export const sha256hex = (b: string | Uint8Array): string => createHash("sha256").update(b).digest("hex");
