import { zodToJsonSchema } from "zod-to-json-schema";
import { IntentMandateSchema } from "./intent-mandate.js";

/** JSON Schema (draft-07 style via zod-to-json-schema) for IntentMandate. */
export const IntentMandateJsonSchema = zodToJsonSchema(IntentMandateSchema, {
  name: "IntentMandate",
  $refStrategy: "none",
});
