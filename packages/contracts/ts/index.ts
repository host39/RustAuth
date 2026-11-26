// Zod schemas for the RustAuth HTTP contracts. The Rust structs in `crates/rustauth-contracts/` are
// the source of truth: `make contracts` regenerates the types in `ts/generated/`, and each schema
// below must satisfy its generated type, so drift fails `make type-check`.
//
// Internal imports use the `#generated/*` subpath import from package.json, so they resolve the
// same way inside this repository and in applications that install the package from git.

import { z } from "zod";
import type { ErrorResponse } from "#generated/ErrorResponse";

export type { ErrorResponse } from "#generated/ErrorResponse";

export const REQUEST_ID_HEADER = "X-Request-Id";

export const errorResponseSchema = z.object({
  error: z.string(),
  code: z.string().optional(),
  field: z.string().optional(),
  details: z.record(z.string(), z.json()).optional(),
  requestId: z.string().optional(),
}) satisfies z.ZodType<ErrorResponse>;
