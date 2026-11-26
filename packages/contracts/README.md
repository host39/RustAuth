# @rustauth/contracts

TypeScript types and Zod schemas for the RustAuth HTTP API. The types are generated from the Rust DTOs in `crates/rustauth-contracts` (`make contracts`), and every schema `satisfies` its generated type.

## Install

The package is not published to a registry. Install it from the lib-rustauth repository, pinned to the same tag or commit as the `rustauth` crate:

```sh
pnpm add "@rustauth/contracts@github:host39/lib-rustauth#<tag-or-commit>&path:packages/contracts"
```

`zod` 4 is a peer dependency, so the schemas share the application's copy.

## Compile From Source

The package ships TypeScript sources (`ts/index.ts`), not JavaScript. The application's bundler compiles them, and its `tsconfig.json` needs `"moduleResolution": "bundler"` (the package uses `exports` and `#generated/*` subpath imports). Rsbuild compiles TypeScript in `node_modules` by default; with another bundler, or an Rsbuild `source.exclude` that covers it, add the package to the compiled files (Rsbuild `source.include`). Node cannot run it from `node_modules` directly.

## Usage

```ts
import { authRoutes, errorResponseSchema, signInBodySchema } from "@rustauth/contracts";

const response = await fetch(`/api${authRoutes.login}`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username, password }),
});
if (!response.ok) throw errorResponseSchema.parse(await response.json());
const { data } = signInBodySchema.parse(await response.json());
```

See [docs/integration.md](../../docs/integration.md) for the whole integration, server and web.
