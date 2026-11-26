#!/usr/bin/env bash
# Installs @rustauth/contracts into a scratch application the way applications install it (a pnpm
# git dependency with `&path:packages/contracts`), then type-checks a consumer file under the
# strict compiler options web apps enable. Catches a package.json that ships or resolves the
# sources wrongly (`files`, `exports`, the `#generated/*` imports, the zod peer).
#
# It installs the committed HEAD of this repository through `git+file://`, which uses the same
# git fetcher as `github:host39/lib-rustauth#<ref>&path:packages/contracts`. Commit first.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
commit="$(git -C "$root" rev-parse HEAD)"
tsc="$root/node_modules/.bin/tsc"
zod="$(node -p 'require(process.argv[1]).version' "$root/packages/contracts/node_modules/zod/package.json")"

if ! git -C "$root" diff --quiet HEAD -- packages/contracts; then
  echo "check-package: uncommitted changes in packages/contracts are not part of this check"
fi

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/src"

cat >"$scratch/package.json" <<EOF
{
  "name": "contracts-consumer",
  "private": true,
  "type": "module",
  "dependencies": {
    "@rustauth/contracts": "git+file://$root#$commit&path:packages/contracts",
    "zod": "$zod"
  }
}
EOF

cat >"$scratch/tsconfig.json" <<'EOF'
{
  "compilerOptions": {
    "lib": ["DOM", "ES2022"],
    "target": "ES2022",
    "module": "ESNext",
    "moduleDetection": "force",
    "moduleResolution": "bundler",
    "noEmit": true,
    "skipLibCheck": true,
    "strict": true,
    "verbatimModuleSyntax": true,
    "allowImportingTsExtensions": true,
    "noUncheckedSideEffectImports": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noUncheckedIndexedAccess": true,
    "noPropertyAccessFromIndexSignature": true,
    "types": []
  },
  "include": ["src"]
}
EOF

cat >"$scratch/src/client.ts" <<'EOF'
import {
  AUTH_ERROR_CODES,
  type AuthErrorCode,
  authRoutes,
  type ErrorResponse,
  errorResponseSchema,
  REQUEST_ID_HEADER,
  registerRequestSchema,
  retryAfterSecs,
  type SignInResponse,
  signInBodySchema,
  USER_ROLES,
  type UserRole,
  userListBodySchema,
} from "@rustauth/contracts";

export async function signIn(base: string, username: string, password: string) {
  const response = await fetch(`${base}${authRoutes.login}`, {
    method: "POST",
    headers: { "content-type": "application/json", [REQUEST_ID_HEADER]: "consumer-1" },
    body: JSON.stringify({ username, password }),
  });
  const body: unknown = await response.json();
  if (!response.ok) {
    const error: ErrorResponse = errorResponseSchema.parse(body);
    const code = AUTH_ERROR_CODES.find((known): known is AuthErrorCode => known === error.code);
    return { code, wait: retryAfterSecs(error) };
  }
  const session: SignInResponse = signInBodySchema.parse(body).data;
  const role: UserRole = session.user.role;
  return { token: session.token, admin: role === USER_ROLES[0] };
}

export const form = registerRequestSchema.safeParse({});
export const users = userListBodySchema.parse({ items: [], total: 0 }).items;
EOF

cd "$scratch"
pnpm install --silent
test -f node_modules/@rustauth/contracts/ts/index.ts
test ! -e node_modules/@rustauth/contracts/test
"$tsc" -p tsconfig.json
echo "check-package: @rustauth/contracts at $commit installs from git and type-checks (zod $zod)"
