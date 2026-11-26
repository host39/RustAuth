#!/usr/bin/env bash
# The upgrade check ("Upgrade Testing" in docs/design/rustauth.md; the CI `upgrade` job and
# `make test-upgrade`). It plays an application that upgrades from the previous release tag to
# the current code:
#
# 1. Checks out the previous release tag into a temporary git worktree and runs its upgrade
#    harness (`cargo run -p rustauth --example upgrade -- seed`): a fresh database, that
#    release's migrations, and sample data written through that release's code.
# 2. Runs the current harness (`-- check`): the current migrate step on that database, then the
#    sample accounts, sessions, lockouts, and application rows through the current code.
# 3. Runs the Postgres test suite (`make test-db`) with that database as its maintenance
#    database. This is a regression run of the current code only: `#[sqlx::test]` creates and
#    migrates a throwaway database per test next to it, so no test reads the upgraded schema or
#    rows. Step 2 is what checks them; add anything an upgrade must preserve to the harness.
#
# Before the first release tag there is nothing to upgrade from: the check then seeds with the
# current code as well, so the harness the first tag ships is known to work, and passes with a
# notice.
#
# DATABASE_URL names the server's maintenance database, as for `make test-db`. The upgrade
# database `rustauth_upgrade` (RUSTAUTH_UPGRADE_DATABASE_URL overrides it) is dropped and
# recreated next to it, and left in place afterwards for inspection. Needs the full git history
# with tags (in CI, actions/checkout with `fetch-depth: 0`).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

database_url="${DATABASE_URL:-postgres://postgres:postgres@localhost:5433/postgres}"
base="${database_url%%\?*}"
query="${database_url#"$base"}"
export RUSTAUTH_UPGRADE_DATABASE_URL="${RUSTAUTH_UPGRADE_DATABASE_URL:-${base%/*}/rustauth_upgrade$query}"
# Both releases build into one target directory, so the dependencies they share compile once.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target}"

scratch="$(mktemp -d)"
previous_dir="$scratch/previous"
export RUSTAUTH_UPGRADE_MANIFEST="$scratch/manifest.json"
cleanup() {
  if [ -d "$previous_dir" ]; then
    git -C "$root" worktree remove --force "$previous_dir" || true
  fi
  rm -rf "$scratch"
}
trap cleanup EXIT

notice() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::notice title=Upgrade check::$1"
  else
    echo "check-upgrade: $1"
  fi
}

if [ "$(git rev-parse --is-shallow-repository)" = "true" ]; then
  echo "check-upgrade: needs the full history and tags (actions/checkout with fetch-depth: 0)" >&2
  exit 1
fi

# The previous release: the newest release tag reachable from HEAD, leaving out tags on HEAD
# itself (the release being made is not its own predecessor).
exclude=()
while read -r tag; do
  if [ -n "$tag" ]; then
    exclude+=(--exclude "$tag")
  fi
done < <(git tag --points-at HEAD)
previous="$(git describe --tags --abbrev=0 --match 'v[0-9]*' ${exclude[@]+"${exclude[@]}"} HEAD 2>/dev/null || true)"

if [ -n "$previous" ]; then
  echo "check-upgrade: upgrading from $previous to $(git rev-parse --short HEAD)"
  git worktree add --detach "$previous_dir" "$previous"
  seed_dir="$previous_dir"
else
  notice "No release tag yet, so there is nothing to upgrade from: seeded and checked with the current code to test the upgrade harness."
  seed_dir="$root"
fi

# Run from the release's own directory, so its rust-toolchain.toml and Cargo.lock apply.
(cd "$seed_dir" && cargo run --locked -p rustauth --example upgrade -- seed)
cargo run --locked -p rustauth --example upgrade -- check
make test-db DATABASE_URL="$RUSTAUTH_UPGRADE_DATABASE_URL"

if [ -n "$previous" ]; then
  echo "check-upgrade: $previous upgrades cleanly"
fi
