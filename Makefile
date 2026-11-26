.PHONY: help install update lint format type-check test test-db boundaries contracts package check ci example clean

.DEFAULT_GOAL := help

CONTRACTS_TS := packages/contracts/ts/generated
# `make test-db` connects to the server's `postgres` maintenance database, where `#[sqlx::test]`
# keeps its bookkeeping and from which it creates a throwaway database per test. `make example`
# runs the example server against its own database. Override either on the command line or in the
# environment; the defaults match docker-compose.yml (`pnpm db:start`).
DATABASE_URL ?= postgres://postgres:postgres@localhost:5433/postgres
EXAMPLE_DATABASE_URL ?= postgres://postgres:postgres@localhost:5433/rustauth

help:
	@echo "Targets:"
	@echo "  install     Install pnpm and Cargo dependencies"
	@echo "  update      Update dependencies within semver ranges"
	@echo "  lint        rustfmt, clippy, Rust import paths, Biome, markdownlint"
	@echo "  format      Auto-fix formatting and lint"
	@echo "  type-check  cargo check + tsc across the workspace"
	@echo "  test        Rust and TypeScript unit tests"
	@echo "  test-db     Tests that need Postgres (ignored by default; uses DATABASE_URL)"
	@echo "  boundaries  Enforce crate dependency rules"
	@echo "  contracts   Regenerate TypeScript bindings from the Rust contracts"
	@echo "  package     Install @rustauth/contracts from git (HEAD) into a scratch app and type-check it"
	@echo "  check       format + lint + type-check + test + boundaries"
	@echo "  ci          check without writes, plus contract drift and the package check"
	@echo "  example     Run the example server (uses EXAMPLE_DATABASE_URL)"
	@echo "  clean       Wipe build output, dependencies, and the database volume"

install:
	pnpm install
	cargo fetch

update:
	pnpm update
	cargo update

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	bash scripts/lint-rust-imports.sh
	pnpm check:all
	pnpm check:markdown

format:
	cargo fmt --all
	pnpm check:fix:all
	pnpm check:markdown:fix

type-check:
	cargo check --workspace --all-targets --all-features
	pnpm type-check

test:
	cargo test --workspace
	pnpm test

test-db:
	DATABASE_URL=$(DATABASE_URL) cargo test --workspace --all-features -- --ignored

boundaries:
	node scripts/boundaries.mjs

contracts:
	rm -rf $(CONTRACTS_TS)
	cargo test -q -p rustauth-contracts --features ts export_bindings

package:
	bash scripts/check-package.sh

check: format lint type-check test boundaries

ci: lint type-check test boundaries contracts package
	git diff --exit-code -- $(CONTRACTS_TS) || (echo "Run 'make contracts' and commit the result." && false)
	@test -z "$$(git ls-files --others --exclude-standard -- $(CONTRACTS_TS))" || (echo "Untracked bindings: run 'make contracts' and commit." && false)

example:
	DATABASE_URL=$(EXAMPLE_DATABASE_URL) cargo run -p example-server

clean:
	docker compose down -v
	cargo clean
	find . -name node_modules -type d -prune -exec rm -rf {} +
