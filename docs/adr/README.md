# Architecture Decision Records

This directory captures significant technical decisions for RustAuth. Each ADR records **why** a choice was made, not how it is implemented today. The working spec is [docs/design/rustauth.md](../design/rustauth.md).

To add a new ADR:

1. Copy `000-template.md` to a new file with the next number in sequence (for example `002-my-decision.md`).
2. Fill in the sections and set the status.
3. Update the status of any ADRs this one supersedes.

## Index

- [001 - Layered Crates and Storage in the `auth` Schema](./001-architecture.md)
