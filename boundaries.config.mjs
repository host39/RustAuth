// Dependency boundaries between workspace crates, checked by `make boundaries`
// (scripts/boundaries.mjs). Cargo already limits a crate to what its Cargo.toml lists; these
// rules stop the wrong entries from being added there. The table in docs/design/rustauth.md
// ("Repository Layout") is the source for these rules.
//
// `from` is a crate name; `to` lists crates it must not depend on directly (normal or build
// dependencies; dev-dependencies are only compiled for tests and are not checked).

/** Crates that ship in the library (everything except the example application). */
const LIBRARY_CRATES = [
  "rustauth",
  "rustauth-axum",
  "rustauth-contracts",
  "rustauth-core",
  "rustauth-crypto",
  "rustauth-postgres",
];

/** @type {{ forbidden: { name: string, severity: "error" | "warn", comment: string, from: string, to: string[] }[] }} */
export default {
  forbidden: [
    {
      name: "core-is-pure",
      severity: "error",
      comment:
        "rustauth-core is the domain: no HTTP, database, OpenAPI, TypeScript, or hashing crates, and no other rustauth crate",
      from: "rustauth-core",
      to: [
        "rustauth",
        "rustauth-axum",
        "rustauth-contracts",
        "rustauth-crypto",
        "rustauth-postgres",
        "argon2",
        "axum",
        "hyper",
        "sqlx",
        "tower",
        "tower-http",
        "tracing-subscriber",
        "ts-rs",
        "utoipa",
        "utoipa-axum",
      ],
    },
    {
      name: "crypto-no-infrastructure",
      severity: "error",
      comment: "rustauth-crypto implements core ports only: no HTTP or database crates",
      from: "rustauth-crypto",
      to: ["rustauth-axum", "rustauth-postgres", "axum", "sqlx"],
    },
    {
      name: "postgres-no-http",
      severity: "error",
      comment: "rustauth-postgres implements core ports only: no HTTP, OpenAPI, or crypto crates",
      from: "rustauth-postgres",
      to: ["rustauth-axum", "rustauth-crypto", "axum", "utoipa"],
    },
    {
      name: "contracts-transport-only",
      severity: "error",
      comment: "rustauth-contracts holds DTOs only: no database or HTTP framework crates",
      from: "rustauth-contracts",
      to: ["rustauth-postgres", "axum", "sqlx"],
    },
    {
      name: "axum-talks-to-core",
      severity: "error",
      comment:
        "rustauth-axum talks to core services only; the facade wires the storage and crypto adapters",
      from: "rustauth-axum",
      to: ["rustauth-crypto", "rustauth-postgres", "sqlx"],
    },
    {
      name: "example-uses-facade",
      severity: "error",
      comment:
        "examples/server shows the supported integration: the rustauth facade, never the inner crates",
      from: "example-server",
      to: [
        "rustauth-axum",
        "rustauth-contracts",
        "rustauth-core",
        "rustauth-crypto",
        "rustauth-postgres",
      ],
    },
    ...LIBRARY_CRATES.map((from) => ({
      name: "no-outbound-http",
      severity: "error",
      comment: "the library makes no outbound HTTP calls in v0.1 (keep it reqwest-free)",
      from,
      to: ["reqwest"],
    })),
  ],
};
