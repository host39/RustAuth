//! Rebuilds the crate when a migration is added, so `sqlx::migrate!` embeds it. (Changes to an
//! existing file are tracked already; a new file in the directory is not.) Cargo reads these
//! instructions from standard output, and Clippy's `print_stdout` lint skips build scripts.

fn main() {
    println!("cargo::rerun-if-changed=migrations");
}
