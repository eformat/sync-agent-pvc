//! The UI bundle is embedded via `#[derive(RustEmbed)]` in api.rs at compile
//! time. Without this script cargo only recompiles when a .rs file changes —
//! a UI-only rebuild (npm → dist) shipped a STALE embedded bundle (the served
//! asset hash didn't change; hit 2026-11-06 with the tabs/filter work).
fn main() {
    println!("cargo:rerun-if-changed=ui/dist");
    println!("cargo:rerun-if-changed=ui/src");
}
