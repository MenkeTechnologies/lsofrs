//! `lsof` — the traditional command name, dispatching into `lsofrs::run()`.
//!
//! Installing this crate shadows the system `lsof` on PATH with lsofrs. The
//! implementation lives entirely in the `lsofrs` crate; this file exists only
//! to claim the binary name.

fn main() {
    lsofrs::run();
}
