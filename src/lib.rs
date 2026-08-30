//! lsofrs — modern, high-performance lsof implementation in Rust
//!
//! Maps the relationship between processes and the files they hold open.
//! Supports regular files, directories, sockets, pipes, devices, and streams.
//!
//! The binary entry points (`lsofrs`, `lsf`, and the `lsof` alias crate) are
//! all one line over [`run()`], so every shipped name runs identical code.

#![allow(dead_code)]

pub mod cli;
/// `config` submodule.
pub mod config;
/// `csv_out` submodule.
pub mod csv_out;
/// `darwin` submodule.
#[cfg(target_os = "macos")]
pub mod darwin;
/// `delta` submodule.
pub mod delta;
/// `filter` submodule.
pub mod filter;
/// `follow` submodule.
pub mod follow;
/// `freebsd` submodule.
#[cfg(target_os = "freebsd")]
pub mod freebsd;
/// `json` submodule.
pub mod json;
/// `leak` submodule.
pub mod leak;
/// `linux` submodule.
#[cfg(target_os = "linux")]
pub mod linux;
/// `monitor` submodule.
pub mod monitor;
/// `net_map` submodule.
pub mod net_map;
/// `output` submodule.
pub mod output;
/// `pipe_chain` submodule.
pub mod pipe_chain;
/// `ports` submodule.
pub mod ports;
/// `run` submodule — the CLI dispatch shared by every binary name.
pub mod run;
/// `stale` submodule.
pub mod stale;
/// `stall` submodule.
pub mod stall;
/// `strutil` submodule.
pub mod strutil;
/// `summary` submodule.
pub mod summary;
/// `theme` submodule.
pub mod theme;
/// `top` submodule.
pub mod top;
/// `tree` submodule.
pub mod tree;
/// `tui_app` submodule.
pub mod tui_app;
/// `tui_tabs` submodule.
pub mod tui_tabs;
/// `types` submodule.
pub mod types;
/// `watch` submodule.
pub mod watch;

pub use run::{gather_processes, run};
