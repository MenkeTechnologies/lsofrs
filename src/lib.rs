//! lsofrs — modern, high-performance lsof implementation in Rust
//!
//! Maps the relationship between processes and the files they hold open.
//! Supports regular files, directories, sockets, pipes, devices, and streams.

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
/// `freebsd` submodule.
#[cfg(target_os = "freebsd")]
pub mod freebsd;
/// `linux` submodule.
#[cfg(target_os = "linux")]
pub mod linux;
/// `net_map` submodule.
pub mod net_map;
/// `output` submodule.
pub mod output;
/// `pipe_chain` submodule.
pub mod pipe_chain;
/// `strutil` submodule.
pub mod strutil;
/// `types` submodule.
pub mod types;
