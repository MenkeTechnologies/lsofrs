//! lsofrs — modern, high-performance lsof implementation in Rust
//!
//! Maps the relationship between processes and the files they hold open.
//! Supports regular files, directories, sockets, pipes, devices, and streams.

#![allow(dead_code)]

pub mod cli;
#[cfg(target_os = "macos")]
pub mod darwin;
pub mod delta;
pub mod filter;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod output;
pub mod types;
