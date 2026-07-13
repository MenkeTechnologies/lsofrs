//! Per-FD socket backpressure classifier — poll each socket FD's kernel
//! send/recv buffer occupancy over successive samples and classify the
//! direction of the stall.
//!
//! Verdicts, per `(pid, fd)`:
//!   * `TX-STALLED`  — the send buffer stays persistently near capacity and is
//!     not draining. The local process keeps writing but the kernel cannot hand
//!     the bytes off: the peer (or the network) is not reading.
//!   * `RX-STARVED`  — the receive buffer stays persistently high (and often
//!     grows). Bytes have arrived but the local process is not `read()`-ing them
//!     fast enough.
//!   * `HEALTHY`     — neither buffer is persistently backed up.
//!
//! On macOS all four inputs (`recv_queue`/`send_queue`/`recv_buf_size`/
//! `send_buf_size`) are available, so classification is fill-ratio based. On
//! Linux `/proc/net/tcp` exposes the queue occupancies but not the socket buffer
//! limits, so the classifier falls back to a trend rule (persistently non-zero
//! and non-draining/growing).

use std::collections::HashMap;
use std::io::{self, Write};

use crate::output::Theme;
use crate::strutil::truncate_max_bytes;
use crate::types::*;

const HISTORY_SIZE: usize = 16;

/// Minimum consecutive samples required before a verdict can be issued.
const MIN_SAMPLES: usize = 3;

/// A buffer is "near capacity" once its occupancy reaches this fraction of the
/// socket buffer limit.
const HIGH_RATIO: f64 = 0.80;

/// Directional backpressure verdict for a single `(pid, fd)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Neither direction is backed up.
    Healthy,
    /// Send buffer persistently near capacity, not draining — peer not reading.
    TxStalled,
    /// Recv buffer persistently high/growing — local process not draining.
    RxStarved,
}

impl Verdict {
    /// Short label for tabular output.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "HEALTHY",
            Self::TxStalled => "TX-STALLED",
            Self::RxStarved => "RX-STARVED",
        }
    }

    /// Whether this verdict represents backpressure worth reporting.
    fn is_stalled(self) -> bool {
        !matches!(self, Self::Healthy)
    }
}

/// One occupancy snapshot for a single socket FD.
#[derive(Debug, Clone, Copy)]
struct StallSample {
    /// Bytes currently queued in the send buffer.
    send_q: u64,
    /// Bytes currently queued in the recv buffer.
    recv_q: u64,
    /// Send buffer capacity (`0` = unknown, e.g. Linux `/proc/net/tcp`).
    send_buf: u64,
    /// Recv buffer capacity (`0` = unknown).
    recv_buf: u64,
    timestamp: i64,
}

struct StallEntry {
    pid: i32,
    fd: i32,
    command: String,
    proto: String,
    peer: String,
    history: Vec<StallSample>,
    verdict: Verdict,
    seen: bool,
}

/// `StallDetector` — tracks per-`(pid, fd)` socket buffer occupancy history and
/// classifies backpressure direction.
pub struct StallDetector {
    table: HashMap<(i32, i32), StallEntry>,
    iteration: u64,
}

impl StallDetector {
    /// `new` — empty detector.
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
            iteration: 0,
        }
    }

    /// Ingest one scan: record a fresh occupancy sample for every socket FD and
    /// recompute its verdict.
    pub fn update(&mut self, procs: &[Process]) {
        self.iteration += 1;
        let now = chrono::Utc::now().timestamp();

        for entry in self.table.values_mut() {
            entry.seen = false;
        }

        for p in procs {
            for f in &p.files {
                let FdName::Number(fd) = f.fd else {
                    continue;
                };
                let Some(si) = &f.socket_info else {
                    continue;
                };
                // Only sockets that expose at least one queue occupancy are
                // classifiable.
                let (Some(send_q), Some(recv_q)) = (si.send_queue, si.recv_queue) else {
                    continue;
                };

                let sample = StallSample {
                    send_q,
                    recv_q,
                    send_buf: si.send_buf_size.unwrap_or(0),
                    recv_buf: si.recv_buf_size.unwrap_or(0),
                    timestamp: now,
                };

                let key = (p.pid, fd);
                let entry = self.table.entry(key).or_insert_with(|| StallEntry {
                    pid: p.pid,
                    fd,
                    command: p.command.clone(),
                    proto: si.protocol.clone(),
                    peer: f.name.clone(),
                    history: Vec::with_capacity(HISTORY_SIZE),
                    verdict: Verdict::Healthy,
                    seen: false,
                });

                entry.seen = true;

                // PID reuse: a different command on the same (pid, fd) restarts.
                if entry.command != p.command {
                    entry.command = p.command.clone();
                    entry.history.clear();
                    entry.verdict = Verdict::Healthy;
                }
                entry.proto = si.protocol.clone();
                entry.peer = f.name.clone();

                if entry.history.len() >= HISTORY_SIZE {
                    entry.history.remove(0);
                }
                entry.history.push(sample);

                entry.verdict = classify(&entry.history);
            }
        }

        // Drop FDs that are gone and not currently stalled.
        self.table
            .retain(|_, e| e.seen || e.verdict.is_stalled());
    }

    /// Print the current backpressure report.
    pub fn report(&self, theme: &Theme) {
        let out = io::stdout();
        let mut out = out.lock();

        let mut stalled: Vec<&StallEntry> = self
            .table
            .values()
            .filter(|e| e.seen && e.verdict.is_stalled())
            .collect();
        stalled.sort_by_key(|e| (e.pid, e.fd));

        let scanned = self.table.values().filter(|e| e.seen).count();

        let _ = writeln!(
            out,
            "\n{bold}═══ lsofrs socket backpressure ═══{reset}",
            bold = theme.bold(),
            reset = theme.reset(),
        );
        let _ = writeln!(
            out,
            "  iteration: {} | sockets: {} | stalled: {red}{}{reset}\n",
            self.iteration,
            scanned,
            stalled.len(),
            red = if stalled.is_empty() { "" } else { theme.red() },
            reset = theme.reset(),
        );

        if stalled.is_empty() {
            let _ = writeln!(
                out,
                "  {green}No stalled sockets detected.{reset}",
                green = theme.green(),
                reset = theme.reset(),
            );
            let _ = writeln!(out);
            return;
        }

        let _ = writeln!(
            out,
            "  {hdr}{bold}{:>7}  {:>5}  {:<12}  {:<11}  {:>7}  PEER{reset}",
            "PID",
            "FD",
            "COMMAND",
            "VERDICT",
            "PROTO",
            hdr = theme.hdr_bg(),
            bold = theme.bold(),
            reset = theme.reset(),
        );

        for e in &stalled {
            let cmd = truncate_max_bytes(&e.command, 12);
            let peer = truncate_max_bytes(&e.peer, 40);
            let color = match e.verdict {
                Verdict::TxStalled => theme.red(),
                Verdict::RxStarved => theme.yellow(),
                Verdict::Healthy => theme.green(),
            };

            let _ = writeln!(
                out,
                "  {red}{:>7}{reset}  {:>5}  {cyan}{:<12}{reset}  {color}{:<11}{reset}  {:>7}  {}",
                e.pid,
                e.fd,
                cmd,
                e.verdict.as_str(),
                e.proto,
                peer,
                red = theme.red(),
                cyan = theme.cyan(),
                color = color,
                reset = theme.reset(),
            );
        }

        let _ = writeln!(out);
    }
}

impl Default for StallDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify the send direction over the trailing window. Returns the stall
/// severity (min fill ratio, or a growth proxy when buffer sizes are unknown)
/// when the send buffer is persistently backed up, else `None`.
fn tx_severity(w: &[StallSample]) -> Option<f64> {
    if w.iter().all(|s| s.send_buf > 0) {
        // Fill-ratio rule: send buffer never drained below the high-water mark
        // across the window, and is not on a downward trend.
        let ratios: Vec<f64> = w.iter().map(|s| s.send_q as f64 / s.send_buf as f64).collect();
        let min_r = ratios.iter().copied().fold(f64::INFINITY, f64::min);
        let first = *ratios.first().unwrap();
        let last = *ratios.last().unwrap();
        if min_r >= HIGH_RATIO && last >= first - f64::EPSILON {
            return Some(min_r);
        }
        None
    } else {
        // Trend fallback: send queue persistently non-zero and non-draining.
        let qs: Vec<u64> = w.iter().map(|s| s.send_q).collect();
        let all_pos = qs.iter().all(|&q| q > 0);
        let non_decreasing = qs.windows(2).all(|p| p[1] >= p[0]);
        if all_pos && non_decreasing {
            let max = *qs.iter().max().unwrap() as f64;
            return Some(if max > 0.0 {
                *qs.last().unwrap() as f64 / max
            } else {
                0.0
            });
        }
        None
    }
}

/// Classify the receive direction over the trailing window. Returns the stall
/// severity when the recv buffer is persistently high (and not draining), else
/// `None`.
fn rx_severity(w: &[StallSample]) -> Option<f64> {
    if w.iter().all(|s| s.recv_buf > 0) {
        let ratios: Vec<f64> = w.iter().map(|s| s.recv_q as f64 / s.recv_buf as f64).collect();
        let min_r = ratios.iter().copied().fold(f64::INFINITY, f64::min);
        let first = *ratios.first().unwrap();
        let last = *ratios.last().unwrap();
        // Persistently high and not draining down (flat or growing).
        if min_r >= HIGH_RATIO && last >= first - f64::EPSILON {
            return Some(min_r);
        }
        None
    } else {
        // Trend fallback: recv queue persistently non-zero and strictly growing.
        let qs: Vec<u64> = w.iter().map(|s| s.recv_q).collect();
        let all_pos = qs.iter().all(|&q| q > 0);
        let non_decreasing = qs.windows(2).all(|p| p[1] >= p[0]);
        let grew = *qs.last().unwrap() > *qs.first().unwrap();
        if all_pos && non_decreasing && grew {
            let max = *qs.iter().max().unwrap() as f64;
            return Some(if max > 0.0 {
                *qs.last().unwrap() as f64 / max
            } else {
                0.0
            });
        }
        None
    }
}

/// Classify a `(pid, fd)` history into a directional [`Verdict`]. When both
/// directions are backed up, the one with the higher severity wins.
fn classify(history: &[StallSample]) -> Verdict {
    let n = history.len();
    if n < MIN_SAMPLES {
        return Verdict::Healthy;
    }
    let w = &history[n - MIN_SAMPLES..];

    match (tx_severity(w), rx_severity(w)) {
        (Some(tx), Some(rx)) => {
            if tx >= rx {
                Verdict::TxStalled
            } else {
                Verdict::RxStarved
            }
        }
        (Some(_), None) => Verdict::TxStalled,
        (None, Some(_)) => Verdict::RxStarved,
        (None, None) => Verdict::Healthy,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(send_q: u64, recv_q: u64, send_buf: u64, recv_buf: u64) -> StallSample {
        StallSample {
            send_q,
            recv_q,
            send_buf,
            recv_buf,
            timestamp: 0,
        }
    }

    #[test]
    fn classifier_directional_verdicts() {
        // Fewer than MIN_SAMPLES samples cannot be classified yet.
        let warmup = vec![sample(98, 2, 100, 100), sample(97, 3, 100, 100)];
        assert_eq!(classify(&warmup), Verdict::Healthy);

        // TX-STALLED: send buffer pinned near capacity (>=80%) across the whole
        // window and not draining; recv buffer near-empty.
        let tx = vec![
            sample(95, 4, 100, 100),
            sample(96, 5, 100, 100),
            sample(97, 3, 100, 100),
            sample(98, 4, 100, 100),
        ];
        assert_eq!(classify(&tx), Verdict::TxStalled);

        // RX-STARVED: recv buffer persistently high and growing; send drained.
        let rx = vec![
            sample(3, 85, 100, 100),
            sample(2, 90, 100, 100),
            sample(4, 95, 100, 100),
            sample(1, 98, 100, 100),
        ];
        assert_eq!(classify(&rx), Verdict::RxStarved);

        // HEALTHY: a send buffer that actually drains (falls below high-water).
        let draining = vec![
            sample(95, 4, 100, 100),
            sample(50, 3, 100, 100),
            sample(10, 5, 100, 100),
            sample(4, 2, 100, 100),
        ];
        assert_eq!(classify(&draining), Verdict::Healthy);

        // HEALTHY: both buffers comfortably below the high-water mark.
        let idle = vec![
            sample(10, 8, 100, 100),
            sample(12, 6, 100, 100),
            sample(9, 7, 100, 100),
        ];
        assert_eq!(classify(&idle), Verdict::Healthy);

        // Linux trend fallback (buffer sizes unknown = 0): a growing recv queue
        // that never drains classifies as RX-STARVED without any ratio input.
        let linux_rx = vec![
            sample(0, 1000, 0, 0),
            sample(0, 4000, 0, 0),
            sample(0, 9000, 0, 0),
        ];
        assert_eq!(classify(&linux_rx), Verdict::RxStarved);
    }
}
