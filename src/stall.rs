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
        self.table.retain(|_, e| e.seen || e.verdict.is_stalled());
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
        let ratios: Vec<f64> = w
            .iter()
            .map(|s| s.send_q as f64 / s.send_buf as f64)
            .collect();
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
        let ratios: Vec<f64> = w
            .iter()
            .map(|s| s.recv_q as f64 / s.recv_buf as f64)
            .collect();
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

    /// A process with one TCP socket on `fd` reporting the given occupancies.
    fn sock_proc(
        pid: i32,
        cmd: &str,
        fd: i32,
        send_q: u64,
        recv_q: u64,
        bufs: Option<u64>,
    ) -> Process {
        Process::new(
            pid,
            1,
            1,
            501,
            cmd.to_string(),
            vec![OpenFile {
                fd: FdName::Number(fd),
                file_type: FileType::IPv4,
                name: "10.0.0.1:5000->10.0.0.2:80".to_string(),
                socket_info: Some(SocketInfo {
                    protocol: "TCP".to_string(),
                    send_queue: Some(send_q),
                    recv_queue: Some(recv_q),
                    send_buf_size: bufs,
                    recv_buf_size: bufs,
                    ..Default::default()
                }),
                ..Default::default()
            }],
        )
    }

    fn verdict_of(d: &StallDetector, pid: i32, fd: i32) -> Option<Verdict> {
        d.table.get(&(pid, fd)).map(|e| e.verdict)
    }

    #[test]
    fn verdict_labels_match_report_column() {
        assert_eq!(Verdict::Healthy.as_str(), "HEALTHY");
        assert_eq!(Verdict::TxStalled.as_str(), "TX-STALLED");
        assert_eq!(Verdict::RxStarved.as_str(), "RX-STARVED");
        assert!(!Verdict::Healthy.is_stalled());
        assert!(Verdict::TxStalled.is_stalled());
        assert!(Verdict::RxStarved.is_stalled());
    }

    #[test]
    fn classifier_only_looks_at_trailing_window() {
        // An early drain followed by three pinned samples is a stall now.
        let h = vec![
            sample(10, 0, 100, 100),
            sample(5, 0, 100, 100),
            sample(90, 0, 100, 100),
            sample(91, 0, 100, 100),
            sample(92, 0, 100, 100),
        ];
        assert_eq!(classify(&h), Verdict::TxStalled);

        // A stall that has since drained is healthy, regardless of history.
        let h = vec![
            sample(95, 0, 100, 100),
            sample(96, 0, 100, 100),
            sample(97, 0, 100, 100),
            sample(97, 0, 100, 100),
            sample(40, 0, 100, 100),
        ];
        assert_eq!(classify(&h), Verdict::Healthy);
    }

    #[test]
    fn classifier_ratio_rule_boundaries() {
        // Exactly the high-water mark counts as near capacity.
        let at_mark = vec![sample(80, 0, 100, 100); 3];
        assert_eq!(classify(&at_mark), Verdict::TxStalled);

        // One sample just under the mark breaks the stall.
        let dip = vec![
            sample(90, 0, 100, 100),
            sample(79, 0, 100, 100),
            sample(90, 0, 100, 100),
        ];
        assert_eq!(classify(&dip), Verdict::Healthy);

        // Above the mark but trending down is draining, not stalled.
        let easing = vec![
            sample(99, 0, 100, 100),
            sample(95, 0, 100, 100),
            sample(90, 0, 100, 100),
        ];
        assert_eq!(classify(&easing), Verdict::Healthy);

        // A recv buffer pinned flat at capacity is starved (no growth needed
        // when the limit is known).
        let rx_flat = vec![sample(0, 100, 100, 100); 3];
        assert_eq!(classify(&rx_flat), Verdict::RxStarved);
    }

    #[test]
    fn classifier_both_directions_higher_severity_wins() {
        // Send pinned at >=95%, recv at >=85%: TX is the worse direction.
        let tx_worse = vec![
            sample(95, 85, 100, 100),
            sample(96, 86, 100, 100),
            sample(97, 87, 100, 100),
        ];
        assert_eq!(classify(&tx_worse), Verdict::TxStalled);

        let rx_worse = vec![
            sample(85, 95, 100, 100),
            sample(86, 96, 100, 100),
            sample(87, 97, 100, 100),
        ];
        assert_eq!(classify(&rx_worse), Verdict::RxStarved);

        // A tie goes to TX.
        let tie = vec![sample(90, 90, 100, 100); 3];
        assert_eq!(classify(&tie), Verdict::TxStalled);
    }

    #[test]
    fn classifier_trend_fallback_without_buffer_limits() {
        // Linux /proc/net/tcp: no buffer sizes. A send queue that never drains
        // is TX-STALLED even when flat.
        let tx_flat = vec![sample(4096, 0, 0, 0); 3];
        assert_eq!(classify(&tx_flat), Verdict::TxStalled);

        // A recv queue must actually grow; flat non-zero is not starvation.
        let rx_flat = vec![sample(0, 4096, 0, 0); 3];
        assert_eq!(classify(&rx_flat), Verdict::Healthy);

        // Any zero in the window means the queue drained at some point.
        let tx_gap = vec![
            sample(100, 0, 0, 0),
            sample(0, 0, 0, 0),
            sample(200, 0, 0, 0),
        ];
        assert_eq!(classify(&tx_gap), Verdict::Healthy);

        // Shrinking queues are draining.
        let rx_shrink = vec![
            sample(0, 900, 0, 0),
            sample(0, 950, 0, 0),
            sample(0, 100, 0, 0),
        ];
        assert_eq!(classify(&rx_shrink), Verdict::Healthy);

        // One sample with an unknown limit forces the whole window onto the
        // trend rule: the ratios here would say stalled, the trend says drain.
        let mixed = vec![
            sample(99, 0, 100, 100),
            sample(98, 0, 0, 0),
            sample(97, 0, 100, 100),
        ];
        assert_eq!(classify(&mixed), Verdict::Healthy);
    }

    #[test]
    fn detector_skips_non_numeric_fds_and_queueless_sockets() {
        let mut p = sock_proc(10, "srv", 3, 90, 0, Some(100));
        p.files.push(OpenFile {
            fd: FdName::Cwd,
            socket_info: Some(SocketInfo {
                send_queue: Some(90),
                recv_queue: Some(0),
                ..Default::default()
            }),
            ..Default::default()
        });
        p.files.push(OpenFile {
            fd: FdName::Number(4),
            socket_info: Some(SocketInfo {
                send_queue: Some(90),
                recv_queue: None,
                ..Default::default()
            }),
            ..Default::default()
        });
        p.files.push(OpenFile {
            fd: FdName::Number(5),
            ..Default::default()
        });

        let mut d = StallDetector::new();
        d.update(std::slice::from_ref(&p));
        assert_eq!(d.table.len(), 1);
        assert!(d.table.contains_key(&(10, 3)));
        assert_eq!(d.iteration, 1);
    }

    #[test]
    fn detector_reaches_verdict_after_min_samples_and_caps_history() {
        let mut d = StallDetector::new();
        let p = sock_proc(20, "writer", 7, 95, 0, Some(100));
        for i in 1..=HISTORY_SIZE + 4 {
            d.update(std::slice::from_ref(&p));
            let expected = if i < MIN_SAMPLES {
                Verdict::Healthy
            } else {
                Verdict::TxStalled
            };
            assert_eq!(verdict_of(&d, 20, 7), Some(expected), "after {i} samples");
        }
        assert_eq!(d.table[&(20, 7)].history.len(), HISTORY_SIZE);
    }

    #[test]
    fn detector_pid_reuse_resets_history() {
        let mut d = StallDetector::new();
        let old = sock_proc(30, "old", 4, 95, 0, Some(100));
        for _ in 0..MIN_SAMPLES {
            d.update(std::slice::from_ref(&old));
        }
        assert_eq!(verdict_of(&d, 30, 4), Some(Verdict::TxStalled));

        // Same (pid, fd), different command: the old history must not carry
        // over, so one fresh sample cannot be a verdict yet.
        let new = sock_proc(30, "new", 4, 95, 0, Some(100));
        d.update(std::slice::from_ref(&new));
        let e = &d.table[&(30, 4)];
        assert_eq!(e.command, "new");
        assert_eq!(e.history.len(), 1);
        assert_eq!(e.verdict, Verdict::Healthy);
    }

    #[test]
    fn detector_drops_vanished_healthy_fds() {
        let mut d = StallDetector::new();
        let stalled = sock_proc(40, "stuck", 3, 95, 0, Some(100));
        let idle = sock_proc(41, "idle", 3, 1, 1, Some(100));
        let both = [stalled, idle];
        for _ in 0..MIN_SAMPLES {
            d.update(&both);
        }
        assert_eq!(verdict_of(&d, 40, 3), Some(Verdict::TxStalled));
        assert_eq!(verdict_of(&d, 41, 3), Some(Verdict::Healthy));

        d.update(&[]);
        assert!(
            !d.table.contains_key(&(41, 3)),
            "healthy vanished fd dropped"
        );
        assert!(
            d.table.get(&(40, 3)).is_none_or(|e| !e.seen),
            "a vanished fd is never reported as seen"
        );
    }
}
