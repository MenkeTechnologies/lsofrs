//! FD leak detection — track monotonically increasing FD counts

use std::collections::HashMap;
use std::io::{self, Write};

use crate::output::Theme;
use crate::types::*;

const HISTORY_SIZE: usize = 16;

struct LeakSample {
    fd_count: usize,
    timestamp: i64,
}

struct LeakEntry {
    pid: i32,
    command: String,
    uid: u32,
    history: Vec<LeakSample>,
    consecutive_increases: usize,
    flagged: bool,
    seen: bool,
}

pub struct LeakDetector {
    table: HashMap<i32, LeakEntry>,
    iteration: u64,
    threshold: usize,
}

impl LeakDetector {
    pub fn new(threshold: usize) -> Self {
        Self {
            table: HashMap::new(),
            iteration: 0,
            threshold,
        }
    }

    pub fn update(&mut self, procs: &[Process]) {
        self.iteration += 1;
        let now = chrono::Utc::now().timestamp();

        // Mark all unseen
        for entry in self.table.values_mut() {
            entry.seen = false;
        }

        for p in procs {
            let fd_count = p.files.len();

            let entry = self.table.entry(p.pid).or_insert_with(|| LeakEntry {
                pid: p.pid,
                command: p.command.clone(),
                uid: p.uid,
                history: Vec::with_capacity(HISTORY_SIZE),
                consecutive_increases: 0,
                flagged: false,
                seen: false,
            });

            entry.seen = true;

            // Check if PID was reused (different command)
            if entry.command != p.command {
                entry.command = p.command.clone();
                entry.uid = p.uid;
                entry.history.clear();
                entry.consecutive_increases = 0;
                entry.flagged = false;
            }

            // Compare to previous
            if let Some(last) = entry.history.last() {
                if fd_count > last.fd_count {
                    entry.consecutive_increases += 1;
                } else {
                    entry.consecutive_increases = 0;
                }
            }

            // Store sample (circular)
            if entry.history.len() >= HISTORY_SIZE {
                entry.history.remove(0);
            }
            entry.history.push(LeakSample {
                fd_count,
                timestamp: now,
            });

            // Flag
            if entry.consecutive_increases >= self.threshold && !entry.flagged {
                entry.flagged = true;
            }
        }

        // Reset unseen entries
        for entry in self.table.values_mut() {
            if !entry.seen {
                entry.consecutive_increases = 0;
            }
        }

        // Remove long-gone processes
        self.table.retain(|_, e| e.seen || e.flagged);
    }

    pub fn report(&self, theme: &Theme) {
        let out = io::stdout();
        let mut out = out.lock();

        let flagged: Vec<&LeakEntry> = self
            .table
            .values()
            .filter(|e| e.flagged)
            .collect();

        let scanned = self.table.values().filter(|e| e.seen).count();

        let _ = writeln!(
            out,
            "\n{bold}═══ lsofrs leak detection ═══{reset}",
            bold = theme.bold(),
            reset = theme.reset(),
        );
        let _ = writeln!(
            out,
            "  iteration: {} | scanned: {} | suspects: {red}{}{reset}\n",
            self.iteration,
            scanned,
            flagged.len(),
            red = if flagged.is_empty() { "" } else { theme.red() },
            reset = theme.reset(),
        );

        if flagged.is_empty() {
            let _ = writeln!(
                out,
                "  {green}No FD leaks detected.{reset}",
                green = theme.green(),
                reset = theme.reset(),
            );
        } else {
            let _ = writeln!(
                out,
                "  {hdr}{bold}{:>7}  {:<15}  {:>6}  {:>8}  {}{reset}",
                "PID", "COMMAND", "UID", "SAMPLES", "FD TREND",
                hdr = theme.hdr_bg(),
                bold = theme.bold(),
                reset = theme.reset(),
            );

            for entry in &flagged {
                let trend: String = entry
                    .history
                    .iter()
                    .map(|s| s.fd_count.to_string())
                    .collect::<Vec<_>>()
                    .join("->");

                let cmd = if entry.command.len() > 15 {
                    &entry.command[..15]
                } else {
                    &entry.command
                };

                let _ = writeln!(
                    out,
                    "  {red}{:>7}{reset}  {cyan}{:<15}{reset}  {:>6}  {:>8}  {yellow}{}{reset}",
                    entry.pid,
                    cmd,
                    entry.uid,
                    entry.history.len(),
                    trend,
                    red = theme.red(),
                    cyan = theme.cyan(),
                    yellow = theme.yellow(),
                    reset = theme.reset(),
                );
            }
        }

        let _ = writeln!(out);
    }
}
