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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, n_files: usize) -> Process {
        Process {
            pid, ppid: 1, pgid: 1, uid: 501,
            command: cmd.to_string(),
            files: (0..n_files).map(|i| OpenFile {
                fd: FdName::Number(i as i32),
                access: Access::Read,
                file_type: FileType::Reg,
                name: format!("/tmp/file{i}"),
                ..Default::default()
            }).collect(),
            sel_flags: 0, sel_state: 0,
        }
    }

    #[test]
    fn no_leak_on_stable_fd_count() {
        let mut ld = LeakDetector::new(3);
        for _ in 0..10 {
            ld.update(&[make_proc(100, "stable", 5)]);
        }
        let flagged: Vec<_> = ld.table.values().filter(|e| e.flagged).collect();
        assert!(flagged.is_empty());
    }

    #[test]
    fn leak_detected_on_monotonic_increase() {
        let mut ld = LeakDetector::new(3);
        for i in 0..5 {
            ld.update(&[make_proc(100, "leaky", 10 + i)]);
        }
        let flagged: Vec<_> = ld.table.values().filter(|e| e.flagged).collect();
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].pid, 100);
    }

    #[test]
    fn leak_not_flagged_below_threshold() {
        let mut ld = LeakDetector::new(5);
        // Only 3 increases
        for i in 0..3 {
            ld.update(&[make_proc(100, "test", 10 + i)]);
        }
        let flagged: Vec<_> = ld.table.values().filter(|e| e.flagged).collect();
        assert!(flagged.is_empty());
    }

    #[test]
    fn decrease_resets_consecutive_count() {
        let mut ld = LeakDetector::new(3);
        // Increase 2x, decrease, increase 2x — never hits threshold
        ld.update(&[make_proc(100, "test", 10)]);
        ld.update(&[make_proc(100, "test", 11)]);
        ld.update(&[make_proc(100, "test", 12)]);
        ld.update(&[make_proc(100, "test", 8)]);  // decrease resets
        ld.update(&[make_proc(100, "test", 9)]);
        ld.update(&[make_proc(100, "test", 10)]);
        let flagged: Vec<_> = ld.table.values().filter(|e| e.flagged).collect();
        assert!(flagged.is_empty());
    }

    #[test]
    fn pid_reuse_resets_tracking() {
        let mut ld = LeakDetector::new(3);
        ld.update(&[make_proc(100, "old_cmd", 10)]);
        ld.update(&[make_proc(100, "old_cmd", 11)]);
        // PID reused with different command
        ld.update(&[make_proc(100, "new_cmd", 12)]);
        ld.update(&[make_proc(100, "new_cmd", 13)]);
        // Only 1 increase since reset (12->13), not enough
        let flagged: Vec<_> = ld.table.values().filter(|e| e.flagged).collect();
        assert!(flagged.is_empty());
    }

    #[test]
    fn iteration_counter() {
        let mut ld = LeakDetector::new(3);
        assert_eq!(ld.iteration, 0);
        ld.update(&[make_proc(1, "a", 5)]);
        assert_eq!(ld.iteration, 1);
        ld.update(&[make_proc(1, "a", 5)]);
        assert_eq!(ld.iteration, 2);
    }

    #[test]
    fn gone_unflagged_processes_removed() {
        let mut ld = LeakDetector::new(3);
        ld.update(&[make_proc(100, "temp", 5)]);
        assert!(ld.table.contains_key(&100));
        ld.update(&[]); // process gone
        assert!(!ld.table.contains_key(&100));
    }

    #[test]
    fn flagged_processes_retained_after_gone() {
        let mut ld = LeakDetector::new(2);
        for i in 0..4 {
            ld.update(&[make_proc(100, "leaky", 10 + i)]);
        }
        assert!(ld.table[&100].flagged);
        ld.update(&[]); // gone but flagged
        assert!(ld.table.contains_key(&100));
    }

    #[test]
    fn history_capped_at_history_size() {
        let mut ld = LeakDetector::new(100); // high threshold so never flagged
        for i in 0..50 {
            ld.update(&[make_proc(100, "test", 10 + i)]);
        }
        assert!(ld.table[&100].history.len() <= HISTORY_SIZE);
    }
}
