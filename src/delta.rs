//! Delta highlighting — track FD changes between iterations

use std::collections::HashMap;
use std::io::{self, Write};

use crate::output::Theme;
use crate::types::*;

type DeltaKey = (i32, String, String); // (pid, fd, name)

struct DeltaEntry {
    pid: i32,
    fd: String,
    name: String,
    file_type: String,
    command: String,
    uid: u32,
}

pub struct DeltaTracker {
    prev: HashMap<DeltaKey, DeltaEntry>,
    curr: HashMap<DeltaKey, DeltaEntry>,
    pub new_count: usize,
    pub gone_count: usize,
}

impl Default for DeltaTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DeltaTracker {
    pub fn new() -> Self {
        Self {
            prev: HashMap::new(),
            curr: HashMap::new(),
            new_count: 0,
            gone_count: 0,
        }
    }

    pub fn begin_iteration(&mut self) {
        self.prev = std::mem::take(&mut self.curr);
        self.new_count = 0;
        self.gone_count = 0;
    }

    pub fn record(&mut self, proc: &Process) {
        for f in &proc.files {
            let fd_str = f.fd.with_access(f.access);
            let key = (proc.pid, fd_str.clone(), f.name.clone());
            self.curr.insert(
                key,
                DeltaEntry {
                    pid: proc.pid,
                    fd: fd_str,
                    name: f.name.clone(),
                    file_type: f.file_type.as_str().to_string(),
                    command: proc.command.clone(),
                    uid: proc.uid,
                },
            );
        }
    }

    pub fn classify(&self, pid: i32, fd: &str, name: &str) -> DeltaStatus {
        let key = (pid, fd.to_string(), name.to_string());
        if self.prev.contains_key(&key) {
            DeltaStatus::Unchanged
        } else {
            DeltaStatus::New
        }
    }

    pub fn count_gone(&mut self) {
        for key in self.prev.keys() {
            if !self.curr.contains_key(key) {
                self.gone_count += 1;
            }
        }
        self.new_count = self
            .curr
            .keys()
            .filter(|k| !self.prev.contains_key(k))
            .count();
    }

    pub fn print_gone(&self, theme: &Theme) {
        let out = io::stdout();
        let mut out = out.lock();

        for (key, entry) in &self.prev {
            if !self.curr.contains_key(key) {
                let username = users::get_user_by_uid(entry.uid)
                    .map(|u| u.name().to_string_lossy().into_owned())
                    .unwrap_or_else(|| entry.uid.to_string());

                let _ = writeln!(
                    out,
                    "{red}{cmd:<15} {pid:>7} {user:<8} {fd:<6} {type_:<5} {name} [GONE]{reset}",
                    cmd = if entry.command.len() > 15 {
                        &entry.command[..15]
                    } else {
                        &entry.command
                    },
                    pid = entry.pid,
                    user = if username.len() > 8 {
                        &username[..8]
                    } else {
                        &username
                    },
                    fd = entry.fd,
                    type_ = entry.file_type,
                    name = entry.name,
                    red = theme.red(),
                    reset = theme.reset(),
                );
            }
        }
    }

    pub fn print_summary(&self, theme: &Theme) {
        let out = io::stdout();
        let mut out = out.lock();
        let _ = writeln!(
            out,
            "{dim}[delta]{reset} {green}new: {}{reset}  {red}gone: {}{reset}",
            self.new_count,
            self.gone_count,
            dim = theme.dim(),
            green = theme.green(),
            red = theme.red(),
            reset = theme.reset(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, files: Vec<(&str, &str)>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: 1,
            uid: 501,
            command: cmd.to_string(),
            files: files
                .into_iter()
                .map(|(fd, name)| OpenFile {
                    fd: FdName::Number(fd.parse().unwrap()),
                    access: Access::ReadWrite,
                    file_type: FileType::Reg,
                    name: name.to_string(),
                    ..Default::default()
                })
                .collect(),
            sel_flags: 0,
            sel_state: 0,
        }
    }

    #[test]
    fn default_matches_new() {
        let a = DeltaTracker::new();
        let b = DeltaTracker::default();
        assert_eq!(a.new_count, b.new_count);
        assert_eq!(a.gone_count, b.gone_count);
    }

    #[test]
    fn new_tracker_starts_empty() {
        let dt = DeltaTracker::new();
        assert_eq!(dt.new_count, 0);
        assert_eq!(dt.gone_count, 0);
    }

    #[test]
    fn begin_iteration_resets_counts() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a")]));
        dt.count_gone();
        assert_eq!(dt.new_count, 1);
        dt.begin_iteration();
        assert_eq!(dt.new_count, 0);
        assert_eq!(dt.gone_count, 0);
    }

    #[test]
    fn count_gone_on_empty_iteration_is_zero() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.count_gone();
        assert_eq!(dt.gone_count, 0);
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn first_iteration_all_new() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        let p = make_proc(100, "test", vec![("3", "/tmp/a"), ("4", "/tmp/b")]);
        dt.record(&p);
        dt.count_gone();
        assert_eq!(dt.new_count, 2);
        assert_eq!(dt.gone_count, 0);
    }

    #[test]
    fn unchanged_files_not_counted() {
        let mut dt = DeltaTracker::new();

        // Iteration 1
        dt.begin_iteration();
        let p = make_proc(100, "test", vec![("3", "/tmp/a")]);
        dt.record(&p);
        dt.count_gone();

        // Iteration 2 - same files
        dt.begin_iteration();
        dt.record(&p);
        dt.count_gone();
        assert_eq!(dt.new_count, 0);
        assert_eq!(dt.gone_count, 0);
    }

    #[test]
    fn gone_files_detected() {
        let mut dt = DeltaTracker::new();

        // Iteration 1
        dt.begin_iteration();
        let p = make_proc(100, "test", vec![("3", "/tmp/a"), ("4", "/tmp/b")]);
        dt.record(&p);
        dt.count_gone();

        // Iteration 2 - one file removed
        dt.begin_iteration();
        let p2 = make_proc(100, "test", vec![("3", "/tmp/a")]);
        dt.record(&p2);
        dt.count_gone();
        assert_eq!(dt.gone_count, 1);
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn new_files_detected() {
        let mut dt = DeltaTracker::new();

        // Iteration 1
        dt.begin_iteration();
        let p = make_proc(100, "test", vec![("3", "/tmp/a")]);
        dt.record(&p);
        dt.count_gone();

        // Iteration 2 - new file added
        dt.begin_iteration();
        let p2 = make_proc(100, "test", vec![("3", "/tmp/a"), ("5", "/tmp/c")]);
        dt.record(&p2);
        dt.count_gone();
        assert_eq!(dt.new_count, 1);
        assert_eq!(dt.gone_count, 0);
    }

    #[test]
    fn classify_new_vs_unchanged() {
        let mut dt = DeltaTracker::new();

        dt.begin_iteration();
        let p = make_proc(100, "test", vec![("3", "/tmp/a")]);
        dt.record(&p);
        dt.count_gone();

        dt.begin_iteration();
        let p2 = make_proc(100, "test", vec![("3", "/tmp/a"), ("5", "/tmp/new")]);
        dt.record(&p2);

        assert_eq!(dt.classify(100, "3u", "/tmp/a"), DeltaStatus::Unchanged);
        assert_eq!(dt.classify(100, "5u", "/tmp/new"), DeltaStatus::New);
    }

    #[test]
    fn multiple_processes_tracked() {
        let mut dt = DeltaTracker::new();

        dt.begin_iteration();
        dt.record(&make_proc(100, "a", vec![("3", "/tmp/a")]));
        dt.record(&make_proc(200, "b", vec![("4", "/tmp/b")]));
        dt.count_gone();

        dt.begin_iteration();
        dt.record(&make_proc(100, "a", vec![("3", "/tmp/a")]));
        // pid 200 gone
        dt.count_gone();
        assert_eq!(dt.gone_count, 1);
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn process_removed_entirely_counts_all_fds_gone() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "gone", vec![("3", "/a"), ("4", "/b")]));
        dt.count_gone();

        dt.begin_iteration();
        // No record — curr empty, both keys from prev are gone
        dt.count_gone();
        assert_eq!(dt.gone_count, 2);
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn same_fd_new_name_counts_new_not_unchanged() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/first")]));
        dt.count_gone();

        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/second")]));
        dt.count_gone();
        assert_eq!(dt.gone_count, 1);
        assert_eq!(dt.new_count, 1);
    }

    #[test]
    fn classify_other_pid_is_new_even_if_name_matches() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "a", vec![("3", "/shared")]));
        dt.count_gone();

        dt.begin_iteration();
        dt.record(&make_proc(200, "b", vec![("3", "/shared")]));

        assert_eq!(dt.classify(200, "3u", "/shared"), DeltaStatus::New);
        assert_eq!(dt.classify(100, "3u", "/shared"), DeltaStatus::Unchanged);
    }

    #[test]
    fn print_summary_no_panic() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a")]));
        dt.count_gone();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a"), ("4", "/b")]));
        dt.count_gone();
        let theme = Theme::new(false);
        dt.print_summary(&theme);
    }

    #[test]
    fn print_gone_when_prev_empty_no_panic() {
        let dt = DeltaTracker::new();
        let theme = Theme::new(false);
        dt.print_gone(&theme);
    }

    #[test]
    fn print_summary_zero_counts_no_panic() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        let theme = Theme::new(false);
        dt.print_summary(&theme);
    }

    #[test]
    fn gone_count_includes_all_prev_keys_when_curr_cleared() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "gone", vec![("3", "/a"), ("4", "/b")]));
        dt.count_gone();
        dt.begin_iteration();
        dt.count_gone();
        assert_eq!(dt.gone_count, 2);
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn record_process_with_no_files_has_no_new_entries() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "empty", vec![]));
        dt.count_gone();
        assert_eq!(dt.new_count, 0);
    }

    #[test]
    fn classify_uses_prev_from_begin_iteration() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a")]));
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a"), ("4", "/b")]));
        assert_eq!(dt.classify(100, "3u", "/a"), DeltaStatus::Unchanged);
        assert_eq!(dt.classify(100, "4u", "/b"), DeltaStatus::New);
    }

    #[test]
    fn second_iteration_identical_snapshot_no_new_no_gone() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a")]));
        dt.count_gone();
        assert_eq!(dt.new_count, 1);
        assert_eq!(dt.gone_count, 0);

        dt.begin_iteration();
        dt.record(&make_proc(100, "x", vec![("3", "/a")]));
        dt.count_gone();
        assert_eq!(dt.new_count, 0);
        assert_eq!(dt.gone_count, 0);
    }

    fn proc_with_open_files(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: 1,
            uid: 501,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    #[test]
    fn record_duplicate_fd_replaces_entry_same_iteration() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        let f1 = OpenFile {
            fd: FdName::Number(3),
            access: Access::ReadWrite,
            file_type: FileType::Reg,
            name: "/tmp/x".to_string(),
            ..Default::default()
        };
        let f2 = OpenFile {
            fd: FdName::Number(3),
            access: Access::ReadWrite,
            file_type: FileType::Reg,
            name: "/tmp/x".to_string(),
            ..Default::default()
        };
        dt.record(&proc_with_open_files(100, "x", vec![f1, f2]));
        dt.count_gone();
        assert_eq!(dt.new_count, 1);
    }

    #[test]
    fn different_access_same_fd_and_name_are_distinct_keys() {
        let mut dt = DeltaTracker::new();
        dt.begin_iteration();
        let f_read = OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/same".to_string(),
            ..Default::default()
        };
        let f_write = OpenFile {
            fd: FdName::Number(3),
            access: Access::Write,
            file_type: FileType::Reg,
            name: "/same".to_string(),
            ..Default::default()
        };
        dt.record(&proc_with_open_files(100, "x", vec![f_read, f_write]));
        dt.count_gone();
        assert_eq!(dt.new_count, 2);
        assert_eq!(dt.gone_count, 0);

        dt.begin_iteration();
        let only_read = OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/same".to_string(),
            ..Default::default()
        };
        dt.record(&proc_with_open_files(100, "x", vec![only_read]));
        dt.count_gone();
        assert_eq!(dt.gone_count, 1);
        assert_eq!(dt.new_count, 0);
    }
}
