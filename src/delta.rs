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
        for (key, _) in &self.prev {
            if !self.curr.contains_key(key) {
                self.gone_count += 1;
            }
        }
        self.new_count = self.curr.keys().filter(|k| !self.prev.contains_key(k)).count();
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
                    cmd = if entry.command.len() > 15 { &entry.command[..15] } else { &entry.command },
                    pid = entry.pid,
                    user = if username.len() > 8 { &username[..8] } else { &username },
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
