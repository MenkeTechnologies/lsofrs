//! Find FDs pointing to deleted files

use std::io::{self, Write};

use serde::Serialize;

use crate::output::Theme;
use crate::strutil::truncate_max_bytes;
use crate::types::*;

#[derive(Serialize)]
struct StaleEntry {
    pid: i32,
    user: String,
    command: String,
    fd: String,
    file_type: String,
    size: Option<u64>,
    name: String,
}

fn is_deleted(file: &OpenFile) -> bool {
    file.name.contains("(deleted)")
        || file
            .name_append
            .as_deref()
            .is_some_and(|a| a.contains("(deleted)"))
}

pub fn print_stale(procs: &[Process], theme: &Theme, json: bool) {
    let entries: Vec<StaleEntry> = procs
        .iter()
        .flat_map(|p| {
            let user = p.username();
            let cmd = p.command.clone();
            p.files
                .iter()
                .filter(|f| is_deleted(f))
                .map(move |f| StaleEntry {
                    pid: p.pid,
                    user: user.clone(),
                    command: cmd.clone(),
                    fd: f.fd.with_access(f.access),
                    file_type: f.file_type.as_str().to_string(),
                    size: f.size,
                    name: f.full_name(),
                })
        })
        .collect();

    if json {
        print_stale_json(&entries);
    } else {
        print_stale_text(&entries, theme);
    }
}

fn print_stale_text(entries: &[StaleEntry], theme: &Theme) {
    let out = io::stdout();
    let mut out = out.lock();

    if entries.is_empty() {
        let _ = writeln!(out, "No stale (deleted) file descriptors found.");
        return;
    }

    // Compute column widths
    let w_pid = entries
        .iter()
        .map(|e| e.pid.to_string().len())
        .max()
        .unwrap_or(3)
        .max(3);
    let w_user = entries
        .iter()
        .map(|e| e.user.len().min(8))
        .max()
        .unwrap_or(4)
        .max(4);
    let w_fd = entries.iter().map(|e| e.fd.len()).max().unwrap_or(2).max(2);
    let w_type = entries
        .iter()
        .map(|e| e.file_type.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let w_size = entries
        .iter()
        .map(|e| e.size.map(|s| s.to_string().len()).unwrap_or(0))
        .max()
        .unwrap_or(4)
        .max(4);

    // Header
    let _ = writeln!(
        out,
        "\n{bold}═══ Stale FDs (deleted files) ═══{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );
    let _ = writeln!(
        out,
        "{hdr}{bold}{pid:>pw$}  {user:<uw$}  {fd:<fw$}  {ty:<tw$}  {sz:>sw$}  NAME{reset}",
        hdr = theme.hdr_bg(),
        bold = theme.bold(),
        pid = "PID",
        pw = w_pid,
        user = "USER",
        uw = w_user,
        fd = "FD",
        fw = w_fd,
        ty = "TYPE",
        tw = w_type,
        sz = "SIZE",
        sw = w_size,
        reset = theme.reset(),
    );

    for (i, e) in entries.iter().enumerate() {
        let alt = if i % 2 == 1 { theme.row_alt() } else { "" };
        let user_display = truncate_max_bytes(&e.user, 8);
        let size_str = e.size.map(|s| s.to_string()).unwrap_or_default();

        // Highlight "(deleted)" in red within the name
        let name_colored = e.name.replace(
            "(deleted)",
            &format!(
                "{red}(deleted){reset}",
                red = theme.red(),
                reset = theme.reset()
            ),
        );

        let _ = writeln!(
            out,
            "{alt}{mag}{pid:>pw$}{reset}  {yellow}{user:<uw$}{reset}  {green}{fd:<fw$}{reset}  {blue}{ty:<tw$}{reset}  {sz:>sw$}  {name}{reset}",
            alt = alt,
            mag = theme.magenta(),
            pid = e.pid,
            pw = w_pid,
            reset = theme.reset(),
            yellow = theme.yellow(),
            user = user_display,
            uw = w_user,
            green = theme.green(),
            fd = e.fd,
            fw = w_fd,
            blue = theme.blue(),
            ty = e.file_type,
            tw = w_type,
            sz = size_str,
            sw = w_size,
            name = name_colored,
        );
    }

    let _ = writeln!(
        out,
        "\n{dim}  {} stale FD(s) found{reset}\n",
        entries.len(),
        dim = theme.dim(),
        reset = theme.reset(),
    );
}

fn print_stale_json(entries: &[StaleEntry]) {
    let out = io::stdout();
    let mut out = out.lock();
    let wrapper = serde_json::json!({ "stale_fds": entries });
    let _ = serde_json::to_writer_pretty(&mut out, &wrapper);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 0,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_deleted_file(fd: i32, name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::Reg,
            name: name.to_string(),
            size: Some(1024),
            ..Default::default()
        }
    }

    #[test]
    fn is_deleted_name_contains() {
        let f = make_deleted_file(3, "/tmp/foo (deleted)");
        assert!(is_deleted(&f));
    }

    #[test]
    fn is_deleted_name_append() {
        let mut f = make_deleted_file(3, "/tmp/foo");
        f.name_append = Some("(deleted)".to_string());
        assert!(is_deleted(&f));
    }

    #[test]
    fn is_deleted_name_append_contains_deleted_substring() {
        let mut f = make_deleted_file(3, "/tmp/foo");
        f.name_append = Some("inode (deleted) recycled".to_string());
        assert!(is_deleted(&f));
    }

    #[test]
    fn is_deleted_normal_file() {
        let f = make_deleted_file(3, "/tmp/foo");
        assert!(!is_deleted(&f));
    }

    #[test]
    fn is_deleted_false_when_name_append_has_no_deleted_marker() {
        let mut f = make_deleted_file(3, "/tmp/foo");
        f.name_append = Some(" (mmap)".to_string());
        assert!(!is_deleted(&f));
    }

    #[test]
    fn print_stale_empty_no_panic() {
        let theme = Theme::new(false);
        print_stale(&[], &theme, false);
    }

    #[test]
    fn print_stale_with_deleted_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![
                make_deleted_file(3, "/tmp/foo (deleted)"),
                make_deleted_file(4, "/tmp/bar"),
            ],
        )];
        print_stale(&procs, &theme, false);
    }

    #[test]
    fn print_stale_json_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_deleted_file(3, "/tmp/foo (deleted)")],
        )];
        print_stale(&procs, &theme, true);
    }

    #[test]
    fn print_stale_filters_non_deleted() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_deleted_file(3, "/tmp/normal_file")],
        )];
        // Should print "no stale" message, not crash
        print_stale(&procs, &theme, false);
    }

    #[test]
    fn stale_entry_collects_correctly() {
        let mut f = make_deleted_file(5, "/var/log/app.log");
        f.name_append = Some("(deleted)".to_string());
        let procs = [make_proc(100, "myapp", vec![f])];

        let entries: Vec<StaleEntry> = procs
            .iter()
            .flat_map(|p| {
                let user = p.username();
                let cmd = p.command.clone();
                p.files
                    .iter()
                    .filter(|f| is_deleted(f))
                    .map(move |f| StaleEntry {
                        pid: p.pid,
                        user: user.clone(),
                        command: cmd.clone(),
                        fd: f.fd.with_access(f.access),
                        file_type: f.file_type.as_str().to_string(),
                        size: f.size,
                        name: f.full_name(),
                    })
            })
            .collect();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pid, 100);
        assert_eq!(entries[0].command, "myapp");
        assert!(entries[0].name.contains("(deleted)"));
    }
}
