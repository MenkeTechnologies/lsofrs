//! Watch mode — monitor who opens/closes a specific file over time

use std::collections::HashMap;
use std::io::{self, IsTerminal, Write};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use crate::output::Theme;
use crate::strutil::truncate_max_bytes;

struct WatchEntry {
    pid: i32,
    command: String,
    uid: u32,
    fd: String,
    first_seen: u64,
    last_seen: u64,
    gone: bool,
}

pub fn run_watch(path: &str, interval: u64, theme: &Theme) {
    let mut table: HashMap<(i32, String), WatchEntry> = HashMap::new();
    let mut iteration = 0u64;
    let is_tty = io::stdout().is_terminal();

    // Resolve to canonical path if possible
    let canon = std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());

    if is_tty {
        let _ = crossterm::terminal::enable_raw_mode();
        let r = theme.reset();
        // Print header using stdout with \r\n for raw mode
        let out = io::stdout();
        let mut out = out.lock();
        let _ = write!(
            out,
            "{bold}lsofrs watch{r}: monitoring {cyan}{canon}{r} (refresh {interval}s, q to quit)\r\n\r\n",
            bold = theme.bold(),
            cyan = theme.cyan(),
        );
        let _ = out.flush();
        drop(out);
    }

    loop {
        iteration += 1;

        // Mark all as not-seen this iteration
        for entry in table.values_mut() {
            entry.gone = true;
        }

        let procs = crate::gather_processes();

        for p in &procs {
            for f in &p.files {
                if !file_matches(&f.name, &canon, path) {
                    continue;
                }
                let fd_str = f.fd.with_access(f.access);
                let key = (p.pid, fd_str.clone());

                let entry = table.entry(key).or_insert_with(|| {
                    let e = WatchEntry {
                        pid: p.pid,
                        command: p.command.clone(),
                        uid: p.uid,
                        fd: fd_str.clone(),
                        first_seen: iteration,
                        last_seen: iteration,
                        gone: false,
                    };
                    // Print open event
                    print_event(theme, "+OPEN", p.pid, &p.command, p.uid, &fd_str, iteration);
                    e
                });

                entry.last_seen = iteration;
                entry.gone = false;
            }
        }

        // Report closed FDs
        let gone_keys: Vec<(i32, String)> = table
            .iter()
            .filter(|(_, e)| e.gone)
            .map(|(k, _)| k.clone())
            .collect();

        for key in &gone_keys {
            let entry = &table[key];
            print_event(
                theme,
                "-CLOSE",
                entry.pid,
                &entry.command,
                entry.uid,
                &entry.fd,
                iteration,
            );
        }

        for key in &gone_keys {
            table.remove(key);
        }

        // Non-TTY single-shot
        if !is_tty {
            print_snapshot(theme, &table, &canon, iteration);
            break;
        }

        // Poll for q/Esc/Ctrl-C during sleep interval
        let deadline = std::time::Instant::now() + Duration::from_secs(interval);
        while std::time::Instant::now() < deadline {
            if event::poll(Duration::from_millis(200)).unwrap_or(false)
                && let Ok(Event::Key(key)) = event::read()
            {
                let quit = match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
                    _ => false,
                };
                if quit {
                    break;
                }
            }
        }
    }

    if is_tty {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

fn file_matches(name: &str, canon: &str, original: &str) -> bool {
    name == canon
        || name == original
        || name.starts_with(&format!("{canon}/"))
        || name.starts_with(&format!("{original}/"))
}

fn print_event(theme: &Theme, tag: &str, pid: i32, cmd: &str, uid: u32, fd: &str, _iter: u64) {
    let out = io::stdout();
    let mut out = out.lock();
    let r = theme.reset();

    let username = users::get_user_by_uid(uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| uid.to_string());

    let (color, symbol) = if tag.starts_with('+') {
        (theme.green(), "+")
    } else {
        (theme.red(), "-")
    };

    let cmd_display = truncate_max_bytes(cmd, 20);
    let user_display = truncate_max_bytes(&username, 8);

    let now = chrono::Local::now().format("%H:%M:%S");
    let nl = if theme.is_tty { "\r\n" } else { "\n" };

    let _ = write!(
        out,
        "{dim}{now}{r}  {color}{symbol}{tag:<6}{r}  {mag}{pid:>7}{r}  {yellow}{user:<8}{r}  {fd:<5}  {cyan}{cmd}{r}{nl}",
        dim = theme.dim(),
        mag = theme.magenta(),
        yellow = theme.yellow(),
        cyan = theme.cyan(),
        tag = &tag[1..],
        user = user_display,
        cmd = cmd_display,
    );
    let _ = out.flush();
}

fn print_snapshot(
    theme: &Theme,
    table: &HashMap<(i32, String), WatchEntry>,
    path: &str,
    _iteration: u64,
) {
    let out = io::stdout();
    let mut out = out.lock();
    let r = theme.reset();

    let _ = writeln!(
        out,
        "{bold}Processes with {path} open:{r}",
        bold = theme.bold(),
    );

    if table.is_empty() {
        let _ = writeln!(out, "  (none)");
        return;
    }

    let _ = writeln!(
        out,
        "{bold}{hdr}{:>7}  {:<8}  {:<5}  COMMAND{r}",
        "PID",
        "USER",
        "FD",
        bold = theme.bold(),
        hdr = theme.hdr_bg(),
    );

    let mut entries: Vec<&WatchEntry> = table.values().collect();
    entries.sort_by_key(|e| e.pid);

    for e in entries {
        let username = users::get_user_by_uid(e.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| e.uid.to_string());
        let user_display = truncate_max_bytes(&username, 8);
        let cmd = truncate_max_bytes(&e.command, 25);

        let _ = writeln!(
            out,
            "{mag}{:>7}{r}  {yellow}{:<8}{r}  {green}{:<5}{r}  {cyan}{cmd}{r}",
            e.pid,
            user_display,
            e.fd,
            mag = theme.magenta(),
            yellow = theme.yellow(),
            green = theme.green(),
            cyan = theme.cyan(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_matches_exact() {
        assert!(file_matches(
            "/var/log/syslog",
            "/var/log/syslog",
            "/var/log/syslog"
        ));
    }

    #[test]
    fn file_matches_canonical_vs_original() {
        assert!(file_matches(
            "/private/var/log/syslog",
            "/private/var/log/syslog",
            "/var/log/syslog"
        ));
    }

    #[test]
    fn file_matches_name_equal_to_original_operand() {
        assert!(file_matches(
            "/tmp/watchfile",
            "/private/tmp/watchfile",
            "/tmp/watchfile"
        ));
    }

    #[test]
    fn file_matches_subpath() {
        assert!(file_matches(
            "/var/log/syslog/rotated",
            "/var/log/syslog",
            "/var/log/syslog"
        ));
    }

    #[test]
    fn file_matches_subpath_under_original_when_canon_differs() {
        assert!(file_matches(
            "/var/log/syslog/rotated",
            "/private/var/log/syslog",
            "/var/log/syslog"
        ));
    }

    #[test]
    fn file_matches_no_match() {
        assert!(!file_matches(
            "/tmp/other",
            "/var/log/syslog",
            "/var/log/syslog"
        ));
    }

    #[test]
    fn file_matches_partial_name_no_match() {
        // "/var/logs" should NOT match "/var/log"
        assert!(!file_matches("/var/logs", "/var/log", "/var/log"));
    }

    #[test]
    fn file_matches_child_path_under_original_operand() {
        assert!(file_matches(
            "/etc/hosts/extra",
            "/private/etc/hosts",
            "/etc/hosts"
        ));
    }

    #[test]
    fn print_snapshot_empty() {
        let theme = Theme::new(false);
        let table = HashMap::new();
        print_snapshot(&theme, &table, "/tmp/test", 1);
    }

    #[test]
    fn print_snapshot_with_entries() {
        let theme = Theme::new(false);
        let mut table = HashMap::new();
        table.insert(
            (100, "3r".to_string()),
            WatchEntry {
                pid: 100,
                command: "cat".to_string(),
                uid: 501,
                fd: "3r".to_string(),
                first_seen: 1,
                last_seen: 5,
                gone: false,
            },
        );
        print_snapshot(&theme, &table, "/tmp/test", 5);
    }

    #[test]
    fn print_event_open() {
        let theme = Theme::new(false);
        print_event(&theme, "+OPEN", 100, "cat", 501, "3r", 1);
    }

    #[test]
    fn print_event_close() {
        let theme = Theme::new(false);
        print_event(&theme, "-CLOSE", 100, "cat", 501, "3r", 5);
    }

    #[test]
    fn print_event_long_command() {
        let theme = Theme::new(false);
        print_event(
            &theme,
            "+OPEN",
            100,
            "a_very_long_command_name_exceeding_twenty",
            501,
            "3r",
            1,
        );
    }
}
