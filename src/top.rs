//! Top-N mode — live-sorted processes by FD count, auto-refreshing dashboard

use std::io::{self, Write};
use std::time::Duration;

use crossterm::{
    cursor, execute,
    terminal::{self, ClearType},
};

use crate::filter::Filter;
use crate::output::Theme;
use crate::types::*;

const DEFAULT_TOP_N: usize = 20;

struct TopEntry {
    pid: i32,
    ppid: i32,
    pgid: i32,
    uid: u32,
    command: String,
    fd_count: usize,
    reg_count: usize,
    sock_count: usize,
    pipe_count: usize,
    other_count: usize,
    prev_fd_count: Option<usize>,
}

pub fn run_top(filter: &Filter, interval: u64, theme: &Theme, top_n: usize) {
    let n = if top_n == 0 { DEFAULT_TOP_N } else { top_n };
    let mut prev_counts: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
    let mut iteration = 0u64;

    // Use alternate screen if TTY
    let use_alt = theme.is_tty;
    if use_alt {
        let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
        let _ = terminal::enable_raw_mode();
    }

    // Handle Ctrl-C (only in interactive mode)
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    if use_alt {
        let r = running.clone();
        ctrlc_handler(move || {
            r.store(false, std::sync::atomic::Ordering::SeqCst);
        });
    }

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        iteration += 1;
        let mut procs = crate::darwin::gather_processes();
        procs.retain(|p| filter.matches_process(p));
        for p in &mut procs {
            p.files.retain(|f| filter.matches_file(f));
        }

        let mut entries: Vec<TopEntry> = procs
            .iter()
            .map(|p| {
                let mut reg = 0;
                let mut sock = 0;
                let mut pipe = 0;
                let mut other = 0;
                for f in &p.files {
                    match f.file_type {
                        FileType::Reg | FileType::Dir | FileType::Chr => reg += 1,
                        FileType::IPv4 | FileType::IPv6 | FileType::Unix | FileType::Sock => {
                            sock += 1
                        }
                        FileType::Pipe => pipe += 1,
                        _ => other += 1,
                    }
                }
                TopEntry {
                    pid: p.pid,
                    ppid: p.ppid,
                    pgid: p.pgid,
                    uid: p.uid,
                    command: p.command.clone(),
                    fd_count: p.files.len(),
                    reg_count: reg,
                    sock_count: sock,
                    pipe_count: pipe,
                    other_count: other,
                    prev_fd_count: prev_counts.get(&p.pid).copied(),
                }
            })
            .collect();

        // Sort by FD count descending
        entries.sort_by(|a, b| b.fd_count.cmp(&a.fd_count));
        entries.truncate(n);

        // Update prev counts
        prev_counts.clear();
        for p in &procs {
            prev_counts.insert(p.pid, p.files.len());
        }

        let total_procs = procs.len();
        let total_fds: usize = procs.iter().map(|p| p.files.len()).sum();

        render(
            theme,
            &entries,
            iteration,
            interval,
            total_procs,
            total_fds,
            n,
        );

        // Non-TTY: single-shot, print once and exit
        if !use_alt {
            break;
        }

        // TTY: check for 'q' key during interval
        let deadline = std::time::Instant::now() + Duration::from_secs(interval);
        while std::time::Instant::now() < deadline {
            if crossterm::event::poll(Duration::from_millis(100)).unwrap_or(false)
                && let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read()
                && (key.code == crossterm::event::KeyCode::Char('q')
                    || key.code == crossterm::event::KeyCode::Esc)
            {
                running.store(false, std::sync::atomic::Ordering::SeqCst);
                break;
            }
        }
    }

    if use_alt {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
    }
}

fn ctrlc_handler<F: Fn() + Send + 'static>(f: F) {
    let _ = std::thread::spawn(move || {
        let set = nix::sys::signal::SigSet::from(nix::sys::signal::Signal::SIGINT);
        let _ = set.thread_block();
        let _ = set.wait();
        f();
    });
}

fn render(
    theme: &Theme,
    entries: &[TopEntry],
    iteration: u64,
    interval: u64,
    total_procs: usize,
    total_fds: usize,
    top_n: usize,
) {
    // Build entire frame into a buffer, then write atomically to avoid
    // partial-line flicker in raw mode / alternate screen
    let mut buf = String::with_capacity(4096);

    if theme.is_tty {
        // MoveTo(0,0) + Clear will be done via crossterm before the write
    }

    use std::fmt::Write as FmtWrite;

    let _ = writeln!(
        buf,
        "{bold}{hdr} lsofrs top — {procs} processes, {fds} open files — refresh {int}s — iteration {iter} {reset}",
        bold = theme.bold(),
        hdr = theme.hdr_bg(),
        procs = total_procs,
        fds = total_fds,
        int = interval,
        iter = iteration,
        reset = theme.reset(),
    );
    let _ = writeln!(
        buf,
        "{dim}  showing top {n} by FD count — press q to quit{reset}",
        dim = theme.dim(),
        n = top_n,
        reset = theme.reset(),
    );
    let _ = writeln!(buf);

    // Header
    let r = theme.reset();
    let _ = writeln!(
        buf,
        "{bold}{hdr}{:>7}  {:<8}  {:>5}  {:>6}  {:>4}  {:>4}  {:>4}  {:>5}  {:<20}  COMMAND{r}",
        "PID",
        "USER",
        "FDs",
        "DELTA",
        "REG",
        "SOCK",
        "PIPE",
        "OTHER",
        "DISTRIBUTION",
        bold = theme.bold(),
        hdr = theme.hdr_bg(),
    );

    for (i, e) in entries.iter().enumerate() {
        let username = users::get_user_by_uid(e.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| e.uid.to_string());
        let user_display = if username.len() > 8 {
            &username[..8]
        } else {
            &username
        };
        let cmd = if e.command.len() > 25 {
            &e.command[..25]
        } else {
            &e.command
        };

        let delta_str = match e.prev_fd_count {
            Some(prev) if e.fd_count > prev => format!("+{}", e.fd_count - prev),
            Some(prev) if e.fd_count < prev => format!("-{}", prev - e.fd_count),
            Some(_) => "=".to_string(),
            None => "new".to_string(),
        };
        let delta_color = match e.prev_fd_count {
            Some(prev) if e.fd_count > prev => theme.red(),
            Some(prev) if e.fd_count < prev => theme.green(),
            _ => theme.dim(),
        };

        // Distribution bar (20 chars visible width)
        let bar_width = 20;
        let total = e.fd_count.max(1);
        let reg_w = (e.reg_count * bar_width) / total;
        let sock_w = (e.sock_count * bar_width) / total;
        let pipe_w = (e.pipe_count * bar_width) / total;
        let other_w = bar_width.saturating_sub(reg_w + sock_w + pipe_w);

        let mut bar = String::new();
        if reg_w > 0 {
            bar.push_str(theme.cyan());
            bar.push_str(&"█".repeat(reg_w));
        }
        if sock_w > 0 {
            bar.push_str(theme.green());
            bar.push_str(&"█".repeat(sock_w));
        }
        if pipe_w > 0 {
            bar.push_str(theme.yellow());
            bar.push_str(&"█".repeat(pipe_w));
        }
        if other_w > 0 {
            bar.push_str(theme.dim());
            bar.push_str(&"░".repeat(other_w));
        }
        bar.push_str(r);

        let alt = if i % 2 == 1 { theme.row_alt() } else { "" };

        let _ = writeln!(
            buf,
            "{alt}{}{:>7}{r}  {}{:<8}{r}  {}{:>5}{r}  {}{:>6}{r}  {:>4}  {:>4}  {:>4}  {:>5}  {bar}  {}{cmd}{r}",
            theme.magenta(),
            e.pid,
            theme.yellow(),
            user_display,
            theme.bold(),
            e.fd_count,
            delta_color,
            delta_str,
            e.reg_count,
            e.sock_count,
            e.pipe_count,
            e.other_count,
            theme.cyan(),
        );
    }

    let _ = writeln!(buf);
    let _ = writeln!(
        buf,
        "{dim}  {cyan}██{r}{dim} REG/DIR/CHR  {green}██{r}{dim} SOCK/NET  {yellow}██{r}{dim} PIPE  {dim}░░ OTHER{r}",
        dim = theme.dim(),
        cyan = theme.cyan(),
        green = theme.green(),
        yellow = theme.yellow(),
    );

    // Atomic write: clear screen then dump entire buffer at once
    // In raw mode, \n doesn't return to column 0 — must use \r\n
    if theme.is_tty {
        buf = buf.replace('\n', "\r\n");
    }
    let out = io::stdout();
    let mut out = out.lock();
    if theme.is_tty {
        let _ = execute!(out, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All));
    }
    let _ = out.write_all(buf.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(pid: i32, cmd: &str, fds: usize, prev: Option<usize>) -> TopEntry {
        TopEntry {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 501,
            command: cmd.to_string(),
            fd_count: fds,
            reg_count: fds / 2,
            sock_count: fds / 4,
            pipe_count: fds / 8,
            other_count: fds - fds / 2 - fds / 4 - fds / 8,
            prev_fd_count: prev,
        }
    }

    #[test]
    fn render_empty_no_panic() {
        let theme = Theme::new(false);
        render(&theme, &[], 1, 2, 0, 0, 20);
    }

    #[test]
    fn render_with_entries_no_panic() {
        let theme = Theme::new(false);
        let entries = vec![
            make_entry(100, "chrome", 50, Some(45)),
            make_entry(200, "nginx", 30, Some(30)),
            make_entry(300, "postgres", 20, None),
        ];
        render(&theme, &entries, 3, 1, 100, 500, 20);
    }

    #[test]
    fn render_delta_increase() {
        let theme = Theme::new(false);
        let entries = vec![make_entry(100, "leaky", 100, Some(50))];
        render(&theme, &entries, 1, 1, 1, 100, 20);
    }

    #[test]
    fn render_delta_decrease() {
        let theme = Theme::new(false);
        let entries = vec![make_entry(100, "shrinking", 10, Some(50))];
        render(&theme, &entries, 1, 1, 1, 10, 20);
    }

    #[test]
    fn render_delta_stable() {
        let theme = Theme::new(false);
        let entries = vec![make_entry(100, "stable", 30, Some(30))];
        render(&theme, &entries, 1, 1, 1, 30, 20);
    }

    #[test]
    fn render_delta_new_process() {
        let theme = Theme::new(false);
        let entries = vec![make_entry(100, "new", 10, None)];
        render(&theme, &entries, 1, 1, 1, 10, 20);
    }

    #[test]
    fn render_long_command_truncated() {
        let theme = Theme::new(false);
        let entries = vec![make_entry(
            100,
            "a_very_long_command_name_that_exceeds_25_chars",
            10,
            None,
        )];
        render(&theme, &entries, 1, 1, 1, 10, 20);
    }

    #[test]
    fn render_zero_fds_no_panic() {
        let theme = Theme::new(false);
        let entries = vec![TopEntry {
            pid: 1,
            ppid: 0,
            pgid: 1,
            uid: 0,
            command: "idle".to_string(),
            fd_count: 0,
            reg_count: 0,
            sock_count: 0,
            pipe_count: 0,
            other_count: 0,
            prev_fd_count: Some(0),
        }];
        render(&theme, &entries, 1, 1, 1, 0, 20);
    }

    #[test]
    fn render_tty_mode_no_panic() {
        // Even with is_tty=true, render should not panic (just won't clear screen properly)
        let theme = Theme::new(false); // use false to avoid actual terminal escape
        let entries = vec![make_entry(1, "test", 5, Some(3))];
        render(&theme, &entries, 10, 5, 50, 200, 10);
    }
}
