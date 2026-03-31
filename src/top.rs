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

#[derive(Clone, Copy, PartialEq)]
enum SortCol {
    Fds,
    Pid,
    User,
    Reg,
    Sock,
    Pipe,
    Other,
    Delta,
    Command,
}

impl SortCol {
    fn label(self) -> &'static str {
        match self {
            Self::Fds => "FDs",
            Self::Pid => "PID",
            Self::User => "USER",
            Self::Reg => "REG",
            Self::Sock => "SOCK",
            Self::Pipe => "PIPE",
            Self::Other => "OTHER",
            Self::Delta => "DELTA",
            Self::Command => "CMD",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Fds => Self::Pid,
            Self::Pid => Self::User,
            Self::User => Self::Reg,
            Self::Reg => Self::Sock,
            Self::Sock => Self::Pipe,
            Self::Pipe => Self::Other,
            Self::Other => Self::Delta,
            Self::Delta => Self::Command,
            Self::Command => Self::Fds,
        }
    }
}

struct TopState {
    sort_col: SortCol,
    reverse: bool,
    show_n: usize,
    interval: u64,
    paused: bool,
    show_bar: bool,
    show_help: bool,
    show_delta: bool,
}

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

impl TopEntry {
    fn delta_val(&self) -> i64 {
        match self.prev_fd_count {
            Some(prev) => self.fd_count as i64 - prev as i64,
            None => i64::MAX, // "new" sorts to top
        }
    }

    fn username(&self) -> String {
        users::get_user_by_uid(self.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| self.uid.to_string())
    }
}

pub fn run_top(filter: &Filter, interval: u64, theme: &Theme, top_n: usize) {
    let mut state = TopState {
        sort_col: SortCol::Fds,
        reverse: false,
        show_n: if top_n == 0 { DEFAULT_TOP_N } else { top_n },
        interval,
        paused: false,
        show_bar: true,
        show_help: false,
        show_delta: true,
    };
    let mut prev_counts: std::collections::HashMap<i32, usize> = std::collections::HashMap::new();
    let mut iteration = 0u64;
    let mut cached_entries: Vec<TopEntry> = Vec::new();
    let mut cached_total_procs = 0usize;
    let mut cached_total_fds = 0usize;

    let use_alt = theme.is_tty;
    if use_alt {
        let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
        let _ = terminal::enable_raw_mode();
    }

    let mut running = true;

    while running {
        if !state.paused {
            iteration += 1;
            let mut procs = crate::darwin::gather_processes();
            procs.retain(|p| filter.matches_process(p));
            for p in &mut procs {
                p.files.retain(|f| filter.matches_file(f));
            }

            cached_entries = procs
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

            prev_counts.clear();
            for p in &procs {
                prev_counts.insert(p.pid, p.files.len());
            }

            cached_total_procs = procs.len();
            cached_total_fds = procs.iter().map(|p| p.files.len()).sum();
        }

        // Sort
        sort_entries(&mut cached_entries, &state);
        let display: Vec<&TopEntry> = cached_entries.iter().take(state.show_n).collect();

        render(
            theme,
            &display,
            iteration,
            &state,
            cached_total_procs,
            cached_total_fds,
        );

        // Non-TTY: single-shot
        if !use_alt {
            break;
        }

        // TTY: poll keys during interval
        let deadline = std::time::Instant::now() + Duration::from_secs(state.interval);
        while std::time::Instant::now() < deadline {
            if !crossterm::event::poll(Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }
            let Ok(crossterm::event::Event::Key(key)) = crossterm::event::read() else {
                continue;
            };

            use crossterm::event::KeyCode;

            match key.code {
                // Quit
                KeyCode::Char('q') | KeyCode::Esc => {
                    running = false;
                    break;
                }
                KeyCode::Char('c')
                    if key
                        .modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL) =>
                {
                    running = false;
                    break;
                }

                // Sort
                KeyCode::Char('s') => {
                    state.sort_col = state.sort_col.next();
                    break; // re-render immediately
                }
                KeyCode::Char('S') => {
                    // reverse cycle
                    state.sort_col = state.sort_col.next();
                    state.reverse = !state.reverse;
                    break;
                }
                KeyCode::Char('r') => {
                    state.reverse = !state.reverse;
                    break;
                }

                // Adjust count
                KeyCode::Char('+') | KeyCode::Char('=') => {
                    state.show_n = (state.show_n + 5).min(200);
                    break;
                }
                KeyCode::Char('-') | KeyCode::Char('_') => {
                    state.show_n = state.show_n.saturating_sub(5).max(5);
                    break;
                }

                // Refresh interval
                KeyCode::Char('<') | KeyCode::Char('[') => {
                    state.interval = state.interval.saturating_sub(1).max(1);
                    break;
                }
                KeyCode::Char('>') | KeyCode::Char(']') => {
                    state.interval = (state.interval + 1).min(60);
                    break;
                }
                KeyCode::Char(d @ '1'..='9') => {
                    state.interval = (d as u64) - b'0' as u64;
                    break;
                }

                // Toggles
                KeyCode::Char('p') => {
                    state.paused = !state.paused;
                    break;
                }
                KeyCode::Char('b') => {
                    state.show_bar = !state.show_bar;
                    break;
                }
                KeyCode::Char('d') => {
                    state.show_delta = !state.show_delta;
                    break;
                }
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    state.show_help = !state.show_help;
                    break;
                }

                _ => {}
            }
        }
    }

    if use_alt {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
    }
}

fn sort_entries(entries: &mut [TopEntry], state: &TopState) {
    entries.sort_by(|a, b| {
        let cmp = match state.sort_col {
            SortCol::Fds => a.fd_count.cmp(&b.fd_count),
            SortCol::Pid => a.pid.cmp(&b.pid),
            SortCol::User => a.username().cmp(&b.username()),
            SortCol::Reg => a.reg_count.cmp(&b.reg_count),
            SortCol::Sock => a.sock_count.cmp(&b.sock_count),
            SortCol::Pipe => a.pipe_count.cmp(&b.pipe_count),
            SortCol::Other => a.other_count.cmp(&b.other_count),
            SortCol::Delta => a.delta_val().cmp(&b.delta_val()),
            SortCol::Command => a.command.cmp(&b.command),
        };
        if state.sort_col == SortCol::Pid
            || state.sort_col == SortCol::User
            || state.sort_col == SortCol::Command
        {
            if state.reverse { cmp.reverse() } else { cmp }
        } else {
            // Numeric columns default descending
            if state.reverse { cmp } else { cmp.reverse() }
        }
    });
}

fn render(
    theme: &Theme,
    entries: &[&TopEntry],
    iteration: u64,
    state: &TopState,
    total_procs: usize,
    total_fds: usize,
) {
    use std::fmt::Write as FmtWrite;
    let mut buf = String::with_capacity(4096);
    let r = theme.reset();

    // Title bar
    let pause_indicator = if state.paused { " [PAUSED]" } else { "" };
    let sort_indicator = format!(
        "sort:{}{}",
        state.sort_col.label(),
        if state.reverse { "↑" } else { "↓" }
    );
    let _ = writeln!(
        buf,
        "{bold}{hdr} lsofrs top — {procs} procs, {fds} FDs — {int}s — #{iter}{pause} — {sort} {r}",
        bold = theme.bold(),
        hdr = theme.hdr_bg(),
        procs = total_procs,
        fds = total_fds,
        int = state.interval,
        iter = iteration,
        pause = pause_indicator,
        sort = sort_indicator,
    );

    // Help or status line
    if state.show_help {
        let _ = writeln!(
            buf,
            "{dim}  ── KEYS ──────────────────────────────────────────{r}",
            dim = theme.dim()
        );
        let _ = writeln!(
            buf,
            "{green}  s{r} cycle sort column    {green}r{r} reverse sort order",
            green = theme.green()
        );
        let _ = writeln!(
            buf,
            "{green}  +/-{r} show more/fewer    {green}1-9{r} set refresh interval",
            green = theme.green()
        );
        let _ = writeln!(
            buf,
            "{green}  </>  {r} adjust interval   {green}p{r} pause/resume",
            green = theme.green()
        );
        let _ = writeln!(
            buf,
            "{green}  b{r} toggle bar           {green}d{r} toggle delta column",
            green = theme.green()
        );
        let _ = writeln!(
            buf,
            "{green}  h/?{r} toggle this help    {green}q/Esc/^C{r} quit",
            green = theme.green()
        );
        let _ = writeln!(
            buf,
            "{dim}  ──────────────────────────────────────────────────{r}",
            dim = theme.dim()
        );
    } else {
        let _ = writeln!(
            buf,
            "{dim}  top {n} — s:sort r:reverse +/-:count 1-9:interval p:pause b:bar d:delta ?:help q:quit{r}",
            dim = theme.dim(),
            n = state.show_n,
        );
    }
    let _ = writeln!(buf);

    // Header — highlight the active sort column
    let hdr = |col: SortCol, label: &str, width: usize, right: bool| -> String {
        let marker = if state.sort_col == col {
            if state.sort_col == SortCol::Pid
                || state.sort_col == SortCol::User
                || state.sort_col == SortCol::Command
            {
                if state.reverse { "↓" } else { "↑" }
            } else if state.reverse {
                "↑"
            } else {
                "↓"
            }
        } else {
            ""
        };
        let active = state.sort_col == col;
        let text = format!("{label}{marker}");
        if active {
            if right {
                format!("{}{:>width$}{}", theme.yellow(), text, r, width = width)
            } else {
                format!("{}{:<width$}{}", theme.yellow(), text, r, width = width)
            }
        } else if right {
            format!("{:>width$}", text, width = width)
        } else {
            format!("{:<width$}", text, width = width)
        }
    };

    let _ = write!(
        buf,
        "{bold}{bg}{}  {}  {}  ",
        hdr(SortCol::Pid, "PID", 7, true),
        hdr(SortCol::User, "USER", 8, false),
        hdr(SortCol::Fds, "FDs", 5, true),
        bold = theme.bold(),
        bg = theme.hdr_bg(),
    );
    if state.show_delta {
        let _ = write!(buf, "{}  ", hdr(SortCol::Delta, "DELTA", 6, true));
    }
    let _ = write!(
        buf,
        "{}  {}  {}  {}  ",
        hdr(SortCol::Reg, "REG", 4, true),
        hdr(SortCol::Sock, "SOCK", 4, true),
        hdr(SortCol::Pipe, "PIPE", 4, true),
        hdr(SortCol::Other, "OTHER", 5, true),
    );
    if state.show_bar {
        let _ = write!(buf, "{:<20}  ", "DISTRIBUTION");
    }
    let _ = writeln!(buf, "{}{r}", hdr(SortCol::Command, "COMMAND", 7, false));

    // Rows
    for (i, e) in entries.iter().enumerate() {
        let user = e.username();
        let user_display = if user.len() > 8 { &user[..8] } else { &user };
        let cmd = if e.command.len() > 30 {
            &e.command[..30]
        } else {
            &e.command
        };

        let alt = if i % 2 == 1 { theme.row_alt() } else { "" };

        let _ = write!(
            buf,
            "{alt}{}{:>7}{r}  {}{:<8}{r}  {}{:>5}{r}  ",
            theme.magenta(),
            e.pid,
            theme.yellow(),
            user_display,
            theme.bold(),
            e.fd_count,
        );

        if state.show_delta {
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
            let _ = write!(buf, "{delta_color}{:>6}{r}  ", delta_str);
        }

        let _ = write!(
            buf,
            "{:>4}  {:>4}  {:>4}  {:>5}  ",
            e.reg_count, e.sock_count, e.pipe_count, e.other_count,
        );

        if state.show_bar {
            let bar_width = 20;
            let total = e.fd_count.max(1);
            let reg_w = (e.reg_count * bar_width) / total;
            let sock_w = (e.sock_count * bar_width) / total;
            let pipe_w = (e.pipe_count * bar_width) / total;
            let other_w = bar_width.saturating_sub(reg_w + sock_w + pipe_w);

            if reg_w > 0 {
                let _ = write!(buf, "{}{}", theme.cyan(), "█".repeat(reg_w));
            }
            if sock_w > 0 {
                let _ = write!(buf, "{}{}", theme.green(), "█".repeat(sock_w));
            }
            if pipe_w > 0 {
                let _ = write!(buf, "{}{}", theme.yellow(), "█".repeat(pipe_w));
            }
            if other_w > 0 {
                let _ = write!(buf, "{}{}", theme.dim(), "░".repeat(other_w));
            }
            let _ = write!(buf, "{r}  ");
        }

        let _ = writeln!(buf, "{}{cmd}{r}", theme.cyan());
    }

    // Legend
    let _ = writeln!(buf);
    if state.show_bar {
        let _ = writeln!(
            buf,
            "{dim}  {cyan}██{r}{dim} REG/DIR/CHR  {green}██{r}{dim} SOCK/NET  {yellow}██{r}{dim} PIPE  {dim}░░ OTHER{r}",
            dim = theme.dim(),
            cyan = theme.cyan(),
            green = theme.green(),
            yellow = theme.yellow(),
        );
    }

    // Raw mode: \n → \r\n
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

    fn default_state() -> TopState {
        TopState {
            sort_col: SortCol::Fds,
            reverse: false,
            show_n: 20,
            interval: 1,
            paused: false,
            show_bar: true,
            show_help: false,
            show_delta: true,
        }
    }

    #[test]
    fn render_empty_no_panic() {
        let theme = Theme::new(false);
        render(&theme, &[], 1, &default_state(), 0, 0);
    }

    #[test]
    fn render_with_entries_no_panic() {
        let theme = Theme::new(false);
        let entries = [
            make_entry(100, "chrome", 50, Some(45)),
            make_entry(200, "nginx", 30, Some(30)),
            make_entry(300, "postgres", 20, None),
        ];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        render(&theme, &refs, 3, &default_state(), 100, 500);
    }

    #[test]
    fn render_paused_indicator() {
        let theme = Theme::new(false);
        let mut state = default_state();
        state.paused = true;
        render(&theme, &[], 1, &state, 0, 0);
    }

    #[test]
    fn render_help_overlay() {
        let theme = Theme::new(false);
        let mut state = default_state();
        state.show_help = true;
        render(&theme, &[], 1, &state, 0, 0);
    }

    #[test]
    fn render_no_bar() {
        let theme = Theme::new(false);
        let entries = [make_entry(1, "test", 10, Some(5))];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        let mut state = default_state();
        state.show_bar = false;
        render(&theme, &refs, 1, &state, 1, 10);
    }

    #[test]
    fn render_no_delta() {
        let theme = Theme::new(false);
        let entries = [make_entry(1, "test", 10, Some(5))];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        let mut state = default_state();
        state.show_delta = false;
        render(&theme, &refs, 1, &state, 1, 10);
    }

    #[test]
    fn render_zero_fds_no_panic() {
        let theme = Theme::new(false);
        let entries = [TopEntry {
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
        let refs: Vec<&TopEntry> = entries.iter().collect();
        render(&theme, &refs, 1, &default_state(), 1, 0);
    }

    // ── Sort tests ──────────────────────────────────────────────────

    #[test]
    fn sort_by_fds_descending() {
        let mut entries = vec![
            make_entry(1, "a", 10, None),
            make_entry(2, "b", 50, None),
            make_entry(3, "c", 30, None),
        ];
        let state = default_state();
        sort_entries(&mut entries, &state);
        assert_eq!(entries[0].pid, 2);
        assert_eq!(entries[1].pid, 3);
        assert_eq!(entries[2].pid, 1);
    }

    #[test]
    fn sort_by_fds_reversed_ascending() {
        let mut entries = vec![make_entry(1, "a", 10, None), make_entry(2, "b", 50, None)];
        let mut state = default_state();
        state.reverse = true;
        sort_entries(&mut entries, &state);
        assert_eq!(entries[0].pid, 1);
        assert_eq!(entries[1].pid, 2);
    }

    #[test]
    fn sort_by_pid_ascending() {
        let mut entries = vec![
            make_entry(300, "c", 10, None),
            make_entry(100, "a", 10, None),
            make_entry(200, "b", 10, None),
        ];
        let mut state = default_state();
        state.sort_col = SortCol::Pid;
        sort_entries(&mut entries, &state);
        assert_eq!(entries[0].pid, 100);
        assert_eq!(entries[2].pid, 300);
    }

    #[test]
    fn sort_by_command() {
        let mut entries = vec![
            make_entry(1, "zsh", 10, None),
            make_entry(2, "apache", 10, None),
            make_entry(3, "nginx", 10, None),
        ];
        let mut state = default_state();
        state.sort_col = SortCol::Command;
        sort_entries(&mut entries, &state);
        assert_eq!(entries[0].command, "apache");
        assert_eq!(entries[2].command, "zsh");
    }

    #[test]
    fn sort_by_sock_descending() {
        let mut entries = vec![
            TopEntry {
                sock_count: 5,
                ..make_entry(1, "a", 20, None)
            },
            TopEntry {
                sock_count: 20,
                ..make_entry(2, "b", 20, None)
            },
            TopEntry {
                sock_count: 10,
                ..make_entry(3, "c", 20, None)
            },
        ];
        let mut state = default_state();
        state.sort_col = SortCol::Sock;
        sort_entries(&mut entries, &state);
        assert_eq!(entries[0].pid, 2);
        assert_eq!(entries[1].pid, 3);
    }

    // ── SortCol cycle ───────────────────────────────────────────────

    #[test]
    fn sort_col_cycles_through_all() {
        let mut col = SortCol::Fds;
        let mut seen = vec![col];
        for _ in 0..20 {
            col = col.next();
            if col == SortCol::Fds {
                break;
            }
            seen.push(col);
        }
        assert_eq!(seen.len(), 9); // all 9 columns
    }

    #[test]
    fn sort_col_labels() {
        assert_eq!(SortCol::Fds.label(), "FDs");
        assert_eq!(SortCol::Pid.label(), "PID");
        assert_eq!(SortCol::Command.label(), "CMD");
    }

    // ── TopEntry helpers ────────────────────────────────────────────

    #[test]
    fn delta_val_increase() {
        let e = make_entry(1, "a", 20, Some(10));
        assert_eq!(e.delta_val(), 10);
    }

    #[test]
    fn delta_val_decrease() {
        let e = make_entry(1, "a", 5, Some(10));
        assert_eq!(e.delta_val(), -5);
    }

    #[test]
    fn delta_val_new() {
        let e = make_entry(1, "a", 10, None);
        assert_eq!(e.delta_val(), i64::MAX);
    }

    #[test]
    fn delta_val_stable() {
        let e = make_entry(1, "a", 10, Some(10));
        assert_eq!(e.delta_val(), 0);
    }
}
