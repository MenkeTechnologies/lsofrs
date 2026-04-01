//! Top-N mode — live-sorted processes by FD count, auto-refreshing dashboard

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};

use crate::filter::Filter;
use crate::theme::LsofTheme;
use crate::tui_app::{TuiMode, TuiState, set_cell, set_str};
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
            None => i64::MAX,
        }
    }

    fn username(&self) -> String {
        users::get_user_by_uid(self.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| self.uid.to_string())
    }
}

impl Clone for TopEntry {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            uid: self.uid,
            command: self.command.clone(),
            fd_count: self.fd_count,
            reg_count: self.reg_count,
            sock_count: self.sock_count,
            pipe_count: self.pipe_count,
            other_count: self.other_count,
            prev_fd_count: self.prev_fd_count,
        }
    }
}

pub struct TopMode {
    sort_col: SortCol,
    reverse: bool,
    show_n: usize,
    show_bar: bool,
    show_delta: bool,
    prev_counts: std::collections::HashMap<i32, usize>,
    entries: Vec<TopEntry>,
    total_procs: usize,
    total_fds: usize,
}

impl TopMode {
    pub fn new(top_n: usize) -> Self {
        Self {
            sort_col: SortCol::Fds,
            reverse: false,
            show_n: if top_n == 0 { DEFAULT_TOP_N } else { top_n },
            show_bar: true,
            show_delta: true,
            prev_counts: std::collections::HashMap::new(),
            entries: Vec::new(),
            total_procs: 0,
            total_fds: 0,
        }
    }

    /// Number of entries currently displayed (min of show_n and entries).
    pub fn visible_count(&self) -> usize {
        self.entries.len().min(self.show_n)
    }
}

impl TuiMode for TopMode {
    fn update(&mut self, filter: &Filter) {
        let mut procs = crate::gather_processes();
        procs.retain(|p| filter.matches_process(p));
        for p in &mut procs {
            p.files.retain(|f| filter.matches_file(f));
        }

        self.entries = procs
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
                    prev_fd_count: self.prev_counts.get(&p.pid).copied(),
                }
            })
            .collect();

        self.prev_counts.clear();
        for p in &procs {
            self.prev_counts.insert(p.pid, p.files.len());
        }

        self.total_procs = procs.len();
        self.total_fds = procs.iter().map(|p| p.files.len()).sum();
    }

    fn render(&self, buf: &mut Buffer, area: Rect, theme: &LsofTheme, state: &TuiState) {
        let mut sorted_entries = self.entries.clone();
        sort_entries(&mut sorted_entries, self.sort_col, self.reverse);
        let display: Vec<&TopEntry> = sorted_entries.iter().take(self.show_n).collect();

        render_top(
            buf,
            area,
            theme,
            &display,
            state.iteration,
            self.sort_col,
            self.reverse,
            self.show_n,
            state.interval,
            state.paused,
            self.show_bar,
            self.show_delta,
            self.total_procs,
            self.total_fds,
        );
    }

    fn handle_key(&mut self, key: KeyEvent, _state: &mut TuiState) -> bool {
        use crossterm::event::KeyCode;

        match key.code {
            KeyCode::Char('s') => {
                self.sort_col = self.sort_col.next();
                true
            }
            KeyCode::Char('S') => {
                self.sort_col = self.sort_col.next();
                self.reverse = !self.reverse;
                true
            }
            KeyCode::Char('r') => {
                self.reverse = !self.reverse;
                true
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                self.show_n = (self.show_n + 5).min(200);
                true
            }
            KeyCode::Char('-') | KeyCode::Char('_') => {
                self.show_n = self.show_n.saturating_sub(5).max(5);
                true
            }
            KeyCode::Char('b') => {
                self.show_bar = !self.show_bar;
                true
            }
            KeyCode::Char('d') => {
                self.show_delta = !self.show_delta;
                true
            }
            _ => false,
        }
    }

    fn title(&self) -> &str {
        "top"
    }

    fn help_keys(&self) -> Vec<(&str, &str)> {
        vec![
            ("s", "cycle sort"),
            ("r", "reverse"),
            ("+/-", "count"),
            ("b", "bar"),
            ("d", "delta"),
        ]
    }
}

pub fn run_top(filter: &Filter, interval: u64, theme: &LsofTheme, top_n: usize) {
    let mut mode = TopMode::new(top_n);
    crate::tui_app::run_tui(&mut mode, filter, interval, theme);
}

fn sort_entries(entries: &mut [TopEntry], sort_col: SortCol, reverse: bool) {
    entries.sort_by(|a, b| {
        let cmp = match sort_col {
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
        if sort_col == SortCol::Pid || sort_col == SortCol::User || sort_col == SortCol::Command {
            if reverse { cmp.reverse() } else { cmp }
        } else {
            if reverse { cmp } else { cmp.reverse() }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn render_top(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    entries: &[&TopEntry],
    _iteration: u64,
    sort_col: SortCol,
    reverse: bool,
    show_n: usize,
    _interval: u64,
    paused: bool,
    show_bar: bool,
    show_delta: bool,
    total_procs: usize,
    total_fds: usize,
) {
    let mut row = area.y;

    // Styles from theme
    let pid_s = Style::default().fg(theme.pid_fg);
    let user_s = Style::default().fg(theme.user_fg);
    let cmd_s = Style::default().fg(theme.cmd_fg);
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);
    let dim_s = Style::default().fg(theme.dim_fg);
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let active_s = Style::default()
        .fg(theme.user_fg)
        .add_modifier(Modifier::BOLD);

    // Info line
    if row < area.y + area.height {
        let sort_indicator = format!(
            "sort:{}{}",
            sort_col.label(),
            if reverse { "^" } else { "v" }
        );
        let pause_str = if paused { " [PAUSED]" } else { "" };
        let info = format!(
            "  {} procs, {} FDs -- top {} -- {sort_indicator}{pause_str}",
            total_procs, total_fds, show_n,
        );
        set_str(buf, area.x, row, &info, dim_s, area.width);
        row += 1;
    }
    row += 1; // blank line

    // Column header
    if row < area.y + area.height {
        // Fill header bg
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }

        let mut col_x = area.x + 1;
        let write_hdr = |buf: &mut Buffer,
                         cx: &mut u16,
                         col: SortCol,
                         label: &str,
                         width: usize,
                         right: bool| {
            let marker = if sort_col == col {
                let is_alpha =
                    col == SortCol::Pid || col == SortCol::User || col == SortCol::Command;
                if is_alpha {
                    if reverse { "v" } else { "^" }
                } else if reverse {
                    "^"
                } else {
                    "v"
                }
            } else {
                ""
            };
            let text = format!("{label}{marker}");
            let s = if sort_col == col { active_s } else { hdr_s };
            if right {
                let padded = format!("{:>w$}", text, w = width);
                set_str(buf, *cx, row, &padded, s, width as u16);
            } else {
                let padded = format!("{:<w$}", text, w = width);
                set_str(buf, *cx, row, &padded, s, width as u16);
            }
            *cx += width as u16 + 2;
        };

        write_hdr(buf, &mut col_x, SortCol::Pid, "PID", 7, true);
        write_hdr(buf, &mut col_x, SortCol::User, "USER", 8, false);
        write_hdr(buf, &mut col_x, SortCol::Fds, "FDs", 5, true);
        if show_delta {
            write_hdr(buf, &mut col_x, SortCol::Delta, "DELTA", 6, true);
        }
        write_hdr(buf, &mut col_x, SortCol::Reg, "REG", 4, true);
        write_hdr(buf, &mut col_x, SortCol::Sock, "SOCK", 4, true);
        write_hdr(buf, &mut col_x, SortCol::Pipe, "PIPE", 4, true);
        write_hdr(buf, &mut col_x, SortCol::Other, "OTHER", 5, true);
        if show_bar {
            set_str(buf, col_x, row, "DISTRIBUTION          ", hdr_s, 22);
            col_x += 22;
        }
        write_hdr(buf, &mut col_x, SortCol::Command, "COMMAND", 7, false);
        row += 1;
    }

    // Data rows
    for (i, e) in entries.iter().enumerate() {
        if row >= area.y + area.height {
            break;
        }

        let alt_s = if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };

        // Fill row background for alt rows
        if i % 2 == 1 {
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", alt_s);
            }
        }

        let user = e.username();
        let user_display = if user.len() > 8 { &user[..8] } else { &user };
        let cmd = if e.command.len() > 30 {
            &e.command[..30]
        } else {
            &e.command
        };

        let mut col_x = area.x + 1;

        // PID
        let pid_str = format!("{:>7}", e.pid);
        set_str(buf, col_x, row, &pid_str, pid_s.patch(alt_s), 7);
        col_x += 9;

        // USER
        let user_str = format!("{:<8}", user_display);
        set_str(buf, col_x, row, &user_str, user_s.patch(alt_s), 8);
        col_x += 10;

        // FDs
        let fds_str = format!("{:>5}", e.fd_count);
        set_str(buf, col_x, row, &fds_str, bold_s.patch(alt_s), 5);
        col_x += 7;

        // Delta
        if show_delta {
            let (delta_str, delta_s) = match e.prev_fd_count {
                Some(prev) if e.fd_count > prev => (
                    format!("+{}", e.fd_count - prev),
                    Style::default().fg(theme.delta_plus),
                ),
                Some(prev) if e.fd_count < prev => (
                    format!("-{}", prev - e.fd_count),
                    Style::default().fg(theme.delta_minus),
                ),
                Some(_) => ("=".to_string(), Style::default().fg(theme.delta_stable)),
                None => ("new".to_string(), Style::default().fg(theme.dim_fg)),
            };
            let ds = format!("{:>6}", delta_str);
            set_str(buf, col_x, row, &ds, delta_s.patch(alt_s), 6);
            col_x += 8;
        }

        // REG, SOCK, PIPE, OTHER
        let reg_str = format!("{:>4}", e.reg_count);
        set_str(buf, col_x, row, &reg_str, dim_s.patch(alt_s), 4);
        col_x += 6;
        let sock_str = format!("{:>4}", e.sock_count);
        set_str(buf, col_x, row, &sock_str, dim_s.patch(alt_s), 4);
        col_x += 6;
        let pipe_str = format!("{:>4}", e.pipe_count);
        set_str(buf, col_x, row, &pipe_str, dim_s.patch(alt_s), 4);
        col_x += 6;
        let other_str = format!("{:>5}", e.other_count);
        set_str(buf, col_x, row, &other_str, dim_s.patch(alt_s), 5);
        col_x += 7;

        // Distribution bar
        if show_bar {
            let bar_width: usize = 20;
            let total = e.fd_count.max(1);
            let reg_w = (e.reg_count * bar_width) / total;
            let sock_w = (e.sock_count * bar_width) / total;
            let pipe_w = (e.pipe_count * bar_width) / total;
            let other_w = bar_width.saturating_sub(reg_w + sock_w + pipe_w);

            let reg_s = Style::default().fg(theme.bar_reg);
            let sock_s = Style::default().fg(theme.bar_sock);
            let pipe_s = Style::default().fg(theme.bar_pipe);
            let other_s = Style::default().fg(theme.bar_other);

            let mut bx = col_x;
            for _ in 0..reg_w {
                set_cell(buf, bx, row, "█", reg_s);
                bx += 1;
            }
            for _ in 0..sock_w {
                set_cell(buf, bx, row, "█", sock_s);
                bx += 1;
            }
            for _ in 0..pipe_w {
                set_cell(buf, bx, row, "█", pipe_s);
                bx += 1;
            }
            for _ in 0..other_w {
                set_cell(buf, bx, row, "░", other_s);
                bx += 1;
            }
            col_x += bar_width as u16 + 2;
        }

        // COMMAND
        set_str(buf, col_x, row, cmd, cmd_s.patch(alt_s), 30);

        row += 1;
    }

    // Legend
    row += 1;
    if show_bar && row < area.y + area.height {
        let legend_s = Style::default().fg(theme.legend_fg);
        let reg_s = Style::default().fg(theme.bar_reg);
        let sock_s = Style::default().fg(theme.bar_sock);
        let pipe_s = Style::default().fg(theme.bar_pipe);
        let other_s = Style::default().fg(theme.bar_other);

        let mut lx = area.x + 2;
        set_str(buf, lx, row, "██", reg_s, 2);
        lx += 2;
        set_str(buf, lx, row, " REG/DIR/CHR  ", legend_s, 14);
        lx += 14;
        set_str(buf, lx, row, "██", sock_s, 2);
        lx += 2;
        set_str(buf, lx, row, " SOCK/NET  ", legend_s, 11);
        lx += 11;
        set_str(buf, lx, row, "██", pipe_s, 2);
        lx += 2;
        set_str(buf, lx, row, " PIPE  ", legend_s, 7);
        lx += 7;
        set_str(buf, lx, row, "░░", other_s, 2);
        lx += 2;
        set_str(buf, lx, row, " OTHER", legend_s, 6);
    }
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

    fn test_theme() -> LsofTheme {
        LsofTheme::from_name(crate::theme::ThemeName::NeonSprawl)
    }

    fn test_buf() -> (Buffer, Rect) {
        let area = Rect::new(0, 0, 120, 40);
        (Buffer::empty(area), area)
    }

    #[test]
    fn render_empty_no_panic() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
        render_top(
            &mut buf,
            area,
            &theme,
            &[],
            1,
            SortCol::Fds,
            false,
            20,
            1,
            false,
            true,
            true,
            0,
            0,
        );
    }

    #[test]
    fn render_with_entries_no_panic() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
        let entries = [
            make_entry(100, "chrome", 50, Some(45)),
            make_entry(200, "nginx", 30, Some(30)),
            make_entry(300, "postgres", 20, None),
        ];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        render_top(
            &mut buf,
            area,
            &theme,
            &refs,
            3,
            SortCol::Fds,
            false,
            20,
            1,
            false,
            true,
            true,
            100,
            500,
        );
    }

    #[test]
    fn render_paused_indicator() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
        render_top(
            &mut buf,
            area,
            &theme,
            &[],
            1,
            SortCol::Fds,
            false,
            20,
            1,
            true,
            true,
            true,
            0,
            0,
        );
    }

    #[test]
    fn render_no_bar() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
        let entries = [make_entry(1, "test", 10, Some(5))];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        render_top(
            &mut buf,
            area,
            &theme,
            &refs,
            1,
            SortCol::Fds,
            false,
            20,
            1,
            false,
            false,
            true,
            1,
            10,
        );
    }

    #[test]
    fn render_no_delta() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
        let entries = [make_entry(1, "test", 10, Some(5))];
        let refs: Vec<&TopEntry> = entries.iter().collect();
        render_top(
            &mut buf,
            area,
            &theme,
            &refs,
            1,
            SortCol::Fds,
            false,
            20,
            1,
            false,
            true,
            false,
            1,
            10,
        );
    }

    #[test]
    fn render_zero_fds_no_panic() {
        let (mut buf, area) = test_buf();
        let theme = test_theme();
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
        render_top(
            &mut buf,
            area,
            &theme,
            &refs,
            1,
            SortCol::Fds,
            false,
            20,
            1,
            false,
            true,
            true,
            1,
            0,
        );
    }

    // ── Sort tests ──────────────────────────────────────────────────

    #[test]
    fn sort_by_fds_descending() {
        let mut entries = vec![
            make_entry(1, "a", 10, None),
            make_entry(2, "b", 50, None),
            make_entry(3, "c", 30, None),
        ];
        sort_entries(&mut entries, SortCol::Fds, false);
        assert_eq!(entries[0].pid, 2);
        assert_eq!(entries[1].pid, 3);
        assert_eq!(entries[2].pid, 1);
    }

    #[test]
    fn sort_by_fds_reversed_ascending() {
        let mut entries = vec![make_entry(1, "a", 10, None), make_entry(2, "b", 50, None)];
        sort_entries(&mut entries, SortCol::Fds, true);
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
        sort_entries(&mut entries, SortCol::Pid, false);
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
        sort_entries(&mut entries, SortCol::Command, false);
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
        sort_entries(&mut entries, SortCol::Sock, false);
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
        assert_eq!(seen.len(), 9);
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

    // ── TopMode trait impl ──────────────────────────────────────────

    #[test]
    fn top_mode_help_keys() {
        let mode = TopMode::new(20);
        let keys = mode.help_keys();
        assert_eq!(keys.len(), 5);
        assert_eq!(keys[0].0, "s");
    }

    #[test]
    fn top_mode_title() {
        let mode = TopMode::new(20);
        assert_eq!(mode.title(), "top");
    }
}
