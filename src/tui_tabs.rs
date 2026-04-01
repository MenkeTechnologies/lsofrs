//! Unified tabbed TUI — single `--tui` flag launches all modes as tabs

use std::collections::{BTreeSet, HashMap};
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::{cursor, execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};

use crate::filter::Filter;
use crate::summary::SummaryLiveMode;
use crate::theme::LsofTheme;
#[cfg(test)]
use crate::theme::ThemeName;
use crate::top::TopMode;
use crate::tui_app::{TuiMode, TuiState, draw_help, set_cell, set_str};
use crate::types::*;

// ── Tab enum ──────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Top,
    Summary,
    Ports,
    Stale,
    Tree,
    NetMap,
    PipeChain,
}

impl Tab {
    const ALL: [Tab; 7] = [
        Tab::Top,
        Tab::Summary,
        Tab::Ports,
        Tab::Stale,
        Tab::Tree,
        Tab::NetMap,
        Tab::PipeChain,
    ];

    fn label(self) -> &'static str {
        match self {
            Tab::Top => "TOP",
            Tab::Summary => "SUMMARY",
            Tab::Ports => "PORTS",
            Tab::Stale => "STALE",
            Tab::Tree => "TREE",
            Tab::NetMap => "NET-MAP",
            Tab::PipeChain => "PIPES",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|&t| t == self).unwrap_or(0)
    }
}

// ── Simple tab data types ─────────────────────────────────────────────────────

struct PortRow {
    proto: String,
    addr: String,
    port: u16,
    pid: i32,
    user: String,
    command: String,
}

struct StaleRow {
    pid: i32,
    user: String,
    fd: String,
    file_type: String,
    size: Option<u64>,
    name: String,
}

struct TreeRow {
    indent: usize,
    pid: i32,
    user: String,
    fd_count: usize,
    command: String,
    connector: String,
}

struct NetMapRow {
    host: String,
    count: usize,
    protocols: String,
    ports: String,
    processes: String,
}

struct PipeRow {
    kind: String,
    id: String,
    endpoints: String,
}

// ── Tabbed TUI state ─────────────────────────────────────────────────────────

struct TabbedTui {
    active: Tab,
    // Mode impls for Top and Summary
    top_mode: TopMode,
    summary_mode: SummaryLiveMode,
    // Data for simple tabs
    port_rows: Vec<PortRow>,
    stale_rows: Vec<StaleRow>,
    tree_rows: Vec<TreeRow>,
    net_map_rows: Vec<NetMapRow>,
    pipe_rows: Vec<PipeRow>,
}

impl TabbedTui {
    fn new() -> Self {
        Self {
            active: Tab::Top,
            top_mode: TopMode::new(20),
            summary_mode: SummaryLiveMode::new(),
            port_rows: Vec::new(),
            stale_rows: Vec::new(),
            tree_rows: Vec::new(),
            net_map_rows: Vec::new(),
            pipe_rows: Vec::new(),
        }
    }

    fn update_all(&mut self, filter: &Filter) {
        // Gather once
        let mut procs = crate::gather_processes();
        procs.retain(|p| filter.matches_process(p));
        for p in &mut procs {
            p.files.retain(|f| filter.matches_file(f));
        }

        // Top and Summary use TuiMode::update which gathers internally,
        // so we call them directly (they do their own gathering)
        self.top_mode.update(filter);
        self.summary_mode.update(filter);

        // Simple tabs use the shared process list
        self.update_ports(&procs);
        self.update_stale(&procs);
        self.update_tree(&procs);
        self.update_net_map(&procs);
        self.update_pipes(&procs);
    }

    fn update_ports(&mut self, procs: &[Process]) {
        self.port_rows.clear();
        for p in procs {
            let user = p.username();
            for f in &p.files {
                if let Some(si) = &f.socket_info {
                    let proto = si.protocol.to_uppercase();
                    let is_tcp = proto == "TCP";
                    let is_udp = proto == "UDP";
                    if !is_tcp && !is_udp {
                        continue;
                    }
                    if is_tcp && !matches!(si.tcp_state, Some(TcpState::Listen)) {
                        continue;
                    }
                    let port = si.local.port;
                    if port == 0 {
                        continue;
                    }
                    let addr = si
                        .local
                        .addr
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "*".to_string());
                    self.port_rows.push(PortRow {
                        proto,
                        addr,
                        port,
                        pid: p.pid,
                        user: user.clone(),
                        command: p.command.clone(),
                    });
                }
            }
        }
        self.port_rows.sort_by_key(|r| r.port);
    }

    fn update_stale(&mut self, procs: &[Process]) {
        self.stale_rows.clear();
        for p in procs {
            let user = p.username();
            for f in &p.files {
                let deleted = f.name.contains("(deleted)")
                    || f.name_append
                        .as_deref()
                        .is_some_and(|a| a.contains("(deleted)"));
                if deleted {
                    self.stale_rows.push(StaleRow {
                        pid: p.pid,
                        user: user.clone(),
                        fd: f.fd.with_access(f.access),
                        file_type: f.file_type.as_str().to_string(),
                        size: f.size,
                        name: f.full_name(),
                    });
                }
            }
        }
    }

    fn update_tree(&mut self, procs: &[Process]) {
        self.tree_rows.clear();
        let mut nodes: HashMap<i32, (i32, String, u32, usize, Vec<i32>)> = HashMap::new();
        for p in procs {
            nodes.insert(
                p.pid,
                (p.ppid, p.command.clone(), p.uid, p.files.len(), Vec::new()),
            );
        }
        let pids: Vec<i32> = nodes.keys().copied().collect();
        for &pid in &pids {
            let ppid = nodes[&pid].0;
            if ppid != pid && nodes.contains_key(&ppid) {
                let children = &mut nodes.get_mut(&ppid).unwrap().4;
                children.push(pid);
            }
        }
        for v in nodes.values_mut() {
            v.4.sort();
        }
        let mut roots: Vec<i32> = nodes
            .iter()
            .filter(|&(&pid, &(ppid, ..))| !nodes.contains_key(&ppid) || ppid == pid)
            .map(|(&pid, _)| pid)
            .collect();
        roots.sort();

        fn walk(
            nodes: &HashMap<i32, (i32, String, u32, usize, Vec<i32>)>,
            pid: i32,
            depth: usize,
            is_last: bool,
            rows: &mut Vec<TreeRow>,
        ) {
            let Some((_, cmd, uid, fds, ref children)) = nodes.get(&pid).cloned() else {
                return;
            };
            let connector = if depth == 0 {
                String::new()
            } else if is_last {
                "\\-- ".to_string()
            } else {
                "|-- ".to_string()
            };
            let user = users::get_user_by_uid(uid)
                .map(|u| u.name().to_string_lossy().into_owned())
                .unwrap_or_else(|| uid.to_string());
            rows.push(TreeRow {
                indent: depth,
                pid,
                user,
                fd_count: fds,
                command: cmd,
                connector,
            });
            for (i, &child) in children.iter().enumerate() {
                walk(nodes, child, depth + 1, i == children.len() - 1, rows);
            }
        }

        for (i, &root) in roots.iter().enumerate() {
            walk(&nodes, root, 0, i == roots.len() - 1, &mut self.tree_rows);
        }
    }

    fn update_net_map(&mut self, procs: &[Process]) {
        struct RG {
            host: String,
            protocols: BTreeSet<String>,
            ports: BTreeSet<u16>,
            processes: Vec<(i32, String)>,
            count: usize,
        }
        let mut groups: HashMap<String, RG> = HashMap::new();
        for p in procs {
            for f in &p.files {
                if !matches!(f.file_type, FileType::IPv4 | FileType::IPv6) {
                    continue;
                }
                let Some(si) = &f.socket_info else {
                    continue;
                };
                let addr = si
                    .foreign
                    .addr
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "*".to_string());
                let fport = si.foreign.port;
                if addr == "*" && fport == 0 {
                    continue;
                }
                let key = if addr == "*" {
                    format!("*:{fport}")
                } else {
                    addr.clone()
                };
                let g = groups.entry(key.clone()).or_insert_with(|| RG {
                    host: key,
                    protocols: BTreeSet::new(),
                    ports: BTreeSet::new(),
                    processes: Vec::new(),
                    count: 0,
                });
                g.count += 1;
                if !si.protocol.is_empty() {
                    g.protocols.insert(si.protocol.to_uppercase());
                }
                if fport > 0 {
                    g.ports.insert(fport);
                }
                if !g.processes.iter().any(|(pid, _)| *pid == p.pid) {
                    g.processes.push((p.pid, p.command.clone()));
                }
            }
        }
        let mut rows: Vec<NetMapRow> = groups
            .into_values()
            .map(|g| {
                let procs_str = g
                    .processes
                    .iter()
                    .map(|(pid, cmd)| format!("{pid}/{cmd}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ports_str = g
                    .ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                NetMapRow {
                    host: g.host,
                    count: g.count,
                    protocols: g.protocols.into_iter().collect::<Vec<_>>().join(","),
                    ports: ports_str,
                    processes: procs_str,
                }
            })
            .collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count));
        self.net_map_rows = rows;
    }

    #[allow(clippy::type_complexity)]
    fn update_pipes(&mut self, procs: &[Process]) {
        let mut groups: HashMap<(String, String), Vec<(i32, String, String)>> = HashMap::new();
        for p in procs {
            for f in &p.files {
                if let Some((kind, id)) = pipe_id(f) {
                    groups.entry((kind, id)).or_default().push((
                        p.pid,
                        p.command.clone(),
                        f.fd.with_access(f.access),
                    ));
                }
            }
        }
        let mut rows: Vec<PipeRow> = groups
            .into_iter()
            .filter(|(_, eps)| eps.len() >= 2)
            .map(|((kind, id), eps)| {
                let ep_str = eps
                    .iter()
                    .map(|(pid, cmd, fd)| format!("{pid}/{cmd}({fd})"))
                    .collect::<Vec<_>>()
                    .join(" <-> ");
                PipeRow {
                    kind,
                    id,
                    endpoints: ep_str,
                }
            })
            .collect();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        self.pipe_rows = rows;
    }

    fn help_keys(&self) -> Vec<(&str, &str)> {
        let mut keys = vec![
            ("Tab / Right", "next tab"),
            ("BackTab / Left", "previous tab"),
            ("1-7", "jump to tab"),
        ];
        match self.active {
            Tab::Top => keys.extend(self.top_mode.help_keys()),
            Tab::Summary => keys.extend(self.summary_mode.help_keys()),
            _ => {}
        }
        keys
    }
}

fn pipe_id(file: &OpenFile) -> Option<(String, String)> {
    let name = &file.name;
    if file.file_type == FileType::Pipe {
        if let Some(pos) = name.find("0x") {
            let hex = name[pos..]
                .split_whitespace()
                .next()
                .unwrap_or(&name[pos..]);
            return Some(("pipe".to_string(), hex.to_string()));
        }
        if let Some(start) = name.find("pipe:[") {
            let rest = &name[start + 6..];
            if let Some(end) = rest.find(']') {
                return Some(("pipe".to_string(), rest[..end].to_string()));
            }
        }
        return Some(("pipe".to_string(), name.clone()));
    }
    if file.file_type == FileType::Unix {
        if let Some(start) = name.find("socket:[") {
            let rest = &name[start + 8..];
            if let Some(end) = rest.find(']') {
                return Some(("unix".to_string(), rest[..end].to_string()));
            }
        }
        if let Some(pos) = name.find("0x") {
            let hex = name[pos..]
                .split_whitespace()
                .next()
                .unwrap_or(&name[pos..]);
            return Some(("unix".to_string(), hex.to_string()));
        }
    }
    None
}

// ── Tab bar rendering ─────────────────────────────────────────────────────────

fn draw_tab_bar(buf: &mut Buffer, area: Rect, active: Tab, theme: &LsofTheme) {
    let bg_s = Style::default().fg(theme.dim_fg).bg(theme.header_bg);
    // Fill row
    for x in area.x..area.x + area.width {
        set_cell(buf, x, area.y, " ", bg_s);
    }

    let active_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let inactive_s = Style::default().fg(theme.dim_fg).bg(theme.header_bg);
    let sep_s = Style::default().fg(theme.dim_fg).bg(theme.header_bg);

    let mut x = area.x + 1;
    for (i, &tab) in Tab::ALL.iter().enumerate() {
        if i > 0 {
            set_str(buf, x, area.y, " | ", sep_s, 3);
            x += 3;
        }
        let label = format!(" {} ", tab.label());
        let s = if tab == active { active_s } else { inactive_s };
        set_str(buf, x, area.y, &label, s, label.len() as u16);
        x += label.len() as u16;
    }
}

fn draw_status_bar(buf: &mut Buffer, area: Rect, state: &TuiState, active: Tab) {
    let t = &state.theme;
    let bg_s = Style::default().fg(t.dim_fg).bg(t.row_alt_bg);
    for x in area.x..area.x + area.width {
        set_cell(buf, x, area.y, " ", bg_s);
    }
    let pause_str = if state.paused { " [PAUSED]" } else { "" };
    let status = format!(
        " {} -- {}s -- #{}{} -- theme: {}",
        active.label(),
        state.interval,
        state.iteration,
        pause_str,
        state.theme.name.display_name(),
    );
    set_str(buf, area.x, area.y, &status, bg_s, area.width);
}

// ── Simple tab renderers ──────────────────────────────────────────────────────

fn render_ports(buf: &mut Buffer, area: Rect, theme: &LsofTheme, rows: &[PortRow]) {
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let pid_s = Style::default().fg(theme.pid_fg);
    let user_s = Style::default().fg(theme.user_fg);
    let cmd_s = Style::default().fg(theme.cmd_fg);
    let type_s = Style::default().fg(theme.type_fg);
    let dim_s = Style::default().fg(theme.dim_fg);

    let mut row = area.y;
    let cx = area.x + 2;
    let w = area.width;

    if rows.is_empty() {
        set_str(buf, cx, row, "No listening ports found.", dim_s, w);
        return;
    }

    let info = format!("{} listening port(s)", rows.len());
    set_str(buf, cx, row, &info, bold_s, w);
    row += 2;

    if row < area.y + area.height {
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }
        let hdr = format!(
            "{:<5}  {:<15}  {:>5}  {:>7}  {:<8}  COMMAND",
            "PROTO", "LOCAL ADDR", "PORT", "PID", "USER"
        );
        set_str(buf, cx, row, &hdr, hdr_s, w);
        row += 1;
    }

    for (i, r) in rows.iter().enumerate() {
        if row >= area.y + area.height {
            break;
        }
        let alt_s = if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if i % 2 == 1 {
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", alt_s);
            }
        }
        let user = if r.user.len() > 8 {
            &r.user[..8]
        } else {
            &r.user
        };
        let cmd = if r.command.len() > 20 {
            &r.command[..20]
        } else {
            &r.command
        };

        set_str(
            buf,
            cx,
            row,
            &format!("{:<5}", r.proto),
            type_s.patch(alt_s),
            5,
        );
        set_str(
            buf,
            cx + 7,
            row,
            &format!("{:<15}", r.addr),
            dim_s.patch(alt_s),
            15,
        );
        set_str(
            buf,
            cx + 24,
            row,
            &format!("{:>5}", r.port),
            bold_s.patch(alt_s),
            5,
        );
        set_str(
            buf,
            cx + 31,
            row,
            &format!("{:>7}", r.pid),
            pid_s.patch(alt_s),
            7,
        );
        set_str(
            buf,
            cx + 40,
            row,
            &format!("{:<8}", user),
            user_s.patch(alt_s),
            8,
        );
        set_str(buf, cx + 50, row, cmd, cmd_s.patch(alt_s), 20);
        row += 1;
    }
}

fn render_stale(buf: &mut Buffer, area: Rect, theme: &LsofTheme, rows: &[StaleRow]) {
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let pid_s = Style::default().fg(theme.pid_fg);
    let user_s = Style::default().fg(theme.user_fg);
    let type_s = Style::default().fg(theme.type_fg);
    let dim_s = Style::default().fg(theme.dim_fg);
    let del_s = Style::default().fg(theme.delta_plus);

    let mut row = area.y;
    let cx = area.x + 2;
    let w = area.width;

    if rows.is_empty() {
        set_str(
            buf,
            cx,
            row,
            "No stale (deleted) file descriptors found.",
            dim_s,
            w,
        );
        return;
    }

    let info = format!("{} stale FD(s)", rows.len());
    set_str(buf, cx, row, &info, bold_s, w);
    row += 2;

    if row < area.y + area.height {
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }
        let hdr = format!(
            "{:>7}  {:<8}  {:<5}  {:<5}  {:>8}  NAME",
            "PID", "USER", "FD", "TYPE", "SIZE"
        );
        set_str(buf, cx, row, &hdr, hdr_s, w);
        row += 1;
    }

    for (i, r) in rows.iter().enumerate() {
        if row >= area.y + area.height {
            break;
        }
        let alt_s = if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if i % 2 == 1 {
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", alt_s);
            }
        }
        let user = if r.user.len() > 8 {
            &r.user[..8]
        } else {
            &r.user
        };
        let size_str = r.size.map(|s| s.to_string()).unwrap_or_default();
        let name = if r.name.len() as u16 > w.saturating_sub(50) {
            &r.name[..w.saturating_sub(50) as usize]
        } else {
            &r.name
        };

        set_str(
            buf,
            cx,
            row,
            &format!("{:>7}", r.pid),
            pid_s.patch(alt_s),
            7,
        );
        set_str(
            buf,
            cx + 9,
            row,
            &format!("{:<8}", user),
            user_s.patch(alt_s),
            8,
        );
        set_str(
            buf,
            cx + 19,
            row,
            &format!("{:<5}", r.fd),
            dim_s.patch(alt_s),
            5,
        );
        set_str(
            buf,
            cx + 26,
            row,
            &format!("{:<5}", r.file_type),
            type_s.patch(alt_s),
            5,
        );
        set_str(
            buf,
            cx + 33,
            row,
            &format!("{:>8}", size_str),
            dim_s.patch(alt_s),
            8,
        );
        set_str(
            buf,
            cx + 43,
            row,
            name,
            del_s.patch(alt_s),
            w.saturating_sub(45),
        );
        row += 1;
    }
}

fn render_tree(buf: &mut Buffer, area: Rect, theme: &LsofTheme, rows: &[TreeRow]) {
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let pid_s = Style::default().fg(theme.pid_fg);
    let user_s = Style::default().fg(theme.user_fg);
    let cmd_s = Style::default().fg(theme.cmd_fg);
    let dim_s = Style::default().fg(theme.dim_fg);
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);

    let mut row = area.y;
    let cx = area.x + 2;
    let w = area.width;

    if rows.is_empty() {
        set_str(buf, cx, row, "No processes found.", dim_s, w);
        return;
    }

    if row < area.y + area.height {
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }
        set_str(buf, cx, row, "  PID   USER     FDs  COMMAND", hdr_s, w);
        row += 1;
    }

    for r in rows {
        if row >= area.y + area.height {
            break;
        }
        let indent_str = "    ".repeat(r.indent);
        let prefix = format!("{}{}", indent_str, r.connector);
        let user = if r.user.len() > 8 {
            &r.user[..8]
        } else {
            &r.user
        };
        let cmd = if r.command.len() > 20 {
            &r.command[..20]
        } else {
            &r.command
        };

        let mut x = cx;
        set_str(buf, x, row, &prefix, dim_s, prefix.len() as u16);
        x += prefix.len() as u16;
        let pid_str = format!("{:>5}", r.pid);
        set_str(buf, x, row, &pid_str, pid_s, 5);
        x += 6;
        let user_str = format!("{:<8}", user);
        set_str(buf, x, row, &user_str, user_s, 8);
        x += 9;
        let fd_str = format!("{:>4}", r.fd_count);
        set_str(buf, x, row, &fd_str, bold_s, 4);
        x += 5;
        set_str(buf, x, row, cmd, cmd_s, w.saturating_sub(x - area.x));
        row += 1;
    }
}

fn render_net_map(buf: &mut Buffer, area: Rect, theme: &LsofTheme, rows: &[NetMapRow]) {
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let dim_s = Style::default().fg(theme.dim_fg);
    let cmd_s = Style::default().fg(theme.cmd_fg);
    let type_s = Style::default().fg(theme.type_fg);
    let pid_s = Style::default().fg(theme.pid_fg);

    let mut row = area.y;
    let cx = area.x + 2;
    let w = area.width;

    if rows.is_empty() {
        set_str(buf, cx, row, "No network connections found.", dim_s, w);
        return;
    }

    let total: usize = rows.iter().map(|r| r.count).sum();
    let info = format!("{} remote host(s), {} connection(s)", rows.len(), total);
    set_str(buf, cx, row, &info, bold_s, w);
    row += 2;

    if row < area.y + area.height {
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }
        let hdr = format!(
            "{:<20}  {:>5}  {:<9}  {:<10}  PROCESSES",
            "REMOTE HOST", "CONNS", "PROTOCOLS", "PORTS"
        );
        set_str(buf, cx, row, &hdr, hdr_s, w);
        row += 1;
    }

    for (i, r) in rows.iter().enumerate() {
        if row >= area.y + area.height {
            break;
        }
        let alt_s = if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if i % 2 == 1 {
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", alt_s);
            }
        }
        let host = if r.host.len() > 20 {
            &r.host[..20]
        } else {
            &r.host
        };
        set_str(
            buf,
            cx,
            row,
            &format!("{:<20}", host),
            pid_s.patch(alt_s),
            20,
        );
        set_str(
            buf,
            cx + 22,
            row,
            &format!("{:>5}", r.count),
            bold_s.patch(alt_s),
            5,
        );
        set_str(
            buf,
            cx + 29,
            row,
            &format!("{:<9}", r.protocols),
            type_s.patch(alt_s),
            9,
        );
        set_str(
            buf,
            cx + 40,
            row,
            &format!("{:<10}", r.ports),
            dim_s.patch(alt_s),
            10,
        );
        let proc_w = w.saturating_sub(52);
        let procs = if r.processes.len() as u16 > proc_w {
            &r.processes[..proc_w as usize]
        } else {
            &r.processes
        };
        set_str(buf, cx + 52, row, procs, cmd_s.patch(alt_s), proc_w);
        row += 1;
    }
}

fn render_pipes(buf: &mut Buffer, area: Rect, theme: &LsofTheme, rows: &[PipeRow]) {
    let bold_s = Style::default()
        .fg(theme.bold_fg)
        .add_modifier(Modifier::BOLD);
    let hdr_s = Style::default()
        .fg(theme.header_fg)
        .bg(theme.header_bg)
        .add_modifier(Modifier::BOLD);
    let dim_s = Style::default().fg(theme.dim_fg);
    let cmd_s = Style::default().fg(theme.cmd_fg);
    let type_s = Style::default().fg(theme.type_fg);

    let mut row = area.y;
    let cx = area.x + 2;
    let w = area.width;

    if rows.is_empty() {
        set_str(
            buf,
            cx,
            row,
            "No pipe/socket IPC connections found.",
            dim_s,
            w,
        );
        return;
    }

    let info = format!("{} IPC connection(s)", rows.len());
    set_str(buf, cx, row, &info, bold_s, w);
    row += 2;

    if row < area.y + area.height {
        for x in area.x..area.x + area.width {
            set_cell(buf, x, row, " ", hdr_s);
        }
        let hdr = format!("{:<6}  {:<20}  ENDPOINTS", "TYPE", "IDENTIFIER");
        set_str(buf, cx, row, &hdr, hdr_s, w);
        row += 1;
    }

    for (i, r) in rows.iter().enumerate() {
        if row >= area.y + area.height {
            break;
        }
        let alt_s = if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if i % 2 == 1 {
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", alt_s);
            }
        }
        let id = if r.id.len() > 20 { &r.id[..20] } else { &r.id };
        set_str(
            buf,
            cx,
            row,
            &format!("{:<6}", r.kind),
            type_s.patch(alt_s),
            6,
        );
        set_str(
            buf,
            cx + 8,
            row,
            &format!("{:<20}", id),
            dim_s.patch(alt_s),
            20,
        );
        let ep_w = w.saturating_sub(30);
        let eps = if r.endpoints.len() as u16 > ep_w {
            &r.endpoints[..ep_w as usize]
        } else {
            &r.endpoints
        };
        set_str(buf, cx + 30, row, eps, cmd_s.patch(alt_s), ep_w);
        row += 1;
    }
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub fn run_tui_tabs(filter: &Filter, interval: u64, theme: &LsofTheme) {
    if !io::stdout().is_terminal() {
        eprintln!("lsofrs: --tui requires a terminal (not a pipe or redirect)");
        return;
    }

    let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
    let _ = terminal::enable_raw_mode();

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = TuiState::new_pub(interval, theme.clone());
    let mut tui = TabbedTui::new();
    let mut running = true;

    while running {
        if !state.paused {
            state.iteration += 1;
            tui.update_all(filter);
        }

        let _ = terminal.draw(|frame| {
            let size = frame.area();
            if size.width < 10 || size.height < 5 {
                return;
            }

            // Row 0: tab bar
            draw_tab_bar(
                frame.buffer_mut(),
                Rect {
                    x: 0,
                    y: 0,
                    width: size.width,
                    height: 1,
                },
                tui.active,
                &state.theme,
            );

            // Row 1: status bar
            if size.height > 1 {
                draw_status_bar(
                    frame.buffer_mut(),
                    Rect {
                        x: 0,
                        y: 1,
                        width: size.width,
                        height: 1,
                    },
                    &state,
                    tui.active,
                );
            }

            // Row 2+: content
            if size.height > 2 {
                let content_area = Rect {
                    x: 0,
                    y: 2,
                    width: size.width,
                    height: size.height.saturating_sub(2),
                };
                match tui.active {
                    Tab::Top => {
                        tui.top_mode
                            .render(frame.buffer_mut(), content_area, &state.theme, &state)
                    }
                    Tab::Summary => tui.summary_mode.render(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &state,
                    ),
                    Tab::Ports => render_ports(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.port_rows,
                    ),
                    Tab::Stale => render_stale(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.stale_rows,
                    ),
                    Tab::Tree => render_tree(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.tree_rows,
                    ),
                    Tab::NetMap => render_net_map(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.net_map_rows,
                    ),
                    Tab::PipeChain => render_pipes(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.pipe_rows,
                    ),
                }
            }

            // Help overlay
            if state.show_help {
                draw_help(frame.buffer_mut(), size, &state.theme, tui.help_keys());
            }
        });

        // Poll keys
        let deadline = Instant::now() + Duration::from_secs(state.interval);
        while Instant::now() < deadline {
            if !event::poll(Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }
            let Ok(Event::Key(key)) = event::read() else {
                continue;
            };

            // Tab navigation first
            match key.code {
                KeyCode::Tab | KeyCode::Right => {
                    let idx = (tui.active.index() + 1) % Tab::ALL.len();
                    tui.active = Tab::ALL[idx];
                    break;
                }
                KeyCode::BackTab | KeyCode::Left => {
                    let idx = (tui.active.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                    tui.active = Tab::ALL[idx];
                    break;
                }
                _ => {}
            }

            // Number keys 1-7 for tab jump (only when not consumed by interval)
            // Check for active tab mode-specific keys
            let consumed = match tui.active {
                Tab::Top => tui.top_mode.handle_key(key, &mut state),
                Tab::Summary => tui.summary_mode.handle_key(key, &mut state),
                _ => false,
            };
            if consumed {
                break;
            }

            // Common keybindings
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    running = false;
                    break;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    running = false;
                    break;
                }
                KeyCode::Char('p') => {
                    state.paused = !state.paused;
                    break;
                }
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    state.show_help = !state.show_help;
                    break;
                }
                KeyCode::Char('c') => {
                    state.cycle_theme();
                    break;
                }
                KeyCode::Char(d @ '1'..='7') => {
                    let idx = (d as usize) - ('1' as usize);
                    if idx < Tab::ALL.len() {
                        tui.active = Tab::ALL[idx];
                    }
                    break;
                }
                KeyCode::Char(d @ '8'..='9') => {
                    state.interval = (d as u64) - b'0' as u64;
                    break;
                }
                KeyCode::Char('<') | KeyCode::Char('[') => {
                    state.interval = state.interval.saturating_sub(1).max(1);
                    break;
                }
                KeyCode::Char('>') | KeyCode::Char(']') => {
                    state.interval = (state.interval + 1).min(60);
                    break;
                }
                _ => {}
            }
        }
    }

    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tab_all_count() {
        assert_eq!(Tab::ALL.len(), 7);
    }

    #[test]
    fn tab_labels() {
        assert_eq!(Tab::Top.label(), "TOP");
        assert_eq!(Tab::PipeChain.label(), "PIPES");
    }

    #[test]
    fn tab_index_roundtrip() {
        for (i, &tab) in Tab::ALL.iter().enumerate() {
            assert_eq!(tab.index(), i);
        }
    }

    #[test]
    fn tabbed_tui_new() {
        let tui = TabbedTui::new();
        assert_eq!(tui.active, Tab::Top);
        assert!(tui.port_rows.is_empty());
        assert!(tui.stale_rows.is_empty());
    }

    #[test]
    fn pipe_id_macos_pipe() {
        let f = OpenFile {
            fd: FdName::Number(3),
            access: Access::ReadWrite,
            file_type: FileType::Pipe,
            name: "->0xabc123".to_string(),
            ..Default::default()
        };
        let result = pipe_id(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "pipe");
        assert_eq!(id, "0xabc123");
    }

    #[test]
    fn pipe_id_regular_file() {
        let f = OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/tmp/foo".to_string(),
            ..Default::default()
        };
        assert!(pipe_id(&f).is_none());
    }

    #[test]
    fn render_ports_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_ports(&mut buf, area, &theme, &[]);
    }

    #[test]
    fn render_stale_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_stale(&mut buf, area, &theme, &[]);
    }

    #[test]
    fn render_tree_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_tree(&mut buf, area, &theme, &[]);
    }

    #[test]
    fn render_net_map_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_net_map(&mut buf, area, &theme, &[]);
    }

    #[test]
    fn render_pipes_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_pipes(&mut buf, area, &theme, &[]);
    }

    #[test]
    fn draw_tab_bar_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 1);
        let mut buf = Buffer::empty(area);
        draw_tab_bar(&mut buf, area, Tab::Top, &theme);
    }

    #[test]
    fn draw_tab_bar_each_active() {
        let theme = LsofTheme::from_name(ThemeName::Classic);
        let area = Rect::new(0, 0, 100, 1);
        for &tab in &Tab::ALL {
            let mut buf = Buffer::empty(area);
            draw_tab_bar(&mut buf, area, tab, &theme);
        }
    }

    #[test]
    fn help_keys_includes_tab_nav() {
        let tui = TabbedTui::new();
        let keys = tui.help_keys();
        assert!(keys.iter().any(|(k, _)| *k == "Tab / Right"));
        assert!(keys.iter().any(|(k, _)| *k == "1-7"));
    }

    #[test]
    fn help_keys_top_includes_sort() {
        let mut tui = TabbedTui::new();
        tui.active = Tab::Top;
        let keys = tui.help_keys();
        assert!(keys.iter().any(|(k, _)| *k == "s"));
    }

    #[test]
    fn render_ports_with_data() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        let rows = vec![
            PortRow {
                proto: "TCP".to_string(),
                addr: "*".to_string(),
                port: 80,
                pid: 100,
                user: "root".to_string(),
                command: "nginx".to_string(),
            },
            PortRow {
                proto: "TCP".to_string(),
                addr: "*".to_string(),
                port: 443,
                pid: 100,
                user: "root".to_string(),
                command: "nginx".to_string(),
            },
        ];
        render_ports(&mut buf, area, &theme, &rows);
    }

    #[test]
    fn render_stale_with_data() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        let rows = vec![StaleRow {
            pid: 42,
            user: "root".to_string(),
            fd: "3u".to_string(),
            file_type: "REG".to_string(),
            size: Some(1024),
            name: "/tmp/foo (deleted)".to_string(),
        }];
        render_stale(&mut buf, area, &theme, &rows);
    }

    #[test]
    fn render_tree_with_data() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        let rows = vec![
            TreeRow {
                indent: 0,
                pid: 1,
                user: "root".to_string(),
                fd_count: 10,
                command: "init".to_string(),
                connector: String::new(),
            },
            TreeRow {
                indent: 1,
                pid: 100,
                user: "root".to_string(),
                fd_count: 5,
                command: "bash".to_string(),
                connector: "|-- ".to_string(),
            },
        ];
        render_tree(&mut buf, area, &theme, &rows);
    }
}
