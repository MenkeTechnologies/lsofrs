//! Unified tabbed TUI — single `--tui` flag launches all modes as tabs

use std::collections::{BTreeSet, HashMap};
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};

use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
    MouseEventKind,
};
use crossterm::{cursor, execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};

use ratatui::style::Color;

use crate::config;
use crate::filter::Filter;
use crate::summary::SummaryLiveMode;
use crate::theme::{LsofTheme, ThemeName};
use crate::top::TopMode;
use crate::tui_app::{TuiMode, TuiState, draw_box, draw_help, set_cell, set_str};
use crate::types::*;

// ── Filter input state ───────────────────────────────────────────────────────

struct FilterState {
    active: bool,
    buf: String,
    cursor: usize,
    prev: Option<String>,
}

impl Default for FilterState {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterState {
    fn new() -> Self {
        Self {
            active: false,
            buf: String::new(),
            cursor: 0,
            prev: None,
        }
    }
    fn open(&mut self, current: &Option<String>) {
        self.active = true;
        self.buf = current.clone().unwrap_or_default();
        self.cursor = self.buf.len();
        self.prev = current.clone();
    }
    fn insert(&mut self, ch: char) {
        self.buf.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }
    fn backspace(&mut self) {
        if self.cursor > 0 {
            let prev = self.buf[..self.cursor]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
            self.buf.drain(prev..self.cursor);
            self.cursor = prev;
        }
    }
    fn delete_word(&mut self) {
        let s = &self.buf[..self.cursor];
        let trimmed = s.trim_end();
        let word_start = trimmed
            .rfind(char::is_whitespace)
            .map(|i| i + 1)
            .unwrap_or(0);
        self.buf.drain(word_start..self.cursor);
        self.cursor = word_start;
    }
    fn home(&mut self) {
        self.cursor = 0;
    }
    fn end(&mut self) {
        self.cursor = self.buf.len();
    }
    fn left(&mut self) {
        if self.cursor > 0 {
            self.cursor = self.buf[..self.cursor]
                .char_indices()
                .next_back()
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
    }
    fn right(&mut self) {
        if self.cursor < self.buf.len() {
            self.cursor = self.buf[self.cursor..]
                .char_indices()
                .nth(1)
                .map(|(i, _)| self.cursor + i)
                .unwrap_or(self.buf.len());
        }
    }
    fn kill_to_end(&mut self) {
        self.buf.truncate(self.cursor);
    }
}

// ── Status message with auto-dismiss ─────────────────────────────────────────

struct StatusMsg {
    text: String,
    since: Instant,
}

impl StatusMsg {
    fn new(text: String) -> Self {
        Self {
            text,
            since: Instant::now(),
        }
    }
    fn expired(&self) -> bool {
        self.since.elapsed().as_secs() >= 3
    }
}

// ── Tooltip state ────────────────────────────────────────────────────────────

#[derive(Default)]
struct Tooltip {
    active: bool,
    x: u16,
    y: u16,
    lines: Vec<(String, String)>,
}

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

/// Hit-test the tab bar: given an x coordinate, return which tab was clicked.
fn tab_at_x(x: u16) -> Option<Tab> {
    let mut pos = 1u16; // starts at x=1 (1 space padding)
    for &tab in &Tab::ALL {
        // labels are rendered as " LABEL " (space-padded)
        let label_len = tab.label().len() as u16 + 2;
        if x >= pos && x < pos + label_len {
            return Some(tab);
        }
        pos += label_len + 3; // " | " separator
    }
    None
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
    // Theme chooser modal
    show_theme_chooser: bool,
    theme_chooser_idx: usize,
    theme_before_chooser: usize, // to revert on Esc
    // Theme editor modal
    show_theme_editor: bool,
    editor_slot: usize,     // which color slot is selected (0-5)
    editor_colors: [u8; 6], // current palette values
    editor_naming: bool,    // in naming mode
    editor_name: String,    // custom theme name input
    editor_cursor: usize,   // cursor position in name
    // Custom themes loaded from config
    custom_themes: std::collections::HashMap<String, config::CustomThemeColors>,
    active_custom_theme: Option<String>,
    // Totals for status bar
    total_procs: usize,
    total_files: usize,
    // Filter popup (/ key)
    filter_state: FilterState,
    screen_filter: Option<String>,
    // Selection per tab
    selected_idx: [Option<usize>; 7],
    // Scroll offset per tab (for simple tabs)
    scroll_offset: [usize; 7],
    // Right-click tooltip
    tooltip: Tooltip,
    // Status message (auto-dismiss)
    status_msg: Option<StatusMsg>,
    // Sort reverse for simple tabs
    sort_reverse: bool,
    // Content area y for mouse hit-testing
    content_area_y: u16,
    content_area_h: u16,
}

impl TabbedTui {
    fn new(theme_idx: usize, prefs: &config::Prefs) -> Self {
        Self {
            active: Tab::Top,
            top_mode: TopMode::new(20),
            summary_mode: SummaryLiveMode::new(),
            port_rows: Vec::new(),
            stale_rows: Vec::new(),
            tree_rows: Vec::new(),
            net_map_rows: Vec::new(),
            pipe_rows: Vec::new(),
            show_theme_chooser: false,
            theme_chooser_idx: theme_idx,
            theme_before_chooser: theme_idx,
            show_theme_editor: false,
            editor_slot: 0,
            editor_colors: [0; 6],
            editor_naming: false,
            editor_name: String::new(),
            editor_cursor: 0,
            custom_themes: prefs.custom_themes.clone(),
            active_custom_theme: prefs.active_custom_theme.clone(),
            total_procs: 0,
            total_files: 0,
            filter_state: FilterState::new(),
            screen_filter: None,
            selected_idx: [None; 7],
            scroll_offset: [0; 7],
            tooltip: Tooltip::default(),
            status_msg: None,
            sort_reverse: false,
            content_area_y: 0,
            content_area_h: 0,
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.status_msg = Some(StatusMsg::new(msg.into()));
    }

    /// Row count for the current simple tab (not Top/Summary which manage their own).
    fn row_count(&self) -> usize {
        match self.active {
            Tab::Ports => self.port_rows.len(),
            Tab::Stale => self.stale_rows.len(),
            Tab::Tree => self.tree_rows.len(),
            Tab::NetMap => self.net_map_rows.len(),
            Tab::PipeChain => self.pipe_rows.len(),
            _ => 0,
        }
    }

    fn selected(&self) -> Option<usize> {
        self.selected_idx[self.active.index()]
    }

    fn set_selected(&mut self, v: Option<usize>) {
        self.selected_idx[self.active.index()] = v;
    }

    fn scroll(&self) -> usize {
        self.scroll_offset[self.active.index()]
    }

    fn set_scroll(&mut self, v: usize) {
        self.scroll_offset[self.active.index()] = v;
    }

    fn select_next(&mut self) {
        let max = self.row_count().saturating_sub(1);
        let sel = match self.selected() {
            Some(i) => (i + 1).min(max),
            None => 0,
        };
        self.set_selected(Some(sel));
        let visible = self.content_area_h.saturating_sub(4) as usize;
        if sel >= self.scroll() + visible {
            self.set_scroll(sel.saturating_sub(visible.saturating_sub(1)));
        }
    }

    fn select_prev(&mut self) {
        let sel = match self.selected() {
            Some(i) => i.saturating_sub(1),
            None => 0,
        };
        self.set_selected(Some(sel));
        if sel < self.scroll() {
            self.set_scroll(sel);
        }
    }

    fn page_down(&mut self) {
        let half = (self.content_area_h / 2) as usize;
        let max = self.row_count().saturating_sub(1);
        let sel = match self.selected() {
            Some(i) => (i + half).min(max),
            None => half.min(max),
        };
        self.set_selected(Some(sel));
        let visible = self.content_area_h.saturating_sub(4) as usize;
        if sel >= self.scroll() + visible {
            self.set_scroll(sel.saturating_sub(visible.saturating_sub(1)));
        }
    }

    fn page_up(&mut self) {
        let half = (self.content_area_h / 2) as usize;
        let sel = match self.selected() {
            Some(i) => i.saturating_sub(half),
            None => 0,
        };
        self.set_selected(Some(sel));
        if sel < self.scroll() {
            self.set_scroll(sel);
        }
    }

    fn jump_top(&mut self) {
        self.set_selected(Some(0));
        self.set_scroll(0);
    }

    fn jump_bottom(&mut self) {
        let last = self.row_count().saturating_sub(1);
        self.set_selected(Some(last));
        let visible = self.content_area_h.saturating_sub(4) as usize;
        self.set_scroll(last.saturating_sub(visible.saturating_sub(1)));
    }

    /// Build tooltip lines for a right-click on a simple tab row.
    fn build_tooltip(&self, idx: usize) -> Vec<(String, String)> {
        match self.active {
            Tab::Ports => {
                if let Some(r) = self.port_rows.get(idx) {
                    vec![
                        ("Protocol".into(), r.proto.clone()),
                        ("Address".into(), r.addr.clone()),
                        ("Port".into(), r.port.to_string()),
                        ("PID".into(), r.pid.to_string()),
                        ("User".into(), r.user.clone()),
                        ("Command".into(), r.command.clone()),
                    ]
                } else {
                    vec![]
                }
            }
            Tab::Stale => {
                if let Some(r) = self.stale_rows.get(idx) {
                    vec![
                        ("PID".into(), r.pid.to_string()),
                        ("User".into(), r.user.clone()),
                        ("FD".into(), r.fd.clone()),
                        ("Type".into(), r.file_type.clone()),
                        (
                            "Size".into(),
                            r.size.map(|s| s.to_string()).unwrap_or_default(),
                        ),
                        ("Name".into(), r.name.clone()),
                    ]
                } else {
                    vec![]
                }
            }
            Tab::Tree => {
                if let Some(r) = self.tree_rows.get(idx) {
                    vec![
                        ("PID".into(), r.pid.to_string()),
                        ("User".into(), r.user.clone()),
                        ("FDs".into(), r.fd_count.to_string()),
                        ("Command".into(), r.command.clone()),
                    ]
                } else {
                    vec![]
                }
            }
            Tab::NetMap => {
                if let Some(r) = self.net_map_rows.get(idx) {
                    vec![
                        ("Host".into(), r.host.clone()),
                        ("Connections".into(), r.count.to_string()),
                        ("Protocols".into(), r.protocols.clone()),
                        ("Ports".into(), r.ports.clone()),
                        ("Processes".into(), r.processes.clone()),
                    ]
                } else {
                    vec![]
                }
            }
            Tab::PipeChain => {
                if let Some(r) = self.pipe_rows.get(idx) {
                    vec![
                        ("Type".into(), r.kind.clone()),
                        ("ID".into(), r.id.clone()),
                        ("Endpoints".into(), r.endpoints.clone()),
                    ]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }

    /// Copy selected row info to clipboard.
    fn copy_selected(&mut self) {
        let idx = match self.selected() {
            Some(i) => i,
            None => {
                self.set_status("Select a row first (j/k)");
                return;
            }
        };
        let text = match self.active {
            Tab::Ports => self.port_rows.get(idx).map(|r| {
                format!(
                    "{}:{} {} PID:{} {}",
                    r.addr, r.port, r.proto, r.pid, r.command
                )
            }),
            Tab::Stale => self
                .stale_rows
                .get(idx)
                .map(|r| format!("PID:{} {} {} {}", r.pid, r.fd, r.file_type, r.name)),
            Tab::Tree => self
                .tree_rows
                .get(idx)
                .map(|r| format!("PID:{} {} FDs:{}", r.pid, r.command, r.fd_count)),
            Tab::NetMap => self
                .net_map_rows
                .get(idx)
                .map(|r| format!("{} conns:{} {}", r.host, r.count, r.processes)),
            Tab::PipeChain => self
                .pipe_rows
                .get(idx)
                .map(|r| format!("{} {} {}", r.kind, r.id, r.endpoints)),
            _ => {
                self.set_status("Copy not supported for this tab");
                return;
            }
        };
        let text = match text {
            Some(t) => t,
            None => {
                self.set_status("No row to copy");
                return;
            }
        };
        let result = if cfg!(target_os = "macos") {
            std::process::Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(ref mut stdin) = child.stdin {
                        stdin.write_all(text.as_bytes())?;
                    }
                    child.wait()
                })
        } else {
            std::process::Command::new("xclip")
                .args(["-selection", "clipboard"])
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(ref mut stdin) = child.stdin {
                        stdin.write_all(text.as_bytes())?;
                    }
                    child.wait()
                })
        };
        match result {
            Ok(_) => self.set_status(format!("Copied: {}", text)),
            Err(e) => self.set_status(format!("Copy failed: {}", e)),
        }
    }

    /// Export current tab data to file.
    fn export(&mut self) {
        let tab_name = self.active.label().to_lowercase();
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let filename = format!("lsofrs-export-{}-{}.txt", tab_name, ts);
        let path = dirs::home_dir()
            .map(|h| h.join(&filename))
            .unwrap_or_else(|| std::path::PathBuf::from(&filename));

        let mut lines = Vec::new();
        lines.push(format!(
            "LSOFRS EXPORT [{}] -- {}",
            self.active.label(),
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        ));
        lines.push(String::new());

        match self.active {
            Tab::Ports => {
                lines.push(format!(
                    "{:<5}  {:<15}  {:>5}  {:>7}  {:<8}  COMMAND",
                    "PROTO", "ADDR", "PORT", "PID", "USER"
                ));
                for r in &self.port_rows {
                    lines.push(format!(
                        "{:<5}  {:<15}  {:>5}  {:>7}  {:<8}  {}",
                        r.proto, r.addr, r.port, r.pid, r.user, r.command
                    ));
                }
            }
            Tab::Stale => {
                lines.push(format!(
                    "{:>7}  {:<8}  {:<5}  {:<5}  {:>8}  NAME",
                    "PID", "USER", "FD", "TYPE", "SIZE"
                ));
                for r in &self.stale_rows {
                    let sz = r.size.map(|s| s.to_string()).unwrap_or_default();
                    lines.push(format!(
                        "{:>7}  {:<8}  {:<5}  {:<5}  {:>8}  {}",
                        r.pid, r.user, r.fd, r.file_type, sz, r.name
                    ));
                }
            }
            Tab::Tree => {
                for r in &self.tree_rows {
                    let indent = "    ".repeat(r.indent);
                    lines.push(format!(
                        "{}{}{:>5} {:<8} {:>4} {}",
                        indent, r.connector, r.pid, r.user, r.fd_count, r.command
                    ));
                }
            }
            Tab::NetMap => {
                lines.push(format!(
                    "{:<20}  {:>5}  {:<9}  {:<10}  PROCESSES",
                    "HOST", "CONNS", "PROTOCOLS", "PORTS"
                ));
                for r in &self.net_map_rows {
                    lines.push(format!(
                        "{:<20}  {:>5}  {:<9}  {:<10}  {}",
                        r.host, r.count, r.protocols, r.ports, r.processes
                    ));
                }
            }
            Tab::PipeChain => {
                lines.push(format!("{:<6}  {:<20}  ENDPOINTS", "TYPE", "IDENTIFIER"));
                for r in &self.pipe_rows {
                    lines.push(format!("{:<6}  {:<20}  {}", r.kind, r.id, r.endpoints));
                }
            }
            _ => {
                lines.push("(use Top/Summary export via their own modes)".into());
            }
        }

        match std::fs::write(&path, lines.join("\n")) {
            Ok(_) => self.set_status(format!("Exported to {}", path.display())),
            Err(e) => self.set_status(format!("Export failed: {}", e)),
        }
    }

    /// Summary info line for the current tab.
    fn summary_info(&self) -> String {
        match self.active {
            Tab::Top => format!(
                "showing {} procs, {} FDs",
                self.top_mode.visible_count(),
                self.total_files
            ),
            Tab::Summary => format!("{} procs, {} files", self.total_procs, self.total_files),
            Tab::Ports => format!("{} listening port(s)", self.port_rows.len()),
            Tab::Stale => format!("{} stale FD(s)", self.stale_rows.len()),
            Tab::Tree => format!("{} tree node(s)", self.tree_rows.len()),
            Tab::NetMap => {
                let total: usize = self.net_map_rows.iter().map(|r| r.count).sum();
                format!("{} host(s), {} conn(s)", self.net_map_rows.len(), total)
            }
            Tab::PipeChain => format!("{} IPC chain(s)", self.pipe_rows.len()),
        }
    }

    fn update_all(&mut self, filter: &Filter) {
        // Expire status messages
        if let Some(ref msg) = self.status_msg
            && msg.expired()
        {
            self.status_msg = None;
        }

        // Gather once
        let mut procs = crate::gather_processes();
        procs.retain(|p| filter.matches_process(p));
        for p in &mut procs {
            p.files.retain(|f| filter.matches_file(f));
        }

        // Apply screen filter (/ key) on top of CLI filter
        if let Some(ref sf) = self.screen_filter {
            let lower = sf.to_lowercase();
            procs.retain(|p| {
                p.command.to_lowercase().contains(&lower)
                    || p.pid.to_string().contains(&lower)
                    || p.username().to_lowercase().contains(&lower)
            });
        }

        // Track totals for status bar
        self.total_procs = procs.len();
        self.total_files = procs.iter().map(|p| p.files.len()).sum();

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
        if self.sort_reverse {
            self.port_rows.reverse();
        }
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
            ("/", "filter popup"),
            ("0", "clear filter"),
            ("j / k", "select next/prev"),
            ("Ctrl-D/U", "page down/up"),
            ("Home / End/G", "jump top/bottom"),
            ("e", "export to file"),
            ("y", "copy selected"),
            ("r", "reverse sort"),
            ("f", "cycle refresh rate"),
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

fn draw_bottom_bar(
    buf: &mut Buffer,
    area: Rect,
    state: &TuiState,
    total_procs: usize,
    total_files: usize,
    elapsed: &str,
    screen_filter: &Option<String>,
) {
    let t = &state.theme;
    let dim_s = Style::default().fg(t.dim_fg);
    let bar_s = Style::default().fg(t.dim_fg).bg(t.row_alt_bg);

    // Separator line (row h-2)
    let sep_y = area.y;
    for x in area.x..area.x + area.width {
        set_cell(buf, x, sep_y, "\u{2500}", dim_s); // ─
    }

    // Status info (row h-1)
    let info_y = sep_y + 1;
    for x in area.x..area.x + area.width {
        set_cell(buf, x, info_y, " ", bar_s);
    }
    let running_str = if state.paused { "paused" } else { "running" };
    let mut status = format!(
        " procs:{} \u{2502} files:{} \u{2502} theme:{} \u{2502} {}s \u{2502} {} \u{2502} #{}",
        total_procs,
        total_files,
        state.theme.display_name(),
        state.interval,
        running_str,
        state.iteration,
    );
    if let Some(f) = screen_filter {
        status.push_str(&format!(" \u{2502} filter:{}", f));
    }
    set_str(buf, area.x, info_y, &status, bar_s, area.width);

    // Right-aligned elapsed time
    if !elapsed.is_empty() {
        let e = format!(" {} ", elapsed);
        let ex = area.x + area.width.saturating_sub(e.len() as u16);
        set_str(buf, ex, info_y, &e, bar_s, e.len() as u16);
    }
}

// ── Simple tab renderers ──────────────────────────────────────────────────────

fn render_ports(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    rows: &[PortRow],
    scroll: usize,
    selected: Option<usize>,
) {
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

    for (i, r) in rows.iter().enumerate().skip(scroll) {
        if row >= area.y + area.height {
            break;
        }
        let is_selected = selected == Some(i);
        let alt_s = if is_selected {
            Style::default().bg(theme.select_bg)
        } else if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if is_selected || i % 2 == 1 {
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

fn render_stale(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    rows: &[StaleRow],
    scroll: usize,
    selected: Option<usize>,
) {
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

    for (i, r) in rows.iter().enumerate().skip(scroll) {
        if row >= area.y + area.height {
            break;
        }
        let is_selected = selected == Some(i);
        let alt_s = if is_selected {
            Style::default().bg(theme.select_bg)
        } else if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if is_selected || i % 2 == 1 {
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

fn render_tree(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    rows: &[TreeRow],
    scroll: usize,
    selected: Option<usize>,
) {
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

    for (i, r) in rows.iter().enumerate().skip(scroll) {
        if row >= area.y + area.height {
            break;
        }
        let is_selected = selected == Some(i);
        if is_selected {
            let sel_s = Style::default().bg(theme.select_bg);
            for x in area.x..area.x + area.width {
                set_cell(buf, x, row, " ", sel_s);
            }
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

fn render_net_map(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    rows: &[NetMapRow],
    scroll: usize,
    selected: Option<usize>,
) {
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

    for (i, r) in rows.iter().enumerate().skip(scroll) {
        if row >= area.y + area.height {
            break;
        }
        let is_selected = selected == Some(i);
        let alt_s = if is_selected {
            Style::default().bg(theme.select_bg)
        } else if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if is_selected || i % 2 == 1 {
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

fn render_pipes(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    rows: &[PipeRow],
    scroll: usize,
    selected: Option<usize>,
) {
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

    for (i, r) in rows.iter().enumerate().skip(scroll) {
        if row >= area.y + area.height {
            break;
        }
        let is_selected = selected == Some(i);
        let alt_s = if is_selected {
            Style::default().bg(theme.select_bg)
        } else if i % 2 == 1 {
            Style::default().bg(theme.row_alt_bg)
        } else {
            Style::default()
        };
        if is_selected || i % 2 == 1 {
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

// ── Filter popup rendering ────────────────────────────────────────────────────

fn draw_filter_popup(buf: &mut Buffer, area: Rect, theme: &LsofTheme, tui: &TabbedTui) {
    let fs = &tui.filter_state;
    let bw = 54u16.min(area.width.saturating_sub(4));
    let bh = 9u16.min(area.height.saturating_sub(2));
    let bg = theme.help_bg;
    let bs = Style::default().fg(theme.help_border);
    let ts = Style::default()
        .fg(theme.help_title)
        .bg(bg)
        .add_modifier(Modifier::BOLD);
    let input_s = Style::default().fg(theme.help_key).bg(Color::Indexed(235));
    let hint_s = Style::default().fg(Color::Indexed(240)).bg(bg);
    let label_s = Style::default().fg(theme.help_val).bg(bg);

    let (x0, y0) = draw_box(buf, area, bw, bh, bg, bs);

    // Title
    let title = "FILTER PROCESSES";
    let tlen = title.chars().count() as u16;
    set_str(
        buf,
        x0 + (bw.saturating_sub(tlen)) / 2,
        y0 + 1,
        title,
        ts,
        bw - 2,
    );

    // Active filter display
    let current_val = tui.screen_filter.as_deref().unwrap_or("(none)");
    set_str(buf, x0 + 2, y0 + 2, "Active: ", label_s, 8);
    set_str(
        buf,
        x0 + 10,
        y0 + 2,
        current_val,
        Style::default().fg(Color::White).bg(bg),
        bw.saturating_sub(13),
    );

    // Input field
    let input_w = bw.saturating_sub(4);
    let field_y = y0 + 3;
    for x in x0 + 2..x0 + 2 + input_w {
        set_cell(buf, x, field_y, " ", input_s);
    }
    set_str(buf, x0 + 2, field_y, "> ", input_s, 2);

    let max_visible = (input_w as usize).saturating_sub(3);
    let buf_len = fs.buf.len();
    let cursor_pos = fs.cursor;

    let (vis_start, vis_end) = if buf_len <= max_visible {
        (0, buf_len)
    } else {
        let start = cursor_pos.saturating_sub(max_visible);
        (start, (start + max_visible).min(buf_len))
    };

    let display_buf = &fs.buf[vis_start..vis_end];
    set_str(
        buf,
        x0 + 4,
        field_y,
        display_buf,
        input_s,
        input_w.saturating_sub(3),
    );

    // Block cursor
    let cursor_x = x0 + 4 + (cursor_pos - vis_start) as u16;
    if cursor_x < x0 + 2 + input_w {
        let ch = fs
            .buf
            .get(cursor_pos..cursor_pos + 1)
            .unwrap_or(" ")
            .chars()
            .next()
            .unwrap_or(' ');
        let cursor_s = Style::default().fg(Color::Indexed(235)).bg(theme.help_key);
        set_cell(buf, cursor_x, field_y, &ch.to_string(), cursor_s);
    }

    // Match count
    let info = format!("{} procs matched", tui.total_procs);
    set_str(buf, x0 + 2, y0 + 4, &info, hint_s, bw - 4);

    // Hints
    let hints1 = "Enter=apply  Esc=cancel  ^W=del word";
    let h1x = x0 + (bw.saturating_sub(hints1.len() as u16)) / 2;
    set_str(buf, h1x, y0 + 5, hints1, hint_s, bw.saturating_sub(2));

    let hints2 = "^A=home ^E=end ^U=clear ^K=kill";
    let h2x = x0 + (bw.saturating_sub(hints2.len() as u16)) / 2;
    set_str(buf, h2x, y0 + 6, hints2, hint_s, bw.saturating_sub(2));

    let hints3 = "0=clear filter (from main view)";
    let h3x = x0 + (bw.saturating_sub(hints3.len() as u16)) / 2;
    set_str(buf, h3x, y0 + 7, hints3, hint_s, bw.saturating_sub(2));
}

// ── Right-click tooltip rendering ────────────────────────────────────────────

fn draw_tooltip(buf: &mut Buffer, area: Rect, theme: &LsofTheme, tt: &Tooltip) {
    if tt.lines.is_empty() {
        return;
    }
    let max_label = tt.lines.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let max_val = tt.lines.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    let inner_w = (max_label + 3 + max_val).max(20);
    let bw = (inner_w + 4) as u16;
    let bh = (tt.lines.len() + 2) as u16;

    let x0 = if tt.x + bw + 2 < area.width {
        tt.x + 1
    } else {
        tt.x.saturating_sub(bw + 1)
    };
    let y0 = if tt.y + bh + 1 < area.height {
        tt.y
    } else {
        tt.y.saturating_sub(bh)
    };

    let bg = theme.help_bg;
    let bs = Style::default().fg(theme.help_border);
    let label_s = Style::default().fg(theme.help_val).bg(bg);
    let val_s = Style::default().fg(theme.help_key).bg(bg);

    // Fill + rounded border
    for y in y0..y0 + bh {
        for x in x0..x0 + bw {
            set_cell(buf, x, y, " ", Style::default().bg(bg));
        }
    }
    set_cell(buf, x0, y0, "\u{256d}", bs);
    set_cell(buf, x0 + bw - 1, y0, "\u{256e}", bs);
    set_cell(buf, x0, y0 + bh - 1, "\u{2570}", bs);
    set_cell(buf, x0 + bw - 1, y0 + bh - 1, "\u{256f}", bs);
    for x in x0 + 1..x0 + bw - 1 {
        set_cell(buf, x, y0, "\u{2500}", bs);
        set_cell(buf, x, y0 + bh - 1, "\u{2500}", bs);
    }
    for y in y0 + 1..y0 + bh - 1 {
        set_cell(buf, x0, y, "\u{2502}", bs);
        set_cell(buf, x0 + bw - 1, y, "\u{2502}", bs);
    }

    // Content
    for (i, (label, value)) in tt.lines.iter().enumerate() {
        let ey = y0 + 1 + i as u16;
        if ey >= y0 + bh - 1 {
            break;
        }
        set_str(buf, x0 + 2, ey, label, label_s, max_label as u16 + 1);
        if !value.is_empty() {
            let vx = x0 + 2 + max_label as u16 + 2;
            let remaining = bw.saturating_sub(max_label as u16 + 5);
            set_str(buf, vx, ey, value, val_s, remaining);
        }
    }
}

// ── Status message rendering ─────────────────────────────────────────────────

fn draw_status_msg(buf: &mut Buffer, area: Rect, theme: &LsofTheme, text: &str) {
    let msg_len = text.chars().count() as u16 + 4;
    let x0 = (area.width.saturating_sub(msg_len)) / 2;
    let y0 = area.height.saturating_sub(4);
    let s = Style::default().fg(Color::Black).bg(theme.help_key);
    set_str(buf, x0, y0, &format!(" {} ", text), s, msg_len);
}

// ── Summary info bar rendering ───────────────────────────────────────────────

fn draw_summary_bar(buf: &mut Buffer, area: Rect, theme: &LsofTheme, tui: &TabbedTui) {
    let info_s = Style::default().fg(theme.dim_fg).bg(theme.header_bg);
    for x in area.x..area.x + area.width {
        set_cell(buf, x, area.y, " ", info_s);
    }
    let mut text = format!(" {} | {}", tui.active.label(), tui.summary_info());
    if let Some(ref f) = tui.screen_filter {
        text.push_str(&format!(" | filter: {}", f));
    }
    set_str(buf, area.x, area.y, &text, info_s, area.width);
}

// ── Custom theme helpers ──────────────────────────────────────────────────────

/// Get sorted list of custom theme names for deterministic ordering.
fn sorted_custom_names(
    custom_themes: &std::collections::HashMap<String, config::CustomThemeColors>,
) -> Vec<String> {
    let mut names: Vec<String> = custom_themes.keys().cloned().collect();
    names.sort();
    names
}

/// Apply a theme chooser selection (handles both built-in and custom themes).
fn apply_chooser_selection(
    idx: usize,
    state: &mut TuiState,
    active_custom: &mut Option<String>,
    custom_themes: &std::collections::HashMap<String, config::CustomThemeColors>,
    custom_names: &[String],
) {
    let builtin_count = ThemeName::ALL.len();
    if idx < builtin_count {
        state.theme_idx = idx;
        state.theme = LsofTheme::from_name(ThemeName::ALL[idx]);
        *active_custom = None;
    } else {
        let ci = idx - builtin_count;
        if ci < custom_names.len() {
            let name = &custom_names[ci];
            if let Some(ct) = custom_themes.get(name) {
                state.theme =
                    LsofTheme::from_custom(name, ct.c1, ct.c2, ct.c3, ct.c4, ct.c5, ct.c6);
                *active_custom = Some(name.clone());
            }
        }
    }
}

// ── Theme chooser modal ──────────────────────────────────────────────────────

/// Draw theme chooser as a centered modal overlay. Returns the rect used for hit-testing.
fn draw_theme_chooser(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    chooser_idx: usize,
    current_theme_idx: usize,
    custom_themes: &std::collections::HashMap<String, config::CustomThemeColors>,
) -> (u16, u16, u16, u16) {
    let custom_names = sorted_custom_names(custom_themes);
    let theme_count = ThemeName::ALL.len() + custom_names.len();
    let bw = 50u16.min(area.width.saturating_sub(4));
    let bh = ((theme_count + 4) as u16).min(area.height.saturating_sub(2));
    let bg = theme.help_bg;
    let bs = Style::default().fg(theme.help_border);

    let (x0, y0) = draw_box(buf, area, bw, bh, bg, bs);
    let inner_w = bw.saturating_sub(4);
    let cx = x0 + 2;

    // Title centered in top border
    let title = " THEME CHOOSER ";
    let title_x = x0 + (bw.saturating_sub(title.len() as u16)) / 2;
    let title_s = Style::default()
        .fg(theme.help_title)
        .bg(bg)
        .add_modifier(Modifier::BOLD);
    set_str(buf, title_x, y0, title, title_s, title.len() as u16);

    // Footer
    let footer = "j/k navigate  Enter apply  Esc close";
    let footer_x = x0 + (bw.saturating_sub(footer.len() as u16)) / 2;
    let footer_s = Style::default().fg(theme.dim_fg).bg(bg);
    set_str(
        buf,
        footer_x,
        y0 + bh - 1,
        footer,
        footer_s,
        footer.len() as u16,
    );

    // Theme rows
    let row_start = y0 + 2;
    let max_rows = (bh.saturating_sub(4)) as usize;
    // Scroll so the selected item is visible
    let scroll = if chooser_idx >= max_rows {
        chooser_idx - max_rows + 1
    } else {
        0
    };

    let builtin_count = ThemeName::ALL.len();
    for i in 0..max_rows {
        let ti = scroll + i;
        if ti >= theme_count {
            break;
        }
        let row_y = row_start + i as u16;
        if row_y >= y0 + bh - 1 {
            break;
        }

        let is_selected = ti == chooser_idx;
        let is_active = ti == current_theme_idx;

        let row_bg = if is_selected { theme.select_bg } else { bg };
        let text_s = Style::default().fg(Color::Indexed(252)).bg(row_bg);

        // Fill row background
        for x in cx..cx + inner_w {
            set_cell(buf, x, row_y, " ", Style::default().bg(row_bg));
        }

        if ti < builtin_count {
            // Built-in theme
            let name = ThemeName::ALL[ti];
            let swatch = name.swatch_colors();

            let marker = if is_active { "\u{25b8}" } else { " " }; // ▸
            set_str(buf, cx, row_y, marker, text_s, 2);

            for (si, &color_idx) in swatch.iter().enumerate() {
                let swatch_s = Style::default().fg(Color::Indexed(color_idx)).bg(row_bg);
                set_str(buf, cx + 2 + si as u16, row_y, "\u{2588}", swatch_s, 1);
            }

            let display = name.display_name();
            set_str(
                buf,
                cx + 9,
                row_y,
                display,
                text_s,
                inner_w.saturating_sub(10),
            );
        } else {
            // Custom theme
            let ci = ti - builtin_count;
            if ci < custom_names.len() {
                let cname = &custom_names[ci];
                if let Some(ct) = custom_themes.get(cname) {
                    let swatch = [ct.c1, ct.c2, ct.c3, ct.c4, ct.c5, ct.c6];

                    let marker = if is_active { "\u{2605}" } else { "\u{2606}" }; // ★ / ☆
                    set_str(buf, cx, row_y, marker, text_s, 2);

                    for (si, &color_idx) in swatch.iter().enumerate() {
                        let swatch_s = Style::default().fg(Color::Indexed(color_idx)).bg(row_bg);
                        set_str(buf, cx + 2 + si as u16, row_y, "\u{2588}", swatch_s, 1);
                    }

                    set_str(
                        buf,
                        cx + 9,
                        row_y,
                        cname,
                        text_s,
                        inner_w.saturating_sub(10),
                    );
                }
            }
        }
    }

    (x0, y0 + 2, bw, max_rows as u16)
}

// ── Theme editor modal ───────────────────────────────────────────────────────

/// Draw the theme editor as a centered modal overlay. Returns (x0, y0, bw, bh) for hit-testing.
fn draw_theme_editor(
    buf: &mut Buffer,
    area: Rect,
    theme: &LsofTheme,
    tui: &TabbedTui,
) -> (u16, u16, u16, u16) {
    let bw = 56u16.min(area.width.saturating_sub(4));
    let bh: u16 = if tui.editor_naming { 16 } else { 15 };
    let bh = bh.min(area.height.saturating_sub(4));
    let bg = theme.help_bg;
    let bs = Style::default().fg(theme.help_border);
    let bgs = Style::default().fg(Color::White).bg(bg);
    let ts = Style::default()
        .fg(theme.help_title)
        .bg(bg)
        .add_modifier(Modifier::BOLD);
    let hint_s = Style::default().fg(Color::Indexed(240)).bg(bg);
    let sel_s = Style::default().fg(Color::White).bg(Color::Indexed(237));

    let (x0, y0) = draw_box(buf, area, bw, bh, bg, bs);

    // Title
    let title = "THEME EDITOR";
    let tlen = title.len() as u16;
    set_str(
        buf,
        x0 + (bw.saturating_sub(tlen)) / 2,
        y0 + 1,
        title,
        ts,
        bw - 2,
    );

    // Color channel labels
    let labels = ["primary", "accent", "c3", "c4", "c5", "c6"];
    let colors = tui.editor_colors;

    for (i, label) in labels.iter().enumerate() {
        let row_y = y0 + 3 + i as u16;
        if row_y >= y0 + bh - 2 {
            break;
        }
        let is_sel = i == tui.editor_slot;

        let row_style = if is_sel { sel_s } else { bgs };
        if is_sel {
            for x in x0 + 1..x0 + bw - 1 {
                set_cell(buf, x, row_y, " ", sel_s);
            }
        }

        let marker = if is_sel { "\u{25b8} " } else { "  " };
        set_str(buf, x0 + 2, row_y, marker, row_style, 2);

        let label_str = format!("{:<10}", label);
        set_str(buf, x0 + 4, row_y, &label_str, row_style, 10);

        let val_str = format!("{:>3}", colors[i]);
        set_str(buf, x0 + 15, row_y, &val_str, row_style, 3);

        // Color swatch
        let swatch_s = Style::default().fg(Color::Indexed(colors[i])).bg(bg);
        set_str(
            buf,
            x0 + 20,
            row_y,
            "\u{2588}\u{2588}\u{2588}\u{2588}\u{2588}",
            swatch_s,
            5,
        );

        // Arrow preview
        let arrow_s = Style::default().fg(Color::Indexed(colors[i])).bg(bg);
        set_str(
            buf,
            x0 + 26,
            row_y,
            " \u{25c0}\u{2500}\u{2500}\u{25b6}",
            arrow_s,
            5,
        );
    }

    // Preview bar using the full palette
    let preview_y = y0 + 10;
    if preview_y < y0 + bh - 2 {
        set_str(buf, x0 + 2, preview_y, "preview:", hint_s, 8);
        let preview_w = (bw as usize).saturating_sub(13);
        for j in 0..preview_w {
            let frac = j as f64 / preview_w as f64;
            let c = if frac < 0.20 {
                Color::Indexed(colors[0])
            } else if frac < 0.40 {
                Color::Indexed(colors[1])
            } else if frac < 0.55 {
                Color::Indexed(colors[2])
            } else if frac < 0.70 {
                Color::Indexed(colors[3])
            } else if frac < 0.85 {
                Color::Indexed(colors[4])
            } else {
                Color::Indexed(colors[5])
            };
            set_cell(
                buf,
                x0 + 11 + j as u16,
                preview_y,
                "\u{2588}",
                Style::default().fg(c).bg(bg),
            );
        }
    }

    // Naming prompt or keybind hints
    if tui.editor_naming {
        let name_y = y0 + 12;
        if name_y < y0 + bh - 1 {
            let input_s = Style::default()
                .fg(Color::Indexed(48))
                .bg(Color::Indexed(235));
            set_str(buf, x0 + 2, name_y, "Theme name:", bgs, 11);
            let name_display = format!("{}_", tui.editor_name);
            set_str(buf, x0 + 14, name_y, &name_display, input_s, bw - 16);
            set_str(
                buf,
                x0 + 2,
                name_y + 1,
                "Enter:save  Esc:back",
                hint_s,
                bw - 4,
            );
        }
    } else {
        let hint_y = y0 + 12;
        if hint_y < y0 + bh - 1 {
            set_str(
                buf,
                x0 + 2,
                hint_y,
                "j/k:select  h/l:\u{00b1}1  H/L:\u{00b1}10",
                hint_s,
                bw - 4,
            );
            set_str(
                buf,
                x0 + 2,
                hint_y + 1,
                "Enter/s:save  Esc/q:cancel",
                hint_s,
                bw - 4,
            );
        }
    }

    (x0, y0, bw, bh)
}

/// Save current TUI state to config file
fn save_prefs_with_tab(state: &TuiState, tab: Tab) {
    let mut prefs = config::load();
    prefs.theme = Some(state.theme.display_name().to_string());
    prefs.refresh_rate = Some(state.interval);
    prefs.show_border = state.show_border;
    prefs.active_tab = Some(tab.index() as u8);
    config::save(&prefs);
}

fn save_prefs(state: &TuiState) {
    let mut prefs = config::load();
    prefs.theme = Some(state.theme.display_name().to_string());
    prefs.refresh_rate = Some(state.interval);
    prefs.show_border = state.show_border;
    config::save(&prefs);
}

// ── Main entry point ──────────────────────────────────────────────────────────

pub fn run_tui_tabs(filter: &Filter, interval: u64, theme: &LsofTheme) {
    if !io::stdout().is_terminal() {
        eprintln!("lsofrs: --tui requires a terminal (not a pipe or redirect)");
        return;
    }

    let mut stdout = io::stdout();
    let _ = execute!(
        stdout,
        terminal::EnterAlternateScreen,
        cursor::Hide,
        EnableMouseCapture
    );
    let _ = terminal::enable_raw_mode();

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = TuiState::new_pub(interval, theme.clone());
    let prefs = config::load();
    state.show_border = prefs.show_border;
    let mut tui = TabbedTui::new(state.theme_idx, &prefs);
    // Restore saved tab
    if let Some(tab_idx) = prefs.active_tab
        && (tab_idx as usize) < Tab::ALL.len()
    {
        tui.active = Tab::ALL[tab_idx as usize];
    }
    let mut running = true;
    let start_time = Instant::now();
    // Track modal regions for mouse hit-testing
    let mut chooser_rect: (u16, u16, u16, u16) = (0, 0, 0, 0);
    let mut editor_rect: (u16, u16, u16, u16) = (0, 0, 0, 0);

    while running {
        if !state.paused {
            state.iteration += 1;
            tui.update_all(filter);
        }

        let elapsed_secs = start_time.elapsed().as_secs();
        let elapsed_str = if elapsed_secs >= 3600 {
            format!(
                "{}h{:02}m{:02}s",
                elapsed_secs / 3600,
                (elapsed_secs % 3600) / 60,
                elapsed_secs % 60
            )
        } else if elapsed_secs >= 60 {
            format!("{}m{:02}s", elapsed_secs / 60, elapsed_secs % 60)
        } else {
            format!("{}s", elapsed_secs)
        };

        let _ = terminal.draw(|frame| {
            let size = frame.area();
            if size.width < 10 || size.height < 5 {
                return;
            }

            let h = size.height;
            let w = size.width;
            let bdr = state.show_border;
            let margin = if bdr { 1u16 } else { 0u16 };

            // Optional double-line border around the entire terminal
            if bdr && w > 2 && h > 2 {
                let buf = frame.buffer_mut();
                let border_style = Style::default().fg(state.theme.dim_fg);
                set_cell(buf, 0, 0, "╔", border_style);
                for x in 1..w - 1 {
                    set_cell(buf, x, 0, "═", border_style);
                }
                set_cell(buf, w - 1, 0, "╗", border_style);
                set_cell(buf, 0, h - 1, "╚", border_style);
                for x in 1..w - 1 {
                    set_cell(buf, x, h - 1, "═", border_style);
                }
                set_cell(buf, w - 1, h - 1, "╝", border_style);
                for y in 1..h - 1 {
                    set_cell(buf, 0, y, "║", border_style);
                    set_cell(buf, w - 1, y, "║", border_style);
                }
            }

            let inner_x = margin;
            let inner_w = w.saturating_sub(margin * 2);

            // Tab bar
            draw_tab_bar(
                frame.buffer_mut(),
                Rect {
                    x: inner_x,
                    y: margin,
                    width: inner_w,
                    height: 1,
                },
                tui.active,
                &state.theme,
            );

            // Summary info bar
            if h > 5 + margin * 2 {
                draw_summary_bar(
                    frame.buffer_mut(),
                    Rect {
                        x: inner_x,
                        y: margin + 1,
                        width: inner_w,
                        height: 1,
                    },
                    &state.theme,
                    &tui,
                );
            }

            // Content area (shifted down by 1 for summary bar)
            if h > 5 + margin * 2 {
                let content_area = Rect {
                    x: inner_x,
                    y: margin + 2,
                    width: inner_w,
                    height: h.saturating_sub(4 + margin * 2),
                };
                tui.content_area_y = content_area.y;
                tui.content_area_h = content_area.height;
                let tab_idx = tui.active.index();
                let scroll = tui.scroll_offset[tab_idx];
                let selected = tui.selected_idx[tab_idx];
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
                        scroll,
                        selected,
                    ),
                    Tab::Stale => render_stale(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.stale_rows,
                        scroll,
                        selected,
                    ),
                    Tab::Tree => render_tree(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.tree_rows,
                        scroll,
                        selected,
                    ),
                    Tab::NetMap => render_net_map(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.net_map_rows,
                        scroll,
                        selected,
                    ),
                    Tab::PipeChain => render_pipes(
                        frame.buffer_mut(),
                        content_area,
                        &state.theme,
                        &tui.pipe_rows,
                        scroll,
                        selected,
                    ),
                }
            }

            // Bottom 2 rows: separator + status
            if h > 3 + margin * 2 {
                draw_bottom_bar(
                    frame.buffer_mut(),
                    Rect {
                        x: inner_x,
                        y: h - 2 - margin,
                        width: inner_w,
                        height: 2,
                    },
                    &state,
                    tui.total_procs,
                    tui.total_files,
                    &elapsed_str,
                    &tui.screen_filter,
                );
            }

            // Help overlay
            if state.show_help {
                draw_help(frame.buffer_mut(), size, &state.theme, tui.help_keys());
            }

            // Theme chooser overlay (on top of everything)
            if tui.show_theme_chooser {
                chooser_rect = draw_theme_chooser(
                    frame.buffer_mut(),
                    size,
                    &state.theme,
                    tui.theme_chooser_idx,
                    state.theme_idx,
                    &tui.custom_themes,
                );
            }

            // Theme editor overlay (on top of everything)
            if tui.show_theme_editor {
                editor_rect = draw_theme_editor(frame.buffer_mut(), size, &state.theme, &tui);
            }

            // Filter popup overlay
            if tui.filter_state.active {
                draw_filter_popup(frame.buffer_mut(), size, &state.theme, &tui);
            }

            // Tooltip overlay
            if tui.tooltip.active {
                draw_tooltip(frame.buffer_mut(), size, &state.theme, &tui.tooltip);
            }

            // Status message overlay
            if let Some(ref msg) = tui.status_msg
                && !msg.expired()
            {
                draw_status_msg(frame.buffer_mut(), size, &state.theme, &msg.text);
            }
        });

        // Poll events
        let deadline = Instant::now() + Duration::from_secs(state.interval);
        while Instant::now() < deadline {
            if !event::poll(Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }
            let Ok(ev) = event::read() else {
                continue;
            };

            match ev {
                Event::Key(key) => {
                    // Dismiss tooltip on any key
                    tui.tooltip.active = false;

                    // Ctrl+C always quits
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        running = false;
                        break;
                    }

                    // Filter input mode intercepts ALL keys when open
                    if tui.filter_state.active {
                        match key.code {
                            KeyCode::Enter => {
                                tui.filter_state.active = false;
                                let f = tui.filter_state.buf.clone();
                                tui.screen_filter = if f.is_empty() { None } else { Some(f) };
                                tui.set_status(if tui.screen_filter.is_some() {
                                    "Filter applied"
                                } else {
                                    "Filter cleared"
                                });
                            }
                            KeyCode::Esc => {
                                tui.filter_state.active = false;
                                tui.screen_filter = tui.filter_state.prev.clone();
                            }
                            KeyCode::Backspace => tui.filter_state.backspace(),
                            KeyCode::Left => tui.filter_state.left(),
                            KeyCode::Right => tui.filter_state.right(),
                            KeyCode::Home => tui.filter_state.home(),
                            KeyCode::End => tui.filter_state.end(),
                            KeyCode::Char(ch) => {
                                if key.modifiers.contains(KeyModifiers::CONTROL) {
                                    match ch {
                                        'w' => tui.filter_state.delete_word(),
                                        'a' => tui.filter_state.home(),
                                        'e' => tui.filter_state.end(),
                                        'k' => tui.filter_state.kill_to_end(),
                                        'u' => {
                                            tui.filter_state.buf.clear();
                                            tui.filter_state.cursor = 0;
                                        }
                                        _ => {}
                                    }
                                } else {
                                    tui.filter_state.insert(ch);
                                }
                                // Live filter preview
                                let f = tui.filter_state.buf.clone();
                                tui.screen_filter = if f.is_empty() { None } else { Some(f) };
                            }
                            _ => {}
                        }
                        break;
                    }

                    // Theme editor intercepts ALL keys when open
                    if tui.show_theme_editor {
                        if tui.editor_naming {
                            match key.code {
                                KeyCode::Enter => {
                                    let name = tui.editor_name.trim().to_string();
                                    if !name.is_empty() {
                                        let c = tui.editor_colors;
                                        tui.custom_themes.insert(
                                            name.clone(),
                                            config::CustomThemeColors {
                                                c1: c[0],
                                                c2: c[1],
                                                c3: c[2],
                                                c4: c[3],
                                                c5: c[4],
                                                c6: c[5],
                                            },
                                        );
                                        tui.active_custom_theme = Some(name.clone());
                                        state.theme = LsofTheme::from_custom(
                                            &name, c[0], c[1], c[2], c[3], c[4], c[5],
                                        );
                                        let mut prefs = config::load();
                                        prefs.custom_themes = tui.custom_themes.clone();
                                        prefs.active_custom_theme = Some(name);
                                        prefs.theme = state.theme.display_name().to_string().into();
                                        config::save(&prefs);
                                    }
                                    tui.show_theme_editor = false;
                                    tui.editor_naming = false;
                                    tui.editor_name.clear();
                                    tui.editor_cursor = 0;
                                }
                                KeyCode::Esc => {
                                    tui.editor_naming = false;
                                    tui.editor_name.clear();
                                    tui.editor_cursor = 0;
                                }
                                KeyCode::Backspace => {
                                    if tui.editor_cursor > 0 {
                                        tui.editor_cursor -= 1;
                                        tui.editor_name.remove(tui.editor_cursor);
                                    }
                                }
                                KeyCode::Left => {
                                    tui.editor_cursor = tui.editor_cursor.saturating_sub(1);
                                }
                                KeyCode::Right => {
                                    tui.editor_cursor =
                                        (tui.editor_cursor + 1).min(tui.editor_name.len());
                                }
                                KeyCode::Char(c) => {
                                    if tui.editor_name.len() < 20 {
                                        tui.editor_name.insert(tui.editor_cursor, c);
                                        tui.editor_cursor += 1;
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            match key.code {
                                KeyCode::Esc | KeyCode::Char('q') => {
                                    tui.show_theme_editor = false;
                                    // Restore original theme
                                    if let Some(ref name) = tui.active_custom_theme {
                                        if let Some(ct) = tui.custom_themes.get(name) {
                                            state.theme = LsofTheme::from_custom(
                                                name, ct.c1, ct.c2, ct.c3, ct.c4, ct.c5, ct.c6,
                                            );
                                        }
                                    } else {
                                        state.theme =
                                            LsofTheme::from_name(ThemeName::ALL[state.theme_idx]);
                                    }
                                }
                                KeyCode::Char('j') | KeyCode::Down => {
                                    tui.editor_slot = (tui.editor_slot + 1).min(5);
                                }
                                KeyCode::Char('k') | KeyCode::Up => {
                                    tui.editor_slot = tui.editor_slot.saturating_sub(1);
                                }
                                KeyCode::Char('l') | KeyCode::Right => {
                                    tui.editor_colors[tui.editor_slot] =
                                        tui.editor_colors[tui.editor_slot].wrapping_add(1);
                                    let c = tui.editor_colors;
                                    state.theme = LsofTheme::from_custom(
                                        "editing", c[0], c[1], c[2], c[3], c[4], c[5],
                                    );
                                }
                                KeyCode::Char('h') | KeyCode::Left => {
                                    tui.editor_colors[tui.editor_slot] =
                                        tui.editor_colors[tui.editor_slot].wrapping_sub(1);
                                    let c = tui.editor_colors;
                                    state.theme = LsofTheme::from_custom(
                                        "editing", c[0], c[1], c[2], c[3], c[4], c[5],
                                    );
                                }
                                KeyCode::Char('L') => {
                                    tui.editor_colors[tui.editor_slot] =
                                        tui.editor_colors[tui.editor_slot].wrapping_add(10);
                                    let c = tui.editor_colors;
                                    state.theme = LsofTheme::from_custom(
                                        "editing", c[0], c[1], c[2], c[3], c[4], c[5],
                                    );
                                }
                                KeyCode::Char('H') => {
                                    tui.editor_colors[tui.editor_slot] =
                                        tui.editor_colors[tui.editor_slot].wrapping_sub(10);
                                    let c = tui.editor_colors;
                                    state.theme = LsofTheme::from_custom(
                                        "editing", c[0], c[1], c[2], c[3], c[4], c[5],
                                    );
                                }
                                KeyCode::Enter | KeyCode::Char('s') | KeyCode::Char('S') => {
                                    tui.editor_naming = true;
                                    tui.editor_name.clear();
                                    tui.editor_cursor = 0;
                                }
                                _ => {}
                            }
                        }
                        break;
                    }

                    // Theme chooser intercepts keys when open
                    if tui.show_theme_chooser {
                        let custom_names = sorted_custom_names(&tui.custom_themes);
                        let theme_count = ThemeName::ALL.len() + custom_names.len();
                        let mut chooser_changed = true;
                        match key.code {
                            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('c') => {
                                tui.show_theme_chooser = false;
                            }
                            KeyCode::Char('j') | KeyCode::Down => {
                                if tui.theme_chooser_idx + 1 < theme_count {
                                    tui.theme_chooser_idx += 1;
                                }
                            }
                            KeyCode::Char('k') | KeyCode::Up => {
                                tui.theme_chooser_idx = tui.theme_chooser_idx.saturating_sub(1);
                            }
                            KeyCode::Home | KeyCode::Char('g') => {
                                tui.theme_chooser_idx = 0;
                            }
                            KeyCode::End | KeyCode::Char('G') => {
                                tui.theme_chooser_idx = theme_count.saturating_sub(1);
                            }
                            KeyCode::PageDown => {
                                tui.theme_chooser_idx =
                                    (tui.theme_chooser_idx + 10).min(theme_count - 1);
                            }
                            KeyCode::PageUp => {
                                tui.theme_chooser_idx = tui.theme_chooser_idx.saturating_sub(10);
                            }
                            KeyCode::Enter | KeyCode::Char(' ') => {
                                apply_chooser_selection(
                                    tui.theme_chooser_idx,
                                    &mut state,
                                    &mut tui.active_custom_theme,
                                    &tui.custom_themes,
                                    &custom_names,
                                );
                                tui.show_theme_chooser = false;
                                let mut prefs = config::load();
                                prefs.theme = Some(state.theme.display_name().to_string());
                                prefs.refresh_rate = Some(state.interval);
                                prefs.active_custom_theme = tui.active_custom_theme.clone();
                                config::save(&prefs);
                            }
                            _ => {
                                chooser_changed = false;
                            }
                        }
                        if chooser_changed {
                            // Live-preview: apply theme as you navigate
                            if tui.show_theme_chooser && tui.theme_chooser_idx < theme_count {
                                apply_chooser_selection(
                                    tui.theme_chooser_idx,
                                    &mut state,
                                    &mut tui.active_custom_theme,
                                    &tui.custom_themes,
                                    &custom_names,
                                );
                            }
                            // Re-render immediately without re-gathering data
                            break;
                        }
                        continue; // unhandled key, stay in event loop
                    }

                    // Tab navigation
                    match key.code {
                        KeyCode::Tab | KeyCode::Right => {
                            let idx = (tui.active.index() + 1) % Tab::ALL.len();
                            tui.active = Tab::ALL[idx];
                            save_prefs_with_tab(&state, tui.active);
                            break;
                        }
                        KeyCode::BackTab | KeyCode::Left => {
                            let idx = (tui.active.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                            tui.active = Tab::ALL[idx];
                            save_prefs_with_tab(&state, tui.active);
                            break;
                        }
                        _ => {}
                    }

                    // Mode-specific keys
                    let consumed = match tui.active {
                        Tab::Top => tui.top_mode.handle_key(key, &mut state),
                        Tab::Summary => tui.summary_mode.handle_key(key, &mut state),
                        _ => false,
                    };
                    if consumed {
                        break;
                    }

                    // Ctrl+key combos
                    if key.modifiers.contains(KeyModifiers::CONTROL) {
                        match key.code {
                            KeyCode::Char('d') => {
                                tui.page_down();
                                break;
                            }
                            KeyCode::Char('u') => {
                                tui.page_up();
                                break;
                            }
                            _ => {}
                        }
                    }

                    // Common keybindings
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
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
                            tui.show_theme_chooser = !tui.show_theme_chooser;
                            tui.theme_chooser_idx = state.theme_idx;
                            break;
                        }
                        KeyCode::Char('C') => {
                            // Open theme editor with current palette
                            let palette = if let Some(ref cname) = tui.active_custom_theme {
                                if let Some(ct) = tui.custom_themes.get(cname) {
                                    [ct.c1, ct.c2, ct.c3, ct.c4, ct.c5, ct.c6]
                                } else {
                                    state.theme.name.swatch_colors()
                                }
                            } else {
                                state.theme.name.swatch_colors()
                            };
                            tui.editor_colors = palette;
                            tui.editor_slot = 0;
                            tui.editor_naming = false;
                            tui.editor_name.clear();
                            tui.editor_cursor = 0;
                            tui.show_theme_editor = true;
                            break;
                        }

                        // Filter
                        KeyCode::Char('/') => {
                            state.show_help = false;
                            tui.filter_state.open(&tui.screen_filter);
                            break;
                        }
                        KeyCode::Char('0') => {
                            tui.screen_filter = None;
                            tui.set_status("Filter cleared");
                            break;
                        }

                        // Navigation
                        KeyCode::Char('j') | KeyCode::Down => {
                            tui.select_next();
                            break;
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            tui.select_prev();
                            break;
                        }
                        KeyCode::Home => {
                            tui.jump_top();
                            break;
                        }
                        KeyCode::End | KeyCode::Char('G') => {
                            tui.jump_bottom();
                            break;
                        }

                        // Export
                        KeyCode::Char('e') => {
                            tui.export();
                            break;
                        }

                        // Copy
                        KeyCode::Char('y') => {
                            tui.copy_selected();
                            break;
                        }

                        // Reverse sort
                        KeyCode::Char('r') => {
                            tui.sort_reverse = !tui.sort_reverse;
                            tui.set_status(if tui.sort_reverse {
                                "Sort: reversed"
                            } else {
                                "Sort: normal"
                            });
                            break;
                        }

                        // Cycle refresh rate
                        KeyCode::Char('f') => {
                            state.interval = match state.interval {
                                1 => 2,
                                2 => 5,
                                5 => 10,
                                _ => 1,
                            };
                            tui.set_status(format!("Refresh rate: {}s", state.interval));
                            save_prefs(&state);
                            break;
                        }

                        KeyCode::Char(d @ '1'..='7') => {
                            let idx = (d as usize) - ('1' as usize);
                            if idx < Tab::ALL.len() {
                                tui.active = Tab::ALL[idx];
                                save_prefs_with_tab(&state, tui.active);
                            }
                            break;
                        }
                        KeyCode::Char(d @ '8'..='9') => {
                            state.interval = (d as u64) - b'0' as u64;
                            save_prefs(&state);
                            break;
                        }
                        KeyCode::Char('<') | KeyCode::Char('[') => {
                            state.interval = state.interval.saturating_sub(1).max(1);
                            save_prefs(&state);
                            break;
                        }
                        KeyCode::Char('>') | KeyCode::Char(']') => {
                            state.interval = (state.interval + 1).min(60);
                            save_prefs(&state);
                            break;
                        }
                        KeyCode::Char('x') => {
                            state.show_border = !state.show_border;
                            save_prefs(&state);
                            break;
                        }
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    // Dismiss tooltip on any click
                    if matches!(mouse.kind, MouseEventKind::Down(_)) {
                        tui.tooltip.active = false;
                    }

                    match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => {
                            let x = mouse.column;
                            let y = mouse.row;

                            // Theme editor click handling (takes priority when open)
                            if tui.show_theme_editor {
                                let (ex0, ey0, ew, eh) = editor_rect;
                                if x >= ex0 && x < ex0 + ew && y >= ey0 && y < ey0 + eh {
                                    let slot_y_start = ey0 + 3;
                                    if y >= slot_y_start && y < slot_y_start + 6 {
                                        tui.editor_slot = (y - slot_y_start) as usize;
                                    }
                                } else {
                                    tui.show_theme_editor = false;
                                }
                                break;
                            }

                            // Theme chooser click handling
                            if tui.show_theme_chooser {
                                let (cx0, cy0, cw, ch) = chooser_rect;
                                if x >= cx0 && x < cx0 + cw && y >= cy0 && y < cy0 + ch {
                                    let custom_names = sorted_custom_names(&tui.custom_themes);
                                    let total_count = ThemeName::ALL.len() + custom_names.len();
                                    let max_rows = ch as usize;
                                    let scroll = if tui.theme_chooser_idx >= max_rows {
                                        tui.theme_chooser_idx - max_rows + 1
                                    } else {
                                        0
                                    };
                                    let clicked_idx = scroll + (y - cy0) as usize;
                                    if clicked_idx < total_count {
                                        tui.theme_chooser_idx = clicked_idx;
                                        apply_chooser_selection(
                                            clicked_idx,
                                            &mut state,
                                            &mut tui.active_custom_theme,
                                            &tui.custom_themes,
                                            &custom_names,
                                        );
                                        tui.show_theme_chooser = false;
                                        let mut prefs = config::load();
                                        prefs.theme = Some(state.theme.display_name().to_string());
                                        prefs.active_custom_theme = tui.active_custom_theme.clone();
                                        config::save(&prefs);
                                    }
                                } else {
                                    tui.show_theme_chooser = false;
                                }
                                break;
                            }

                            // Filter popup dismiss
                            if tui.filter_state.active {
                                break;
                            }

                            // Tab bar click
                            let margin = if state.show_border { 1u16 } else { 0 };
                            if y == margin {
                                if let Some(tab) = tab_at_x(x) {
                                    tui.active = tab;
                                    save_prefs_with_tab(&state, tui.active);
                                }
                                break;
                            }

                            // Content area row click → select
                            if y >= tui.content_area_y
                                && y < tui.content_area_y + tui.content_area_h
                                && matches!(
                                    tui.active,
                                    Tab::Ports
                                        | Tab::Stale
                                        | Tab::Tree
                                        | Tab::NetMap
                                        | Tab::PipeChain
                                )
                            {
                                // +3 for info line + header row + blank row
                                let data_row_offset =
                                    (y - tui.content_area_y).saturating_sub(3) as usize;
                                let idx = tui.scroll() + data_row_offset;
                                if idx < tui.row_count() {
                                    tui.set_selected(Some(idx));
                                }
                                break;
                            }
                        }
                        MouseEventKind::Down(MouseButton::Right) => {
                            let x = mouse.column;
                            let y = mouse.row;
                            // Right-click in content area → tooltip
                            if y >= tui.content_area_y
                                && y < tui.content_area_y + tui.content_area_h
                                && matches!(
                                    tui.active,
                                    Tab::Ports
                                        | Tab::Stale
                                        | Tab::Tree
                                        | Tab::NetMap
                                        | Tab::PipeChain
                                )
                            {
                                let data_row_offset =
                                    (y - tui.content_area_y).saturating_sub(3) as usize;
                                let idx = tui.scroll() + data_row_offset;
                                if idx < tui.row_count() {
                                    tui.set_selected(Some(idx));
                                    let lines = tui.build_tooltip(idx);
                                    if !lines.is_empty() {
                                        tui.tooltip = Tooltip {
                                            active: true,
                                            x,
                                            y,
                                            lines,
                                        };
                                    }
                                }
                                break;
                            }
                        }
                        MouseEventKind::ScrollDown => {
                            tui.select_next();
                            break;
                        }
                        MouseEventKind::ScrollUp => {
                            tui.select_prev();
                            break;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    let _ = terminal::disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        cursor::Show,
        DisableMouseCapture,
        terminal::LeaveAlternateScreen
    );
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
        let tui = TabbedTui::new(0, &config::Prefs::default());
        assert_eq!(tui.active, Tab::Top);
        assert!(tui.port_rows.is_empty());
        assert!(tui.stale_rows.is_empty());
        assert!(!tui.show_theme_chooser);
        assert_eq!(tui.theme_chooser_idx, 0);
        assert_eq!(tui.total_procs, 0);
        assert_eq!(tui.total_files, 0);
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
        render_ports(&mut buf, area, &theme, &[], 0, None);
    }

    #[test]
    fn render_stale_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_stale(&mut buf, area, &theme, &[], 0, None);
    }

    #[test]
    fn render_tree_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_tree(&mut buf, area, &theme, &[], 0, None);
    }

    #[test]
    fn render_net_map_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_net_map(&mut buf, area, &theme, &[], 0, None);
    }

    #[test]
    fn render_pipes_empty() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        render_pipes(&mut buf, area, &theme, &[], 0, None);
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
        let tui = TabbedTui::new(0, &config::Prefs::default());
        let keys = tui.help_keys();
        assert!(keys.iter().any(|(k, _)| *k == "Tab / Right"));
        assert!(keys.iter().any(|(k, _)| *k == "1-7"));
    }

    #[test]
    fn help_keys_top_includes_sort() {
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
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
        render_ports(&mut buf, area, &theme, &rows, 0, None);
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
        render_stale(&mut buf, area, &theme, &rows, 0, None);
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
        render_tree(&mut buf, area, &theme, &rows, 0, None);
    }

    #[test]
    fn tab_at_x_first_tab() {
        // First tab " TOP " starts at x=1, len=5
        assert_eq!(tab_at_x(1), Some(Tab::Top));
        assert_eq!(tab_at_x(5), Some(Tab::Top));
    }

    #[test]
    fn tab_at_x_second_tab() {
        // " TOP " = 5 chars at pos 1, then " | " = 3, so " SUMMARY " at pos 9
        assert_eq!(tab_at_x(9), Some(Tab::Summary));
    }

    #[test]
    fn tab_at_x_out_of_range() {
        assert_eq!(tab_at_x(200), None);
    }

    #[test]
    fn tab_at_x_zero() {
        assert_eq!(tab_at_x(0), None);
    }

    #[test]
    fn draw_theme_chooser_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        draw_theme_chooser(
            &mut buf,
            area,
            &theme,
            0,
            0,
            &std::collections::HashMap::new(),
        );
    }

    #[test]
    fn draw_theme_chooser_selected_middle() {
        let theme = LsofTheme::from_name(ThemeName::Classic);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        draw_theme_chooser(
            &mut buf,
            area,
            &theme,
            15,
            5,
            &std::collections::HashMap::new(),
        );
    }

    #[test]
    fn draw_bottom_bar_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let state = TuiState::new_pub(2, theme);
        let area = Rect::new(0, 0, 80, 2);
        let mut buf = Buffer::empty(area);
        draw_bottom_bar(&mut buf, area, &state, 42, 1337, "5s", &None);
    }

    #[test]
    fn draw_theme_editor_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        let tui = TabbedTui::new(0, &config::Prefs::default());
        draw_theme_editor(&mut buf, area, &theme, &tui);
    }

    #[test]
    fn draw_theme_editor_naming_mode() {
        let theme = LsofTheme::from_name(ThemeName::Classic);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
        tui.editor_naming = true;
        tui.editor_name = "MyTheme".to_string();
        draw_theme_editor(&mut buf, area, &theme, &tui);
    }

    #[test]
    fn draw_theme_chooser_with_custom_themes() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 45);
        let mut buf = Buffer::empty(area);
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "MyCustom".to_string(),
            config::CustomThemeColors {
                c1: 100,
                c2: 200,
                c3: 150,
                c4: 50,
                c5: 75,
                c6: 25,
            },
        );
        draw_theme_chooser(&mut buf, area, &theme, 0, 0, &custom);
    }

    #[test]
    fn sorted_custom_names_ordering() {
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "Zebra".to_string(),
            config::CustomThemeColors {
                c1: 1,
                c2: 2,
                c3: 3,
                c4: 4,
                c5: 5,
                c6: 6,
            },
        );
        custom.insert(
            "Alpha".to_string(),
            config::CustomThemeColors {
                c1: 10,
                c2: 20,
                c3: 30,
                c4: 40,
                c5: 50,
                c6: 60,
            },
        );
        let names = sorted_custom_names(&custom);
        assert_eq!(names, vec!["Alpha", "Zebra"]);
    }

    #[test]
    fn apply_chooser_builtin() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let mut state = TuiState::new_pub(1, theme);
        let mut active = None;
        let custom = std::collections::HashMap::new();
        let names: Vec<String> = vec![];
        apply_chooser_selection(5, &mut state, &mut active, &custom, &names);
        assert_eq!(state.theme.name, ThemeName::ALL[5]);
        assert!(active.is_none());
    }

    #[test]
    fn apply_chooser_custom() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let mut state = TuiState::new_pub(1, theme);
        let mut active = None;
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "Test".to_string(),
            config::CustomThemeColors {
                c1: 100,
                c2: 200,
                c3: 150,
                c4: 50,
                c5: 75,
                c6: 25,
            },
        );
        let names = vec!["Test".to_string()];
        let idx = ThemeName::ALL.len(); // first custom theme
        apply_chooser_selection(idx, &mut state, &mut active, &custom, &names);
        assert_eq!(active, Some("Test".to_string()));
        assert_eq!(state.theme.custom_name.as_deref(), Some("Test"));
    }

    #[test]
    fn custom_theme_from_custom() {
        let t = LsofTheme::from_custom("MyTheme", 100, 200, 150, 50, 75, 25);
        assert_eq!(t.custom_name.as_deref(), Some("MyTheme"));
        assert_eq!(t.display_name(), "MyTheme");
    }

    #[test]
    fn builtin_theme_display_name() {
        let t = LsofTheme::from_name(ThemeName::Matrix);
        assert_eq!(t.display_name(), "Matrix");
        assert!(t.custom_name.is_none());
    }

    #[test]
    fn prefs_custom_themes_roundtrip() {
        let mut p = config::Prefs::default();
        p.custom_themes.insert(
            "TestTheme".to_string(),
            config::CustomThemeColors {
                c1: 10,
                c2: 20,
                c3: 30,
                c4: 40,
                c5: 50,
                c6: 60,
            },
        );
        p.active_custom_theme = Some("TestTheme".to_string());
        let s = toml::to_string_pretty(&p).unwrap();
        let p2: config::Prefs = toml::from_str(&s).unwrap();
        assert!(p2.custom_themes.contains_key("TestTheme"));
        assert_eq!(p2.active_custom_theme, Some("TestTheme".to_string()));
        let ct = &p2.custom_themes["TestTheme"];
        assert_eq!(ct.c1, 10);
        assert_eq!(ct.c6, 60);
    }

    #[test]
    fn tabbed_tui_editor_fields() {
        let tui = TabbedTui::new(0, &config::Prefs::default());
        assert!(!tui.show_theme_editor);
        assert_eq!(tui.editor_slot, 0);
        assert_eq!(tui.editor_colors, [0; 6]);
        assert!(!tui.editor_naming);
        assert!(tui.editor_name.is_empty());
        assert_eq!(tui.editor_cursor, 0);
        assert!(tui.custom_themes.is_empty());
        assert!(tui.active_custom_theme.is_none());
    }

    // ── New TUI feature tests ─────────────────────────────────────────────

    #[test]
    fn filter_state_insert_and_backspace() {
        let mut fs = FilterState::new();
        fs.insert('h');
        fs.insert('e');
        fs.insert('l');
        assert_eq!(fs.buf, "hel");
        assert_eq!(fs.cursor, 3);
        fs.backspace();
        assert_eq!(fs.buf, "he");
        assert_eq!(fs.cursor, 2);
    }

    #[test]
    fn filter_state_delete_word() {
        let mut fs = FilterState::new();
        fs.buf = "hello world".to_string();
        fs.cursor = fs.buf.len();
        fs.delete_word();
        assert_eq!(fs.buf, "hello ");
    }

    #[test]
    fn filter_state_home_end() {
        let mut fs = FilterState::new();
        fs.buf = "hello".to_string();
        fs.cursor = 3;
        fs.home();
        assert_eq!(fs.cursor, 0);
        fs.end();
        assert_eq!(fs.cursor, 5);
    }

    #[test]
    fn filter_state_left_right() {
        let mut fs = FilterState::new();
        fs.buf = "abc".to_string();
        fs.cursor = 2;
        fs.left();
        assert_eq!(fs.cursor, 1);
        fs.right();
        assert_eq!(fs.cursor, 2);
    }

    #[test]
    fn filter_state_kill_to_end() {
        let mut fs = FilterState::new();
        fs.buf = "hello world".to_string();
        fs.cursor = 5;
        fs.kill_to_end();
        assert_eq!(fs.buf, "hello");
    }

    #[test]
    fn filter_state_open() {
        let mut fs = FilterState::new();
        let current = Some("test".to_string());
        fs.open(&current);
        assert!(fs.active);
        assert_eq!(fs.buf, "test");
        assert_eq!(fs.cursor, 4);
        assert_eq!(fs.prev, Some("test".to_string()));
    }

    #[test]
    fn filter_state_open_none() {
        let mut fs = FilterState::new();
        fs.open(&None);
        assert!(fs.active);
        assert!(fs.buf.is_empty());
        assert_eq!(fs.cursor, 0);
    }

    #[test]
    fn status_msg_expires() {
        let msg = StatusMsg {
            text: "test".into(),
            since: Instant::now() - Duration::from_secs(5),
        };
        assert!(msg.expired());
    }

    #[test]
    fn status_msg_not_expired() {
        let msg = StatusMsg::new("test".into());
        assert!(!msg.expired());
    }

    #[test]
    fn tooltip_default() {
        let tt = Tooltip::default();
        assert!(!tt.active);
        assert!(tt.lines.is_empty());
    }

    #[test]
    fn tabbed_tui_new_fields() {
        let tui = TabbedTui::new(0, &config::Prefs::default());
        assert!(!tui.filter_state.active);
        assert!(tui.screen_filter.is_none());
        assert_eq!(tui.selected_idx, [None; 7]);
        assert_eq!(tui.scroll_offset, [0; 7]);
        assert!(!tui.tooltip.active);
        assert!(tui.status_msg.is_none());
        assert!(!tui.sort_reverse);
    }

    #[test]
    fn tabbed_tui_set_status() {
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
        tui.set_status("hello");
        assert!(tui.status_msg.is_some());
        assert_eq!(tui.status_msg.as_ref().unwrap().text, "hello");
    }

    #[test]
    fn tabbed_tui_selection_per_tab() {
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
        tui.active = Tab::Ports;
        tui.set_selected(Some(5));
        assert_eq!(tui.selected(), Some(5));
        tui.active = Tab::Stale;
        assert_eq!(tui.selected(), None);
        tui.set_selected(Some(3));
        assert_eq!(tui.selected(), Some(3));
        tui.active = Tab::Ports;
        assert_eq!(tui.selected(), Some(5));
    }

    #[test]
    fn tabbed_tui_scroll_per_tab() {
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
        tui.active = Tab::NetMap;
        tui.set_scroll(10);
        assert_eq!(tui.scroll(), 10);
        tui.active = Tab::Tree;
        assert_eq!(tui.scroll(), 0);
    }

    #[test]
    fn tabbed_tui_summary_info() {
        let mut tui = TabbedTui::new(0, &config::Prefs::default());
        tui.active = Tab::Ports;
        assert!(tui.summary_info().contains("listening port"));
        tui.active = Tab::Stale;
        assert!(tui.summary_info().contains("stale FD"));
    }

    #[test]
    fn tabbed_tui_build_tooltip_empty() {
        let tui = TabbedTui::new(0, &config::Prefs::default());
        // No rows, so tooltip lines should be empty
        assert!(tui.build_tooltip(0).is_empty());
    }

    #[test]
    fn draw_filter_popup_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        let tui = TabbedTui::new(0, &config::Prefs::default());
        draw_filter_popup(&mut buf, area, &theme, &tui);
    }

    #[test]
    fn draw_tooltip_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        let tt = Tooltip {
            active: true,
            x: 10,
            y: 10,
            lines: vec![
                ("PID".into(), "123".into()),
                ("Command".into(), "test".into()),
            ],
        };
        draw_tooltip(&mut buf, area, &theme, &tt);
    }

    #[test]
    fn draw_tooltip_empty_lines() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        let tt = Tooltip {
            active: true,
            x: 10,
            y: 10,
            lines: vec![],
        };
        draw_tooltip(&mut buf, area, &theme, &tt);
    }

    #[test]
    fn draw_status_msg_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        draw_status_msg(&mut buf, area, &theme, "Filter applied");
    }

    #[test]
    fn draw_summary_bar_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 1);
        let mut buf = Buffer::empty(area);
        let tui = TabbedTui::new(0, &config::Prefs::default());
        draw_summary_bar(&mut buf, area, &theme, &tui);
    }

    #[test]
    fn draw_bottom_bar_with_filter() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let state = TuiState::new_pub(2, theme);
        let area = Rect::new(0, 0, 120, 2);
        let mut buf = Buffer::empty(area);
        let filter = Some("nginx".to_string());
        draw_bottom_bar(&mut buf, area, &state, 42, 1337, "5s", &filter);
        let mut line = String::new();
        for x in 0..120u16 {
            line.push_str(buf[(x, 1)].symbol());
        }
        assert!(line.contains("filter:nginx"));
    }

    #[test]
    fn render_ports_with_selection() {
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
        render_ports(&mut buf, area, &theme, &rows, 0, Some(1));
    }

    #[test]
    fn render_ports_with_scroll() {
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
        render_ports(&mut buf, area, &theme, &rows, 1, None);
    }
}
