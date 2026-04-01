//! Shared TUI application framework using ratatui
//!
//! All live/interactive modes plug into this framework to get:
//! - Alternate screen management
//! - Common keybindings (q/Esc/Ctrl-C quit, p pause, 1-9 interval, c theme, etc.)
//! - Atomic frame rendering via ratatui with direct buffer manipulation
//! - Help overlay with mode-specific keys

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::{cursor, execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

use crate::filter::Filter;
use crate::theme::{LsofTheme, ThemeName};

/// Shared state managed by the TUI framework
pub struct TuiState {
    pub interval: u64,
    pub paused: bool,
    pub iteration: u64,
    pub show_help: bool,
    pub theme: LsofTheme,
    pub theme_idx: usize,
}

impl TuiState {
    fn new(interval: u64, theme: LsofTheme) -> Self {
        let theme_idx = ThemeName::ALL
            .iter()
            .position(|&n| n == theme.name)
            .unwrap_or(0);
        Self {
            interval,
            paused: false,
            iteration: 0,
            show_help: false,
            theme,
            theme_idx,
        }
    }

    /// Public constructor for use by tui_tabs
    pub fn new_pub(interval: u64, theme: LsofTheme) -> Self {
        Self::new(interval, theme)
    }

    pub fn cycle_theme(&mut self) {
        self.theme_idx = (self.theme_idx + 1) % ThemeName::ALL.len();
        self.theme = LsofTheme::from_name(ThemeName::ALL[self.theme_idx]);
    }
}

/// Trait that each live/interactive mode implements
pub trait TuiMode {
    /// Gather fresh data from the system
    fn update(&mut self, filter: &Filter);

    /// Render content directly to the ratatui frame buffer.
    fn render(&self, buf: &mut Buffer, area: Rect, theme: &LsofTheme, state: &TuiState);

    /// Handle mode-specific keys. Return true if the key was consumed.
    fn handle_key(&mut self, _key: KeyEvent, _state: &mut TuiState) -> bool {
        false
    }

    /// Title shown in status bar
    fn title(&self) -> &str;

    /// Mode-specific help keys: Vec<(key, description)>
    fn help_keys(&self) -> Vec<(&str, &str)> {
        vec![]
    }
}

/// Run the TUI main loop for any mode implementing `TuiMode`.
pub fn run_tui(mode: &mut dyn TuiMode, filter: &Filter, interval: u64, theme: &LsofTheme) {
    let is_tty = io::stdout().is_terminal();

    if !is_tty {
        // Non-TTY: single-shot render to a scratch buffer, then print text
        let mut state = TuiState::new(interval, theme.clone());
        state.iteration = 1;
        mode.update(filter);
        // Render to an off-screen buffer and extract text
        let area = Rect::new(0, 0, 120, 50);
        let mut buf = Buffer::empty(area);
        mode.render(&mut buf, area, &state.theme, &state);
        print_buffer_text(&buf, area);
        return;
    }

    // Enter alternate screen + raw mode
    let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
    let _ = terminal::enable_raw_mode();

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).unwrap();
    let mut state = TuiState::new(interval, theme.clone());
    let mut running = true;

    while running {
        if !state.paused {
            state.iteration += 1;
            mode.update(filter);
        }

        // Draw frame
        let _ = terminal.draw(|frame| {
            let size = frame.area();
            if size.width < 10 || size.height < 5 {
                return;
            }

            // Status bar (row 0)
            draw_status_bar(frame.buffer_mut(), size, mode.title(), &state);

            // Content area (rows 1..height)
            let content_area = Rect {
                x: 0,
                y: 1,
                width: size.width,
                height: size.height.saturating_sub(1),
            };
            mode.render(frame.buffer_mut(), content_area, &state.theme, &state);

            // Help overlay on top of everything
            if state.show_help {
                draw_help(frame.buffer_mut(), size, &state.theme, mode.help_keys());
            }
        });

        // Poll keys during interval
        let deadline = Instant::now() + Duration::from_secs(state.interval);
        while Instant::now() < deadline {
            if !event::poll(Duration::from_millis(100)).unwrap_or(false) {
                continue;
            }
            let Ok(Event::Key(key)) = event::read() else {
                continue;
            };

            // Let the mode handle its own keys first
            if mode.handle_key(key, &mut state) {
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
                KeyCode::Char(d @ '1'..='9') => {
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

    // Restore terminal
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
}

// ─── Rendering helpers ─────────────────────────────────────────────────────────

/// Write a string into the buffer at (x, y) with a given style, clamped to max_width.
pub fn set_str(buf: &mut Buffer, x: u16, y: u16, s: &str, st: Style, max_width: u16) {
    let aw = buf.area().x + buf.area().width;
    let ah = buf.area().y + buf.area().height;
    if y >= ah {
        return;
    }
    for (i, ch) in s.chars().enumerate() {
        let cx = x + i as u16;
        if cx >= x + max_width || cx >= aw {
            break;
        }
        let cell = &mut buf[(cx, y)];
        let mut char_buf = [0u8; 4];
        cell.set_symbol(ch.encode_utf8(&mut char_buf));
        cell.set_style(st);
    }
}

/// Set a single cell in the buffer.
pub fn set_cell(buf: &mut Buffer, x: u16, y: u16, ch: &str, s: Style) {
    let a = buf.area();
    if x < a.x + a.width && y < a.y + a.height {
        let c = &mut buf[(x, y)];
        c.set_symbol(ch);
        c.set_style(s);
    }
}

/// Draw a centered box with double-line border. Returns top-left (x0, y0).
pub fn draw_box(
    buf: &mut Buffer,
    area: Rect,
    bw: u16,
    bh: u16,
    bg: Color,
    border_style: Style,
) -> (u16, u16) {
    let x0 = area.x + (area.width.saturating_sub(bw)) / 2;
    let y0 = area.y + (area.height.saturating_sub(bh)) / 2;
    let x1 = x0 + bw - 1;
    let y1 = y0 + bh - 1;
    let fill = Style::default().bg(bg);
    for y in y0..y0 + bh {
        for x in x0..x0 + bw {
            set_cell(buf, x, y, " ", fill);
        }
    }
    set_cell(buf, x0, y0, "╔", border_style);
    set_cell(buf, x1, y0, "╗", border_style);
    set_cell(buf, x0, y1, "╚", border_style);
    set_cell(buf, x1, y1, "╝", border_style);
    for x in x0 + 1..x1 {
        set_cell(buf, x, y0, "═", border_style);
        set_cell(buf, x, y1, "═", border_style);
    }
    for y in y0 + 1..y1 {
        set_cell(buf, x0, y, "║", border_style);
        set_cell(buf, x1, y, "║", border_style);
    }
    (x0, y0)
}

/// Draw the top status bar.
fn draw_status_bar(buf: &mut Buffer, area: Rect, title: &str, state: &TuiState) {
    let t = &state.theme;
    let bg_s = Style::default()
        .fg(t.header_fg)
        .bg(t.header_bg)
        .add_modifier(Modifier::BOLD);
    // Fill the entire row with bg
    for x in area.x..area.x + area.width {
        set_cell(buf, x, area.y, " ", bg_s);
    }
    let pause_str = if state.paused { " [PAUSED]" } else { "" };
    let status = format!(
        " lsofrs {} -- {}s -- #{}{} -- theme: {}",
        title,
        state.interval,
        state.iteration,
        pause_str,
        state.theme.display_name(),
    );
    set_str(buf, area.x, area.y, &status, bg_s, area.width);
}

/// Draw the help overlay as a centered modal.
pub fn draw_help(buf: &mut Buffer, area: Rect, theme: &LsofTheme, mode_keys: Vec<(&str, &str)>) {
    let common_keys: Vec<(&str, &str)> = vec![
        ("q / Esc", "quit"),
        ("p", "pause / resume"),
        ("h / ?", "toggle help"),
        ("c", "theme chooser"),
        ("C", "theme editor"),
        ("1-9", "set refresh interval"),
        ("< / >", "adjust interval"),
    ];

    let total_lines = 3
        + common_keys.len()
        + if mode_keys.is_empty() {
            0
        } else {
            2 + mode_keys.len()
        }
        + 2;
    let bw = 50u16.min(area.width.saturating_sub(4));
    let bh = (total_lines as u16 + 2).min(area.height.saturating_sub(2));
    let bg = theme.help_bg;
    let bs = Style::default().fg(theme.help_border);
    let bgs = Style::default().fg(Color::White).bg(bg);
    let ks = Style::default().fg(theme.help_key).bg(bg);
    let vs = Style::default().fg(theme.help_val).bg(bg);
    let ts = Style::default()
        .fg(theme.help_title)
        .bg(bg)
        .add_modifier(Modifier::BOLD);
    let ss = Style::default()
        .fg(theme.help_key)
        .bg(bg)
        .add_modifier(Modifier::BOLD);

    let (x0, y0) = draw_box(buf, area, bw, bh, bg, bs);
    let inner_w = bw.saturating_sub(4);
    let cx = x0 + 2;
    let mut row = y0 + 1;

    // Title
    let title = "lsofrs -- help";
    let title_x = x0 + (bw.saturating_sub(title.len() as u16)) / 2;
    set_str(buf, title_x, row, title, ts, inner_w);
    row += 2;

    // Common keys section
    set_str(buf, cx, row, "COMMON KEYS", ss, inner_w);
    row += 1;
    for (key, desc) in &common_keys {
        if row >= y0 + bh - 1 {
            break;
        }
        set_str(buf, cx, row, key, ks, 14);
        set_str(buf, cx + 14, row, desc, vs, inner_w.saturating_sub(14));
        row += 1;
    }

    // Mode-specific keys section
    if !mode_keys.is_empty() {
        row += 1;
        if row < y0 + bh - 1 {
            set_str(buf, cx, row, "MODE-SPECIFIC KEYS", ss, inner_w);
            row += 1;
        }
        for (key, desc) in &mode_keys {
            if row >= y0 + bh - 1 {
                break;
            }
            set_str(buf, cx, row, key, ks, 14);
            set_str(buf, cx + 14, row, desc, vs, inner_w.saturating_sub(14));
            row += 1;
        }
    }

    // Footer
    let footer_row = y0 + bh - 1;
    if footer_row > row {
        let footer = "press h to close";
        let footer_x = x0 + (bw.saturating_sub(footer.len() as u16)) / 2;
        set_str(
            buf,
            footer_x,
            footer_row.saturating_sub(1),
            footer,
            bgs,
            inner_w,
        );
    }
}

/// Extract text content from a buffer and print it (for non-TTY mode).
fn print_buffer_text(buf: &Buffer, area: Rect) {
    for y in area.y..area.y + area.height {
        let mut line = String::new();
        for x in area.x..area.x + area.width {
            line.push_str(buf[(x, y)].symbol());
        }
        let trimmed = line.trim_end();
        if !trimmed.is_empty() {
            println!("{trimmed}");
        }
    }
}

use std::io::IsTerminal;

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyMode {
        updated: bool,
    }

    impl TuiMode for DummyMode {
        fn update(&mut self, _filter: &Filter) {
            self.updated = true;
        }

        fn render(&self, buf: &mut Buffer, area: Rect, _theme: &LsofTheme, state: &TuiState) {
            let text = format!("iteration={} paused={}", state.iteration, state.paused);
            let s = Style::default().fg(Color::White);
            set_str(buf, area.x, area.y, &text, s, area.width);
        }

        fn title(&self) -> &str {
            "dummy"
        }

        fn help_keys(&self) -> Vec<(&str, &str)> {
            vec![("x", "test action")]
        }
    }

    #[test]
    fn tui_state_defaults() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let s = TuiState::new(5, theme);
        assert_eq!(s.interval, 5);
        assert!(!s.paused);
        assert_eq!(s.iteration, 0);
        assert!(!s.show_help);
        assert_eq!(s.theme.name, ThemeName::NeonSprawl);
    }

    #[test]
    fn tui_state_cycle_theme() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let mut s = TuiState::new(1, theme);
        assert_eq!(s.theme.name, ThemeName::NeonSprawl);
        s.cycle_theme();
        assert_eq!(s.theme.name, ThemeName::ALL[1]);
        // Cycle through all
        for _ in 0..ThemeName::ALL.len() {
            s.cycle_theme();
        }
        // Should wrap around
        assert_eq!(s.theme.name, ThemeName::ALL[1]);
    }

    #[test]
    fn dummy_mode_render() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let mode = DummyMode { updated: false };
        let state = TuiState::new(1, theme.clone());
        let area = Rect::new(0, 0, 80, 10);
        let mut buf = Buffer::empty(area);
        mode.render(&mut buf, area, &theme, &state);
    }

    #[test]
    fn non_tty_single_shot() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let filter = Filter::default();
        let mut mode = DummyMode { updated: false };
        run_tui(&mut mode, &filter, 1, &theme);
        assert!(mode.updated);
    }

    #[test]
    fn set_str_basic() {
        let area = Rect::new(0, 0, 20, 5);
        let mut buf = Buffer::empty(area);
        let s = Style::default().fg(Color::White);
        set_str(&mut buf, 0, 0, "hello", s, 20);
        assert_eq!(buf[(0, 0)].symbol(), "h");
        assert_eq!(buf[(4, 0)].symbol(), "o");
    }

    #[test]
    fn set_str_clamps_to_max_width() {
        let area = Rect::new(0, 0, 20, 5);
        let mut buf = Buffer::empty(area);
        let s = Style::default();
        set_str(&mut buf, 0, 0, "hello world", s, 5);
        assert_eq!(buf[(4, 0)].symbol(), "o");
        // Position 5 should not have been written (still space)
        assert_eq!(buf[(5, 0)].symbol(), " ");
    }

    #[test]
    fn set_cell_out_of_bounds() {
        let area = Rect::new(0, 0, 10, 5);
        let mut buf = Buffer::empty(area);
        let s = Style::default();
        // Should not panic
        set_cell(&mut buf, 100, 100, "x", s);
    }

    #[test]
    fn draw_box_centered() {
        let area = Rect::new(0, 0, 40, 20);
        let mut buf = Buffer::empty(area);
        let bs = Style::default().fg(Color::White);
        let (x0, y0) = draw_box(&mut buf, area, 20, 10, Color::Black, bs);
        assert_eq!(x0, 10);
        assert_eq!(y0, 5);
        assert_eq!(buf[(x0, y0)].symbol(), "╔");
        assert_eq!(buf[(x0 + 19, y0)].symbol(), "╗");
        assert_eq!(buf[(x0, y0 + 9)].symbol(), "╚");
        assert_eq!(buf[(x0 + 19, y0 + 9)].symbol(), "╝");
    }

    #[test]
    fn draw_status_bar_shows_title() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let state = TuiState::new(2, theme);
        let area = Rect::new(0, 0, 80, 1);
        let mut buf = Buffer::empty(area);
        draw_status_bar(&mut buf, area, "top", &state);
        // Check that "lsofrs top" appears somewhere
        let mut line = String::new();
        for x in 0..80 {
            line.push_str(buf[(x, 0)].symbol());
        }
        assert!(line.contains("lsofrs top"));
    }

    #[test]
    fn draw_help_no_panic() {
        let theme = LsofTheme::from_name(ThemeName::NeonSprawl);
        let area = Rect::new(0, 0, 80, 40);
        let mut buf = Buffer::empty(area);
        draw_help(
            &mut buf,
            area,
            &theme,
            vec![("s", "sort"), ("r", "reverse")],
        );
    }

    #[test]
    fn draw_help_empty_mode_keys() {
        let theme = LsofTheme::from_name(ThemeName::Classic);
        let area = Rect::new(0, 0, 60, 30);
        let mut buf = Buffer::empty(area);
        draw_help(&mut buf, area, &theme, vec![]);
    }

    #[test]
    fn dummy_help_keys() {
        let mode = DummyMode { updated: false };
        let keys = mode.help_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].0, "x");
    }
}
