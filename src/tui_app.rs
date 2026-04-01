//! Shared TUI application framework using ratatui
//!
//! All live/interactive modes plug into this framework to get:
//! - Alternate screen management
//! - Common keybindings (q/Esc/Ctrl-C quit, p pause, 1-9 interval, etc.)
//! - Atomic frame rendering via ratatui

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::{cursor, execute, terminal};
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::Paragraph;

use crate::filter::Filter;
use crate::output::Theme;

/// Shared state managed by the TUI framework
pub struct TuiState {
    pub interval: u64,
    pub paused: bool,
    pub iteration: u64,
    pub show_help: bool,
}

impl TuiState {
    fn new(interval: u64) -> Self {
        Self {
            interval,
            paused: false,
            iteration: 0,
            show_help: false,
        }
    }
}

/// Trait that each live/interactive mode implements
pub trait TuiMode {
    /// Gather fresh data from the system
    fn update(&mut self, filter: &Filter);

    /// Render a frame's content as a pre-formatted ANSI string.
    /// The framework wraps this in a ratatui Paragraph widget.
    fn render_content(&self, theme: &Theme, state: &TuiState) -> String;

    /// Handle mode-specific keys. Return true if the key was consumed.
    fn handle_key(&mut self, _key: KeyEvent, _state: &mut TuiState) -> bool {
        false
    }

    /// Title shown in status messages
    fn title(&self) -> &str;
}

/// Run the TUI main loop for any mode implementing `TuiMode`.
/// Manages alternate screen, raw mode, terminal setup/teardown, and common keybindings.
pub fn run_tui(mode: &mut dyn TuiMode, filter: &Filter, interval: u64, theme: &Theme) {
    let use_alt = theme.is_tty;

    if !use_alt {
        // Non-TTY: single-shot render and exit
        let mut state = TuiState::new(interval);
        state.iteration = 1;
        mode.update(filter);
        let content = mode.render_content(theme, &state);
        print!("{content}");
        return;
    }

    // Enter alternate screen + raw mode
    let _ = execute!(io::stdout(), terminal::EnterAlternateScreen, cursor::Hide);
    let _ = terminal::enable_raw_mode();

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            let _ = terminal::disable_raw_mode();
            let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
            return;
        }
    };

    let mut state = TuiState::new(interval);
    let mut running = true;

    while running {
        if !state.paused {
            state.iteration += 1;
            mode.update(filter);
        }

        // Render frame via ratatui
        let content = mode.render_content(theme, &state);
        let _ = terminal.draw(|frame: &mut Frame| {
            let area = frame.area();
            render_ansi_paragraph(frame, area, &content);
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
                // Quit
                KeyCode::Char('q') | KeyCode::Esc => {
                    running = false;
                    break;
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    running = false;
                    break;
                }

                // Pause/resume
                KeyCode::Char('p') => {
                    state.paused = !state.paused;
                    break;
                }

                // Help toggle
                KeyCode::Char('?') | KeyCode::Char('h') => {
                    state.show_help = !state.show_help;
                    break;
                }

                // Set interval 1-9
                KeyCode::Char(d @ '1'..='9') => {
                    state.interval = (d as u64) - b'0' as u64;
                    break;
                }

                // Adjust interval
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
    drop(terminal);
    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), cursor::Show, terminal::LeaveAlternateScreen);
}

/// Render pre-formatted ANSI text as a ratatui Paragraph using raw ANSI passthrough
fn render_ansi_paragraph(frame: &mut Frame, area: Rect, content: &str) {
    // Convert \n to lines for ratatui Text, preserving ANSI escape sequences
    let text = Text::raw(content);
    let paragraph = Paragraph::new(text);
    frame.render_widget(paragraph, area);
}

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

        fn render_content(&self, _theme: &Theme, state: &TuiState) -> String {
            format!("iteration={} paused={}", state.iteration, state.paused)
        }

        fn title(&self) -> &str {
            "dummy"
        }
    }

    #[test]
    fn tui_state_defaults() {
        let s = TuiState::new(5);
        assert_eq!(s.interval, 5);
        assert!(!s.paused);
        assert_eq!(s.iteration, 0);
        assert!(!s.show_help);
    }

    #[test]
    fn dummy_mode_render() {
        let mode = DummyMode { updated: false };
        let theme = Theme::new(false);
        let state = TuiState::new(1);
        let out = mode.render_content(&theme, &state);
        assert!(out.contains("iteration=0"));
    }

    #[test]
    fn non_tty_single_shot() {
        let theme = Theme::new(false);
        let filter = Filter::default();
        let mut mode = DummyMode { updated: false };
        run_tui(&mut mode, &filter, 1, &theme);
        assert!(mode.updated);
    }
}
