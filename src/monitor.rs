//! Live full-screen monitoring mode (like top)

use std::io::{self, Write};
use std::time::Duration;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};

use crate::filter::Filter;
use crate::output::Theme;
use crate::strutil::truncate_max_bytes;
use crate::types::*;

const SORT_PID: usize = 0;
const SORT_CMD: usize = 1;
const SORT_USER: usize = 2;
const SORT_FDS: usize = 3;
const SORT_NAMES: [&str; 4] = ["PID", "COMMAND", "USER", "FDs"];

struct MonitorState {
    sort_mode: usize,
    sort_reverse: bool,
    paused: bool,
    show_help: bool,
    type_filter: String,
    search_str: String,
    term_rows: u16,
    term_cols: u16,
}

impl Default for MonitorState {
    fn default() -> Self {
        let (cols, rows) = terminal::size().unwrap_or((80, 24));
        Self {
            sort_mode: SORT_PID,
            sort_reverse: false,
            paused: false,
            show_help: false,
            type_filter: String::new(),
            search_str: String::new(),
            term_rows: rows,
            term_cols: cols,
        }
    }
}
/// `run_monitor` — see implementation.
pub fn run_monitor(
    filter: &Filter,
    interval: u64,
    theme: &Theme,
    show_pgid: bool,
    show_ppid: bool,
) {
    let mut state = MonitorState::default();

    // Enter alternate screen and raw mode
    let _ = terminal::enable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide,);

    loop {
        if !state.paused {
            // Refresh terminal size
            if let Ok((cols, rows)) = terminal::size() {
                state.term_rows = rows;
                state.term_cols = cols;
            }

            let mut procs = crate::gather_processes();

            // Apply filters
            procs.retain(|p| filter.matches_process(p));
            for p in &mut procs {
                p.files.retain(|f| filter.matches_file(f));
            }
            procs.retain(|p| !p.files.is_empty() || filter.terse);

            // Apply type filter
            if !state.type_filter.is_empty() {
                let tf = state.type_filter.to_uppercase();
                procs.retain(|p| p.files.iter().any(|f| f.file_type.as_str() == tf));
            }

            // Sort
            sort_procs(&mut procs, &state);

            // Draw frame
            let _ = execute!(
                stdout,
                cursor::MoveTo(0, 0),
                terminal::Clear(ClearType::All)
            );

            // Status bar
            let now = chrono::Local::now().format("%H:%M:%S");
            let total_fds: usize = procs.iter().map(|p| p.files.len()).sum();
            let _ = write!(
                stdout,
                "{bg}{bold}lsofrs monitor{reset} | {cyan}{}{reset} | procs:{green}{}{reset} fds:{yellow}{}{reset} | sort:{mag}{}{reset}{}",
                now,
                procs.len(),
                total_fds,
                SORT_NAMES[state.sort_mode],
                if state.sort_reverse { " [REV]" } else { "" },
                bg = theme.hdr_bg(),
                bold = theme.bold(),
                reset = theme.reset(),
                cyan = theme.cyan(),
                green = theme.green(),
                yellow = theme.yellow(),
                mag = theme.magenta(),
            );
            if state.paused {
                let _ = write!(
                    stdout,
                    " {red}[PAUSED]{reset}",
                    red = theme.red(),
                    reset = theme.reset()
                );
            }
            if !state.type_filter.is_empty() {
                let _ = write!(stdout, " filter:{}", state.type_filter);
            }
            let _ = writeln!(stdout, "\r");

            if state.show_help {
                let _ = writeln!(
                    stdout,
                    "{}Keys: s=sort r=reverse f=filter /=search p=pause q=quit ?=help{}\r",
                    theme.dim(),
                    theme.reset()
                );
            }

            // Limit output to terminal height
            let max_rows = (state.term_rows as usize).saturating_sub(3);
            let mut limited_procs = procs.clone();
            let mut total_files = 0;
            for p in &mut limited_procs {
                if total_files >= max_rows {
                    p.files.clear();
                } else if total_files + p.files.len() > max_rows {
                    p.files.truncate(max_rows - total_files);
                }
                total_files += p.files.len();
            }
            limited_procs.retain(|p| !p.files.is_empty());

            // Print header and data (raw mode requires \r\n)
            print_monitor_procs(&limited_procs, theme, show_pgid, show_ppid, &mut stdout);
        }

        // Wait for input or interval
        if handle_input(&mut state, interval) {
            break;
        }
    }

    // Restore terminal
    let _ = execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen,);
    let _ = terminal::disable_raw_mode();
}

fn sort_procs(procs: &mut [Process], state: &MonitorState) {
    procs.sort_by(|a, b| {
        let ord = match state.sort_mode {
            SORT_PID => a.pid.cmp(&b.pid),
            SORT_CMD => a.command.cmp(&b.command),
            SORT_USER => a.uid.cmp(&b.uid),
            SORT_FDS => a.files.len().cmp(&b.files.len()),
            _ => a.pid.cmp(&b.pid),
        };
        if state.sort_reverse {
            ord.reverse()
        } else {
            ord
        }
    });
}

fn handle_input(state: &mut MonitorState, interval: u64) -> bool {
    let timeout = Duration::from_secs(interval);
    if event::poll(timeout).unwrap_or(false)
        && let Ok(Event::Key(KeyEvent {
            code, modifiers, ..
        })) = event::read()
    {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => return true,
            KeyCode::Char('s') | KeyCode::Char('S') => {
                state.sort_mode = (state.sort_mode + 1) % 4;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                state.sort_reverse = !state.sort_reverse;
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                state.paused = !state.paused;
            }
            KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('H') => {
                state.show_help = !state.show_help;
            }
            KeyCode::Char('f') | KeyCode::Char('F') => {
                // Toggle type filter - cycle through common types
                static FILTERS: &[&str] =
                    &["", "REG", "DIR", "SOCK", "IPv4", "IPv6", "PIPE", "FIFO"];
                let current = FILTERS
                    .iter()
                    .position(|&f| f == state.type_filter)
                    .unwrap_or(0);
                state.type_filter = FILTERS[(current + 1) % FILTERS.len()].to_string();
            }
            _ => {}
        }
    }
    false
}

fn print_monitor_procs(
    procs: &[Process],
    theme: &Theme,
    _show_pgid: bool,
    _show_ppid: bool,
    out: &mut impl Write,
) {
    // Simplified columnar output for monitor mode with \r\n line endings
    let _ = write!(
        out,
        "{bg}{bold}{:<15} {:>7} {:<8} {:<4} {:<5} {:<8} {:>10} {:<6} {}{}\r\n",
        theme.cmd_title(),
        theme.pid_title(),
        theme.user_title(),
        theme.fd_title(),
        theme.type_title(),
        theme.dev_title(),
        theme.size_off_title(),
        theme.node_title(),
        theme.name_title(),
        theme.reset(),
        bg = theme.hdr_bg(),
        bold = theme.bold(),
    );

    for p in procs {
        let username = p.username();
        let user = truncate_max_bytes(username, 8);
        let cmd = truncate_max_bytes(&p.command, 15);

        let mut first = true;
        for f in &p.files {
            if first {
                let _ = write!(
                    out,
                    "{cyan}{:<15}{r} {mag}{:>7}{r} {yel}{:<8}{r} ",
                    cmd,
                    p.pid,
                    user,
                    cyan = theme.cyan(),
                    mag = theme.magenta(),
                    yel = theme.yellow(),
                    r = theme.reset(),
                );
                first = false;
            } else {
                let _ = write!(out, "{:<15} {:>7} {:<8} ", "", "", "");
            }

            let _ = write!(
                out,
                "{grn}{:<4}{r} {blu}{:<5}{r} {dim}{:<8}{r} {:>10} {:<6} {}\r\n",
                f.fd.with_access(f.access),
                f.file_type.as_str(),
                f.device_str(),
                f.size_or_offset_str(),
                f.node_str(),
                f.full_name(),
                grn = theme.green(),
                blu = theme.blue(),
                dim = theme.dim(),
                r = theme.reset(),
            );
        }
    }
}

#[cfg(test)]
mod sort_tests {
    use super::*;

    fn p(pid: i32, uid: u32, cmd: &str, fd_count: usize) -> Process {
        Process::new(
            pid,
            0,
            0,
            uid,
            cmd.to_string(),
            (0..fd_count).map(|_| OpenFile::default()).collect(),
        )
    }

    fn state(mode: usize, reverse: bool) -> MonitorState {
        MonitorState {
            sort_mode: mode,
            sort_reverse: reverse,
            paused: false,
            show_help: false,
            type_filter: String::new(),
            search_str: String::new(),
            term_rows: 24,
            term_cols: 80,
        }
    }

    #[test]
    fn sort_by_pid_ascending() {
        let mut procs = vec![p(300, 0, "c", 0), p(100, 0, "a", 0), p(200, 0, "b", 0)];
        sort_procs(&mut procs, &state(SORT_PID, false));
        assert_eq!(
            procs.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    #[test]
    fn sort_by_pid_descending_via_reverse() {
        let mut procs = vec![p(100, 0, "a", 0), p(200, 0, "b", 0), p(300, 0, "c", 0)];
        sort_procs(&mut procs, &state(SORT_PID, true));
        assert_eq!(
            procs.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![300, 200, 100]
        );
    }

    #[test]
    fn sort_by_command_lexicographic() {
        let mut procs = vec![p(1, 0, "zsh", 0), p(2, 0, "bash", 0), p(3, 0, "fish", 0)];
        sort_procs(&mut procs, &state(SORT_CMD, false));
        let cmds: Vec<&str> = procs.iter().map(|p| p.command.as_str()).collect();
        assert_eq!(cmds, vec!["bash", "fish", "zsh"]);
    }

    #[test]
    fn sort_by_uid() {
        let mut procs = vec![p(1, 1000, "a", 0), p(2, 0, "b", 0), p(3, 501, "c", 0)];
        sort_procs(&mut procs, &state(SORT_USER, false));
        assert_eq!(
            procs.iter().map(|p| p.uid).collect::<Vec<_>>(),
            vec![0, 501, 1000]
        );
    }

    #[test]
    fn sort_by_fd_count_smallest_first() {
        let mut procs = vec![p(1, 0, "a", 50), p(2, 0, "b", 3), p(3, 0, "c", 12)];
        sort_procs(&mut procs, &state(SORT_FDS, false));
        let fds: Vec<usize> = procs.iter().map(|p| p.files.len()).collect();
        assert_eq!(fds, vec![3, 12, 50]);
    }

    #[test]
    fn sort_by_fd_count_descending_via_reverse() {
        let mut procs = vec![p(1, 0, "a", 3), p(2, 0, "b", 12), p(3, 0, "c", 50)];
        sort_procs(&mut procs, &state(SORT_FDS, true));
        let fds: Vec<usize> = procs.iter().map(|p| p.files.len()).collect();
        assert_eq!(fds, vec![50, 12, 3]);
    }

    #[test]
    fn unknown_sort_mode_falls_back_to_pid() {
        // sort_mode is `% 4` in normal flow but the fn must defend
        // against out-of-range values — the wildcard arm uses pid.
        let mut procs = vec![p(300, 0, "c", 0), p(100, 0, "a", 0), p(200, 0, "b", 0)];
        sort_procs(&mut procs, &state(99, false));
        assert_eq!(
            procs.iter().map(|p| p.pid).collect::<Vec<_>>(),
            vec![100, 200, 300]
        );
    }

    #[test]
    fn empty_input_handled() {
        let mut procs: Vec<Process> = Vec::new();
        sort_procs(&mut procs, &state(SORT_PID, false));
        assert!(procs.is_empty());
    }

    #[test]
    fn single_element_already_sorted() {
        let mut procs = vec![p(42, 0, "x", 0)];
        sort_procs(&mut procs, &state(SORT_PID, false));
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].pid, 42);
    }
}
