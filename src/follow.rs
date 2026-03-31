//! Follow mode — watch a single process's FDs in real-time

use std::collections::HashMap;
use std::io::{self, Write};
use std::time::Duration;

use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, ClearType},
};

use crate::darwin;
use crate::output::Theme;
const STATUS_EXISTING: u8 = 0;
const STATUS_NEW: u8 = 1;
const STATUS_GONE: u8 = 2;

struct FollowEntry {
    fd: String,
    file_type: String,
    name: String,
    seen: bool,
    status: u8,
}

pub fn run_follow(target_pid: i32, interval: u64, theme: &Theme) {
    let mut table: HashMap<String, FollowEntry> = HashMap::new();
    let mut initialized = false;
    let _ = terminal::enable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, terminal::EnterAlternateScreen, cursor::Hide);

    loop {
        // Gather process info
        let procs = darwin::gather_processes();
        let target = procs.iter().find(|p| p.pid == target_pid);

        // Mark all as unseen
        for entry in table.values_mut() {
            entry.seen = false;
        }

        let mut new_count = 0usize;
        let mut gone_count = 0usize;

        if let Some(proc) = target {
            for f in &proc.files {
                let key = format!("{}:{}", f.fd.as_display(), f.name);
                let fd_str = f.fd.with_access(f.access);
                let type_str = f.file_type.as_str().to_string();

                if let Some(entry) = table.get_mut(&key) {
                    entry.seen = true;
                    if entry.status == STATUS_GONE {
                        // Resurrected
                        entry.status = STATUS_NEW;
                        new_count += 1;
                    }
                } else {
                    let status = if initialized { STATUS_NEW } else { STATUS_EXISTING };
                    if status == STATUS_NEW {
                        new_count += 1;
                    }
                    table.insert(
                        key,
                        FollowEntry {
                            fd: fd_str,
                            file_type: type_str,
                            name: f.name.clone(),
                            seen: true,
                            status,
                        },
                    );
                }
            }
        }

        // Mark unseen as gone
        for entry in table.values_mut() {
            if !entry.seen && entry.status != STATUS_GONE {
                entry.status = STATUS_GONE;
                gone_count += 1;
            }
        }

        initialized = true;

        // Render
        let _ = execute!(stdout, cursor::MoveTo(0, 0), terminal::Clear(ClearType::All));

        let now = chrono::Local::now().format("%H:%M:%S");
        let total = table.values().filter(|e| e.status != STATUS_GONE).count();

        let _ = write!(
            stdout,
            "{bold}lsofrs follow{reset} PID {mag}{target_pid}{reset} | {cyan}{now}{reset} | FDs:{yellow}{total}{reset}",
            bold = theme.bold(), reset = theme.reset(),
            mag = theme.magenta(), cyan = theme.cyan(), yellow = theme.yellow(),
        );
        if new_count > 0 {
            let _ = write!(stdout, " {green}+{new_count}{reset}", green = theme.green(), reset = theme.reset());
        }
        if gone_count > 0 {
            let _ = write!(stdout, " {red}-{gone_count}{reset}", red = theme.red(), reset = theme.reset());
        }
        let _ = writeln!(stdout, "\r");

        if target.is_none() {
            let _ = writeln!(stdout, "\r\n{red}Process {target_pid} not found{reset}\r", red = theme.red(), reset = theme.reset());
        }

        // Sort entries: new first, gone last, then by fd
        let mut entries: Vec<&FollowEntry> = table.values().collect();
        entries.sort_by(|a, b| {
            a.status.cmp(&b.status).then(a.fd.cmp(&b.fd))
        });

        let (_, rows) = terminal::size().unwrap_or((80, 24));
        let max_rows = (rows as usize).saturating_sub(3);

        for (i, entry) in entries.iter().enumerate() {
            if i >= max_rows {
                break;
            }

            let (mark, color) = match entry.status {
                STATUS_NEW => ("+NEW", theme.green()),
                STATUS_GONE => ("-DEL", theme.red()),
                _ => ("    ", theme.dim()),
            };

            let _ = writeln!(
                stdout,
                "{color}{mark} {:<6} {:<5} {}{reset}\r",
                entry.fd,
                entry.file_type,
                entry.name,
                color = color,
                reset = theme.reset(),
            );
        }

        // Purge gone entries after display and reset new to existing
        table.retain(|_, e| e.status != STATUS_GONE);
        for entry in table.values_mut() {
            if entry.status == STATUS_NEW {
                entry.status = STATUS_EXISTING;
            }
        }

        // Wait with input handling
        if event::poll(Duration::from_secs(interval)).unwrap_or(false) {
            if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = event::read() {
                match code {
                    KeyCode::Char('q') | KeyCode::Char('Q') => break,
                    KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => break,
                    _ => {}
                }
            }
        }
    }

    let _ = execute!(stdout, cursor::Show, terminal::LeaveAlternateScreen);
    let _ = terminal::disable_raw_mode();
}
