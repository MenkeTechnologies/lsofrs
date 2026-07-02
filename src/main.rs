//! `lsofrs` / `lsf` binary entry point — dispatches the CLI through `cli::run()`.
#![allow(dead_code)]

mod cli;
mod config;
mod csv_out;
#[cfg(target_os = "macos")]
mod darwin;
mod delta;
mod filter;
mod follow;
#[cfg(target_os = "freebsd")]
mod freebsd;
mod json;
mod leak;
#[cfg(target_os = "linux")]
mod linux;
mod monitor;
mod net_map;
mod output;
mod pipe_chain;
mod ports;
mod stale;
mod strutil;
mod summary;
mod theme;
mod top;
mod tree;
mod tui_app;
mod tui_tabs;
mod types;
mod watch;

use std::io::{self, IsTerminal};
use std::thread;
use std::time::Duration;

use cli::Args;
use filter::Filter;
use output::Theme;
use theme::{LsofTheme, ThemeName};

fn main() {
    let args = Args::parse_from(std::env::args_os());

    if args.help {
        Args::print_help();
        return;
    }

    if args.version {
        println!("lsofrs {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let is_tty = match args.color.as_str() {
        "always" => true,
        "never" => false,
        _ => io::stdout().is_terminal(), // "auto"
    };
    let theme = Theme::new(is_tty);

    // Load saved preferences; CLI flags override saved values
    let prefs = config::load();
    let theme_name = if args.theme_name != "neon-sprawl" {
        // User explicitly passed --theme on CLI
        args.theme_name.clone()
    } else if let Some(ref saved) = prefs.theme {
        saved.clone()
    } else {
        args.theme_name.clone()
    };
    let tui_theme = LsofTheme::from_name(ThemeName::from_str_loose(&theme_name));
    let filter = Filter::from_args(&args);
    let disp = output::DisplayOpts::from_args(&args);
    let interval = args
        .repeat
        .unwrap_or_else(|| prefs.refresh_rate.unwrap_or(1));

    // Unified TUI mode
    if args.tui {
        tui_tabs::run_tui_tabs(&filter, interval, &tui_theme);
        return;
    }

    // Watch mode
    if let Some(ref path) = args.watch {
        watch::run_watch(path, interval, &theme);
        return;
    }

    // Follow mode
    if let Some(pid) = args.follow {
        follow::run_follow(pid, interval, &theme);
        return;
    }

    // Top mode
    if let Some(ref top_n) = args.top {
        let n = top_n.unwrap_or(20);
        top::run_top(&filter, interval, &tui_theme, n);
        return;
    }

    // Monitor mode
    if args.monitor {
        monitor::run_monitor(&filter, interval, &theme, args.show_pgid, args.show_ppid);
        return;
    }

    // Leak detection mode
    if let Some((leak_interval, threshold)) = args.leak_detect_params() {
        run_leak_detect(&filter, leak_interval, threshold, &theme);
        return;
    }

    // Summary live mode (--summary with -r)
    if args.summary && args.repeat.is_some() {
        summary::run_summary_live(&filter, interval, &tui_theme);
        return;
    }

    // Repeat mode (with optional delta)
    if args.repeat.is_some() {
        run_repeat(&args, &filter, &theme, interval);
        return;
    }

    // Single-shot modes
    let procs = gather_and_filter(&filter);

    if args.stale {
        stale::print_stale(&procs, &theme, args.json);
        return;
    }
    if args.ports {
        ports::print_ports(&procs, &theme, args.json);
        return;
    }
    if args.pipe_chain {
        pipe_chain::print_pipe_chain(&procs, &theme, args.json);
        return;
    }
    if args.csv_output {
        csv_out::print_csv(&procs);
        return;
    }
    if args.net_map {
        net_map::print_net_map(&procs, &theme, args.json);
        return;
    }

    if args.tree {
        tree::print_tree(&procs, &theme, args.json);
        return;
    }

    if args.summary {
        summary::print_summary(&procs, &theme, args.json);
        return;
    }

    if args.json {
        json::print_json(&procs);
        return;
    }

    if args.terse {
        output::print_terse(&procs);
        return;
    }

    if let Some(ref fields) = args.field_output {
        let term = if args.nul_terminator { '\0' } else { '\n' };
        output::print_field_output(&procs, fields, term);
        return;
    }

    if args.report_unfound {
        report_unfound(&args, &procs, &theme);
    }

    output::print_processes(&procs, &theme, args.show_pgid, args.show_ppid, &disp, None);
}
/// `gather_processes` — see implementation.
pub fn gather_processes() -> Vec<types::Process> {
    #[cfg(target_os = "macos")]
    {
        darwin::gather_processes()
    }
    #[cfg(target_os = "linux")]
    {
        linux::gather_processes()
    }
    #[cfg(target_os = "freebsd")]
    {
        freebsd::gather_processes()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        eprintln!("lsofrs: unsupported platform (macOS, Linux, and FreeBSD are supported)");
        Vec::new()
    }
}

/// lsof `-V`: report the positive search specifications (`-p`, `-c`, `-u`, and
/// named files) that matched nothing in the (already-filtered) result set.
/// Written to stderr, one line per unmatched spec, in lsof's terse style.
fn report_unfound(args: &Args, procs: &[types::Process], theme: &Theme) {
    for m in unfound_specs(args, procs) {
        eprintln!("{}lsofrs: {m}{}", theme.red(), theme.reset());
    }
}

/// Pure core of [`report_unfound`]: build the list of "no ... found" messages
/// for every positive search spec that matched nothing. Exclusions (`^`) and
/// regex command specs (`/.../`) are skipped.
fn unfound_specs(args: &Args, procs: &[types::Process]) -> Vec<String> {
    let mut msgs: Vec<String> = Vec::new();

    if let Some(ref pids) = args.pid {
        for spec in pids.split(',').map(str::trim) {
            if spec.starts_with('^') || spec.is_empty() {
                continue;
            }
            if let Ok(pid) = spec.parse::<i32>()
                && !procs.iter().any(|p| p.pid == pid)
            {
                msgs.push(format!("no PID found: {spec}"));
            }
        }
    }

    if let Some(ref cmds) = args.command {
        for spec in cmds.split(',').map(str::trim) {
            if spec.starts_with('^') || spec.is_empty() || spec.starts_with('/') {
                continue; // skip exclusions and regexes
            }
            if !procs.iter().any(|p| p.command.starts_with(spec)) {
                msgs.push(format!("no command found: {spec}"));
            }
        }
    }

    if let Some(ref users) = args.user {
        for spec in users.split(',').map(str::trim) {
            if spec.starts_with('^') || spec.is_empty() {
                continue;
            }
            let found = if let Ok(uid) = spec.parse::<u32>() {
                procs.iter().any(|p| p.uid == uid)
            } else {
                procs.iter().any(|p| p.username() == spec)
            };
            if !found {
                msgs.push(format!("no user found: {spec}"));
            }
        }
    }

    for path in &args.files {
        let matched = procs
            .iter()
            .flat_map(|p| &p.files)
            .any(|f| f.name == *path || f.name.starts_with(&format!("{path}/")));
        if !matched {
            msgs.push(format!("no file found: {path}"));
        }
    }

    msgs
}

fn gather_and_filter(filter: &Filter) -> Vec<types::Process> {
    let mut procs = gather_processes();

    procs.retain(|p| filter.matches_process(p));
    for p in &mut procs {
        p.files.retain(|f| filter.matches_file(f));
    }

    if !filter.terse {
        procs.retain(|p| !p.files.is_empty());
    }

    // Sort by PID
    procs.sort_by_key(|p| p.pid);

    procs
}

fn run_repeat(args: &Args, filter: &Filter, theme: &Theme, interval: u64) {
    let mut delta_tracker = if args.delta {
        Some(delta::DeltaTracker::new())
    } else {
        None
    };

    loop {
        if let Some(ref mut dt) = delta_tracker {
            dt.begin_iteration();
        }

        let procs = gather_and_filter(filter);

        // Record delta
        if let Some(ref mut dt) = delta_tracker {
            for p in &procs {
                dt.record(p);
            }
            dt.count_gone();
        }

        // Output
        if args.json {
            json::print_json(&procs);
        } else if args.terse {
            output::print_terse(&procs);
        } else if args.summary {
            summary::print_summary(&procs, theme, false);
        } else {
            let delta_fn = delta_tracker.as_ref().map(|dt| {
                move |pid: i32, fd: &str, name: &str| -> types::DeltaStatus {
                    dt.classify(pid, fd, name)
                }
            });

            let disp = output::DisplayOpts::from_args(args);
            match delta_fn {
                Some(f) => output::print_processes(
                    &procs,
                    theme,
                    args.show_pgid,
                    args.show_ppid,
                    &disp,
                    Some(&f),
                ),
                None => output::print_processes(
                    &procs,
                    theme,
                    args.show_pgid,
                    args.show_ppid,
                    &disp,
                    None,
                ),
            }

            // Print gone entries
            if let Some(ref dt) = delta_tracker {
                dt.print_gone(theme);
                dt.print_summary(theme);
            }
        }

        println!("========");
        thread::sleep(Duration::from_secs(interval));
    }
}

fn run_leak_detect(filter: &Filter, interval: u64, threshold: usize, theme: &Theme) {
    let mut detector = leak::LeakDetector::new(threshold);

    loop {
        let procs = gather_and_filter(filter);
        detector.update(&procs);
        detector.report(theme);

        thread::sleep(Duration::from_secs(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{OpenFile, Process};

    fn proc_with(pid: i32, uid: u32, cmd: &str, file: &str) -> Process {
        let f = OpenFile {
            name: file.to_string(),
            ..Default::default()
        };
        Process::new(pid, 1, pid, uid, cmd.to_string(), vec![f])
    }

    #[test]
    fn unfound_reports_missing_pid_only() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        let args = Args::parse_from(["lsofrs", "-V", "-p", "100,999"]);
        assert_eq!(unfound_specs(&args, &procs), vec!["no PID found: 999"]);
    }

    #[test]
    fn unfound_skips_excluded_pid_spec() {
        // `^100` is an exclusion, never reported even though no proc "matches" it.
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        let args = Args::parse_from(["lsofrs", "-V", "-p", "^100"]);
        assert!(unfound_specs(&args, &procs).is_empty());
    }

    #[test]
    fn unfound_command_prefix_match_counts_as_found() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        // "ba" is a prefix of "bash" -> found; "ghost" -> unfound.
        let args = Args::parse_from(["lsofrs", "-V", "-c", "ba,ghost"]);
        assert_eq!(unfound_specs(&args, &procs), vec!["no command found: ghost"]);
    }

    #[test]
    fn unfound_command_regex_spec_is_skipped() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        let args = Args::parse_from(["lsofrs", "-V", "-c", "/nomatch/"]);
        assert!(unfound_specs(&args, &procs).is_empty());
    }

    #[test]
    fn unfound_numeric_user_spec() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        let args = Args::parse_from(["lsofrs", "-V", "-u", "501,4242"]);
        assert_eq!(unfound_specs(&args, &procs), vec!["no user found: 4242"]);
    }

    #[test]
    fn unfound_file_exact_and_prefix() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        // "/tmp" matches "/tmp/x" as a directory prefix -> found; "/no/such" -> unfound.
        let args = Args::parse_from(["lsofrs", "-V", "/tmp", "/no/such"]);
        assert_eq!(unfound_specs(&args, &procs), vec!["no file found: /no/such"]);
    }

    #[test]
    fn unfound_empty_when_all_specs_match() {
        let procs = vec![proc_with(100, 501, "bash", "/tmp/x")];
        let args = Args::parse_from(["lsofrs", "-V", "-p", "100", "-c", "bash", "-u", "501"]);
        assert!(unfound_specs(&args, &procs).is_empty());
    }
}
