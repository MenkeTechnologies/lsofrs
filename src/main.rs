#![allow(dead_code)]

mod cli;
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

use clap::Parser;

use cli::Args;
use filter::Filter;
use output::Theme;
use theme::{LsofTheme, ThemeName};

fn main() {
    let args = Args::parse();

    if args.help {
        Args::print_help();
        return;
    }

    let is_tty = io::stdout().is_terminal();
    let theme = Theme::new(is_tty);
    let tui_theme = LsofTheme::from_name(ThemeName::from_str_loose(&args.theme_name));
    let filter = Filter::from_args(&args);
    let interval = args.repeat.unwrap_or(1);

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

    output::print_processes(&procs, &theme, args.show_pgid, args.show_ppid, None);
}

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

            match delta_fn {
                Some(f) => {
                    output::print_processes(&procs, theme, args.show_pgid, args.show_ppid, Some(&f))
                }
                None => {
                    output::print_processes(&procs, theme, args.show_pgid, args.show_ppid, None)
                }
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
