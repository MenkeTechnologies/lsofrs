#![allow(dead_code)]

mod cli;
#[cfg(target_os = "macos")]
mod darwin;
mod delta;
mod filter;
mod follow;
mod json;
mod leak;
mod monitor;
mod output;
mod summary;
mod top;
mod tree;
mod types;
mod watch;

use std::io::{self, IsTerminal};
use std::thread;
use std::time::Duration;

use clap::Parser;

use cli::Args;
use filter::Filter;
use output::Theme;

fn main() {
    let args = Args::parse();

    if args.help {
        Args::print_help();
        return;
    }

    let is_tty = io::stdout().is_terminal();
    let theme = Theme::new(is_tty);
    let filter = Filter::from_args(&args);
    let interval = args.repeat.unwrap_or(1);

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
        top::run_top(&filter, interval, &theme, n);
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

    // Repeat mode (with optional delta)
    if args.repeat.is_some() {
        run_repeat(&args, &filter, &theme, interval);
        return;
    }

    // Single-shot modes
    let procs = gather_and_filter(&filter);

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
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("lsofrs: only macOS is currently supported");
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
