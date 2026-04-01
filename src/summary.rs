//! Aggregate FD summary/statistics mode

use std::collections::HashMap;
use std::io::{self, Write};

use crate::output::Theme;
use crate::types::*;

const TOP_N: usize = 10;
const BAR_MAX: usize = 20;

struct TypeStats {
    type_name: String,
    count: usize,
}

struct ProcStats {
    pid: i32,
    command: String,
    uid: u32,
    fd_count: usize,
}

struct UserStats {
    uid: u32,
    username: String,
    proc_count: usize,
    file_count: usize,
}

pub fn print_summary(procs: &[Process], theme: &Theme, json_output: bool) {
    let mut type_map: HashMap<String, usize> = HashMap::new();
    let mut user_map: HashMap<u32, (String, usize, usize)> = HashMap::new();
    let mut proc_stats: Vec<ProcStats> = Vec::new();
    let mut total_files = 0usize;

    for p in procs {
        let fd_count = p.files.len();
        total_files += fd_count;

        // Type breakdown
        for f in &p.files {
            *type_map
                .entry(f.file_type.as_str().to_string())
                .or_insert(0) += 1;
        }

        // Per-user stats
        let entry = user_map
            .entry(p.uid)
            .or_insert_with(|| (p.username(), 0, 0));
        entry.1 += 1; // proc_count
        entry.2 += fd_count; // file_count

        // Proc stats
        proc_stats.push(ProcStats {
            pid: p.pid,
            command: p.command.clone(),
            uid: p.uid,
            fd_count,
        });
    }

    // Sort procs by fd_count descending
    proc_stats.sort_by(|a, b| b.fd_count.cmp(&a.fd_count).then(a.pid.cmp(&b.pid)));

    // Sort types by count descending
    let mut type_stats: Vec<TypeStats> = type_map
        .into_iter()
        .map(|(type_name, count)| TypeStats { type_name, count })
        .collect();
    type_stats.sort_by(|a, b| b.count.cmp(&a.count).then(a.type_name.cmp(&b.type_name)));

    // Sort users by file_count descending
    let mut user_stats: Vec<UserStats> = user_map
        .into_iter()
        .map(|(uid, (username, proc_count, file_count))| UserStats {
            uid,
            username,
            proc_count,
            file_count,
        })
        .collect();
    user_stats.sort_by(|a, b| b.file_count.cmp(&a.file_count).then(a.uid.cmp(&b.uid)));

    if json_output {
        print_summary_json(
            procs.len(),
            total_files,
            &type_stats,
            &proc_stats,
            &user_stats,
        );
    } else {
        print_summary_text(
            procs.len(),
            total_files,
            &type_stats,
            &proc_stats,
            &user_stats,
            theme,
        );
    }
}

fn print_summary_text(
    total_procs: usize,
    total_files: usize,
    types: &[TypeStats],
    procs: &[ProcStats],
    users: &[UserStats],
    theme: &Theme,
) {
    let out = io::stdout();
    let mut out = out.lock();

    // Header
    let _ = writeln!(
        out,
        "\n{bold}═══ lsofrs summary ═══{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );
    let _ = writeln!(
        out,
        "  {cyan}Processes:{reset} {:<10}  {yellow}Open files:{reset} {}",
        fmt_num(total_procs),
        fmt_num(total_files),
        cyan = theme.cyan(),
        yellow = theme.yellow(),
        reset = theme.reset(),
    );

    // Type breakdown
    let _ = writeln!(
        out,
        "\n{bold}── File type breakdown ──{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );

    let max_count = types.first().map(|t| t.count).unwrap_or(1);
    for (i, ts) in types.iter().enumerate() {
        if i >= 15 {
            let other: usize = types[i..].iter().map(|t| t.count).sum();
            let pct = if total_files > 0 {
                other as f64 / total_files as f64 * 100.0
            } else {
                0.0
            };
            let bar_len = (other as f64 / max_count as f64 * BAR_MAX as f64) as usize;
            let bar: String = "█".repeat(bar_len);
            let _ = writeln!(
                out,
                "  {dim}(other){reset}  {:>8}  {:>5.1}%  {green}{bar}{reset}",
                fmt_num(other),
                pct,
                dim = theme.dim(),
                green = theme.green(),
                reset = theme.reset(),
            );
            break;
        }
        let pct = if total_files > 0 {
            ts.count as f64 / total_files as f64 * 100.0
        } else {
            0.0
        };
        let bar_len = (ts.count as f64 / max_count as f64 * BAR_MAX as f64) as usize;
        let bar: String = "█".repeat(bar_len);
        let _ = writeln!(
            out,
            "  {blue}{:<6}{reset}  {:>8}  {:>5.1}%  {green}{bar}{reset}",
            ts.type_name,
            fmt_num(ts.count),
            pct,
            blue = theme.blue(),
            green = theme.green(),
            reset = theme.reset(),
        );
    }

    // Top processes
    let _ = writeln!(
        out,
        "\n{bold}── Top {TOP_N} processes by FD count ──{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );
    let _ = writeln!(
        out,
        "  {hdr}{bold}{:>7}  {:<15}  {:<8}  {:>8}{reset}",
        "PID",
        "COMMAND",
        "USER",
        "FDs",
        hdr = theme.hdr_bg(),
        bold = theme.bold(),
        reset = theme.reset(),
    );
    for ps in procs.iter().take(TOP_N) {
        let username = users::get_user_by_uid(ps.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| ps.uid.to_string());
        let cmd = if ps.command.len() > 15 {
            &ps.command[..15]
        } else {
            &ps.command
        };
        let _ = writeln!(
            out,
            "  {mag}{:>7}{reset}  {cyan}{:<15}{reset}  {yellow}{:<8}{reset}  {:>8}",
            ps.pid,
            cmd,
            if username.len() > 8 {
                &username[..8]
            } else {
                &username
            },
            fmt_num(ps.fd_count),
            mag = theme.magenta(),
            cyan = theme.cyan(),
            yellow = theme.yellow(),
            reset = theme.reset(),
        );
    }

    // Per-user totals
    let _ = writeln!(
        out,
        "\n{bold}── Per-user totals ──{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );
    let _ = writeln!(
        out,
        "  {hdr}{bold}{:<10}  {:>8}  {:>8}{reset}",
        "USER",
        "PROCS",
        "FILES",
        hdr = theme.hdr_bg(),
        bold = theme.bold(),
        reset = theme.reset(),
    );
    for us in users.iter().take(20) {
        let uname = if us.username.len() > 10 {
            &us.username[..10]
        } else {
            &us.username
        };
        let _ = writeln!(
            out,
            "  {yellow}{:<10}{reset}  {:>8}  {:>8}",
            uname,
            fmt_num(us.proc_count),
            fmt_num(us.file_count),
            yellow = theme.yellow(),
            reset = theme.reset(),
        );
    }

    let _ = writeln!(out);
}

fn print_summary_json(
    total_procs: usize,
    total_files: usize,
    types: &[TypeStats],
    procs: &[ProcStats],
    users: &[UserStats],
) {
    let out = io::stdout();
    let mut out = out.lock();

    let types_obj: serde_json::Value = types
        .iter()
        .map(|t| (t.type_name.clone(), serde_json::json!(t.count)))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    let top_procs: Vec<serde_json::Value> = procs
        .iter()
        .take(TOP_N)
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "command": p.command,
                "uid": p.uid,
                "fd_count": p.fd_count,
            })
        })
        .collect();

    let users_arr: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            serde_json::json!({
                "uid": u.uid,
                "username": u.username,
                "proc_count": u.proc_count,
                "file_count": u.file_count,
            })
        })
        .collect();

    let summary = serde_json::json!({
        "summary": {
            "total_files": total_files,
            "total_processes": total_procs,
            "types": types_obj,
            "top_processes": top_procs,
            "users": users_arr,
        }
    });

    let _ = serde_json::to_writer_pretty(&mut out, &summary);
    let _ = writeln!(out);
}

fn fmt_num(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, uid: u32, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: pid,
            uid,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_file(ft: FileType) -> OpenFile {
        OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: ft,
            name: "/tmp/x".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn print_summary_empty() {
        let theme = Theme::new(false);
        print_summary(&[], &theme, false);
    }

    #[test]
    fn print_summary_json_empty() {
        let theme = Theme::new(false);
        print_summary(&[], &theme, true);
    }

    #[test]
    fn print_summary_with_data() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(
                1,
                "init",
                0,
                vec![make_file(FileType::Reg), make_file(FileType::Dir)],
            ),
            make_proc(
                2,
                "bash",
                501,
                vec![make_file(FileType::Reg), make_file(FileType::Pipe)],
            ),
        ];
        print_summary(&procs, &theme, false);
    }

    #[test]
    fn print_summary_json_with_data() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(1, "init", 0, vec![make_file(FileType::IPv4)]),
            make_proc(
                2,
                "nginx",
                33,
                vec![make_file(FileType::IPv4), make_file(FileType::IPv4)],
            ),
        ];
        print_summary(&procs, &theme, true);
    }

    #[test]
    fn fmt_num_small() {
        assert_eq!(fmt_num(0), "0");
        assert_eq!(fmt_num(42), "42");
        assert_eq!(fmt_num(999), "999");
    }

    #[test]
    fn fmt_num_thousands() {
        assert_eq!(fmt_num(1000), "1,000");
        assert_eq!(fmt_num(12345), "12,345");
        assert_eq!(fmt_num(1234567), "1,234,567");
    }
}
