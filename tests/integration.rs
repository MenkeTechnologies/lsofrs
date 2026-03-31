//! Integration tests — exercise the lsofrs binary end-to-end

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

// ── Help & version ──────────────────────────────────────────────────

#[test]
fn help_flag_short() {
    let out = lsofrs().arg("-h").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FILE DESCRIPTOR SCANNER"));
    assert!(stdout.contains("USAGE:"));
    assert!(stdout.contains("SELECTION"));
    assert!(stdout.contains("NETWORK"));
    assert!(stdout.contains("EXAMPLES"));
}

#[test]
fn help_flag_long() {
    let out = lsofrs().arg("--help").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FILE DESCRIPTOR SCANNER"));
}

#[test]
fn version_flag() {
    let out = lsofrs().arg("-V").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1.0.0"));
}

// ── Basic output ────────────────────────────────────────────────────

#[test]
fn default_run_produces_output() {
    let out = lsofrs().output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should have a header line
    assert!(stdout.contains("COMMAND"));
    assert!(stdout.contains("PID"));
    assert!(stdout.contains("USER"));
    assert!(stdout.contains("FD"));
    assert!(stdout.contains("TYPE"));
    assert!(stdout.contains("NAME"));
}

#[test]
fn default_run_has_processes() {
    let out = lsofrs().output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // Header + at least a few processes
    assert!(lines.len() > 5, "expected output lines, got {}", lines.len());
}

// ── PID filter ──────────────────────────────────────────────────────

#[test]
fn pid_filter_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Every non-header line should contain our PID
    for line in stdout.lines().skip(1) {
        if line.trim().is_empty() { continue; }
        // Continuation lines (indented) are part of same process
        if !line.starts_with(' ') {
            assert!(line.contains(&my_pid), "line doesn't contain our pid: {line}");
        }
    }
}

#[test]
fn pid_filter_nonexistent() {
    let out = lsofrs().args(["-p", "9999999"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // Only header, no data
    assert!(lines.len() <= 1, "expected no data for nonexistent pid");
}

// ── Terse output ────────────────────────────────────────────────────

#[test]
fn terse_output_pids_only() {
    let out = lsofrs().arg("-t").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if line.trim().is_empty() { continue; }
        assert!(
            line.trim().parse::<i32>().is_ok(),
            "terse line should be a PID: '{line}'"
        );
    }
}

#[test]
fn terse_with_pid_filter() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-t", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let pids: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(!pids.is_empty());
    assert!(pids.contains(&my_pid.as_str()));
}

// ── JSON output ─────────────────────────────────────────────────────

#[test]
fn json_output_valid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .expect("JSON output should be valid JSON");
    assert!(parsed.is_array());
}

#[test]
fn json_output_has_fields() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    assert!(!parsed.is_empty());
    let proc = &parsed[0];
    assert!(proc.get("command").is_some());
    assert!(proc.get("pid").is_some());
    assert!(proc.get("uid").is_some());
    assert!(proc.get("files").is_some());
    assert_eq!(proc["pid"].as_i64().unwrap(), std::process::id() as i64);
}

#[test]
fn json_files_have_fd_and_name() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    let files = parsed[0]["files"].as_array().unwrap();
    assert!(!files.is_empty());
    for f in files {
        assert!(f.get("fd").is_some(), "file missing fd field");
        assert!(f.get("name").is_some(), "file missing name field");
        assert!(f.get("type").is_some(), "file missing type field");
    }
}

// ── Field output ────────────────────────────────────────────────────

#[test]
fn field_output_pid_and_name() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "pn", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should have p<pid> lines and n<name> lines
    assert!(stdout.contains(&format!("p{my_pid}")));
    assert!(stdout.lines().any(|l| l.starts_with('n')));
}

#[test]
fn field_output_nul_terminator() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "p", "-0", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = &out.stdout;
    // Should contain NUL bytes
    assert!(stdout.contains(&0u8), "NUL terminator should be present");
}

// ── Command filter ──────────────────────────────────────────────────

#[test]
fn command_filter_prefix() {
    // Use our own binary name — always accessible without root
    let out = lsofrs().args(["-c", "lsofrs"]).output().unwrap();
    assert!(out.status.success());
    // Should run without error; may or may not find results depending on timing
}

// ── Network filter (basic, no sudo) ─────────────────────────────────

#[test]
fn inet_flag_no_crash() {
    let out = lsofrs().arg("-i").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_tcp_no_crash() {
    let out = lsofrs().args(["-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_udp_no_crash() {
    let out = lsofrs().args(["-i", "UDP"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_port_no_crash() {
    let out = lsofrs().args(["-i", ":443"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_4_no_crash() {
    let out = lsofrs().args(["-i", "4"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_6_no_crash() {
    let out = lsofrs().args(["-i", "6"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_4tcp_no_crash() {
    let out = lsofrs().args(["-i", "4TCP"]).output().unwrap();
    assert!(out.status.success());
}

// ── Unix socket filter ──────────────────────────────────────────────

#[test]
fn unix_socket_flag_no_crash() {
    let out = lsofrs().arg("-U").output().unwrap();
    assert!(out.status.success());
}

// ── NFS filter ──────────────────────────────────────────────────────

#[test]
fn nfs_flag_no_crash() {
    let out = lsofrs().arg("-N").output().unwrap();
    assert!(out.status.success());
}

// ── Summary mode ────────────────────────────────────────────────────

#[test]
fn summary_mode() {
    let out = lsofrs().arg("--summary").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FD") || stdout.contains("summary") || stdout.contains("TYPE"));
}

#[test]
fn summary_json() {
    let out = lsofrs().args(["--summary", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .expect("summary --json should produce valid JSON");
    assert!(parsed.is_object() || parsed.is_array());
}

// ── FD filter ───────────────────────────────────────────────────────

#[test]
fn fd_filter_range() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-d", "0-2", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn fd_filter_cwd() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-d", "cwd", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    // cwd may not be visible without root; just verify no crash
}

// ── AND mode ────────────────────────────────────────────────────────

#[test]
fn and_mode_narrows_results() {
    let my_pid = std::process::id().to_string();
    // Without -a: OR mode
    let out_or = lsofrs().args(["-p", &my_pid, "-c", "nonexistent_cmd"]).output().unwrap();
    let count_or = String::from_utf8_lossy(&out_or.stdout).lines().count();
    // With -a: AND mode, both must match — "nonexistent_cmd" won't match our process
    let out_and = lsofrs().args(["-a", "-p", &my_pid, "-c", "nonexistent_cmd"]).output().unwrap();
    let count_and = String::from_utf8_lossy(&out_and.stdout).lines().count();
    assert!(count_and < count_or, "AND mode should produce fewer results");
}

// ── PGID / PPID display ────────────────────────────────────────────

#[test]
fn pgid_show_flag() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--pgid-show", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PGID") || stdout.contains("PG/ID"));
}

#[test]
fn ppid_show_flag() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-R", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PPID") || stdout.contains("P/PID"));
}

// ── Exclude filters ────────────────────────────────────────────────

#[test]
fn pid_exclude() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-p", &format!("^{my_pid}")]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Our PID should not appear in process lines
    for line in stdout.lines().skip(1) {
        if line.starts_with(' ') || line.trim().is_empty() { continue; }
        assert!(!line.contains(&format!(" {my_pid} ")),
            "excluded pid should not appear: {line}");
    }
}

// ── File argument ───────────────────────────────────────────────────

#[test]
fn file_arg_no_crash() {
    let out = lsofrs().arg("/dev/null").output().unwrap();
    assert!(out.status.success());
}

// ── Combination flags ───────────────────────────────────────────────

#[test]
fn combined_flags_no_crash() {
    let out = lsofrs().args(["-n", "-P", "-w"]).output().unwrap();
    assert!(out.status.success());
}

// ── Invalid args ────────────────────────────────────────────────────

#[test]
fn invalid_flag_exits_nonzero() {
    let out = lsofrs().arg("--nonexistent-flag-xyz").output().unwrap();
    assert!(!out.status.success());
}
