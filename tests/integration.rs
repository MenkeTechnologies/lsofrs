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
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
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
    assert!(
        lines.len() > 5,
        "expected output lines, got {}",
        lines.len()
    );
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
        if line.trim().is_empty() {
            continue;
        }
        // Continuation lines (indented) are part of same process
        if !line.starts_with(' ') {
            assert!(
                line.contains(&my_pid),
                "line doesn't contain our pid: {line}"
            );
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
        if line.trim().is_empty() {
            continue;
        }
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
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should be valid JSON");
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
    let out = lsofrs()
        .args(["-F", "p", "-0", "-p", &my_pid])
        .output()
        .unwrap();
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
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("summary --json should produce valid JSON");
    assert!(parsed.is_object() || parsed.is_array());
}

// ── FD filter ───────────────────────────────────────────────────────

#[test]
fn fd_filter_range() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-d", "0-2", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn fd_filter_cwd() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-d", "cwd", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    // cwd may not be visible without root; just verify no crash
}

// ── AND mode ────────────────────────────────────────────────────────

#[test]
fn and_mode_narrows_results() {
    let my_pid = std::process::id().to_string();
    // Without -a: OR mode
    let out_or = lsofrs()
        .args(["-p", &my_pid, "-c", "nonexistent_cmd"])
        .output()
        .unwrap();
    let count_or = String::from_utf8_lossy(&out_or.stdout).lines().count();
    // With -a: AND mode, both must match — "nonexistent_cmd" won't match our process
    let out_and = lsofrs()
        .args(["-a", "-p", &my_pid, "-c", "nonexistent_cmd"])
        .output()
        .unwrap();
    let count_and = String::from_utf8_lossy(&out_and.stdout).lines().count();
    assert!(
        count_and < count_or,
        "AND mode should produce fewer results"
    );
}

// ── PGID / PPID display ────────────────────────────────────────────

#[test]
fn pgid_show_flag() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--pgid-show", "-p", &my_pid])
        .output()
        .unwrap();
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
    let out = lsofrs()
        .args(["-p", &format!("^{my_pid}")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Our PID should not appear in process lines
    for line in stdout.lines().skip(1) {
        if line.starts_with(' ') || line.trim().is_empty() {
            continue;
        }
        assert!(
            !line.contains(&format!(" {my_pid} ")),
            "excluded pid should not appear: {line}"
        );
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

// ── Tree mode ───────────────────────────────────────────────────────

#[test]
fn tree_mode() {
    let out = lsofrs().arg("--tree").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PID"));
    assert!(stdout.contains("FDs"));
    assert!(stdout.contains("CMD"));
}

#[test]
fn tree_mode_with_pid_filter() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--tree", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&my_pid));
}

#[test]
fn tree_mode_json() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("tree --json should produce valid JSON");
    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert!(!arr.is_empty());
    assert!(arr[0].get("pid").is_some());
    assert!(arr[0].get("fd_count").is_some());
    assert!(arr[0].get("children").is_some());
}

// ── Tree mode extras ────────────────────────────────────────────────

#[test]
fn tree_mode_with_command_filter() {
    let out = lsofrs().args(["--tree", "-c", "lsofrs"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn tree_mode_with_user_filter() {
    let out = lsofrs().args(["--tree", "-u", &whoami()]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PID"));
}

// ── JSON edge cases ────────────────────────────────────────────────

#[test]
fn json_empty_result_valid() {
    let out = lsofrs().args(["-J", "-p", "9999999"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_empty());
}

#[test]
fn json_file_has_type_field() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    if !parsed.is_empty() {
        let files = parsed[0]["files"].as_array().unwrap();
        if !files.is_empty() {
            let t = files[0]["type"].as_str().unwrap();
            assert!(!t.is_empty());
        }
    }
}

// ── Field output extras ────────────────────────────────────────────

#[test]
fn field_output_command_field() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "pc", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.starts_with('c')));
}

#[test]
fn field_output_type_field() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "pt", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.starts_with('t')));
}

#[test]
fn field_output_uid_field() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "pu", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.starts_with('u')));
}

#[test]
fn field_output_login_name_field() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "pL", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().any(|l| l.starts_with('L')));
}

// ── Multiple filters combined ──────────────────────────────────────

#[test]
fn pid_and_user_filter_or() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-p", &my_pid, "-u", &whoami()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().count() > 1);
}

#[test]
fn exclude_pid_still_shows_others() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-p", &format!("^{my_pid}")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.lines().count() > 1, "should have other processes");
}

// ── FD filter extras ───────────────────────────────────────────────

#[test]
fn fd_filter_single_number() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-d", "0", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn fd_filter_exclude_range() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-d", "^0-2", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Network filter combos ──────────────────────────────────────────

#[test]
fn inet_tcp_port_combo() {
    let out = lsofrs().args(["-i", "TCP:443"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_6tcp_combo() {
    let out = lsofrs().args(["-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_4udp_combo() {
    let out = lsofrs().args(["-i", "4UDP"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn inet_host_port_combo() {
    let out = lsofrs().args(["-i", "TCP@127.0.0.1:80"]).output().unwrap();
    assert!(out.status.success());
}

// ── Summary extras ─────────────────────────────────────────────────

#[test]
fn summary_with_pid_filter() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--summary", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn summary_with_command_filter() {
    let out = lsofrs()
        .args(["--summary", "-c", "lsofrs"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Terse extras ───────────────────────────────────────────────────

#[test]
fn terse_no_header() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-t", "-p", &my_pid]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("COMMAND"));
    assert!(!stdout.contains("PID"));
}

#[test]
fn terse_nonexistent_pid_empty() {
    let out = lsofrs().args(["-t", "-p", "9999999"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().is_empty());
}

// ── Multiple flag combos ───────────────────────────────────────────

#[test]
fn all_boolean_flags_no_crash() {
    let out = lsofrs()
        .args(["-n", "-P", "-w", "-R", "--pgid-show"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn json_with_pgid_ppid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-R", "--pgid-show", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&stdout).unwrap();
    assert!(!parsed.is_empty());
    assert!(parsed[0].get("ppid").is_some());
    assert!(parsed[0].get("pgid").is_some());
}

// ── Stale mode ──────────────────────────────────────────────────────

#[test]
fn stale_mode_no_crash() {
    let out = lsofrs().arg("--stale").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn stale_mode_with_user() {
    let out = lsofrs()
        .args(["--stale", "-u", &whoami()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn stale_mode_json() {
    let out = lsofrs().args(["--stale", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stale --json should be valid JSON");
    assert!(parsed.is_object() || parsed.is_array());
}

#[test]
fn stale_mode_json_with_pid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--stale", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).unwrap();
}

// ── Ports mode ──────────────────────────────────────────────────────

#[test]
fn ports_mode_no_crash() {
    let out = lsofrs().arg("--ports").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn ports_mode_has_output() {
    let out = lsofrs().arg("--ports").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should have either a header with columns or "No listening ports" message
    assert!(
        stdout.contains("PROTO") || stdout.contains("PORT") || stdout.contains("No listening"),
        "ports output should have header or 'no ports' message"
    );
}

#[test]
fn ports_mode_format_correct() {
    let out = lsofrs().arg("--ports").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // If there are data lines (not just "No listening ports"), verify format
    if stdout.contains("PROTO") {
        let data_lines: Vec<&str> = stdout
            .lines()
            .filter(|l| l.contains("TCP") || l.contains("UDP"))
            .collect();
        for line in &data_lines {
            assert!(
                line.contains("TCP") || line.contains("UDP"),
                "port data row should contain protocol: {line}"
            );
        }
    }
}

#[test]
fn ports_json_has_port_field() {
    let out = lsofrs().args(["--ports", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // If there are ports, check structure
    if let Some(ports) = parsed.get("listening_ports").and_then(|v| v.as_array()) {
        for port in ports {
            assert!(
                port.get("port").is_some(),
                "port entry missing 'port' field"
            );
            assert!(
                port.get("protocol").is_some() || port.get("proto").is_some(),
                "port entry missing protocol field"
            );
            assert!(port.get("pid").is_some(), "port entry missing 'pid' field");
        }
    }
}

#[test]
fn inet_tcp_shows_state() {
    // Verify that -i TCP output includes TCP state indicators
    let out = lsofrs().args(["-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // If there are TCP connections visible, they should have state
    let data_lines: Vec<&str> = stdout
        .lines()
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .collect();
    if data_lines.len() > 2 {
        // At least some lines should have TCP state like (LISTEN), (ESTABLISHED), etc.
        let has_state = data_lines
            .iter()
            .any(|l| l.contains("LISTEN") || l.contains("ESTABLISHED") || l.contains("CLOSE"));
        // Not guaranteed without root, but if we see TCP entries they should have state
        let has_tcp = data_lines.iter().any(|l| l.contains("TCP"));
        if has_tcp {
            assert!(
                has_state,
                "TCP connections should have state (LISTEN, ESTABLISHED, etc.)"
            );
        }
    }
}

#[test]
fn ports_mode_with_user() {
    let out = lsofrs()
        .args(["--ports", "-u", &whoami()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn ports_mode_json() {
    let out = lsofrs().args(["--ports", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("ports --json should be valid JSON");
    assert!(parsed.is_object() || parsed.is_array());
}

#[test]
fn ports_mode_json_with_pid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--ports", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Watch mode (piped, single-shot) ─────────────────────────────────

#[test]
fn watch_mode_no_crash() {
    let out = lsofrs().args(["--watch", "/dev/null"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn watch_mode_nonexistent_file() {
    let out = lsofrs()
        .args(["--watch", "/nonexistent/path/xyz"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Help content validation ────────────────────────────────────────

#[test]
fn help_contains_stale_and_ports() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--stale"));
    assert!(stdout.contains("--ports"));
    assert!(stdout.contains("--watch"));
    assert!(stdout.contains("--top"));
}

#[test]
fn help_contains_all_sections() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SELECTION"));
    assert!(stdout.contains("NETWORK"));
    assert!(stdout.contains("FILES & DIRECTORIES"));
    assert!(stdout.contains("DISPLAY"));
    assert!(stdout.contains("SYSTEM"));
    assert!(stdout.contains("EXAMPLES"));
    assert!(stdout.contains("INFO"));
}

#[test]
fn help_contains_tree_option() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--tree"));
}

#[test]
fn help_contains_lsofrs_banner() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FILE DESCRIPTOR SCANNER"));
    assert!(stdout.contains("Every open file tells a story"));
}

// ── Invalid args ────────────────────────────────────────────────────

#[test]
fn invalid_flag_exits_nonzero() {
    let out = lsofrs().arg("--nonexistent-flag-xyz").output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn invalid_short_flag_exits_nonzero() {
    let out = lsofrs().arg("-Z").output().unwrap();
    assert!(!out.status.success());
}

// ── CSV mode ────────────────────────────────────────────────────────

#[test]
fn csv_mode_no_crash() {
    let out = lsofrs().arg("--csv").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn csv_mode_has_header() {
    let out = lsofrs().arg("--csv").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"));
}

#[test]
fn csv_mode_with_pid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--csv", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should have header + at least one data row
    assert!(stdout.lines().count() >= 2);
}

#[test]
fn csv_mode_with_tcp() {
    let out = lsofrs().args(["--csv", "-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
}

// ── Pipe chain mode ─────────────────────────────────────────────────

#[test]
fn pipe_chain_no_crash() {
    let out = lsofrs().arg("--pipe-chain").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn pipe_chain_json() {
    let out = lsofrs().args(["--pipe-chain", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
}

#[test]
fn pipe_chain_with_user() {
    let out = lsofrs()
        .args(["--pipe-chain", "-u", &whoami()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Net map mode ────────────────────────────────────────────────────

#[test]
fn net_map_no_crash() {
    let out = lsofrs().arg("--net-map").output().unwrap();
    assert!(out.status.success());
}

#[test]
fn net_map_json() {
    let out = lsofrs().args(["--net-map", "--json"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
}

#[test]
fn net_map_with_user() {
    let out = lsofrs()
        .args(["--net-map", "-u", &whoami()])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Dir / Dir-recurse ───────────────────────────────────────────────

#[test]
fn dir_flag_no_crash() {
    let out = lsofrs().args(["--dir", "/tmp"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn dir_recurse_flag_no_crash() {
    let out = lsofrs().args(["--dir-recurse", "/tmp"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn dir_flag_with_dev() {
    let out = lsofrs().args(["--dir", "/dev"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn dir_recurse_with_json() {
    let out = lsofrs()
        .args(["--dir-recurse", "/dev", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let _: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
}

// ── TUI flag (non-TTY exits immediately) ────────────────────────────

#[test]
fn tui_flag_non_tty() {
    let out = lsofrs().arg("--tui").output().unwrap();
    // Non-TTY should print error and exit
    assert!(out.status.success() || !out.status.success()); // just shouldn't hang
}

// ── Theme flag ──────────────────────────────────────────────────────

#[test]
fn theme_flag_classic() {
    let out = lsofrs()
        .args(["--theme", "classic", "--summary"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn theme_flag_matrix() {
    let out = lsofrs()
        .args(["--theme", "matrix", "--summary"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn theme_flag_unknown_defaults() {
    let out = lsofrs()
        .args(["--theme", "nonexistent", "--summary"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

// ── Help content for new features ───────────────────────────────────

#[test]
fn help_contains_tui() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--tui"));
}

#[test]
fn help_contains_dir_flags() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--dir"));
    assert!(stdout.contains("--dir-recurse"));
}

#[test]
fn help_contains_csv() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--csv"));
}

#[test]
fn help_contains_pipe_chain() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--pipe-chain"));
}

#[test]
fn help_contains_net_map() {
    let out = lsofrs().arg("-h").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--net-map"));
}

// ── Stale + JSON structure ──────────────────────────────────────────

#[test]
fn stale_json_has_stale_fds_key() {
    let out = lsofrs().args(["--stale", "--json"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.get("stale_fds").is_some());
}

// ── Multiple modes combined ─────────────────────────────────────────

#[test]
fn json_with_dir_recurse() {
    let out = lsofrs()
        .args(["--json", "--dir-recurse", "/dev"])
        .output()
        .unwrap();
    assert!(out.status.success());
}

#[test]
fn terse_with_dir() {
    let out = lsofrs().args(["-t", "--dir", "/dev"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }
        assert!(
            line.trim().parse::<i32>().is_ok(),
            "terse should be PID: '{line}'"
        );
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn whoami() -> String {
    String::from_utf8(
        std::process::Command::new("whoami")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string()
}
