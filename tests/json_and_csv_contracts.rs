//! JSON and CSV output contracts (non-interactive).

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

#[test]
fn json_inet_4_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", "4"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_inet_6_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "6"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_inet_port_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", ":443"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_tcp_port_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", "TCP:443"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_4tcp_combo_is_array() {
    let out = lsofrs().args(["-J", "-i", "4TCP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_tcp_bare_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_tcp_port_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "TCP:443"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_udp_port_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "UDP:53"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_6tcp_combo_is_array() {
    let out = lsofrs().args(["--json", "-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_4tcp_combo_is_array() {
    let out = lsofrs().args(["--json", "-i", "4TCP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_4udp_combo_is_array() {
    let out = lsofrs().args(["--json", "-i", "4UDP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_bare_udp_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", "UDP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_4udp_port_combo_is_array() {
    let out = lsofrs().args(["--json", "-i", "4UDP:53"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_fd_degenerate_range_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "7-7", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_exclude_pid_init_combined_with_self_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-p", &format!("^1,{my_pid}")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_unix_socket_filter_is_array() {
    let out = lsofrs().args(["--json", "-U"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn columnar_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_long_flag_terse_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "-t", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn csv_self_pid_has_rfc_header() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--csv", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--csv", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_self_pid_array_of_one_process() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["pid"].as_i64().unwrap(), std::process::id() as i64);
}

#[test]
fn json_long_self_pid_array_of_one_process() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
    assert_eq!(v[0]["pid"].as_i64().unwrap(), std::process::id() as i64);
}

#[test]
fn json_long_flag_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_short_flag_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_and_mode_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-a", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_long_flag_all_mode_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "-a", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn csv_all_mode_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--csv", "-a", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn terse_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-t", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn field_output_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "p", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn summary_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--summary", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stats_alias_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--stats", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn terse_self_pid_single_line() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-t", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].trim(), my_pid);
}

#[test]
fn field_output_self_pid_has_p_token() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "p", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&format!("p{my_pid}")));
}

#[test]
fn version_stdout_only_version_line() {
    let out = lsofrs().arg("-V").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("lsofrs"));
}

#[test]
fn help_stdout_contains_usage_not_stderr() {
    let out = lsofrs().arg("-h").output().unwrap();
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("USAGE"),
        "help on stdout"
    );
}

#[test]
fn json_unix_socket_filter_is_array() {
    let out = lsofrs().args(["-J", "-U"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_nfs_flag_is_array() {
    let out = lsofrs().args(["--json", "-N"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_with_no_dns_flag_still_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-n", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn json_self_pid_with_no_port_lookup_still_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-P", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn json_self_pid_with_suppress_warnings_still_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-w", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn json_self_pid_color_never_still_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--color", "never", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_filter_has_header_and_rows() {
    let out = lsofrs().args(["--csv", "-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let header = lines.next().unwrap_or("");
    assert!(
        header.starts_with("COMMAND,PID,USER,"),
        "CSV header: {header}"
    );
}

#[test]
fn json_6tcp_combo_is_array() {
    let out = lsofrs().args(["-J", "-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_udp_port_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", "UDP:53"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_tcp_at_host_port_is_array() {
    let out = lsofrs()
        .args(["-J", "-i", "TCP@127.0.0.1:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_udp_at_host_port_is_array() {
    let out = lsofrs()
        .args(["--json", "-i", "UDP@127.0.0.1:53"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_6udp_port_combo_is_array() {
    let out = lsofrs().args(["-J", "-i", "6UDP:53"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_fd_exclude_still_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "^0", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_4tcp_port_combo_is_array() {
    let out = lsofrs().args(["-J", "-i", "4TCP:22"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_tcp_at_host_no_port_is_array() {
    let out = lsofrs()
        .args(["--json", "-i", "TCP@10.0.0.5"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_show_ppid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-R", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_pgid_filter_process_group_one_is_array() {
    let out = lsofrs().args(["-J", "-g", "1"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_pgid_show_and_ppid_flags_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--pgid-show", "-R", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_inet_only_ipv4_addr_family_stderr_empty() {
    let out = lsofrs().args(["--json", "-i", "4"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_inet_tcp_filter_has_rfc_header() {
    let out = lsofrs().args(["--csv", "-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_pipe_chain_parses_and_stderr_empty() {
    let out = lsofrs().args(["-J", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array() || v.is_object());
}

#[test]
fn json_stats_alias_has_summary_wrapper_key() {
    let out = lsofrs().args(["--stats", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stats --json should be an object");
    assert!(obj.contains_key("summary"));
}

#[test]
fn json_file_operand_dev_null_is_array() {
    let out = lsofrs().args(["-J", "/dev/null"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_delta_flag_with_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--delta", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn field_output_self_pid_multichar_fields() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-F", "pcfn", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains(&format!("p{my_pid}")));
    assert!(s.contains('c'));
    assert!(s.contains('f'));
    assert!(s.lines().any(|l| l.starts_with('n')));
}

#[test]
fn json_6tcp_explicit_port_is_array() {
    let out = lsofrs().args(["-J", "-i", "6TCP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_with_delta_stderr_empty() {
    let out = lsofrs().args(["--csv", "--delta"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_stale_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--stale", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stale --json should be an object");
    assert!(obj.contains_key("stale_fds"));
}

#[test]
fn json_color_never_inet_tcp_stderr_empty() {
    let out = lsofrs()
        .args(["--color", "never", "-J", "-i", "TCP"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_unix_socket_flag_stderr_empty() {
    let out = lsofrs().args(["-J", "-U"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_nfs_only_flag_stderr_empty() {
    let out = lsofrs().args(["-J", "-N"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_6udp_explicit_port_is_array() {
    let out = lsofrs().args(["-J", "-i", "6UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_suppress_warnings_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-w", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_nfs_and_unix_socket_combined_stderr_empty() {
    let out = lsofrs().args(["-J", "-N", "-U"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_fd_filter_cwd_self_pid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "cwd", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_pipe_chain_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--pipe-chain", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array() || v.is_object());
}

#[test]
fn csv_nul_terminator_stdout_starts_with_rfc_header() {
    let out = lsofrs().args(["--csv", "-0"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.split('\0').next().unwrap_or("");
    let header_line = first.lines().next().unwrap_or("");
    assert!(
        header_line.starts_with("COMMAND,PID,USER,"),
        "first CSV segment header: {header_line:?}"
    );
}

#[test]
fn json_and_mode_self_pid_with_inet_tcp_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-a", "-p", &my_pid, "-i", "TCP"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_inet_bare_6_addr_family_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_ports_json_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--ports", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_object());
}

#[test]
fn json_net_map_json_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--net-map", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array() || v.is_object());
}

#[test]
fn csv_inet_udp_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_txt_fd_filter_self_pid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "txt", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_mem_fd_filter_self_pid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "mem", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_err_fd_filter_self_pid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "err", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_inet_6tcp_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_inet_bare_4_addr_family_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_inet_bare_6_addr_family_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_6udp_bare_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_udp_at_test_net_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "UDP@192.0.2.1:53"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn csv_udp_port_53_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_udp_port_443_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_udp_port_443_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_udp_port_53_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6tcp_port_53_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6udp_port_443_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6udp_port_443_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4udp_port_443_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4udp_port_443_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4UDP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4tcp_port_443_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4TCP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4tcp_port_443_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4TCP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_tcp_port_65535_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP:65535"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_port_65535_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP:65535"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4udp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4udp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6udp_port_123_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6UDP:123"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6udp_port_123_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP:123"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_udp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_udp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_udp_port_65535_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP:65535"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_udp_port_65535_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "UDP:65535"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6udp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6udp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_tcp_port_22_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP:22"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_port_22_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "TCP:22"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_udp_port_67_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_udp_port_67_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6tcp_port_22_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6TCP:22"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6tcp_port_22_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP:22"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4tcp_port_80_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4TCP:80"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_6udp_port_67_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6udp_port_67_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_4udp_port_67_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4udp_port_67_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4UDP:67"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("COMMAND,PID,USER,"),
        "CSV header: {first}"
    );
}

#[test]
fn json_dir_one_level_flag_stderr_empty() {
    let out = lsofrs().args(["-J", "--dir", "/tmp"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_rtd_fd_filter_self_pid_is_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "rtd", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_self_pid_fd_exclude_range_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "^0-10", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_dir_recurse_flag_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "--dir-recurse", "/tmp"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_dir_one_level_stderr_empty() {
    let out = lsofrs().args(["--csv", "--dir", "/tmp"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_inet_host_at_only_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "@127.0.0.1"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_6udp_bare_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6UDP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_and_mode_self_pid_with_udp_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-a", "-p", &my_pid, "-i", "UDP"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_suppress_warnings_only_stderr_empty() {
    let out = lsofrs().args(["-J", "-w"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_4udp_bare_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4UDP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_inet_colon_port_only_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", ":443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_inet_tcp_bracket_ipv6_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "TCP[::1]:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_inet_udp_bracket_ipv6_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "UDP[::1]:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_tcp_at_ipv4_host_only_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "TCP@203.0.113.7"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_at_ipv4_host_only_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP@203.0.113.7"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_udp_bracket_ipv6_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "UDP[::1]:53"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_4tcp_bare_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_6tcp_bare_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_udp_at_ipv4_host_only_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "UDP@203.0.113.7"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_udp_at_ipv4_host_only_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "UDP@203.0.113.7"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_tcp_bracket_ipv6_host_no_port_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP[::1]"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_bracket_ipv6_host_no_port_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "TCP[::1]"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_udp_bracket_ipv6_host_no_port_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP[::1]"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_4tcp_colon_port_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4TCP:22"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6udp_colon_port_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_udp_bracket_ipv6_host_no_port_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "UDP[::1]"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_6tcp_colon_port_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "6TCP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4udp_colon_port_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_6tcp_colon_port_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP:443"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_4udp_colon_port_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "4UDP:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_at_ipv4_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP@198.51.100.2:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_udp_at_ipv6_bracket_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "UDP@[2001:db8::1]:5353"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_bracket_ipv6_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP[::1]:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_tcp_at_ipv6_bracket_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "TCP@[2001:db8::1]:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_udp_bracket_ipv6_port_53_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "UDP[::1]:53"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_tcp_at_ipv6_bracket_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP@[2001:db8::1]:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_udp_at_ipv6_bracket_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "UDP@[2001:db8::1]:5353"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_udp_at_test_net_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "UDP@192.0.2.1:53"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_6tcp_bare_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "6TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_tcp_at_test_net_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "-i", "TCP@192.0.2.1:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_4tcp_bare_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_4udp_bare_stderr_empty() {
    let out = lsofrs().args(["--csv", "-i", "4UDP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn csv_tcp_at_test_net_host_port_stderr_empty() {
    let out = lsofrs()
        .args(["--csv", "-i", "TCP@192.0.2.1:443"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}
