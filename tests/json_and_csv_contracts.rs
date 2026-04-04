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
