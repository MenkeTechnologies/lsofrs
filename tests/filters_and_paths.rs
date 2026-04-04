//! Filter combinations, path arguments, and display flags (non-interactive).

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

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

#[test]
fn file_arg_dev_null_json() {
    let out = lsofrs().args(["-J", "/dev/null"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn file_arg_dev_null_json_long_flag() {
    let out = lsofrs().args(["--json", "/dev/null"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn file_arg_dev_null_columnar() {
    let out = lsofrs().arg("/dev/null").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("COMMAND") || s.contains("PROCESS"));
}

#[test]
fn fd_range_filter_with_self_pid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-d", "0-20", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_fd_range_with_self_pid() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "-d", "0-20", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_with_user_filter_current_user() {
    let u = whoami();
    let out = lsofrs().args(["-J", "-u", &u]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_with_user_filter_current_user() {
    let u = whoami();
    let out = lsofrs().args(["--json", "-u", &u]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_inet_port_only_is_array() {
    let out = lsofrs().args(["--json", "-i", ":443"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn columnar_with_user_filter() {
    let u = whoami();
    let out = lsofrs().args(["-u", &u]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.trim().is_empty());
}

#[test]
fn json_inet_all_flag() {
    let out = lsofrs().args(["-J", "-i"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_inet_all_bare_is_array() {
    let out = lsofrs().args(["--json", "-i"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn terse_multiple_pids_or() {
    let a = std::process::id().to_string();
    let out = lsofrs()
        .args(["-t", "-p", &format!("{a},1")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty());
}

#[test]
fn json_command_regex_filter() {
    let out = lsofrs().args(["-J", "-c", ".*"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_command_regex_filter() {
    let out = lsofrs().args(["--json", "-c", ".*"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn show_pgid_json_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--pgid-show", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn show_pgid_json_long_flag_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "--pgid-show", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn show_ppid_json_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-R", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn show_ppid_json_long_flag_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "-R", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v.len(), 1);
}

#[test]
fn combined_npw_flags_json() {
    let out = lsofrs().args(["-J", "-n", "-P", "-w"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_udp_only_filter_is_array() {
    let out = lsofrs().args(["-J", "-i", "UDP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn csv_with_user_filter_has_header() {
    let u = whoami();
    let out = lsofrs().args(["--csv", "-u", &u]).output().unwrap();
    assert!(out.status.success());
    let first = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(first.starts_with("COMMAND,PID,USER,"));
}

#[test]
fn json_long_flag_udp_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "UDP"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_inet_4_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "4"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn json_long_flag_inet_6_filter_is_array() {
    let out = lsofrs().args(["--json", "-i", "6"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}
