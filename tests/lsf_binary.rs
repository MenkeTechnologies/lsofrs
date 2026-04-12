//! The `lsf` binary is an alias of `lsofrs` (same `main.rs`). These tests lock in parity.

use std::process::Command;

fn lsf() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsf"))
}

#[test]
fn lsf_help_matches_banner() {
    let out = lsf().arg("-h").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FILE DESCRIPTOR SCANNER"));
    assert!(stdout.contains("USAGE:"));
}

#[test]
fn lsf_version_reports_package_version() {
    let out = lsf().arg("-V").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn lsf_default_run_columnar_header() {
    let out = lsf().output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("COMMAND") && stdout.contains("PID"));
}

#[test]
fn lsf_json_self_pid_valid_array() {
    let my_pid = std::process::id().to_string();
    let out = lsf().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
    let arr = v.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["pid"].as_i64().unwrap(), std::process::id() as i64);
}

#[test]
fn lsf_csv_header_matches_lsofrs_contract() {
    let out = lsf().arg("--csv").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"));
}
