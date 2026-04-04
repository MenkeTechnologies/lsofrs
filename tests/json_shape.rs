//! JSON output shape invariants for the self process (end-to-end).

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

fn self_json_process() -> serde_json::Value {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let arr: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(arr.len(), 1);
    arr.into_iter().next().unwrap()
}

#[test]
fn json_self_pid_command_is_string() {
    let p = self_json_process();
    assert!(p["command"].as_str().is_some());
}

#[test]
fn json_self_pid_matches_os_pid() {
    let p = self_json_process();
    assert_eq!(p["pid"].as_i64().unwrap(), std::process::id() as i64);
}

#[test]
fn json_self_has_uid_number() {
    let p = self_json_process();
    assert!(
        p["uid"].as_u64().is_some() || p["uid"].as_i64().is_some(),
        "uid should be numeric: {:?}",
        p["uid"]
    );
}

#[test]
fn json_self_has_pgid_ppid_numbers() {
    let p = self_json_process();
    assert!(p["pgid"].as_i64().is_some());
    assert!(p["ppid"].as_i64().is_some());
}

#[test]
fn json_self_files_is_nonempty_array() {
    let p = self_json_process();
    let files = p["files"].as_array().expect("files array");
    assert!(!files.is_empty());
}

#[test]
fn json_long_flag_files_array_non_empty_for_self() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    let files = v[0]["files"].as_array().expect("files array");
    assert!(!files.is_empty());
}

#[test]
fn json_each_file_has_fd_type_name_strings() {
    let p = self_json_process();
    for f in p["files"].as_array().unwrap() {
        assert!(
            f["fd"].as_str().is_some(),
            "fd should be string: {:?}",
            f["fd"]
        );
        assert!(
            f["type"].as_str().is_some(),
            "type should be string: {:?}",
            f["type"]
        );
        assert!(
            f["name"].as_str().is_some(),
            "name should be string: {:?}",
            f["name"]
        );
    }
}

#[test]
fn json_output_stream_is_utf8() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(String::from_utf8(out.stdout.clone()).is_ok());
}

#[test]
fn json_short_and_long_flags_same_process_row() {
    let my_pid = std::process::id().to_string();
    let a = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    let b = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(a.status.success() && b.status.success());
    let pa: Vec<serde_json::Value> = serde_json::from_slice(&a.stdout).unwrap();
    let pb: Vec<serde_json::Value> = serde_json::from_slice(&b.stdout).unwrap();
    assert_eq!(pa[0]["pid"], pb[0]["pid"]);
    assert_eq!(pa[0]["command"], pb[0]["command"]);
}

#[test]
fn json_stderr_empty_for_success() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}
