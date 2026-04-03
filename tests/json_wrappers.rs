//! Top-level JSON wrapper keys for `--json` modes (stable API contract).

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

#[test]
fn net_map_json_has_net_map_key() {
    let out = lsofrs().args(["--net-map", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("net-map JSON should be an object");
    assert!(obj.contains_key("net_map"));
    assert!(obj["net_map"].is_array());
}

#[test]
fn ports_json_has_listening_ports_key() {
    let out = lsofrs().args(["--ports", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("ports JSON should be an object");
    assert!(obj.contains_key("listening_ports"));
    assert!(obj["listening_ports"].is_array());
}

#[test]
fn pipe_chain_json_has_pipe_chains_key() {
    let out = lsofrs().args(["--pipe-chain", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("pipe-chain JSON should be an object");
    assert!(obj.contains_key("pipe_chains"));
}

#[test]
fn stale_json_has_stale_fds_key() {
    let out = lsofrs().args(["--stale", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stale JSON should be an object");
    assert!(obj.contains_key("stale_fds"));
    assert!(obj["stale_fds"].is_array());
}

#[test]
fn summary_json_parses_to_value() {
    let out = lsofrs().args(["--summary", "--json"]).output().unwrap();
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
}

#[test]
fn tree_json_self_pid_parses() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
}

#[test]
fn default_json_is_top_level_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn net_map_json_stderr_empty() {
    let out = lsofrs().args(["--net-map", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn ports_json_stderr_empty() {
    let out = lsofrs().args(["--ports", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}
