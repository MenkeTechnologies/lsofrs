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
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("summary JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn stats_alias_json_has_summary_key() {
    let out = lsofrs().args(["--stats", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stats JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
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

#[test]
fn stale_json_stderr_empty() {
    let out = lsofrs().args(["--stale", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn pipe_chain_json_stderr_empty() {
    let out = lsofrs().args(["--pipe-chain", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn summary_json_stderr_empty() {
    let out = lsofrs().args(["--summary", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn tree_json_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stats_alias_json_stderr_empty() {
    let out = lsofrs().args(["--stats", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn net_map_json_long_flag_before_net_map_same_wrapper() {
    let out = lsofrs().args(["--json", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("net-map JSON should be an object");
    assert!(obj.contains_key("net_map"));
    assert!(obj["net_map"].is_array());
}

#[test]
fn ports_json_long_flag_before_ports_same_wrapper() {
    let out = lsofrs().args(["--json", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("ports JSON should be an object");
    assert!(obj.contains_key("listening_ports"));
    assert!(obj["listening_ports"].is_array());
}

#[test]
fn stale_json_long_flag_before_stale_same_wrapper() {
    let out = lsofrs().args(["--json", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stale JSON should be an object");
    assert!(obj.contains_key("stale_fds"));
    assert!(obj["stale_fds"].is_array());
}

#[test]
fn tree_json_long_flag_before_tree_same_shape() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--json", "--tree", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let arr = v.as_array().expect("tree --json should be a JSON array");
    assert!(!arr.is_empty());
    assert!(arr[0].get("children").is_some());
}

#[test]
fn pipe_chain_json_long_flag_before_pipe_chain_same_wrapper() {
    let out = lsofrs().args(["--json", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("pipe-chain JSON should be an object");
    assert!(obj.contains_key("pipe_chains"));
}

#[test]
fn summary_json_long_flag_before_summary_same_wrapper() {
    let out = lsofrs().args(["--json", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("summary JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn net_map_json_short_flag_before_net_map_same_wrapper() {
    let out = lsofrs().args(["-J", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("net-map JSON should be an object");
    assert!(obj.contains_key("net_map"));
    assert!(obj["net_map"].is_array());
}

#[test]
fn ports_json_short_flag_before_ports_same_wrapper() {
    let out = lsofrs().args(["-J", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("ports JSON should be an object");
    assert!(obj.contains_key("listening_ports"));
    assert!(obj["listening_ports"].is_array());
}

#[test]
fn stale_json_short_flag_before_stale_same_wrapper() {
    let out = lsofrs().args(["-J", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stale JSON should be an object");
    assert!(obj.contains_key("stale_fds"));
    assert!(obj["stale_fds"].is_array());
}

#[test]
fn tree_json_short_flag_before_tree_same_shape() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "--tree", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let arr = v.as_array().expect("tree -J should be a JSON array");
    assert!(!arr.is_empty());
    assert!(arr[0].get("children").is_some());
}

#[test]
fn pipe_chain_json_short_flag_before_pipe_chain_same_wrapper() {
    let out = lsofrs().args(["-J", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("pipe-chain JSON should be an object");
    assert!(obj.contains_key("pipe_chains"));
}

#[test]
fn summary_json_short_flag_before_summary_same_wrapper() {
    let out = lsofrs().args(["-J", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("summary JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn stats_json_long_flag_before_stats_same_wrapper() {
    let out = lsofrs().args(["--json", "--stats"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stats JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn stats_json_short_flag_before_stats_same_wrapper() {
    let out = lsofrs().args(["-J", "--stats"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stats JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn stale_json_json_flag_before_stale_stderr_empty() {
    let out = lsofrs().args(["--json", "--stale"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn ports_json_json_flag_before_ports_stderr_empty() {
    let out = lsofrs().args(["--json", "--ports"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn summary_json_json_flag_before_summary_stderr_empty() {
    let out = lsofrs().args(["--json", "--summary"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn net_map_json_json_flag_before_net_map_stderr_empty() {
    let out = lsofrs().args(["--json", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn pipe_chain_json_json_flag_before_pipe_chain_stderr_empty() {
    let out = lsofrs().args(["--json", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stats_json_json_flag_before_stats_stderr_empty() {
    let out = lsofrs().args(["--json", "--stats"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}
