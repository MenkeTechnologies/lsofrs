//! Single-shot dispatch order: flags checked in `main` before `args.json`.

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

#[test]
fn csv_flag_takes_precedence_over_json_flag() {
    let out = lsofrs().args(["--csv", "-J"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"),
        "CSV runs before JSON branch: {stdout:?}"
    );
}

#[test]
fn csv_flag_takes_precedence_over_json_when_json_short_first() {
    let out = lsofrs().args(["-J", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"),
        "CSV runs before JSON when -J appears first on argv"
    );
}

#[test]
fn csv_flag_takes_precedence_over_json_when_json_long_first() {
    let out = lsofrs().args(["--json", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"),
        "CSV runs before JSON when --json appears first on argv"
    );
}

#[test]
fn stale_flag_runs_before_csv_in_cli_order() {
    // --stale is handled before --csv in main; stale + csv both set → stale wins
    let out = lsofrs().args(["--stale", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "stale text should not be RFC CSV header: {}",
        stdout.lines().next().unwrap_or("")
    );
}

#[test]
fn ports_flag_runs_before_csv() {
    let out = lsofrs().args(["--ports", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "ports mode should not emit CSV header"
    );
}

#[test]
fn tree_with_json_uses_tree_serializer() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let _: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
}

#[test]
fn summary_with_json_not_columnar_array() {
    let out = lsofrs().args(["--summary", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("summary JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn stats_alias_with_json_same_wrapper_as_summary() {
    let out = lsofrs().args(["--stats", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stats JSON should be an object");
    assert!(obj.contains_key("summary"));
    assert!(obj["summary"].is_object());
}

#[test]
fn csv_flag_takes_precedence_over_net_map_flag() {
    // `main` checks `csv_output` before `net_map`
    let out = lsofrs().args(["--net-map", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"),
        "CSV branch runs before net-map"
    );
}

#[test]
fn csv_wins_over_net_map_when_csv_flag_first() {
    let out = lsofrs().args(["--csv", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.starts_with("COMMAND,PID,USER,FD,TYPE,DEVICE,SIZE/OFF,NODE,NAME"),
        "dispatch order is fixed in main, not argv order"
    );
}

#[test]
fn pipe_chain_text_not_json_array() {
    let out = lsofrs().args(["--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        !first.trim_start().starts_with('['),
        "pipe-chain text should not start with JSON array"
    );
}

#[test]
fn json_flag_alone_produces_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn terse_flag_after_json_branch_not_reached_with_json() {
    // When -J is set, main hits json::print_json before terse
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-t", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim_start().starts_with('[') || stdout.contains('['),
        "JSON should win over terse when both passed: {}",
        &stdout[..stdout.len().min(80)]
    );
}

#[test]
fn field_output_wins_over_columnar_when_no_higher_mode() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "p", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("p{my_pid}")),
        "field output should contain p<pid>"
    );
}

#[test]
fn stale_wins_over_ports_when_both_set() {
    let out = lsofrs().args(["--stale", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("Listening Ports"),
        "ports branch must not run when stale is set first in main"
    );
}

#[test]
fn stale_wins_over_ports_when_ports_flag_first() {
    let out = lsofrs().args(["--ports", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("Listening Ports"),
        "stale still wins when --ports appears first on argv"
    );
}

#[test]
fn ports_wins_over_pipe_chain_when_both_set() {
    let out = lsofrs().args(["--ports", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "ports branch runs before pipe-chain in main: {}",
        s.lines().take(2).collect::<Vec<_>>().join(" | ")
    );
}

#[test]
fn ports_wins_over_net_map_when_both_set() {
    let out = lsofrs().args(["--ports", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "ports branch runs before net-map in main"
    );
}

#[test]
fn pipe_chain_wins_over_net_map_when_both_set() {
    let out = lsofrs()
        .args(["--pipe-chain", "--net-map"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "pipe-chain runs before net-map in main: {}",
        s.lines().take(3).collect::<Vec<_>>().join(" | ")
    );
}

#[test]
fn stale_wins_over_pipe_chain_when_both_set() {
    let out = lsofrs().args(["--stale", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("IPC Topology"),
        "stale runs before pipe-chain in main"
    );
}

#[test]
fn stale_wins_over_pipe_chain_when_pipe_chain_flag_first() {
    let out = lsofrs().args(["--pipe-chain", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("IPC Topology"),
        "stale still wins when --pipe-chain appears first on argv"
    );
}

#[test]
fn stale_wins_over_net_map_when_both_set() {
    let out = lsofrs().args(["--stale", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("Network Connection Map"),
        "stale runs before net-map in main"
    );
}

#[test]
fn stale_wins_over_net_map_when_net_map_flag_first() {
    let out = lsofrs().args(["--net-map", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("Network Connection Map"),
        "stale still wins when --net-map appears first on argv"
    );
}

#[test]
fn pipe_chain_wins_over_csv_when_both_set() {
    let out = lsofrs().args(["--pipe-chain", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "pipe-chain runs before CSV in main"
    );
}

#[test]
fn pipe_chain_wins_over_csv_when_csv_flag_first() {
    let out = lsofrs().args(["--csv", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "pipe-chain still wins when --csv appears first on argv"
    );
}

#[test]
fn net_map_wins_over_tree_when_both_set() {
    let out = lsofrs().args(["--net-map", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Network Connection Map") || s.contains("No network connections"),
        "net-map runs before tree in main"
    );
}

#[test]
fn tree_wins_over_summary_when_both_set() {
    let out = lsofrs().args(["--tree", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "tree runs before summary in main"
    );
    assert!(
        s.contains("OPEN FILES"),
        "expected tree header: {}",
        s.lines().next().unwrap_or("")
    );
}

#[test]
fn tree_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs().args(["--summary", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "tree still wins when --summary appears first on argv"
    );
    assert!(
        s.contains("OPEN FILES"),
        "expected tree header: {}",
        s.lines().next().unwrap_or("")
    );
}

#[test]
fn csv_wins_over_tree_when_both_set() {
    let out = lsofrs().args(["--csv", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "CSV runs before tree in main"
    );
}

#[test]
fn stale_wins_over_csv_when_both_set() {
    let out = lsofrs().args(["--stale", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "stale runs before CSV in main"
    );
}

#[test]
fn net_map_wins_over_summary_when_both_set() {
    let out = lsofrs().args(["--net-map", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "net-map runs before summary in main"
    );
    assert!(
        s.contains("Network Connection Map") || s.contains("No network connections"),
        "expected net-map output: {}",
        s.lines().take(2).collect::<Vec<_>>().join(" | ")
    );
}

#[test]
fn csv_wins_over_summary_when_both_set() {
    let out = lsofrs().args(["--csv", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "CSV runs before summary in main"
    );
}

#[test]
fn ports_wins_over_summary_when_both_set() {
    let out = lsofrs().args(["--ports", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "ports runs before summary in main"
    );
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "expected ports output"
    );
}

#[test]
fn pipe_chain_wins_over_summary_when_both_set() {
    let out = lsofrs()
        .args(["--pipe-chain", "--summary"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "pipe-chain runs before summary in main"
    );
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "expected pipe-chain output"
    );
}

#[test]
fn stale_wins_over_summary_when_both_set() {
    let out = lsofrs().args(["--stale", "--summary"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "stale runs before summary in main"
    );
}

#[test]
fn stale_wins_over_tree_when_both_set() {
    let out = lsofrs().args(["--stale", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "stale runs before tree in main"
    );
}

#[test]
fn pipe_chain_wins_over_tree_when_both_set() {
    let out = lsofrs().args(["--pipe-chain", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "pipe-chain runs before tree in main"
    );
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "expected pipe-chain output"
    );
}

#[test]
fn ports_wins_over_tree_when_both_set() {
    let out = lsofrs().args(["--ports", "--tree"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "ports runs before tree in main"
    );
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "expected ports output"
    );
}

#[test]
fn ports_wins_over_tree_when_tree_flag_first() {
    let out = lsofrs().args(["--tree", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "ports still wins when --tree appears first on argv"
    );
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "expected ports output"
    );
}

#[test]
fn ports_wins_over_pipe_chain_when_pipe_chain_flag_first() {
    let out = lsofrs().args(["--pipe-chain", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "ports still wins when --pipe-chain appears first on argv"
    );
}

#[test]
fn ports_wins_over_net_map_when_net_map_flag_first() {
    let out = lsofrs().args(["--net-map", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "ports still wins when --net-map appears first on argv"
    );
}

#[test]
fn pipe_chain_wins_over_net_map_when_net_map_flag_first() {
    let out = lsofrs()
        .args(["--net-map", "--pipe-chain"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "pipe-chain still wins when --net-map appears first on argv"
    );
}

#[test]
fn net_map_wins_over_tree_when_tree_flag_first() {
    let out = lsofrs().args(["--tree", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("Network Connection Map") || s.contains("No network connections"),
        "net-map still wins when --tree appears first on argv"
    );
}

#[test]
fn csv_wins_over_tree_when_tree_flag_first() {
    let out = lsofrs().args(["--tree", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "CSV still wins when --tree appears first on argv"
    );
}

#[test]
fn net_map_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs().args(["--summary", "--net-map"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "net-map still wins when --summary appears first on argv"
    );
    assert!(
        s.contains("Network Connection Map") || s.contains("No network connections"),
        "expected net-map output"
    );
}

#[test]
fn csv_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs().args(["--summary", "--csv"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "CSV still wins when --summary appears first on argv"
    );
}

#[test]
fn ports_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs().args(["--summary", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "ports still wins when --summary appears first on argv"
    );
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "expected ports output"
    );
}

#[test]
fn pipe_chain_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs()
        .args(["--summary", "--pipe-chain"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "pipe-chain still wins when --summary appears first on argv"
    );
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "expected pipe-chain output"
    );
}

#[test]
fn stale_wins_over_summary_when_summary_flag_first() {
    let out = lsofrs().args(["--summary", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("=== lsofrs summary ==="),
        "stale still wins when --summary appears first on argv"
    );
}

#[test]
fn stale_wins_over_tree_when_tree_flag_first() {
    let out = lsofrs().args(["--tree", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "stale still wins when --tree appears first on argv"
    );
}

#[test]
fn stale_wins_over_csv_when_csv_flag_first() {
    let out = lsofrs().args(["--csv", "--stale"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "stale still wins when --csv appears first on argv"
    );
}

#[test]
fn ports_wins_over_csv_when_csv_flag_first() {
    let out = lsofrs().args(["--csv", "--ports"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.starts_with("COMMAND,PID,USER,FD,TYPE"),
        "ports still wins when --csv appears first on argv"
    );
    assert!(
        s.contains("Listening Ports") || s.contains("No listening ports"),
        "expected ports output"
    );
}

#[test]
fn pipe_chain_wins_over_tree_when_tree_flag_first() {
    let out = lsofrs().args(["--tree", "--pipe-chain"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("PID   USER     FDs  CMD  ──  OPEN FILES"),
        "pipe-chain still wins when --tree appears first on argv"
    );
    assert!(
        s.contains("IPC Topology") || s.contains("Pipe/Socket") || s.contains("No pipe"),
        "expected pipe-chain output"
    );
}

#[test]
fn json_long_flag_alone_produces_array() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}
