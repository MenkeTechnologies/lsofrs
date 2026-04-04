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
