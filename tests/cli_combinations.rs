//! CLI combinations and structured JSON smoke tests (non-interactive).

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

#[test]
fn json_two_pids_or_mode_is_array() {
    let a = std::process::id().to_string();
    let b = "1".to_string();
    let out = lsofrs()
        .args(["-J", "-p", &format!("{a},{b}")])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: Vec<serde_json::Value> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(
        !v.is_empty(),
        "OR of two PIDs should return at least the matching process"
    );
}

#[test]
fn json_and_mode_with_pid_and_inet_no_panic() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-a", "-p", &my_pid, "-i", "TCP"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn tree_json_self_pid_is_non_empty_value() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--json", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty());
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(!v.is_null());
}

#[test]
fn summary_json_parses_and_has_keys() {
    let out = lsofrs().args(["--summary", "--json"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    match v {
        serde_json::Value::Object(ref m) => {
            assert!(!m.is_empty(), "summary object should have keys");
        }
        serde_json::Value::Array(ref a) => {
            assert!(!a.is_empty(), "summary array should be non-empty");
        }
        _ => panic!("summary --json should be object or array"),
    }
}

#[test]
fn net_map_json_is_structured() {
    let out = lsofrs().args(["--net-map", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(
        v.is_array() || v.is_object(),
        "net-map --json should be JSON array or object"
    );
}

#[test]
fn pipe_chain_json_top_level_array_or_object() {
    let out = lsofrs().args(["--pipe-chain", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array() || v.is_object());
}

#[test]
fn stale_json_top_level_object_with_stale_fds() {
    let out = lsofrs().args(["--stale", "--json"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let obj = v.as_object().expect("stale --json should be an object");
    assert!(obj.contains_key("stale_fds"));
}

#[test]
fn default_output_stderr_empty_on_success() {
    let out = lsofrs().output().unwrap();
    assert!(out.status.success());
    assert!(
        out.stderr.is_empty(),
        "default run stderr should be empty on success"
    );
}

#[test]
fn json_stderr_empty_on_success() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-J", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_long_flag_stderr_empty_on_success() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--json", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_long_combined_npw_flags_is_array() {
    let out = lsofrs()
        .args(["--json", "-n", "-P", "-w"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn field_output_self_pid_stderr_empty_on_success() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["-F", "p", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn csv_stderr_empty_on_success() {
    let out = lsofrs().arg("--csv").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn ports_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--ports").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn net_map_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--net-map").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn pipe_chain_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--pipe-chain").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stale_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--stale").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn tree_text_self_pid_stderr_empty_on_success() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs().args(["--tree", "-p", &my_pid]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn summary_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--summary").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stats_alias_text_stderr_empty_on_success() {
    let out = lsofrs().arg("--stats").output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn exclude_user_syntax_no_crash() {
    let out = lsofrs().args(["-u", "^root"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn exclude_pid_syntax_no_crash() {
    let out = lsofrs().args(["-p", "^1"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn json_inet_tcp_filter_stderr_empty() {
    let out = lsofrs().args(["-J", "-i", "TCP"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_and_mode_with_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-a", "-p", &my_pid, "-u", "nonexistent_user_xyz"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_long_flag_bare_inet_all_stderr_empty() {
    let out = lsofrs().args(["--json", "-i"]).output().unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn columnar_show_pgid_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--pgid-show", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn exclude_two_usernames_no_crash() {
    let out = lsofrs().args(["-u", "^root,^nobody"]).output().unwrap();
    assert!(out.status.success());
}

#[test]
fn json_no_dns_no_port_lookup_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-n", "-P", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn summary_text_color_never_stderr_empty() {
    let out = lsofrs()
        .args(["--summary", "--color", "never"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn columnar_color_always_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--color", "always", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_command_literal_filter_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-J", "-c", "lsofrs", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn tree_self_pid_color_never_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--tree", "--color", "never", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn net_map_text_color_never_stderr_empty() {
    let out = lsofrs()
        .args(["--net-map", "--color", "never"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn ports_text_color_never_stderr_empty() {
    let out = lsofrs()
        .args(["--ports", "--color", "never"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn pipe_chain_text_color_never_stderr_empty() {
    let out = lsofrs()
        .args(["--pipe-chain", "--color", "never"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn stale_text_color_never_stderr_empty() {
    let out = lsofrs()
        .args(["--stale", "--color", "never"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn summary_text_color_always_stderr_empty() {
    let out = lsofrs()
        .args(["--summary", "--color", "always"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}

#[test]
fn json_with_theme_classic_stderr_empty() {
    let out = lsofrs()
        .args(["-J", "--theme", "classic"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(v.is_array());
}

#[test]
fn field_output_color_never_self_pid_stderr_empty() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["-F", "p", "--color", "never", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(out.stderr.is_empty());
}
