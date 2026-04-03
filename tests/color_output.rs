//! Integration tests for `--color` and stable output contracts when stdout is not a TTY.

use std::process::Command;

fn lsofrs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// Piped columnar mode uses plain titles, but padding widths depend on live FD data,
/// so two invocations are not guaranteed to produce byte-identical header lines.
fn assert_pipe_plain_header(line: &str) {
    assert!(line.contains("COMMAND"), "{line}");
    assert!(line.contains("PID"), "{line}");
    assert!(
        !line.contains("PROCESS"),
        "piped plain header must not use PROCESS: {line}"
    );
    assert!(
        !line.contains("PRC"),
        "piped plain header must not use PRC: {line}"
    );
}

#[test]
fn color_never_uses_plain_column_titles() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--color", "never", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = first_line(&out.stdout);
    assert!(
        first.contains("COMMAND"),
        "expected COMMAND in header: {first}"
    );
    assert!(first.contains("PID"), "expected PID in header: {first}");
    assert!(
        !first.contains("PROCESS"),
        "never must not use PROCESS title: {first}"
    );
    assert!(
        !first.contains("PRC"),
        "never must not use PRC title: {first}"
    );
}

#[test]
fn color_always_uses_tty_column_titles_when_captured() {
    let my_pid = std::process::id().to_string();
    let out = lsofrs()
        .args(["--color", "always", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let first = first_line(&out.stdout);
    assert!(
        first.contains("PROCESS"),
        "expected PROCESS in header: {first}"
    );
    assert!(first.contains("PRC"), "expected PRC in header: {first}");
    assert!(
        !first.contains("COMMAND"),
        "always must not use plain COMMAND title: {first}"
    );
}

#[test]
fn color_auto_when_piped_matches_never_header_row() {
    let my_pid = std::process::id().to_string();
    let out_auto = lsofrs().args(["-p", &my_pid]).output().unwrap();
    let out_never = lsofrs()
        .args(["--color", "never", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(out_auto.status.success() && out_never.status.success());
    assert_pipe_plain_header(&first_line(&out_auto.stdout));
    assert_pipe_plain_header(&first_line(&out_never.stdout));
}

#[test]
fn help_documents_color_flag() {
    let out = lsofrs().arg("-h").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("--color"), "help should document --color");
    assert!(
        s.contains("auto") && s.contains("always") && s.contains("never"),
        "help should mention auto/always/never"
    );
}

#[test]
fn unknown_color_value_falls_back_to_auto_behavior() {
    let my_pid = std::process::id().to_string();
    let out_bad = lsofrs()
        .args(["--color", "bogus", "-p", &my_pid])
        .output()
        .unwrap();
    let out_auto = lsofrs().args(["-p", &my_pid]).output().unwrap();
    assert!(out_bad.status.success() && out_auto.status.success());
    assert_pipe_plain_header(&first_line(&out_bad.stdout));
    assert_pipe_plain_header(&first_line(&out_auto.stdout));
}

#[test]
fn color_never_terse_matches_auto_terse() {
    let my_pid = std::process::id().to_string();
    let a = lsofrs().args(["-t", "-p", &my_pid]).output().unwrap();
    let b = lsofrs()
        .args(["--color", "never", "-t", "-p", &my_pid])
        .output()
        .unwrap();
    assert!(a.status.success() && b.status.success());
    fn terse_pids(stdout: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().to_string())
            .collect()
    }
    let pa = terse_pids(&a.stdout);
    let pb = terse_pids(&b.stdout);
    assert_eq!(pa, pb, "auto vs never terse should list the same PIDs");
    assert_eq!(
        pa,
        vec![my_pid.clone()],
        "terse -p self should list only our PID"
    );
}
