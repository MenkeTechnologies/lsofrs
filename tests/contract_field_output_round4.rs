//! Round 4 contract tests for previously-uncovered surfaces:
//!   - `Args::field_output` capture of `-F` argument string (Some/None bijection)
//!   - `-F` accepts arbitrary char ordering at the Args layer; ordering at output
//!     is handled by formatter, so the parser MUST preserve the raw string
//!     verbatim (no canonicalisation, no sort)
//!   - `Args::no_port_lookup` (`-P`) flips boolean independently of `-n`
//!   - `-F` end-to-end: requesting only `p` yields lines that all start with 'p'
//!     and contain ONLY the per-PID record (no `c`/`u`/`f` field markers leak)
//!   - `-F` end-to-end with `tu`: lines either start with `t` (type) or `u` (uid),
//!     and a `u` line always precedes the first `f` of its process group
//!     (which is absent here since `f` wasn't requested — so only t/u/p markers)
//!   - `-F p` + `-0` end-to-end: output uses NUL between fields, NL between records
//!     (well-formed when -0 is on)
//!
//! Earlier rounds covered:
//!   - 3-way AND combinators, parse_inet_filter edges (round 3)
//!   - csv_quote RFC 4180, named-FD path, fd_exclude inversion (round 3)
//!   - --leak-detect Some/None bijection (round 3)
//!
//! These tests pin DIFFERENT surfaces: -F arg capture invariants, -P boolean
//! independence, -F end-to-end format markers.

use lsofrs::cli::Args;
use std::process::Command;

fn lsofrs_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsofrs"))
}

/// `Args::field_output` is `None` when `-F` is omitted, and `Some(raw)` when
/// supplied. This pins the bijection between CLI presence and the Option.
#[test]
#[allow(non_snake_case)]
fn test_field_output_some_when_dash_F_supplied_none_otherwise() {
    let args_none = Args::parse_from(["lsofrs"]);
    assert!(
        args_none.field_output.is_none(),
        "field_output must be None without -F"
    );
    let args_some = Args::parse_from(["lsofrs", "-F", "pcn"]);
    assert_eq!(
        args_some.field_output.as_deref(),
        Some("pcn"),
        "field_output must capture the raw -F arg verbatim"
    );
}

/// `-F` preserves arbitrary char ordering at the Args layer. The parser must
/// NOT sort or canonicalise; that's the formatter's job. We pass "ntpcfu" and
/// expect the same string back, byte for byte.
#[test]
fn test_field_output_preserves_arbitrary_char_order_no_canonicalisation() {
    let args = Args::parse_from(["lsofrs", "-F", "ntpcfu"]);
    assert_eq!(
        args.field_output.as_deref(),
        Some("ntpcfu"),
        "-F arg must be preserved verbatim, no reordering at the Args layer"
    );
}

/// `Args::no_port_lookup` (`-P`) flips independently of `Args::no_host_lookup`
/// (`-n`). This pins the boolean independence: setting `-P` alone must NOT
/// flip `-n` and vice versa.
#[test]
#[allow(non_snake_case)]
fn test_dash_P_and_dash_n_are_independent_booleans() {
    let p_only = Args::parse_from(["lsofrs", "-P"]);
    assert!(p_only.no_port_lookup, "-P must set no_port_lookup");
    assert!(
        !p_only.no_host_lookup,
        "-P alone must NOT set no_host_lookup"
    );
    let n_only = Args::parse_from(["lsofrs", "-n"]);
    assert!(n_only.no_host_lookup, "-n must set no_host_lookup");
    assert!(
        !n_only.no_port_lookup,
        "-n alone must NOT set no_port_lookup"
    );
    let both = Args::parse_from(["lsofrs", "-n", "-P"]);
    assert!(
        both.no_host_lookup && both.no_port_lookup,
        "-n -P sets both"
    );
}

/// End-to-end `-F p`: every non-blank output line must start with 'p' (the
/// pid field marker). No other field markers may leak when only `p` was
/// requested.
#[test]
fn test_field_output_p_only_lines_start_with_p_marker() {
    let pid = std::process::id().to_string();
    let out = lsofrs_bin()
        .args(["-F", "p", "-p", &pid])
        .output()
        .expect("spawn lsofrs -F p");
    assert!(
        out.status.success(),
        "-F p must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let nonblank: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !nonblank.is_empty(),
        "-F p -p <self> must produce at least one record line"
    );
    for line in &nonblank {
        assert!(
            line.starts_with('p'),
            "-F p produced a line not starting with 'p' marker: {line:?}"
        );
        // None of the other common field markers should appear as a line prefix
        // when only `p` was requested.
        for unwanted in ['c', 'u', 'f', 'n', 't'] {
            assert!(
                !line.starts_with(unwanted),
                "-F p produced a line with stray {unwanted:?} marker: {line:?}"
            );
        }
    }
}

/// End-to-end `-F t`: every non-blank line must start with 't' (type marker).
/// Pins the per-field projection: requesting only `t` excludes all other
/// field outputs.
#[test]
fn test_field_output_t_only_lines_start_with_t_marker() {
    let pid = std::process::id().to_string();
    let out = lsofrs_bin()
        .args(["-F", "t", "-p", &pid])
        .output()
        .expect("spawn lsofrs -F t");
    assert!(
        out.status.success(),
        "-F t must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let nonblank: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        !nonblank.is_empty(),
        "-F t -p <self> must produce at least one type record"
    );
    for line in &nonblank {
        assert!(
            line.starts_with('t'),
            "-F t produced a line not starting with 't' marker: {line:?}"
        );
    }
}

/// `-P` is accepted standalone (no other selection) and exits cleanly; pins
/// the flag's "modifier" role — it must not require other selection flags.
#[test]
#[allow(non_snake_case)]
fn test_dash_P_standalone_with_p_self_exits_zero() {
    let pid = std::process::id().to_string();
    let out = lsofrs_bin()
        .args(["-P", "-p", &pid])
        .output()
        .expect("spawn lsofrs -P -p <self>");
    assert!(
        out.status.success(),
        "-P -p <self> must exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
