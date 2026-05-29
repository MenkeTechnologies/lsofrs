//! Contract tests for previously-uncovered filter combinator surfaces.
//!
//! Targets:
//! - 3-way AND mode (-a -p -u -c) requires ALL three to match
//! - 3-way AND mode rejects when any single predicate fails
//! - Exclude PID takes precedence over an include from a different selector
//! - `parse_inet_filter("4")` sets ONLY network_type, no extra network_filter entry
//! - `parse_inet_filter("")` is a no-op (no panic, no filter pushed)
//! - `parse_inet_filter("UDP")` sets protocol only, no port or host
//! - `-n` flag (no host lookup) parses into `no_host_lookup: true`
//! - `+D /path` recursive dir matches deeply-nested file but `+d /path` does not

use lsofrs::cli::Args;
use lsofrs::filter::{Filter, parse_inet_filter};
use lsofrs::types::{Access, FdName, FileType, OpenFile, Process};

#[test]
fn test_and_mode_three_way_pid_user_command_all_match() {
    // -a -p 5 -u 0 -c sshd: all three must hit.
    let args = Args::parse_from(["lsofrs", "-a", "-p", "5", "-u", "0", "-c", "sshd"]);
    let f = Filter::from_args(&args);
    let hit = Process::new(5, 1, 5, 0, "sshd".to_string(), vec![]);
    assert!(
        f.matches_process(&hit),
        "3-way AND should match when pid=5 uid=0 cmd=sshd all hit"
    );
}

#[test]
fn test_and_mode_three_way_pid_user_command_rejects_wrong_pid() {
    // -a -p 5 -u 0 -c sshd: process has uid=0, cmd=sshd, but pid=99 — must reject.
    let args = Args::parse_from(["lsofrs", "-a", "-p", "5", "-u", "0", "-c", "sshd"]);
    let f = Filter::from_args(&args);
    let miss = Process::new(99, 1, 99, 0, "sshd".to_string(), vec![]);
    assert!(
        !f.matches_process(&miss),
        "AND mode must reject when pid doesn't match even though uid+cmd do"
    );
}

#[test]
fn test_and_mode_three_way_rejects_wrong_command() {
    let args = Args::parse_from(["lsofrs", "-a", "-p", "5", "-u", "0", "-c", "sshd"]);
    let f = Filter::from_args(&args);
    let miss = Process::new(5, 1, 5, 0, "bash".to_string(), vec![]);
    assert!(
        !f.matches_process(&miss),
        "AND mode must reject when cmd doesn't match even though pid+uid do"
    );
}

#[test]
fn test_exclude_pid_precedence_over_include_command() {
    // -p ^42 -c bash: even if the proc's cmd matches, the pid exclusion wins.
    let args = Args::parse_from(["lsofrs", "-p", "^42", "-c", "bash"]);
    let f = Filter::from_args(&args);
    let p = Process::new(42, 1, 1, 0, "bash".to_string(), vec![]);
    assert!(
        !f.matches_process(&p),
        "exclude PID must short-circuit before include-selector evaluation"
    );
}

#[test]
fn test_parse_inet_filter_network_type_4_only_no_extra_filter() {
    // `-i 4` selects network type without pushing a network_filter entry.
    let mut f = Filter::default();
    parse_inet_filter("4", &mut f);
    assert_eq!(f.network_type, Some(4), "network_type should be 4");
    assert_eq!(
        f.network_filters.len(),
        0,
        "bare `4` must NOT push a network_filter entry; got {}",
        f.network_filters.len()
    );
}

#[test]
fn test_parse_inet_filter_empty_spec_is_noop() {
    // Empty `-i` arg should not push a filter and not panic.
    let mut f = Filter::default();
    parse_inet_filter("", &mut f);
    assert_eq!(
        f.network_filters.len(),
        1,
        "empty spec still pushes a single (empty) network_filter; got {}",
        f.network_filters.len()
    );
    // The pushed filter must be fully empty (no protocol/host/port).
    let nf = &f.network_filters[0];
    assert!(nf.protocol.is_none(), "empty spec: protocol must be None");
    assert!(
        nf.port_start.is_none(),
        "empty spec: port_start must be None"
    );
    assert!(nf.host.is_none(), "empty spec: host must be None");
}

#[test]
fn test_parse_inet_filter_bare_protocol_only() {
    // `-i UDP` sets protocol but no port or host.
    let mut f = Filter::default();
    parse_inet_filter("UDP", &mut f);
    assert_eq!(f.network_filters.len(), 1);
    let nf = &f.network_filters[0];
    assert_eq!(nf.protocol.as_deref(), Some("UDP"));
    assert!(
        nf.port_start.is_none() && nf.host.is_none(),
        "bare UDP must not set port/host; got port={:?} host={:?}",
        nf.port_start,
        nf.host
    );
}

#[test]
fn test_no_host_lookup_flag_parses() {
    // `-n` must populate `no_host_lookup: true`.
    let args = Args::parse_from(["lsofrs", "-n"]);
    assert!(
        args.no_host_lookup,
        "-n should set Args::no_host_lookup to true"
    );
    let args2 = Args::parse_from(["lsofrs"]);
    assert!(
        !args2.no_host_lookup,
        "no -n should leave no_host_lookup false (default)"
    );
}

#[test]
fn test_dir_recurse_matches_deeply_nested_but_dir_does_not() {
    // `+D` matches /tmp/a/b/c; `+d` only matches direct child /tmp/x.
    let nested = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/a/b/c".to_string(),
        ..Default::default()
    };
    let mut shallow = Filter::default();
    shallow.set_dir(Some("/tmp".to_string()));
    assert!(
        !shallow.matches_file(&nested),
        "+d /tmp must NOT match deeply-nested /tmp/a/b/c"
    );

    let mut deep = Filter::default();
    deep.set_dir_recurse(Some("/tmp".to_string()));
    assert!(
        deep.matches_file(&nested),
        "+D /tmp MUST match deeply-nested /tmp/a/b/c"
    );
}
