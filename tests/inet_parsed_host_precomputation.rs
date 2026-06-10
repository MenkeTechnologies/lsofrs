//! `parse_inet_filter` must precompute `parsed_host: Some(IpAddr)` for every
//! literal IPv4/IPv6 address it sees, including the bracketed-IPv6 form like
//! `TCP[::1]:443`. If a refactor accidentally drops that precomputation, the
//! matcher in `filter::matches_file` falls back to a textual `file.name.contains(host)`
//! branch (src/filter.rs:333) which is both a false-positive vector (it matches
//! the IP literal as a substring anywhere in the socket descriptor's name) and
//! an EXACT-string compare on `addr.to_string()` against the user-supplied
//! string (src/filter.rs:325, 330). For the bracketed form `host = "[::1]"`,
//! `addr.to_string()` produces `"::1"` (no brackets) — so the comparison would
//! silently fail, and matching would only "work" by accident through the
//! substring branch. These tests pin the contract that `parsed_host` is set
//! whenever the user input is a parseable IP literal, regardless of brackets,
//! protocol prefix, or 4/6 selector.
//!
//! Non-boilerplate rationale: existing tests in `src/filter.rs` (lines 810-837)
//! verify `host` and `port_start` are populated but never inspect
//! `parsed_host`. A refactor that removes the `bare.parse::<IpAddr>().ok()`
//! line at src/filter.rs:496 would pass every existing test in this crate
//! while silently breaking IP comparison. This file plugs that gap.

use lsofrs::filter::{Filter, parse_inet_filter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn parsed_host_set_for_bare_ipv4_with_port() {
    let mut f = Filter::default();
    parse_inet_filter("TCP@10.0.0.1:443", &mut f);
    let nf = &f.network_filters[0];
    assert_eq!(
        nf.parsed_host,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        "parsed_host must be precomputed as IpAddr for bare IPv4 host (host string was {:?})",
        nf.host
    );
}

#[test]
fn parsed_host_set_for_bracketed_ipv6_with_port() {
    let mut f = Filter::default();
    parse_inet_filter("TCP[::1]:443", &mut f);
    let nf = &f.network_filters[0];
    // host is stored WITH brackets (per existing test inet_filter_tcp_ipv6_literal_host_port),
    // but parsed_host MUST strip them and parse the inner address.
    assert_eq!(nf.host.as_deref(), Some("[::1]"));
    assert_eq!(
        nf.parsed_host,
        Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        "parsed_host for bracketed [::1] must strip brackets and parse as ::1"
    );
}

#[test]
fn parsed_host_none_for_non_ip_hostname() {
    let mut f = Filter::default();
    parse_inet_filter("TCP@example.com:80", &mut f);
    let nf = &f.network_filters[0];
    assert_eq!(nf.host.as_deref(), Some("example.com"));
    assert!(
        nf.parsed_host.is_none(),
        "DNS names that don't parse as IpAddr must yield parsed_host: None, got {:?}",
        nf.parsed_host
    );
}

#[test]
fn parsed_host_set_for_ipv4_with_4_selector_prefix() {
    // The leading `4` is the IPv4 family selector — it must be consumed BEFORE
    // host parsing, and the IPv4 address still has to be precomputed.
    let mut f = Filter::default();
    parse_inet_filter("4TCP@172.16.0.5:53", &mut f);
    assert_eq!(f.network_type, Some(4));
    let nf = &f.network_filters[0];
    assert_eq!(
        nf.parsed_host,
        Some(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5))),
        "selector + protocol + @host:port chain must still leave parsed_host populated"
    );
}
