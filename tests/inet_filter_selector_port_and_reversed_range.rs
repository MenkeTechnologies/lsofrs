//! Two adversarial gaps in `parse_inet_filter` / `matches_file` port handling
//! that no existing test pins.
//!
//! GAP 1 — bare 4/6 selector followed by `:port` (no protocol).
//!   The natural user idiom for "any IPv4 socket on port 80" is `-i 4:80`
//!   (mirroring the documented `[4|6][proto][@host|addr][:svc|port]` grammar
//!   when the `proto` slot is empty). The existing tests cover `4TCP:22`
//!   (with protocol), `:443` (without 4/6 selector), and bare `4` alone —
//!   but never the selector+colon+port combination. A refactor that swapped
//!   the order of the colon-port parse vs. the 4/6 strip (or that treated
//!   `:80` after consuming the selector as a malformed remainder) would pass
//!   every existing test in the crate while silently breaking this common
//!   user pattern. The post-strip remainder must still flow into the
//!   port-only branch and set `port_start = Some(80)`.
//!
//! GAP 2 — descending (reversed-endpoint) port range matches nothing.
//!   `matches_file` evaluates port filters as `p >= start && p <= end` with
//!   `end = port_end.unwrap_or(start)`. When `port_end < port_start`, no port
//!   satisfies both inequalities, so the filter matches zero files. This is
//!   the correct, predictable behavior for malformed range input (a
//!   reasonable alternative would be to auto-swap, which would silently
//!   change semantics). Existing tests pin ASCENDING port ranges
//!   (8000..=8010 and 100..=200 in tests/contract_csv_fd_port_range.rs and
//!   in-source `network_port_range_matches_local_or_foreign`), and they
//!   pin reversed-endpoint FD ranges (`fd_filter_reversed_range_matches_
//!   no_interior_fd`), but they DO NOT pin reversed-endpoint PORT range
//!   semantics. A refactor that did `let (lo, hi) = (start.min(end),
//!   start.max(end))` for "robustness" would pass every existing test while
//!   changing user-visible filter behavior. This test pins the current
//!   (correct, no-auto-swap) behavior.

use lsofrs::filter::{Filter, parse_inet_filter};
use lsofrs::types::{
    Access, FdName, FileType, InetAddr, NetworkFilter, OpenFile, SocketInfo, TcpState,
};

fn tcp_listener_on(local_port: u16, foreign_port: u16) -> OpenFile {
    OpenFile {
        fd: FdName::Number(3),
        access: Access::ReadWrite,
        file_type: FileType::IPv4,
        name: format!("*:{local_port}"),
        socket_info: Some(SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(TcpState::Listen),
            local: InetAddr {
                addr: None,
                port: local_port,
            },
            foreign: InetAddr {
                addr: None,
                port: foreign_port,
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// GAP 1: `parse_inet_filter("4:80")` must populate BOTH `network_type = 4`
/// AND `port_start = 80` with `host = None` and `protocol = None`. The
/// remainder after stripping the `4` selector is `":80"`, which must flow
/// through the same `:port` branch that handles bare `:443` correctly.
#[test]
fn parse_inet_filter_v4_selector_with_colon_port_no_protocol() {
    let mut f = Filter::default();
    parse_inet_filter("4:80", &mut f);

    assert_eq!(
        f.network_type,
        Some(4),
        "4:80 must consume leading `4` as IPv4 selector"
    );
    assert_eq!(
        f.network_filters.len(),
        1,
        "4:80 must push exactly one network_filter entry (the :port half); \
         got {} entries",
        f.network_filters.len()
    );
    let nf = &f.network_filters[0];
    assert!(
        nf.protocol.is_none(),
        "4:80 has no explicit protocol — protocol must remain None; got {:?}",
        nf.protocol
    );
    assert_eq!(
        nf.port_start,
        Some(80),
        "4:80 must set port_start = 80 via the :port parser branch; got {:?}",
        nf.port_start
    );
    assert_eq!(
        nf.port_end,
        Some(80),
        "4:80 is a singleton port range; port_end must equal port_start"
    );
    assert!(
        nf.host.is_none(),
        "4:80 has no host fragment — host must remain None; got {:?}",
        nf.host
    );
}

/// GAP 1 (companion): same contract for `6:443` — IPv6 selector + colon-port.
/// Pinned alongside the v4 variant because the parser branches on the
/// selector character and the v6 path must mirror v4 semantics.
#[test]
fn parse_inet_filter_v6_selector_with_colon_port_no_protocol() {
    let mut f = Filter::default();
    parse_inet_filter("6:443", &mut f);

    assert_eq!(f.network_type, Some(6));
    let nf = &f.network_filters[0];
    assert!(nf.protocol.is_none());
    assert_eq!(nf.port_start, Some(443));
    assert_eq!(nf.port_end, Some(443));
    assert!(nf.host.is_none());
}

/// GAP 2: A network filter with `port_end < port_start` (a "descending"
/// range — invalid input from the user's perspective) must match NO file.
/// The matcher's clause is `p >= start && p <= end`; with start > end no
/// port satisfies both inequalities. Verifying this at ports that span the
/// inverted range (above port_start, below port_end, at both endpoints,
/// and at a port inside the swapped-range that an auto-swap implementation
/// WOULD accept).
#[test]
fn descending_port_range_matches_no_file_at_any_port_value() {
    let mut f = Filter::default();
    f.network = true;
    f.network_filters = vec![NetworkFilter {
        protocol: None,
        addr_family: None,
        addr: None,
        host: None,
        parsed_host: None,
        // Inverted range: start=9000, end=8000.
        port_start: Some(9000),
        port_end: Some(8000),
    }];

    // The KEY adversarial probe — port 8500 falls inside the
    // start.min(end)..=start.max(end) range that an auto-swap "fix" would
    // accept, but it does NOT satisfy the literal `>= 9000 && <= 8000`
    // contract. If this assertion ever fails, someone refactored the
    // matcher to auto-swap endpoints — silently broadening the filter.
    assert!(
        !f.matches_file(&tcp_listener_on(8500, 0)),
        "port 8500 (inside swapped span 8000..=9000) MUST NOT match a \
         descending range 9000..=8000; auto-swap would accept this"
    );

    // Endpoint probes.
    assert!(
        !f.matches_file(&tcp_listener_on(9000, 0)),
        "port 9000 (= port_start) MUST NOT match descending range; \
         9000 >= 9000 is true but 9000 <= 8000 is false"
    );
    assert!(
        !f.matches_file(&tcp_listener_on(8000, 0)),
        "port 8000 (= port_end) MUST NOT match descending range; \
         8000 >= 9000 is false"
    );

    // Outside the swapped span on both sides.
    assert!(!f.matches_file(&tcp_listener_on(7999, 0)));
    assert!(!f.matches_file(&tcp_listener_on(9001, 0)));

    // Foreign-port side of the OR must also reject 8500.
    assert!(
        !f.matches_file(&tcp_listener_on(0, 8500)),
        "foreign-port 8500 also MUST NOT match a descending range"
    );
}
