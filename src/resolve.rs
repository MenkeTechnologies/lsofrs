//! Host and service name resolution for socket names.
//!
//! lsof prints `localhost:https` where the kernel reports `127.0.0.1:443`,
//! and `-n` / `-P` turn the two lookups back off. Both directions are cached
//! process-wide: an address or port is resolved once, however many descriptors
//! mention it, and [`warm`] resolves a whole snapshot in parallel before any
//! of it is printed so the lookups do not serialise behind the output.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use rayon::prelude::*;

use crate::types::{InetAddr, Process, SocketInfo};

static HOST_LOOKUP: AtomicBool = AtomicBool::new(true);
static PORT_LOOKUP: AtomicBool = AtomicBool::new(true);

/// Enable or inhibit the two lookups, from `-n` and `-P`.
pub fn configure(host_lookup: bool, port_lookup: bool) {
    HOST_LOOKUP.store(host_lookup, Ordering::Relaxed);
    PORT_LOOKUP.store(port_lookup, Ordering::Relaxed);
}

/// Whether host names are being resolved.
pub fn host_lookup() -> bool {
    HOST_LOOKUP.load(Ordering::Relaxed)
}

/// Whether port numbers are being turned into service names.
pub fn port_lookup() -> bool {
    PORT_LOOKUP.load(Ordering::Relaxed)
}

fn host_cache() -> &'static Mutex<HashMap<IpAddr, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<IpAddr, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve every distinct address in a snapshot at once.
///
/// Reverse DNS is dominated by waiting, so the lookups run in parallel and
/// land in the cache before printing walks the same addresses one at a time.
pub fn warm(procs: &[Process]) {
    if !host_lookup() {
        return;
    }

    let mut addrs: Vec<IpAddr> = procs
        .iter()
        .flat_map(|p| p.files.iter())
        .filter_map(|f| f.socket_info.as_ref())
        .flat_map(|si| [si.local.addr, si.foreign.addr])
        .flatten()
        .collect();
    addrs.sort();
    addrs.dedup();

    let resolved: Vec<(IpAddr, Option<String>)> =
        addrs.par_iter().map(|a| (*a, lookup_host(a))).collect();

    if let Ok(mut cache) = host_cache().lock() {
        cache.extend(resolved);
    }
}

/// The name for an address, or `None` when it has none (or lookup is off).
pub fn host(addr: &IpAddr) -> Option<String> {
    if !host_lookup() {
        return None;
    }
    if let Ok(cache) = host_cache().lock()
        && let Some(hit) = cache.get(addr)
    {
        return hit.clone();
    }
    let name = lookup_host(addr);
    if let Ok(mut cache) = host_cache().lock() {
        cache.insert(*addr, name.clone());
    }
    name
}

/// Reverse-resolve one address with `getnameinfo(3)`.
fn lookup_host(addr: &IpAddr) -> Option<String> {
    if addr.is_unspecified() {
        return None;
    }

    // c_char is signed on x86 and unsigned on ARM; let libc name the type.
    let mut buf = [0 as libc::c_char; libc::NI_MAXHOST as usize];
    let rc = unsafe {
        match addr {
            IpAddr::V4(v4) => {
                let sa = libc::sockaddr_in {
                    #[cfg(target_os = "macos")]
                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    buf.as_mut_ptr(),
                    buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
            IpAddr::V6(v6) => {
                let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
                #[cfg(target_os = "macos")]
                {
                    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                }
                sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sa.sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                libc::getnameinfo(
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    buf.as_mut_ptr(),
                    buf.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let bytes: Vec<u8> = buf[..end].iter().map(|&c| c as u8).collect();
    String::from_utf8(bytes).ok().filter(|s| !s.is_empty())
}

/// `/etc/services`, keyed by (port, protocol).
fn service_table() -> &'static HashMap<(u16, String), String> {
    static TABLE: OnceLock<HashMap<(u16, String), String>> = OnceLock::new();
    TABLE.get_or_init(|| match std::fs::read_to_string("/etc/services") {
        Ok(text) => parse_services(&text),
        Err(_) => HashMap::new(),
    })
}

/// Parse `/etc/services` into a (port, protocol) -> name map.
///
/// Lines are `name port/proto [aliases…] # comment`; the first name wins, as
/// `getservbyport(3)` returns the primary entry.
fn parse_services(text: &str) -> HashMap<(u16, String), String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        let mut fields = line.split_whitespace();
        let (Some(name), Some(port_proto)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((port, proto)) = port_proto.split_once('/') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        map.entry((port, proto.to_ascii_lowercase()))
            .or_insert_with(|| name.to_string());
    }
    map
}

/// The service name for a port, or `None` when it has none (or lookup is off).
pub fn service(port: u16, protocol: &str) -> Option<String> {
    if !port_lookup() || port == 0 {
        return None;
    }
    let proto = if protocol.is_empty() {
        "tcp".to_string()
    } else {
        protocol.to_ascii_lowercase()
    };
    service_table().get(&(port, proto)).cloned()
}

/// Render one endpoint the way lsof does, resolving where allowed.
pub fn endpoint(addr: &InetAddr, protocol: &str) -> String {
    let host_str = match &addr.addr {
        Some(a) if a.is_unspecified() => "*".to_string(),
        Some(a) => host(a).unwrap_or_else(|| match a {
            IpAddr::V6(v6) => format!("[{v6}]"),
            v4 => v4.to_string(),
        }),
        None => "*".to_string(),
    };

    let port_str = match addr.port {
        0 => "*".to_string(),
        p => service(p, protocol).unwrap_or_else(|| p.to_string()),
    };

    format!("{host_str}:{port_str}")
}

/// Render an internet socket's name: `local` alone when it has no peer,
/// `local->foreign` otherwise.
pub fn inet_name(si: &SocketInfo) -> String {
    let local = endpoint(&si.local, &si.protocol);
    let unconnected =
        si.foreign.port == 0 && si.foreign.addr.as_ref().is_none_or(|a| a.is_unspecified());
    if unconnected {
        local
    } else {
        format!("{local}->{}", endpoint(&si.foreign, &si.protocol))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::MutexGuard;

    /// The lookup switches are process-wide, so the tests that flip them take
    /// turns and put the defaults back when they are done.
    fn exclusive() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        configure(true, true);
        guard
    }

    /// `-P` inhibits the service lookup; without it, well-known ports get the
    /// names lsof shows.
    #[test]
    fn service_names_come_from_etc_services() {
        let _guard = exclusive();
        // Parsed from a fixture: the host's /etc/services may be absent (it is
        // in a minimal container), and the mapping is what matters here.
        let table = parse_services(
            "# comment line\n\
             ssh\t\t22/tcp\n\
             ssh\t\t22/udp\n\
             https\t\t443/tcp\thttp-alt # secure http\n\
             domain\t\t53/udp\n\
             bogus\t\tnotaport/tcp\n",
        );
        assert_eq!(
            table.get(&(22, "tcp".to_string())).map(String::as_str),
            Some("ssh")
        );
        assert_eq!(
            table.get(&(443, "tcp".to_string())).map(String::as_str),
            Some("https")
        );
        assert_eq!(
            table.get(&(53, "udp".to_string())).map(String::as_str),
            Some("domain")
        );
        assert_eq!(table.get(&(443, "udp".to_string())), None);
        assert_eq!(table.len(), 4, "malformed lines must be skipped");

        // Port 0 is the wildcard, never a service, and -P turns the whole
        // lookup off.
        assert_eq!(service(0, "tcp"), None);
        configure(false, false);
        assert_eq!(service(22, "tcp"), None);
    }

    /// The loopback address resolves to a name on every machine that has a
    /// hosts file; an unspecified address never does.
    #[test]
    fn host_lookup_respects_the_inhibit_flag() {
        let _guard = exclusive();
        configure(false, false);
        assert_eq!(host(&IpAddr::V4(Ipv4Addr::LOCALHOST)), None);

        configure(true, false);
        assert_eq!(host(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None);
        assert_eq!(host(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None);
        configure(true, true);
    }

    /// A listening socket is named by its local end alone; a connected one
    /// gets the `->` pair, with the wildcard rendered as `*`.
    #[test]
    fn inet_name_renders_both_shapes() {
        let _guard = exclusive();
        configure(false, false);
        let listen = SocketInfo {
            protocol: "TCP".to_string(),
            local: InetAddr {
                addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 8080,
            },
            ..Default::default()
        };
        assert_eq!(inet_name(&listen), "*:8080");

        let connected = SocketInfo {
            protocol: "TCP".to_string(),
            local: InetAddr {
                addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                port: 45000,
            },
            foreign: InetAddr {
                addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                port: 443,
            },
            ..Default::default()
        };
        assert_eq!(inet_name(&connected), "10.0.0.1:45000->93.184.216.34:443");

        // With the port lookup on, a known port names its service — when the
        // host has an /etc/services to name it from.
        configure(false, true);
        let expected = match service(443, "TCP") {
            Some(name) => format!("10.0.0.1:45000->93.184.216.34:{name}"),
            None => "10.0.0.1:45000->93.184.216.34:443".to_string(),
        };
        assert_eq!(inet_name(&connected), expected);
    }

    /// IPv6 literals are bracketed, the way lsof prints them.
    #[test]
    fn inet_name_brackets_ipv6() {
        let _guard = exclusive();
        configure(false, false);
        let si = SocketInfo {
            protocol: "TCP".to_string(),
            local: InetAddr {
                addr: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                port: 443,
            },
            ..Default::default()
        };
        assert_eq!(inet_name(&si), "[::1]:443");
        configure(true, true);
    }
}
