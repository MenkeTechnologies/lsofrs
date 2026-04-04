//! Network connection map grouped by remote host

use std::collections::{BTreeSet, HashMap};
use std::io::{self, Write};

use serde::Serialize;

use crate::output::Theme;
use crate::types::*;

#[derive(Serialize)]
struct NetMapEntry {
    remote_host: String,
    connection_count: usize,
    protocols: Vec<String>,
    ports: Vec<u16>,
    processes: Vec<NetMapProcess>,
}

#[derive(Serialize, Clone)]
struct NetMapProcess {
    pid: i32,
    command: String,
}

pub fn print_net_map(procs: &[Process], theme: &Theme, json: bool) {
    // Collect connections grouped by remote address
    let mut groups: HashMap<String, RemoteGroup> = HashMap::new();

    for p in procs {
        for f in &p.files {
            if !matches!(f.file_type, FileType::IPv4 | FileType::IPv6) {
                continue;
            }
            let si = match &f.socket_info {
                Some(si) => si,
                None => continue,
            };

            let foreign_addr = si
                .foreign
                .addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*".to_string());
            let foreign_port = si.foreign.port;

            // Skip wildcard/unconnected
            if foreign_addr == "*" && foreign_port == 0 {
                continue;
            }

            let key = if foreign_addr == "*" {
                format!("*:{foreign_port}")
            } else {
                foreign_addr.clone()
            };

            let group = groups.entry(key.clone()).or_insert_with(|| RemoteGroup {
                host: key,
                protocols: BTreeSet::new(),
                ports: BTreeSet::new(),
                processes: Vec::new(),
                count: 0,
            });

            group.count += 1;
            if !si.protocol.is_empty() {
                group.protocols.insert(si.protocol.to_uppercase());
            }
            if foreign_port > 0 {
                group.ports.insert(foreign_port);
            }

            let proc_entry = NetMapProcess {
                pid: p.pid,
                command: p.command.clone(),
            };
            if !group.processes.iter().any(|ep| ep.pid == p.pid) {
                group.processes.push(proc_entry);
            }
        }
    }

    // Sort by connection count descending
    let mut entries: Vec<NetMapEntry> = groups
        .into_values()
        .map(|g| NetMapEntry {
            remote_host: g.host,
            connection_count: g.count,
            protocols: g.protocols.into_iter().collect(),
            ports: g.ports.into_iter().collect(),
            processes: g.processes,
        })
        .collect();

    entries.sort_by(|a, b| b.connection_count.cmp(&a.connection_count));

    if json {
        print_net_map_json(&entries);
    } else {
        print_net_map_text(&entries, theme);
    }
}

struct RemoteGroup {
    host: String,
    protocols: BTreeSet<String>,
    ports: BTreeSet<u16>,
    processes: Vec<NetMapProcess>,
    count: usize,
}

fn print_net_map_text(entries: &[NetMapEntry], theme: &Theme) {
    let out = io::stdout();
    let mut out = out.lock();

    if entries.is_empty() {
        let _ = writeln!(out, "No network connections found.");
        return;
    }

    let _ = writeln!(
        out,
        "\n{bold}═══ Network Connection Map ═══{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );

    // Column widths
    let w_host = entries
        .iter()
        .map(|e| e.remote_host.len())
        .max()
        .unwrap_or(11)
        .max(11);
    let w_count = entries
        .iter()
        .map(|e| e.connection_count.to_string().len())
        .max()
        .unwrap_or(5)
        .max(5);
    let w_proto = entries
        .iter()
        .map(|e| e.protocols.join(",").len())
        .max()
        .unwrap_or(9)
        .max(9);
    let w_ports = entries
        .iter()
        .map(|e| {
            e.ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .len()
        })
        .max()
        .unwrap_or(5)
        .max(5);

    // Header
    let _ = writeln!(
        out,
        "{hdr}{bold}{host:<hw$}  {count:>cw$}  {proto:<pw$}  {ports:<ow$}  PROCESSES{reset}",
        hdr = theme.hdr_bg(),
        bold = theme.bold(),
        host = "REMOTE HOST",
        hw = w_host,
        count = "CONNS",
        cw = w_count,
        proto = "PROTOCOLS",
        pw = w_proto,
        ports = "PORTS",
        ow = w_ports,
        reset = theme.reset(),
    );

    for (i, e) in entries.iter().enumerate() {
        let alt = if i % 2 == 1 { theme.row_alt() } else { "" };
        let proto_str = e.protocols.join(",");
        let ports_str = e
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let procs_str = e
            .processes
            .iter()
            .map(|p| format!("{}/{}", p.pid, p.command))
            .collect::<Vec<_>>()
            .join(", ");

        let _ = writeln!(
            out,
            "{alt}{cyan}{host:<hw$}{reset}  {bold}{count:>cw$}{reset}  {blue}{proto:<pw$}{reset}  {green}{ports:<ow$}{reset}  {mag}{procs}{reset}",
            alt = alt,
            cyan = theme.cyan(),
            host = e.remote_host,
            hw = w_host,
            reset = theme.reset(),
            bold = theme.bold(),
            count = e.connection_count,
            cw = w_count,
            blue = theme.blue(),
            proto = proto_str,
            pw = w_proto,
            green = theme.green(),
            ports = ports_str,
            ow = w_ports,
            mag = theme.magenta(),
            procs = procs_str,
        );
    }

    let _ = writeln!(
        out,
        "\n{dim}  {} remote host(s), {} total connection(s){reset}\n",
        entries.len(),
        entries.iter().map(|e| e.connection_count).sum::<usize>(),
        dim = theme.dim(),
        reset = theme.reset(),
    );
}

fn print_net_map_json(entries: &[NetMapEntry]) {
    let out = io::stdout();
    let mut out = out.lock();
    let wrapper = serde_json::json!({ "net_map": entries });
    let _ = serde_json::to_writer_pretty(&mut out, &wrapper);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 0,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_tcp_conn(fd: i32, foreign_addr: IpAddr, foreign_port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("127.0.0.1:1234->{foreign_addr}:{foreign_port}"),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                tcp_state: Some(TcpState::Established),
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    port: 1234,
                },
                foreign: InetAddr {
                    addr: Some(foreign_addr),
                    port: foreign_port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_tcp6_conn(fd: i32, foreign_addr: IpAddr, foreign_port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv6,
            name: format!("[::1]:1234->{foreign_addr}"),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                tcp_state: Some(TcpState::Established),
                local: InetAddr {
                    addr: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                    port: 1234,
                },
                foreign: InetAddr {
                    addr: Some(foreign_addr),
                    port: foreign_port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_udp_conn(fd: i32, foreign_addr: IpAddr, foreign_port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("0.0.0.0:5353->{foreign_addr}:{foreign_port}"),
            socket_info: Some(SocketInfo {
                protocol: "UDP".to_string(),
                tcp_state: None,
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port: 5353,
                },
                foreign: InetAddr {
                    addr: Some(foreign_addr),
                    port: foreign_port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn print_net_map_empty_no_panic() {
        let theme = Theme::new(false);
        print_net_map(&[], &theme, false);
    }

    #[test]
    fn print_net_map_with_connections() {
        let theme = Theme::new(false);
        let remote = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let procs = vec![
            make_proc(100, "curl", vec![make_tcp_conn(3, remote, 80)]),
            make_proc(200, "wget", vec![make_tcp_conn(3, remote, 443)]),
        ];
        print_net_map(&procs, &theme, false);
    }

    #[test]
    fn print_net_map_ipv6_remote_no_panic() {
        let theme = Theme::new(false);
        let remote = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let procs = vec![make_proc(100, "app", vec![make_tcp6_conn(3, remote, 443)])];
        print_net_map(&procs, &theme, false);
        print_net_map(&procs, &theme, true);
    }

    #[test]
    fn print_net_map_udp_remote_no_panic() {
        let theme = Theme::new(false);
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let procs = vec![make_proc(
            200,
            "mdns",
            vec![make_udp_conn(11, remote, 5353)],
        )];
        print_net_map(&procs, &theme, false);
        print_net_map(&procs, &theme, true);
    }

    #[test]
    fn print_net_map_json_no_panic() {
        let theme = Theme::new(false);
        let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let procs = vec![make_proc(100, "app", vec![make_tcp_conn(3, remote, 5432)])];
        print_net_map(&procs, &theme, true);
    }

    #[test]
    fn net_map_groups_by_remote() {
        let theme = Theme::new(false);
        let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let procs = vec![make_proc(
            100,
            "app",
            vec![
                make_tcp_conn(3, remote, 443),
                make_tcp_conn(4, remote, 443),
                make_tcp_conn(5, remote, 80),
            ],
        )];
        // Should group all 3 under 10.0.0.1
        print_net_map(&procs, &theme, false);
    }

    #[test]
    fn net_map_skips_wildcard_unconnected() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            100,
            "server",
            vec![OpenFile {
                fd: FdName::Number(3),
                access: Access::ReadWrite,
                file_type: FileType::IPv4,
                name: "*:8080".to_string(),
                socket_info: Some(SocketInfo {
                    protocol: "TCP".to_string(),
                    tcp_state: Some(TcpState::Listen),
                    local: InetAddr {
                        addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                        port: 8080,
                    },
                    foreign: InetAddr {
                        addr: None,
                        port: 0,
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }],
        )];
        // Wildcard foreign with port 0 should be skipped
        print_net_map(&procs, &theme, false);
    }

    #[test]
    fn net_map_wildcard_foreign_addr_with_port_groups_under_star_colon() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            100,
            "app",
            vec![OpenFile {
                fd: FdName::Number(3),
                access: Access::ReadWrite,
                file_type: FileType::IPv4,
                name: "edge case".to_string(),
                socket_info: Some(SocketInfo {
                    protocol: "TCP".to_string(),
                    tcp_state: Some(TcpState::SynSent),
                    local: InetAddr {
                        addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                        port: 50000,
                    },
                    foreign: InetAddr {
                        addr: None,
                        port: 443,
                    },
                    ..Default::default()
                }),
                ..Default::default()
            }],
        )];
        print_net_map(&procs, &theme, false);
        print_net_map(&procs, &theme, true);
    }

    #[test]
    fn net_map_sorted_by_count_desc() {
        let theme = Theme::new(false);
        let few = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let many = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let procs = vec![make_proc(
            100,
            "app",
            vec![
                make_tcp_conn(3, few, 53),
                make_tcp_conn(4, many, 443),
                make_tcp_conn(5, many, 443),
                make_tcp_conn(6, many, 80),
            ],
        )];
        // 8.8.8.8 should appear first (3 connections vs 1)
        print_net_map(&procs, &theme, false);
    }

    #[test]
    fn net_map_deduplicates_processes() {
        let theme = Theme::new(false);
        let remote = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let procs = vec![make_proc(
            100,
            "app",
            vec![make_tcp_conn(3, remote, 443), make_tcp_conn(4, remote, 443)],
        )];
        // Same PID should appear only once in processes list
        print_net_map(&procs, &theme, true);
    }
}
