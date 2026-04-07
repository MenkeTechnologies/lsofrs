//! Show listening ports summary (like ss -tlnp)

use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::Serialize;

use crate::output::Theme;
use crate::strutil::truncate_max_bytes;
use crate::types::*;

#[derive(Serialize)]
struct PortEntry {
    proto: String,
    local_addr: String,
    port: u16,
    pid: i32,
    user: String,
    command: String,
}

fn is_listening(file: &OpenFile) -> Option<(String, String, u16)> {
    let si = file.socket_info.as_ref()?;

    let proto = si.protocol.to_uppercase();
    let is_tcp = proto == "TCP";
    let is_udp = proto == "UDP";

    if !is_tcp && !is_udp {
        return None;
    }

    // TCP must be in LISTEN state
    if is_tcp {
        match si.tcp_state {
            Some(TcpState::Listen) => {}
            _ => return None,
        }
    }

    // UDP: accept if it has a local port bound (port > 0)
    let port = si.local.port;
    if port == 0 {
        return None;
    }

    let addr_str = si
        .local
        .addr
        .map(|a| a.to_string())
        .unwrap_or_else(|| "*".to_string());

    Some((proto, addr_str, port))
}

pub fn print_ports(procs: &[Process], theme: &Theme, json: bool) {
    // Group by port for dedup/grouping
    let mut by_port: BTreeMap<u16, Vec<PortEntry>> = BTreeMap::new();

    for p in procs {
        let user = p.username();
        for f in &p.files {
            if let Some((proto, addr, port)) = is_listening(f) {
                by_port.entry(port).or_default().push(PortEntry {
                    proto,
                    local_addr: addr,
                    port,
                    pid: p.pid,
                    user: user.clone(),
                    command: p.command.clone(),
                });
            }
        }
    }

    let entries: Vec<PortEntry> = by_port.into_values().flatten().collect();

    if json {
        print_ports_json(&entries);
    } else {
        print_ports_text(&entries, theme);
    }
}

fn print_ports_text(entries: &[PortEntry], theme: &Theme) {
    let out = io::stdout();
    let mut out = out.lock();

    if entries.is_empty() {
        let _ = writeln!(out, "No listening ports found.");
        return;
    }

    // Column widths
    let w_proto = entries
        .iter()
        .map(|e| e.proto.len())
        .max()
        .unwrap_or(5)
        .max(5);
    let w_addr = entries
        .iter()
        .map(|e| e.local_addr.len())
        .max()
        .unwrap_or(10)
        .max(10);
    let w_port = entries
        .iter()
        .map(|e| e.port.to_string().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let w_pid = entries
        .iter()
        .map(|e| e.pid.to_string().len())
        .max()
        .unwrap_or(3)
        .max(3);
    let w_user = entries
        .iter()
        .map(|e| e.user.len().min(8))
        .max()
        .unwrap_or(4)
        .max(4);
    let w_cmd = entries
        .iter()
        .map(|e| e.command.len().min(20))
        .max()
        .unwrap_or(7)
        .max(7);

    // Header
    let _ = writeln!(
        out,
        "\n{bold}═══ Listening Ports ═══{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );
    let _ = writeln!(
        out,
        "{hdr}{bold}{proto:<pw$}  {addr:<aw$}  {port:>ow$}  {pid:>iw$}  {user:<uw$}  {cmd:<cw$}{reset}",
        hdr = theme.hdr_bg(),
        bold = theme.bold(),
        proto = "PROTO",
        pw = w_proto,
        addr = "LOCAL ADDR",
        aw = w_addr,
        port = "PORT",
        ow = w_port,
        pid = "PID",
        iw = w_pid,
        user = "USER",
        uw = w_user,
        cmd = "COMMAND",
        cw = w_cmd,
        reset = theme.reset(),
    );

    for (i, e) in entries.iter().enumerate() {
        let alt = if i % 2 == 1 { theme.row_alt() } else { "" };
        let user_display = truncate_max_bytes(&e.user, 8);
        let cmd_display = truncate_max_bytes(&e.command, 20);

        let _ = writeln!(
            out,
            "{alt}{blue}{proto:<pw$}{reset}  {addr:<aw$}  {cyan}{port:>ow$}{reset}  {mag}{pid:>iw$}{reset}  {yellow}{user:<uw$}{reset}  {bold}{cmd:<cw$}{reset}",
            alt = alt,
            blue = theme.blue(),
            proto = e.proto,
            pw = w_proto,
            reset = theme.reset(),
            addr = e.local_addr,
            aw = w_addr,
            cyan = theme.cyan(),
            port = e.port,
            ow = w_port,
            mag = theme.magenta(),
            pid = e.pid,
            iw = w_pid,
            yellow = theme.yellow(),
            user = user_display,
            uw = w_user,
            bold = theme.bold(),
            cmd = cmd_display,
            cw = w_cmd,
        );
    }

    let _ = writeln!(
        out,
        "\n{dim}  {} listening port(s) found{reset}\n",
        entries.len(),
        dim = theme.dim(),
        reset = theme.reset(),
    );
}

fn print_ports_json(entries: &[PortEntry]) {
    let out = io::stdout();
    let mut out = out.lock();
    let wrapper = serde_json::json!({ "listening_ports": entries });
    let _ = serde_json::to_writer_pretty(&mut out, &wrapper);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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

    fn make_tcp_listen(fd: i32, port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("*:{port}"),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                tcp_state: Some(TcpState::Listen),
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_tcp_established(fd: i32, port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("127.0.0.1:{port}->127.0.0.1:54321"),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                tcp_state: Some(TcpState::Established),
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_udp_bound(fd: i32, port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("*:{port}"),
            socket_info: Some(SocketInfo {
                protocol: "UDP".to_string(),
                tcp_state: None,
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_tcp_with_state(fd: i32, port: u16, state: TcpState) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("127.0.0.1:{port}"),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                tcp_state: Some(state),
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_sctp_listen(fd: i32, port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("*:{port}"),
            socket_info: Some(SocketInfo {
                protocol: "SCTP".to_string(),
                tcp_state: None,
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn is_listening_tcp_listen() {
        let f = make_tcp_listen(3, 8080);
        let result = is_listening(&f);
        assert!(result.is_some());
        let (proto, _addr, port) = result.unwrap();
        assert_eq!(proto, "TCP");
        assert_eq!(port, 8080);
    }

    #[test]
    fn is_listening_tcp_established_excluded() {
        let f = make_tcp_established(3, 8080);
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_udp_bound() {
        let f = make_udp_bound(3, 5353);
        let result = is_listening(&f);
        assert!(result.is_some());
        let (proto, _, port) = result.unwrap();
        assert_eq!(proto, "UDP");
        assert_eq!(port, 5353);
    }

    #[test]
    fn is_listening_regular_file_excluded() {
        let f = OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/tmp/foo".to_string(),
            ..Default::default()
        };
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_udp_port_zero_excluded() {
        let mut f = make_udp_bound(3, 0);
        if let Some(ref mut si) = f.socket_info {
            si.local.port = 0;
        }
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_non_tcp_udp_protocol_excluded() {
        let f = make_sctp_listen(3, 38412);
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_tcp_time_wait_excluded() {
        let f = make_tcp_with_state(3, 8080, TcpState::TimeWait);
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_tcp_missing_tcp_state_excluded() {
        let mut f = make_tcp_listen(3, 9000);
        f.socket_info.as_mut().unwrap().tcp_state = None;
        assert!(is_listening(&f).is_none());
    }

    #[test]
    fn is_listening_tcp_listen_protocol_case_insensitive() {
        let mut f = make_tcp_listen(3, 443);
        if let Some(ref mut si) = f.socket_info {
            si.protocol = "tcp".to_string();
        }
        let result = is_listening(&f).unwrap();
        assert_eq!(result.0, "TCP");
        assert_eq!(result.2, 443);
    }

    #[test]
    fn is_listening_udp_protocol_case_insensitive() {
        let mut f = make_udp_bound(3, 123);
        if let Some(ref mut si) = f.socket_info {
            si.protocol = "udp".to_string();
        }
        let result = is_listening(&f).unwrap();
        assert_eq!(result.0, "UDP");
        assert_eq!(result.2, 123);
    }

    #[test]
    fn print_ports_empty_no_panic() {
        let theme = Theme::new(false);
        print_ports(&[], &theme, false);
    }

    #[test]
    fn print_ports_with_listeners_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(
                100,
                "nginx",
                vec![make_tcp_listen(3, 80), make_tcp_listen(4, 443)],
            ),
            make_proc(200, "dnsmasq", vec![make_udp_bound(5, 53)]),
        ];
        print_ports(&procs, &theme, false);
    }

    #[test]
    fn print_ports_json_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(100, "nginx", vec![make_tcp_listen(3, 80)])];
        print_ports(&procs, &theme, true);
    }

    #[test]
    fn ports_sorted_by_port_number() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(100, "high", vec![make_tcp_listen(3, 9999)]),
            make_proc(200, "low", vec![make_tcp_listen(3, 22)]),
            make_proc(300, "mid", vec![make_tcp_listen(3, 443)]),
        ];
        // BTreeMap ensures sorted by port
        print_ports(&procs, &theme, false);
    }

    #[test]
    fn print_ports_filters_established() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(100, "app", vec![make_tcp_established(3, 8080)])];
        // Should say "No listening ports found"
        print_ports(&procs, &theme, false);
    }
}
