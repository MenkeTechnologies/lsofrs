//! Linux process enumeration via /proc filesystem

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::types::*;

/// Gather all process information from /proc
pub fn gather_processes() -> Vec<Process> {
    let socket_map = build_socket_map();
    let mut processes = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return processes;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };

        let proc_dir = PathBuf::from("/proc").join(pid.to_string());

        let Some((command, ppid, pgid, uid)) = read_proc_info(&proc_dir) else {
            continue;
        };

        let mut files = Vec::new();

        // cwd
        if let Ok(target) = fs::read_link(proc_dir.join("cwd")) {
            files.push(OpenFile {
                fd: FdName::Cwd,
                access: Access::Read,
                file_type: FileType::Dir,
                name: target.to_string_lossy().into_owned(),
                ..Default::default()
            });
        }

        // root dir
        if let Ok(target) = fs::read_link(proc_dir.join("root")) {
            files.push(OpenFile {
                fd: FdName::Rtd,
                access: Access::Read,
                file_type: FileType::Dir,
                name: target.to_string_lossy().into_owned(),
                ..Default::default()
            });
        }

        // exe (txt)
        if let Ok(target) = fs::read_link(proc_dir.join("exe")) {
            files.push(OpenFile {
                fd: FdName::Txt,
                access: Access::Read,
                file_type: FileType::Reg,
                name: target.to_string_lossy().into_owned(),
                ..Default::default()
            });
        }

        // Open file descriptors
        let fd_dir = proc_dir.join("fd");
        if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
            for fd_entry in fd_entries.flatten() {
                let fd_name = fd_entry.file_name();
                let Some(fd_num) = fd_name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                    continue;
                };

                let fd_path = fd_dir.join(&fd_name);
                if let Some(of) = process_fd(fd_num, &fd_path, &proc_dir, &socket_map) {
                    files.push(of);
                }
            }
        }

        processes.push(Process {
            pid,
            ppid,
            pgid,
            uid,
            command,
            files,
            sel_flags: 0,
            sel_state: 0,
        });
    }

    processes
}

/// Read process info from /proc/<pid>/stat and /proc/<pid>/status
fn read_proc_info(proc_dir: &Path) -> Option<(String, i32, i32, u32)> {
    // Read /proc/<pid>/stat for command, ppid, pgid
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    let (command, ppid, pgid) = parse_stat(&stat)?;

    // Read /proc/<pid>/status for uid
    let status = fs::read_to_string(proc_dir.join("status")).ok()?;
    let uid = parse_uid(&status).unwrap_or(0);

    Some((command, ppid, pgid, uid))
}

/// Parse /proc/<pid>/stat
/// Format: pid (comm) state ppid pgid ...
fn parse_stat(stat: &str) -> Option<(String, i32, i32)> {
    // comm can contain spaces and parens, so find the last ')'
    let comm_start = stat.find('(')?;
    let comm_end = stat.rfind(')')?;
    let command = stat[comm_start + 1..comm_end].to_string();

    let rest = &stat[comm_end + 2..]; // skip ") "
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] = state, fields[1] = ppid, fields[2] = pgid
    let ppid = fields.get(1)?.parse().ok()?;
    let pgid = fields.get(2)?.parse().ok()?;

    Some((command, ppid, pgid))
}

/// Parse UID from /proc/<pid>/status
fn parse_uid(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Process a single fd symlink
fn process_fd(
    fd_num: i32,
    fd_path: &Path,
    proc_dir: &Path,
    socket_map: &HashMap<u64, SocketEntry>,
) -> Option<OpenFile> {
    let target = fs::read_link(fd_path).ok()?;
    let target_str = target.to_string_lossy().into_owned();

    // Read access mode from fdinfo
    let access = read_fd_access(proc_dir, fd_num);
    let offset = read_fd_offset(proc_dir, fd_num);

    // Determine file type from the target
    if let Some(inode_str) = target_str
        .strip_prefix("socket:[")
        .and_then(|s| s.strip_suffix(']'))
    {
        let inode: u64 = inode_str.parse().unwrap_or(0);
        return Some(process_socket(fd_num, inode, access, socket_map));
    }

    if target_str.starts_with("pipe:[") {
        return Some(OpenFile {
            fd: FdName::Number(fd_num),
            access,
            file_type: FileType::Pipe,
            name: target_str,
            offset,
            ..Default::default()
        });
    }

    if target_str.starts_with("anon_inode:[eventfd")
        || target_str.starts_with("anon_inode:[eventpoll")
        || target_str.starts_with("anon_inode:[signalfd")
        || target_str.starts_with("anon_inode:[timerfd")
        || target_str.starts_with("anon_inode:[inotify")
    {
        return Some(OpenFile {
            fd: FdName::Number(fd_num),
            access,
            file_type: FileType::Unknown(target_str.clone()),
            name: target_str,
            ..Default::default()
        });
    }

    // Regular file — stat for metadata
    let meta = fs::symlink_metadata(fd_path)
        .ok()
        .or_else(|| fs::metadata(&target).ok());

    let (file_type, device, inode, size) = if let Some(m) = &meta {
        let ft = mode_to_file_type(m.mode());
        let dev = m.dev();
        let major = ((dev >> 8) & 0xff) as u32;
        let minor = (dev & 0xff) as u32;
        (ft, Some((major, minor)), Some(m.ino()), Some(m.size()))
    } else {
        (FileType::Reg, None, None, None)
    };

    // Check for deleted files
    let (name, name_append) = if target_str.ends_with(" (deleted)") {
        (
            target_str.trim_end_matches(" (deleted)").to_string(),
            Some("(deleted)".to_string()),
        )
    } else {
        (target_str, None)
    };

    Some(OpenFile {
        fd: FdName::Number(fd_num),
        access,
        file_type,
        device,
        size,
        offset,
        inode,
        name,
        name_append,
        ..Default::default()
    })
}

fn mode_to_file_type(mode: u32) -> FileType {
    match mode & 0o170000 {
        0o140000 => FileType::Sock,
        0o120000 => FileType::Link,
        0o100000 => FileType::Reg,
        0o060000 => FileType::Blk,
        0o040000 => FileType::Dir,
        0o020000 => FileType::Chr,
        0o010000 => FileType::Fifo,
        _ => FileType::Unknown(format!("{:04o}", (mode & 0o170000) >> 12)),
    }
}

fn read_fd_access(proc_dir: &Path, fd_num: i32) -> Access {
    let fdinfo_path = proc_dir.join("fdinfo").join(fd_num.to_string());
    let Ok(content) = fs::read_to_string(fdinfo_path) else {
        return Access::None;
    };

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            let flags: u32 = rest
                .trim()
                .trim_start_matches("0")
                .parse()
                .unwrap_or(0o10000);
            let accmode = flags & 3;
            return match accmode {
                0 => Access::Read,
                1 => Access::Write,
                2 => Access::ReadWrite,
                _ => Access::None,
            };
        }
    }
    Access::None
}

fn read_fd_offset(proc_dir: &Path, fd_num: i32) -> Option<u64> {
    let fdinfo_path = proc_dir.join("fdinfo").join(fd_num.to_string());
    let content = fs::read_to_string(fdinfo_path).ok()?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("pos:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

// ── Socket resolution ───────────────────────────────────────────────

#[derive(Clone)]
struct SocketEntry {
    protocol: String,
    file_type: FileType,
    local: InetAddr,
    foreign: InetAddr,
    state: Option<TcpState>,
    unix_path: Option<String>,
}

/// Build a map of inode -> socket info from /proc/net/*
fn build_socket_map() -> HashMap<u64, SocketEntry> {
    let mut map = HashMap::new();

    parse_inet_sockets("/proc/net/tcp", "TCP", FileType::IPv4, &mut map);
    parse_inet_sockets("/proc/net/tcp6", "TCP", FileType::IPv6, &mut map);
    parse_inet_sockets("/proc/net/udp", "UDP", FileType::IPv4, &mut map);
    parse_inet_sockets("/proc/net/udp6", "UDP", FileType::IPv6, &mut map);
    parse_unix_sockets("/proc/net/unix", &mut map);

    map
}

fn parse_inet_sockets(
    path: &str,
    protocol: &str,
    file_type: FileType,
    map: &mut HashMap<u64, SocketEntry>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let local = parse_hex_endpoint(fields[1], &file_type);
        let foreign = parse_hex_endpoint(fields[2], &file_type);
        let state_hex = u32::from_str_radix(fields[3], 16).unwrap_or(0);
        let inode: u64 = fields[9].parse().unwrap_or(0);

        if inode == 0 {
            continue;
        }

        let state = if protocol == "TCP" {
            Some(tcp_state_from_hex(state_hex))
        } else {
            None
        };

        map.insert(
            inode,
            SocketEntry {
                protocol: protocol.to_string(),
                file_type: file_type.clone(),
                local,
                foreign,
                state,
                unix_path: None,
            },
        );
    }
}

fn parse_hex_endpoint(hex: &str, file_type: &FileType) -> InetAddr {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return InetAddr::default();
    }

    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);

    let addr = if *file_type == FileType::IPv4 {
        let n = u32::from_str_radix(parts[0], 16).unwrap_or(0);
        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(n))))
    } else {
        parse_ipv6_hex(parts[0])
    };

    InetAddr { addr, port }
}

fn parse_ipv6_hex(hex: &str) -> Option<IpAddr> {
    if hex.len() != 32 {
        return None;
    }
    let bytes: Vec<u8> = (0..32)
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if bytes.len() != 16 {
        return None;
    }
    // Linux stores IPv6 in 4 groups of 4 bytes, each in host byte order
    let mut octets = [0u8; 16];
    for group in 0..4 {
        let base = group * 4;
        octets[base] = bytes[base + 3];
        octets[base + 1] = bytes[base + 2];
        octets[base + 2] = bytes[base + 1];
        octets[base + 3] = bytes[base];
    }
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

fn tcp_state_from_hex(state: u32) -> TcpState {
    match state {
        0x01 => TcpState::Established,
        0x02 => TcpState::SynSent,
        0x03 => TcpState::SynRecv,
        0x04 => TcpState::FinWait1,
        0x05 => TcpState::FinWait2,
        0x06 => TcpState::TimeWait,
        0x07 => TcpState::Closed,
        0x08 => TcpState::CloseWait,
        0x09 => TcpState::LastAck,
        0x0A => TcpState::Listen,
        0x0B => TcpState::Closing,
        n => TcpState::Unknown(n as i32),
    }
}

fn parse_unix_sockets(path: &str, map: &mut HashMap<u64, SocketEntry>) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }

        let inode: u64 = fields[6].parse().unwrap_or(0);
        if inode == 0 {
            continue;
        }

        let unix_path = fields.get(7).map(|s| s.to_string());

        map.insert(
            inode,
            SocketEntry {
                protocol: String::new(),
                file_type: FileType::Unix,
                local: InetAddr::default(),
                foreign: InetAddr::default(),
                state: None,
                unix_path,
            },
        );
    }
}

fn process_socket(
    fd_num: i32,
    inode: u64,
    access: Access,
    socket_map: &HashMap<u64, SocketEntry>,
) -> OpenFile {
    if let Some(entry) = socket_map.get(&inode) {
        let name = if entry.file_type == FileType::Unix {
            entry
                .unix_path
                .clone()
                .unwrap_or_else(|| format!("socket:[{inode}]"))
        } else {
            format_inet_name(&entry.local, &entry.foreign, &entry.protocol, &entry.state)
        };

        OpenFile {
            fd: FdName::Number(fd_num),
            access,
            file_type: entry.file_type.clone(),
            name,
            socket_info: Some(SocketInfo {
                protocol: entry.protocol.clone(),
                local: entry.local.clone(),
                foreign: entry.foreign.clone(),
                tcp_state: entry.state,
                ..Default::default()
            }),
            ..Default::default()
        }
    } else {
        OpenFile {
            fd: FdName::Number(fd_num),
            access,
            file_type: FileType::Sock,
            name: format!("socket:[{inode}]"),
            ..Default::default()
        }
    }
}

fn format_inet_name(
    local: &InetAddr,
    foreign: &InetAddr,
    protocol: &str,
    state: &Option<TcpState>,
) -> String {
    let local_str = format_endpoint(local);
    let foreign_str = format_endpoint(foreign);

    let mut name = if foreign.port == 0 && foreign.addr.as_ref().is_none_or(|a| a.is_unspecified())
    {
        local_str
    } else {
        format!("{local_str}->{foreign_str}")
    };

    if let Some(s) = state {
        name.push_str(&format!(" ({s})"));
    }

    name
}

fn format_endpoint(addr: &InetAddr) -> String {
    let addr_str = match &addr.addr {
        Some(a) if a.is_unspecified() => "*".to_string(),
        Some(IpAddr::V4(a)) => a.to_string(),
        Some(IpAddr::V6(a)) => format!("[{a}]"),
        None => "*".to_string(),
    };

    if addr.port == 0 {
        format!("{addr_str}:*")
    } else {
        format!("{addr_str}:{}", addr.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_stat ──────────────────────────────────────────────────

    #[test]
    fn parse_stat_simple() {
        let stat = "1234 (bash) S 1000 1234 1234 0 -1 4194304";
        let (cmd, ppid, pgid) = parse_stat(stat).unwrap();
        assert_eq!(cmd, "bash");
        assert_eq!(ppid, 1000);
        assert_eq!(pgid, 1234);
    }

    #[test]
    fn parse_stat_command_with_spaces() {
        let stat = "5678 (Web Content) S 100 5678 5678 0 -1 0";
        let (cmd, ppid, pgid) = parse_stat(stat).unwrap();
        assert_eq!(cmd, "Web Content");
        assert_eq!(ppid, 100);
    }

    #[test]
    fn parse_stat_command_with_parens() {
        let stat = "999 (foo (bar)) S 1 999 999 0 -1 0";
        let (cmd, ppid, pgid) = parse_stat(stat).unwrap();
        assert_eq!(cmd, "foo (bar)");
        assert_eq!(ppid, 1);
    }

    // ── parse_uid ───────────────────────────────────────────────────

    #[test]
    fn parse_uid_found() {
        let status = "Name:\tbash\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_uid(status), Some(1000));
    }

    #[test]
    fn parse_uid_root() {
        let status = "Uid:\t0\t0\t0\t0\n";
        assert_eq!(parse_uid(status), Some(0));
    }

    #[test]
    fn parse_uid_missing() {
        let status = "Name:\tbash\nGid:\t1000\n";
        assert_eq!(parse_uid(status), None);
    }

    // ── mode_to_file_type ───────────────────────────────────────────

    #[test]
    fn mode_regular() {
        assert_eq!(mode_to_file_type(0o100644), FileType::Reg);
    }

    #[test]
    fn mode_directory() {
        assert_eq!(mode_to_file_type(0o040755), FileType::Dir);
    }

    #[test]
    fn mode_symlink() {
        assert_eq!(mode_to_file_type(0o120777), FileType::Link);
    }

    #[test]
    fn mode_socket() {
        assert_eq!(mode_to_file_type(0o140755), FileType::Sock);
    }

    #[test]
    fn mode_chr() {
        assert_eq!(mode_to_file_type(0o020666), FileType::Chr);
    }

    #[test]
    fn mode_fifo() {
        assert_eq!(mode_to_file_type(0o010644), FileType::Fifo);
    }

    #[test]
    fn mode_block() {
        assert_eq!(mode_to_file_type(0o060660), FileType::Blk);
    }

    // ── hex endpoint parsing ────────────────────────────────────────

    #[test]
    fn parse_ipv4_endpoint() {
        // 0100007F = 127.0.0.1 in network byte order (little-endian hex)
        let addr = parse_hex_endpoint("0100007F:0050", &FileType::IPv4);
        assert_eq!(addr.port, 80);
        assert_eq!(addr.addr.unwrap(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn parse_ipv4_any() {
        let addr = parse_hex_endpoint("00000000:0000", &FileType::IPv4);
        assert_eq!(addr.port, 0);
        assert_eq!(addr.addr.unwrap(), IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));
    }

    #[test]
    fn parse_ipv6_loopback() {
        // ::1 in Linux /proc format
        let addr = parse_hex_endpoint("00000000000000000000000001000000:0050", &FileType::IPv6);
        assert_eq!(addr.port, 80);
    }

    // ── tcp state ───────────────────────────────────────────────────

    #[test]
    fn tcp_state_mapping() {
        assert_eq!(tcp_state_from_hex(0x01), TcpState::Established);
        assert_eq!(tcp_state_from_hex(0x0A), TcpState::Listen);
        assert_eq!(tcp_state_from_hex(0x07), TcpState::Closed);
        assert_eq!(tcp_state_from_hex(0xFF), TcpState::Unknown(0xFF));
    }

    // ── format helpers ──────────────────────────────────────────────

    #[test]
    fn format_endpoint_ipv4() {
        let addr = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            port: 8080,
        };
        assert_eq!(format_endpoint(&addr), "10.0.0.1:8080");
    }

    #[test]
    fn format_endpoint_any() {
        let addr = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 80,
        };
        assert_eq!(format_endpoint(&addr), "*:80");
    }

    #[test]
    fn format_endpoint_no_port() {
        let addr = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: 0,
        };
        assert_eq!(format_endpoint(&addr), "1.2.3.4:*");
    }

    #[test]
    fn format_inet_name_listen() {
        let local = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 80,
        };
        let foreign = InetAddr::default();
        let name = format_inet_name(&local, &foreign, "TCP", &Some(TcpState::Listen));
        assert_eq!(name, "*:80 (LISTEN)");
    }

    #[test]
    fn format_inet_name_established() {
        let local = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            port: 45000,
        };
        let foreign = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
            port: 443,
        };
        let name = format_inet_name(&local, &foreign, "TCP", &Some(TcpState::Established));
        assert!(name.contains("10.0.0.1:45000"));
        assert!(name.contains("93.184.216.34:443"));
        assert!(name.contains("ESTABLISHED"));
    }

    // ── Functional (requires /proc) ─────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn gather_processes_nonempty() {
        let procs = gather_processes();
        assert!(!procs.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gather_processes_finds_self() {
        let my_pid = std::process::id() as i32;
        let procs = gather_processes();
        assert!(procs.iter().any(|p| p.pid == my_pid));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gather_processes_self_has_files() {
        let my_pid = std::process::id() as i32;
        let procs = gather_processes();
        let me = procs.iter().find(|p| p.pid == my_pid).unwrap();
        assert!(!me.files.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gather_processes_have_commands() {
        let procs = gather_processes();
        for p in procs.iter().take(20) {
            assert!(!p.command.is_empty(), "pid {} has empty command", p.pid);
        }
    }
}
