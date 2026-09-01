//! Linux process enumeration via /proc filesystem

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rayon::prelude::*;

use crate::types::*;

/// Process a single PID directory into a Process struct
fn process_pid(pid: i32, socket_map: &HashMap<u64, SocketEntry>) -> Option<Process> {
    let proc_dir = PathBuf::from("/proc").join(pid.to_string());

    let (command, ppid, pgid, uid) = read_proc_info(&proc_dir)?;

    let mut files = Vec::new();

    // cwd, root dir, executable (txt)
    for (link, fd, fallback) in [
        ("cwd", FdName::Cwd, FileType::Dir),
        ("root", FdName::Rtd, FileType::Dir),
        ("exe", FdName::Txt, FileType::Reg),
    ] {
        if let Some(f) = path_link_file(&proc_dir, link, fd, fallback) {
            files.push(f);
        }
    }

    // Mapped files (mem) — the executable is already reported as txt.
    let mut mapped_seen: HashSet<(u32, u32, u64)> = files
        .iter()
        .filter_map(|f| match (f.device, f.inode) {
            (Some((maj, min)), Some(ino)) => Some((maj, min, ino)),
            _ => None,
        })
        .collect();
    files.extend(mapped_files(&proc_dir, &mut mapped_seen));

    // Open file descriptors
    let fd_dir = proc_dir.join("fd");
    if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
        for fd_entry in fd_entries.flatten() {
            let fd_name = fd_entry.file_name();
            let Some(fd_num) = fd_name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };

            let fd_path = fd_dir.join(&fd_name);
            if let Some(of) = process_fd(fd_num, &fd_path, &proc_dir, socket_map) {
                files.push(of);
            }
        }
    }

    Some(Process::new(pid, ppid, pgid, uid, command, files))
}

/// Gather all process information from /proc
pub fn gather_processes() -> Vec<Process> {
    // Build the socket map before parallel PID processing (shared read-only state)
    let socket_map = Arc::new(build_socket_map());

    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };

    // Collect PIDs sequentially, then process in parallel
    let pids: Vec<i32> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()))
        .collect();

    let mut processes: Vec<Process> = pids
        .into_par_iter()
        .filter_map(|pid| process_pid(pid, &socket_map))
        .collect();

    processes.sort_by_key(|p| p.pid);
    processes
}

/// Read process info from `/proc/<pid>/stat` and `/proc/<pid>/status`
fn read_proc_info(proc_dir: &Path) -> Option<(String, i32, i32, u32)> {
    // Read /proc/<pid>/stat for command, ppid, pgid
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    let (command, ppid, pgid) = parse_stat(&stat)?;

    // Read /proc/<pid>/status for uid
    let status = fs::read_to_string(proc_dir.join("status")).ok()?;
    let uid = parse_uid(&status).unwrap_or(0);

    Some((command, ppid, pgid, uid))
}

/// Parse `/proc/<pid>/stat`
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

/// Parse UID from `/proc/<pid>/status`
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
        // The pipefs device and inode only come from stat'ing the fd itself.
        let meta = fs::metadata(fd_path).ok();
        return Some(OpenFile {
            fd: FdName::Number(fd_num),
            access,
            file_type: FileType::Pipe,
            device: meta.as_ref().map(|m| split_dev(m.dev())),
            inode: meta.as_ref().map(|m| m.ino()),
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

    // Regular file — stat through the fd link, which is what the descriptor
    // actually refers to. Stat'ing the link itself only describes the /proc
    // symlink (always `LINK`, size 64), never the file behind it.
    let meta = fs::metadata(fd_path)
        .ok()
        .or_else(|| fs::metadata(&target).ok());

    let (file_type, device, rdev, inode, size) = if let Some(m) = &meta {
        let ft = mode_to_file_type(m.mode());
        // Character/block nodes report the device they *are*, like lsof.
        let rdev = match ft {
            FileType::Chr | FileType::Blk => Some(split_dev(m.rdev())),
            _ => None,
        };
        // Devices and FIFOs have no meaningful size; lsof prints the offset.
        let size = match ft {
            FileType::Chr | FileType::Blk | FileType::Fifo => None,
            _ => Some(m.size()),
        };
        (ft, Some(split_dev(m.dev())), rdev, Some(m.ino()), size)
    } else {
        (FileType::Reg, None, None, None, None)
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
        rdev,
        size,
        offset,
        inode,
        name,
        name_append,
        ..Default::default()
    })
}

/// Resolve one of `/proc/<pid>/{cwd,root,exe}` into an `OpenFile`, filling in
/// the device/inode/size columns from the target's metadata when it is
/// readable (it is not for processes owned by another user).
fn path_link_file(proc_dir: &Path, link: &str, fd: FdName, fallback: FileType) -> Option<OpenFile> {
    let target = fs::read_link(proc_dir.join(link)).ok()?;
    let meta = fs::metadata(&target).ok();

    let (file_type, device, inode, size) = match &meta {
        Some(m) => (
            mode_to_file_type(m.mode()),
            Some(split_dev(m.dev())),
            Some(m.ino()),
            Some(m.size()),
        ),
        None => (fallback, None, None, None),
    };

    Some(OpenFile {
        fd,
        access: Access::Read,
        file_type,
        device,
        inode,
        size,
        name: target.to_string_lossy().into_owned(),
        ..Default::default()
    })
}

/// Mapped files (`mem`) read from `/proc/<pid>/maps`.
///
/// One row per distinct file-backed mapping — shared libraries, the loader,
/// `mmap`ed data files — deduped by (device, inode) against `seen`, which
/// already holds the cwd/root/exe entries so the executable is not repeated.
/// Anonymous mappings and pseudo-regions (`[heap]`, `[stack]`, …) have no
/// inode and are skipped, as lsof does.
fn mapped_files(proc_dir: &Path, seen: &mut HashSet<(u32, u32, u64)>) -> Vec<OpenFile> {
    let Ok(maps) = fs::read_to_string(proc_dir.join("maps")) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for line in maps.lines() {
        let Some((dev_field, inode_field, path)) = split_maps_line(line) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let Some(inode) = inode_field.parse::<u64>().ok().filter(|&i| i != 0) else {
            continue;
        };
        let Some(device) = parse_maps_dev(dev_field) else {
            continue;
        };
        if !seen.insert((device.0, device.1, inode)) {
            continue;
        }

        let (name, name_append) = match path.strip_suffix(" (deleted)") {
            Some(p) => (p.to_string(), Some("(deleted)".to_string())),
            None => (path.to_string(), None),
        };

        let meta = fs::metadata(&name).ok();
        out.push(OpenFile {
            fd: FdName::Mem,
            access: Access::Read,
            file_type: meta
                .as_ref()
                .map_or(FileType::Reg, |m| mode_to_file_type(m.mode())),
            device: Some(device),
            size: meta.as_ref().map(|m| m.size()),
            inode: Some(inode),
            name,
            name_append,
            ..Default::default()
        });
    }

    out
}

/// Split a `/proc/<pid>/maps` line into its device, inode and path fields.
///
/// The layout is `addr perms offset dev inode path`; the path is everything
/// after the fifth field and may itself contain spaces.
fn split_maps_line(line: &str) -> Option<(&str, &str, &str)> {
    let mut rest = line;
    let mut fields = [""; 5];
    for field in &mut fields {
        rest = rest.trim_start();
        if rest.is_empty() {
            return None;
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        (*field, rest) = rest.split_at(end);
    }
    Some((fields[3], fields[4], rest.trim()))
}

/// Parse the `maj:min` hex device field of a `/proc/<pid>/maps` line.
fn parse_maps_dev(field: &str) -> Option<(u32, u32)> {
    let (maj, min) = field.split_once(':')?;
    Some((
        u32::from_str_radix(maj, 16).ok()?,
        u32::from_str_radix(min, 16).ok()?,
    ))
}

/// Split a `dev_t` into the (major, minor) pair lsof prints.
///
/// Linux encodes both numbers in a 64-bit `dev_t`: 12 low bits of major at
/// 8..20 plus 32 high bits, 8 low bits of minor plus the rest at 12..32. The
/// naive 8-bit split is only correct for tiny device numbers — it mangles
/// anonymous filesystems (`0,2049`) and any minor above 255.
fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    (major as u32, minor as u32)
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
    /// Bytes queued in the kernel send buffer (`tx_queue` from `/proc/net/tcp`).
    send_queue: Option<u64>,
    /// Bytes queued in the kernel receive buffer (`rx_queue` from `/proc/net/tcp`).
    recv_queue: Option<u64>,
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
        // fields[4] is `tx_queue:rx_queue`, both 8-digit hex byte counts.
        let (send_queue, recv_queue) = parse_hex_queues(fields[4]);
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
                send_queue,
                recv_queue,
            },
        );
    }
}

/// Split the `/proc/net/tcp` `tx_queue:rx_queue` column into `(send, recv)`
/// byte counts. Both halves are hexadecimal; a malformed half yields `None`.
fn parse_hex_queues(field: &str) -> (Option<u64>, Option<u64>) {
    let mut parts = field.split(':');
    let tx = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
    let rx = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
    (tx, rx)
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
                send_queue: None,
                recv_queue: None,
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
                send_queue: entry.send_queue,
                recv_queue: entry.recv_queue,
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
    _protocol: &str,
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

    // ── device numbers ──────────────────────────────────────────────

    /// Linux packs major/minor across the whole 64-bit `dev_t`; the naive
    /// 8-bit split mangled anonymous filesystems and any minor above 255.
    #[test]
    fn split_dev_handles_wide_minors() {
        // /dev/null: 1,3
        assert_eq!(split_dev(0x0103), (1, 3));
        // sda1: 8,1
        assert_eq!(split_dev(0x0801), (8, 1));
        // anonymous fs (overlay, tmpfs): 0,2049 -> minor needs 12 bits
        assert_eq!(split_dev(0x80_0001), (0, 2049));
        // Round-trip a major/minor pair too wide for the 12/8-bit low fields,
        // encoded the way glibc's makedev does.
        let makedev = |maj: u64, min: u64| {
            (min & 0xff) | ((maj & 0xfff) << 8) | ((min & !0xff) << 12) | ((maj & !0xfff) << 32)
        };
        assert_eq!(split_dev(makedev(259, 12_345)), (259, 12_345));
        assert_eq!(split_dev(makedev(0x1_2345, 0x6_789a)), (0x1_2345, 0x6_789a));
    }

    // ── /proc/<pid>/maps ────────────────────────────────────────────

    #[test]
    fn split_maps_line_extracts_dev_inode_and_path() {
        let line = "7f9c1a000000-7f9c1a029000 r--p 00000000 fd:01 1310734 /usr/lib/libc.so.6";
        assert_eq!(
            split_maps_line(line),
            Some(("fd:01", "1310734", "/usr/lib/libc.so.6"))
        );
    }

    /// Paths in maps may contain spaces — everything past the fifth field is
    /// the name, not just the next token.
    #[test]
    fn split_maps_line_keeps_spaces_in_path() {
        let line = "00400000-00452000 r-xp 00000000 08:01 917 /opt/my app/bin/tool (deleted)";
        let (dev, inode, path) = split_maps_line(line).unwrap();
        assert_eq!((dev, inode), ("08:01", "917"));
        assert_eq!(path, "/opt/my app/bin/tool (deleted)");
    }

    #[test]
    fn split_maps_line_rejects_anonymous_regions() {
        // Anonymous mappings still have five fields, with a zero inode.
        let line = "7ffd1c000000-7ffd1c021000 rw-p 00000000 00:00 0 ";
        assert_eq!(split_maps_line(line), Some(("00:00", "0", "")));
        assert_eq!(split_maps_line("garbage"), None);
    }

    #[test]
    fn parse_maps_dev_reads_hex() {
        assert_eq!(parse_maps_dev("fd:01"), Some((253, 1)));
        assert_eq!(parse_maps_dev("08:01"), Some((8, 1)));
        assert_eq!(parse_maps_dev("0"), None);
    }

    /// Our own process always maps libc (or, on a static build, at least the
    /// executable) — the mem rows must be real, deduped, and file-backed.
    #[test]
    fn mapped_files_reports_our_own_mappings() {
        let mut seen = HashSet::new();
        let files = mapped_files(Path::new("/proc/self"), &mut seen);
        assert!(!files.is_empty(), "no mem entries for our own process");
        assert!(files.iter().all(|f| matches!(f.fd, FdName::Mem)));
        assert!(files.iter().all(|f| f.name.starts_with('/')));

        let mut keys: Vec<_> = files.iter().map(|f| (f.device, f.inode)).collect();
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate mem entries emitted");
    }

    /// cwd/root/exe carry the device, inode and size columns, and the exe is
    /// not repeated as a mem row.
    #[test]
    fn path_link_file_fills_metadata_and_suppresses_duplicate_mem() {
        let cwd = path_link_file(Path::new("/proc/self"), "cwd", FdName::Cwd, FileType::Dir)
            .expect("no cwd for our own process");
        assert_eq!(cwd.fd, FdName::Cwd);
        assert_eq!(cwd.file_type, FileType::Dir);
        assert!(cwd.device.is_some() && cwd.inode.is_some());

        let exe = path_link_file(Path::new("/proc/self"), "exe", FdName::Txt, FileType::Reg)
            .expect("no exe for our own process");
        let key = (
            exe.device.unwrap().0,
            exe.device.unwrap().1,
            exe.inode.unwrap(),
        );

        let mut seen = HashSet::from([key]);
        let mem = mapped_files(Path::new("/proc/self"), &mut seen);
        assert!(
            !mem.iter()
                .any(|f| f.inode == exe.inode && f.device == exe.device),
            "executable repeated as a mem row"
        );
    }

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
        assert_eq!(pgid, 5678);
    }

    #[test]
    fn parse_stat_command_with_parens() {
        let stat = "999 (foo (bar)) S 1 999 999 0 -1 0";
        let (cmd, ppid, pgid) = parse_stat(stat).unwrap();
        assert_eq!(cmd, "foo (bar)");
        assert_eq!(ppid, 1);
        assert_eq!(pgid, 999);
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

    // ── tcp state exhaustive ──────────────────────────────────────────

    #[test]
    fn tcp_state_all_values() {
        assert_eq!(tcp_state_from_hex(0x02), TcpState::SynSent);
        assert_eq!(tcp_state_from_hex(0x03), TcpState::SynRecv);
        assert_eq!(tcp_state_from_hex(0x04), TcpState::FinWait1);
        assert_eq!(tcp_state_from_hex(0x05), TcpState::FinWait2);
        assert_eq!(tcp_state_from_hex(0x06), TcpState::TimeWait);
        assert_eq!(tcp_state_from_hex(0x08), TcpState::CloseWait);
        assert_eq!(tcp_state_from_hex(0x09), TcpState::LastAck);
        assert_eq!(tcp_state_from_hex(0x0B), TcpState::Closing);
    }

    // ── parse_hex_endpoint edge cases ───────────────────────────────

    #[test]
    fn parse_hex_endpoint_high_port() {
        let addr = parse_hex_endpoint("00000000:FFFF", &FileType::IPv4);
        assert_eq!(addr.port, 65535);
    }

    #[test]
    fn parse_hex_endpoint_bad_format() {
        let addr = parse_hex_endpoint("garbage", &FileType::IPv4);
        assert_eq!(addr.port, 0);
    }

    // ── format helpers edge cases ───────────────────────────────────

    #[test]
    fn format_endpoint_none_addr() {
        let addr = InetAddr {
            addr: None,
            port: 80,
        };
        assert_eq!(format_endpoint(&addr), "*:80");
    }

    #[test]
    fn format_inet_name_udp_no_state() {
        let local = InetAddr {
            addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: 53,
        };
        let foreign = InetAddr::default();
        let name = format_inet_name(&local, &foreign, "UDP", &None);
        assert_eq!(name, "*:53");
    }

    #[test]
    fn format_inet_name_ipv6() {
        let local = InetAddr {
            addr: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            port: 443,
        };
        let foreign = InetAddr::default();
        let name = format_inet_name(&local, &foreign, "TCP", &Some(TcpState::Listen));
        assert!(name.contains("[::1]:443"));
        assert!(name.contains("LISTEN"));
    }

    // ── parse_stat edge cases ───────────────────────────────────────

    #[test]
    fn parse_stat_pid_1() {
        let stat = "1 (systemd) S 0 1 1 0 -1 4194560";
        let (cmd, ppid, pgid) = parse_stat(stat).unwrap();
        assert_eq!(cmd, "systemd");
        assert_eq!(ppid, 0);
        assert_eq!(pgid, 1);
    }

    #[test]
    fn parse_stat_empty_returns_none() {
        assert!(parse_stat("").is_none());
    }

    #[test]
    fn parse_stat_no_parens_returns_none() {
        assert!(parse_stat("1234 bash S 1 1234").is_none());
    }

    // ── mode_to_file_type edge cases ────────────────────────────────

    #[test]
    fn mode_unknown() {
        let ft = mode_to_file_type(0o170000); // S_IFMT itself
        assert!(matches!(ft, FileType::Unknown(_)));
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
