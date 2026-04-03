//! Selection and filtering logic

use regex::Regex;

use crate::cli::Args;
use crate::types::*;

#[derive(Default)]
pub struct Filter {
    pub pids: Vec<i32>,
    pub exclude_pids: Vec<i32>,
    pub uids: Vec<u32>,
    pub exclude_uids: Vec<u32>,
    pub usernames: Vec<String>,
    pub exclude_usernames: Vec<String>,
    pub pgids: Vec<i32>,
    pub commands: Vec<String>,
    pub command_regexes: Vec<Regex>,
    pub fd_filters: Vec<FdFilter>,
    pub fd_exclude: bool,
    pub network: bool,
    pub network_type: Option<u8>, // 4 or 6
    pub network_filters: Vec<NetworkFilter>,
    pub nfs_only: bool,
    pub unix_socket: bool,
    pub files: Vec<String>,
    pub dir: Option<String>,         // +d: one level
    pub dir_recurse: Option<String>, // +D: recursive
    pub and_mode: bool,
    pub terse: bool,
}

impl Filter {
    pub fn from_args(args: &Args) -> Self {
        let mut f = Self {
            pids: Vec::new(),
            exclude_pids: Vec::new(),
            uids: Vec::new(),
            exclude_uids: Vec::new(),
            usernames: Vec::new(),
            exclude_usernames: Vec::new(),
            pgids: Vec::new(),
            commands: Vec::new(),
            command_regexes: Vec::new(),
            fd_filters: Vec::new(),
            fd_exclude: false,
            network: false,
            network_type: None,
            network_filters: Vec::new(),
            nfs_only: args.nfs,
            unix_socket: args.unix_socket,
            files: args.files.clone(),
            dir: args.dir.clone(),
            dir_recurse: args.dir_recurse.clone(),
            and_mode: args.and_mode,
            terse: args.terse,
        };

        // Parse PIDs
        if let Some(ref pids) = args.pid {
            for p in pids.split(',') {
                let p = p.trim();
                if let Some(stripped) = p.strip_prefix('^') {
                    if let Ok(pid) = stripped.parse::<i32>() {
                        f.exclude_pids.push(pid);
                    }
                } else if let Ok(pid) = p.parse::<i32>() {
                    f.pids.push(pid);
                }
            }
        }

        // Parse UIDs/users
        if let Some(ref users) = args.user {
            for u in users.split(',') {
                let u = u.trim();
                let (exclude, name) = if let Some(stripped) = u.strip_prefix('^') {
                    (true, stripped)
                } else {
                    (false, u)
                };

                if let Ok(uid) = name.parse::<u32>() {
                    if exclude {
                        f.exclude_uids.push(uid);
                    } else {
                        f.uids.push(uid);
                    }
                } else if exclude {
                    f.exclude_usernames.push(name.to_string());
                } else {
                    f.usernames.push(name.to_string());
                }
            }
        }

        // Parse PGIDs
        if let Some(ref pgids) = args.pgid {
            for g in pgids.split(',') {
                if let Ok(pgid) = g.trim().parse::<i32>() {
                    f.pgids.push(pgid);
                }
            }
        }

        // Parse commands
        if let Some(ref cmds) = args.command {
            for c in cmds.split(',') {
                let c = c.trim();
                if c.starts_with('/') && c.ends_with('/') && c.len() > 2 {
                    if let Ok(re) = Regex::new(&c[1..c.len() - 1]) {
                        f.command_regexes.push(re);
                    }
                } else {
                    f.commands.push(c.to_string());
                }
            }
        }

        // Parse FD filters
        if let Some(ref fds) = args.fd {
            for d in fds.split(',') {
                let d = d.trim();
                if let Some(stripped) = d.strip_prefix('^') {
                    f.fd_exclude = true;
                    parse_fd_filter(stripped, &mut f.fd_filters);
                } else {
                    parse_fd_filter(d, &mut f.fd_filters);
                }
            }
        }

        // Parse network filter
        if let Some(ref inet) = args.inet {
            f.network = true;
            if !inet.is_empty() {
                parse_inet_filter(inet, &mut f);
            }
        }

        f
    }

    pub fn matches_process(&self, proc: &Process) -> bool {
        // Check exclusions first
        if self.exclude_pids.contains(&proc.pid) {
            return false;
        }
        if self.exclude_uids.contains(&proc.uid) {
            return false;
        }
        for name in &self.exclude_usernames {
            if proc.username() == *name {
                return false;
            }
        }

        let has_proc_filter = !self.pids.is_empty()
            || !self.uids.is_empty()
            || !self.usernames.is_empty()
            || !self.pgids.is_empty()
            || !self.commands.is_empty()
            || !self.command_regexes.is_empty();

        if !has_proc_filter {
            return true;
        }

        let mut matches = Vec::new();

        if !self.pids.is_empty() {
            matches.push(self.pids.contains(&proc.pid));
        }
        if !self.uids.is_empty() {
            matches.push(self.uids.contains(&proc.uid));
        }
        if !self.usernames.is_empty() {
            let uname = proc.username();
            matches.push(self.usernames.contains(&uname));
        }
        if !self.pgids.is_empty() {
            matches.push(self.pgids.contains(&proc.pgid));
        }
        if !self.commands.is_empty() {
            matches.push(self.commands.iter().any(|c| proc.command.starts_with(c)));
        }
        if !self.command_regexes.is_empty() {
            matches.push(
                self.command_regexes
                    .iter()
                    .any(|re| re.is_match(&proc.command)),
            );
        }

        if self.and_mode {
            matches.iter().all(|&m| m)
        } else {
            matches.iter().any(|&m| m)
        }
    }

    pub fn matches_file(&self, file: &OpenFile) -> bool {
        // FD filter
        if !self.fd_filters.is_empty() {
            let fd_match = match &file.fd {
                FdName::Number(n) => self.fd_filters.iter().any(|f| match f {
                    FdFilter::Range(lo, hi) => *n >= *lo && *n <= *hi,
                    FdFilter::Name(s) => n.to_string() == *s,
                }),
                other => {
                    let name = other.as_display();
                    self.fd_filters.iter().any(|f| match f {
                        FdFilter::Name(s) => *s == name,
                        _ => false,
                    })
                }
            };
            if self.fd_exclude {
                if fd_match {
                    return false;
                }
            } else if !fd_match {
                return false;
            }
        }

        // Network filter
        if self.network {
            let is_network = matches!(
                file.file_type,
                FileType::IPv4 | FileType::IPv6 | FileType::Unix | FileType::Sock
            );
            if !is_network {
                if self.and_mode || !self.files.is_empty() || self.nfs_only {
                    // Allow non-network files through if other file filters exist
                } else {
                    return false;
                }
            }
            // Address family filter (4/6)
            if let Some(net_type) = self.network_type {
                if net_type == 4 && file.file_type != FileType::IPv4 {
                    return false;
                }
                if net_type == 6 && file.file_type != FileType::IPv6 {
                    return false;
                }
            }
            // Protocol/host/port filters from -i spec
            if !self.network_filters.is_empty() && is_network {
                let matches_any = self.network_filters.iter().any(|nf| {
                    // Protocol check
                    if let Some(ref proto) = nf.protocol {
                        if let Some(ref si) = file.socket_info {
                            if !si.protocol.eq_ignore_ascii_case(proto) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    // Port check
                    if let Some(port) = nf.port_start {
                        if let Some(ref si) = file.socket_info {
                            let end = nf.port_end.unwrap_or(port);
                            let local_match = si.local.port >= port && si.local.port <= end;
                            let foreign_match = si.foreign.port >= port && si.foreign.port <= end;
                            if !local_match && !foreign_match {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    // Host check
                    if let Some(ref host) = nf.host {
                        if let Some(ref si) = file.socket_info {
                            let local_match = si
                                .local
                                .addr
                                .as_ref()
                                .is_some_and(|a| a.to_string() == *host);
                            let foreign_match = si
                                .foreign
                                .addr
                                .as_ref()
                                .is_some_and(|a| a.to_string() == *host);
                            let name_match = file.name.contains(host);
                            if !local_match && !foreign_match && !name_match {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    true
                });
                if !matches_any {
                    return false;
                }
            }
        }

        // NFS filter
        if self.nfs_only && !file.is_nfs {
            return false;
        }

        // Unix socket filter
        if self.unix_socket
            && !matches!(file.file_type, FileType::Unix)
            && !self.network
            && self.files.is_empty()
        {
            return false;
        }

        // File name filter
        if !self.files.is_empty() {
            let file_match = self
                .files
                .iter()
                .any(|path| file.name == *path || file.name.starts_with(&format!("{path}/")));
            if !file_match && !self.network && !self.nfs_only && !self.unix_socket {
                return false;
            }
        }

        // +d DIR: files directly in directory (one level, no deeper subdirs)
        if let Some(ref dir) = self.dir {
            let prefix = if dir.ends_with('/') {
                dir.clone()
            } else {
                format!("{dir}/")
            };
            if !file.name.starts_with(&prefix) {
                return false;
            }
            // One level only: no additional '/' after the prefix
            let rest = &file.name[prefix.len()..];
            if rest.contains('/') {
                return false;
            }
        }

        // +D DIR: files recursively under directory
        if let Some(ref dir) = self.dir_recurse {
            let prefix = if dir.ends_with('/') {
                dir.clone()
            } else {
                format!("{dir}/")
            };
            if !file.name.starts_with(&prefix) && file.name != *dir {
                return false;
            }
        }

        true
    }
}

fn parse_fd_filter(s: &str, filters: &mut Vec<FdFilter>) {
    if let Some(dash_pos) = s.find('-')
        && let (Ok(lo), Ok(hi)) = (
            s[..dash_pos].parse::<i32>(),
            s[dash_pos + 1..].parse::<i32>(),
        )
    {
        filters.push(FdFilter::Range(lo, hi));
        return;
    }
    if let Ok(n) = s.parse::<i32>() {
        filters.push(FdFilter::Range(n, n));
    } else {
        filters.push(FdFilter::Name(s.to_string()));
    }
}

pub fn parse_inet_filter(spec: &str, filter: &mut Filter) {
    let mut remaining = spec.trim();

    // Check for 4/6 prefix (may precede protocol, e.g. "4TCP:80")
    if let Some(rest) = remaining.strip_prefix('4') {
        filter.network_type = Some(4);
        remaining = rest;
        if remaining.is_empty() {
            return;
        }
    } else if let Some(rest) = remaining.strip_prefix('6') {
        filter.network_type = Some(6);
        remaining = rest;
        if remaining.is_empty() {
            return;
        }
    }

    let mut nf = NetworkFilter {
        protocol: None,
        addr_family: None,
        addr: None,
        host: None,
        port_start: None,
        port_end: None,
    };

    // Strip protocol prefix (TCP, UDP — bare or followed by @/:)
    let upper = remaining.to_uppercase();
    for proto in &["TCP", "UDP"] {
        if upper.starts_with(proto) {
            nf.protocol = Some(proto.to_string());
            remaining = &remaining[proto.len()..];
            // consume optional separator
            if remaining.starts_with('@') || remaining.starts_with(':') {
                remaining = &remaining[1..];
            }
            break;
        }
    }

    if remaining.is_empty() {
        filter.network_filters.push(nf);
        return;
    }

    // What remains is [@]host[:port] or :port or port
    if let Some(rest) = remaining.strip_prefix('@') {
        remaining = rest;
    }

    // host:port or just port
    if let Some(colon) = remaining.rfind(':') {
        let before = &remaining[..colon];
        let after = &remaining[colon + 1..];
        if let Ok(port) = after.parse::<u16>() {
            if !before.is_empty() {
                nf.host = Some(before.to_string());
            }
            nf.port_start = Some(port);
            nf.port_end = Some(port);
        } else {
            // No valid port, treat whole thing as host
            nf.host = Some(remaining.to_string());
        }
    } else if let Ok(port) = remaining.parse::<u16>() {
        nf.port_start = Some(port);
        nf.port_end = Some(port);
    } else {
        nf.host = Some(remaining.to_string());
    }

    filter.network_filters.push(nf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ── Helper constructors ─────────────────────────────────────────

    fn empty_filter() -> Filter {
        Filter {
            pids: vec![],
            exclude_pids: vec![],
            uids: vec![],
            exclude_uids: vec![],
            usernames: vec![],
            exclude_usernames: vec![],
            pgids: vec![],
            commands: vec![],
            command_regexes: vec![],
            fd_filters: vec![],
            fd_exclude: false,
            network: false,
            network_type: None,
            network_filters: vec![],
            nfs_only: false,
            unix_socket: false,
            files: vec![],
            dir: None,
            dir_recurse: None,
            and_mode: false,
            terse: false,
        }
    }

    fn make_proc(pid: i32, uid: u32, pgid: i32, cmd: &str) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid,
            uid,
            command: cmd.to_string(),
            files: vec![],
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_file(fd: i32, ft: FileType, name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: ft,
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn make_tcp_file(fd: i32, proto: &str, local_port: u16, foreign_port: u16) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: format!("*:{local_port}"),
            socket_info: Some(crate::types::SocketInfo {
                protocol: proto.to_string(),
                local: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port: local_port,
                },
                foreign: InetAddr {
                    addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    port: foreign_port,
                },
                tcp_state: Some(TcpState::Listen),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_cwd_file(name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Cwd,
            access: Access::Read,
            file_type: FileType::Dir,
            name: name.to_string(),
            ..Default::default()
        }
    }

    // ── parse_inet_filter tests ─────────────────────────────────────

    #[test]
    fn inet_filter_bare_4() {
        let mut f = empty_filter();
        parse_inet_filter("4", &mut f);
        assert_eq!(f.network_type, Some(4));
        assert!(f.network_filters.is_empty());
    }

    #[test]
    fn inet_filter_bare_6() {
        let mut f = empty_filter();
        parse_inet_filter("6", &mut f);
        assert_eq!(f.network_type, Some(6));
        assert!(f.network_filters.is_empty());
    }

    #[test]
    fn inet_filter_bare_tcp() {
        let mut f = empty_filter();
        parse_inet_filter("TCP", &mut f);
        assert_eq!(f.network_filters.len(), 1);
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("TCP"));
        assert!(f.network_filters[0].port_start.is_none());
        assert!(f.network_filters[0].host.is_none());
    }

    #[test]
    fn inet_filter_bare_udp_lowercase() {
        let mut f = empty_filter();
        parse_inet_filter("udp", &mut f);
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("UDP"));
    }

    #[test]
    fn inet_filter_tcp_port() {
        let mut f = empty_filter();
        parse_inet_filter("TCP:8080", &mut f);
        let nf = &f.network_filters[0];
        assert_eq!(nf.protocol.as_deref(), Some("TCP"));
        assert_eq!(nf.port_start, Some(8080));
        assert_eq!(nf.port_end, Some(8080));
    }

    #[test]
    fn inet_filter_port_only() {
        let mut f = empty_filter();
        parse_inet_filter(":443", &mut f);
        let nf = &f.network_filters[0];
        assert!(nf.protocol.is_none());
        assert_eq!(nf.port_start, Some(443));
    }

    #[test]
    fn inet_filter_host_port() {
        let mut f = empty_filter();
        parse_inet_filter("@10.0.0.1:80", &mut f);
        let nf = &f.network_filters[0];
        assert_eq!(nf.host.as_deref(), Some("10.0.0.1"));
        assert_eq!(nf.port_start, Some(80));
    }

    #[test]
    fn inet_filter_host_only() {
        let mut f = empty_filter();
        parse_inet_filter("@10.0.0.1", &mut f);
        let nf = &f.network_filters[0];
        assert_eq!(nf.host.as_deref(), Some("10.0.0.1"));
        assert!(nf.port_start.is_none());
    }

    #[test]
    fn inet_filter_4tcp_port() {
        let mut f = empty_filter();
        parse_inet_filter("4TCP:22", &mut f);
        assert_eq!(f.network_type, Some(4));
        let nf = &f.network_filters[0];
        assert_eq!(nf.protocol.as_deref(), Some("TCP"));
        assert_eq!(nf.port_start, Some(22));
    }

    #[test]
    fn inet_filter_6udp() {
        let mut f = empty_filter();
        parse_inet_filter("6UDP", &mut f);
        assert_eq!(f.network_type, Some(6));
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("UDP"));
    }

    #[test]
    fn inet_filter_tcp_at_host_port() {
        let mut f = empty_filter();
        parse_inet_filter("TCP@192.168.1.1:3306", &mut f);
        let nf = &f.network_filters[0];
        assert_eq!(nf.protocol.as_deref(), Some("TCP"));
        assert_eq!(nf.host.as_deref(), Some("192.168.1.1"));
        assert_eq!(nf.port_start, Some(3306));
    }

    // ── parse_fd_filter tests ───────────────────────────────────────

    #[test]
    fn fd_filter_single_number() {
        let mut filters = vec![];
        parse_fd_filter("5", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Range(5, 5)));
    }

    #[test]
    fn fd_filter_range() {
        let mut filters = vec![];
        parse_fd_filter("0-10", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Range(0, 10)));
    }

    #[test]
    fn fd_filter_named() {
        let mut filters = vec![];
        parse_fd_filter("cwd", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Name(s) if s == "cwd"));
    }

    #[test]
    fn fd_filter_txt() {
        let mut filters = vec![];
        parse_fd_filter("txt", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Name(s) if s == "txt"));
    }

    #[test]
    fn fd_filter_empty_string_becomes_name() {
        let mut filters = vec![];
        parse_fd_filter("", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Name(s) if s.is_empty()));
    }

    // ── matches_process tests ───────────────────────────────────────

    #[test]
    fn no_filter_matches_everything() {
        let f = empty_filter();
        assert!(f.matches_process(&make_proc(1, 0, 1, "launchd")));
        assert!(f.matches_process(&make_proc(999, 501, 999, "vim")));
    }

    #[test]
    fn pid_filter_includes() {
        let mut f = empty_filter();
        f.pids = vec![100, 200];
        assert!(f.matches_process(&make_proc(100, 0, 1, "a")));
        assert!(f.matches_process(&make_proc(200, 0, 1, "b")));
        assert!(!f.matches_process(&make_proc(300, 0, 1, "c")));
    }

    #[test]
    fn pid_filter_excludes() {
        let mut f = empty_filter();
        f.exclude_pids = vec![100];
        assert!(!f.matches_process(&make_proc(100, 0, 1, "a")));
        assert!(f.matches_process(&make_proc(200, 0, 1, "b")));
    }

    #[test]
    fn uid_filter() {
        let mut f = empty_filter();
        f.uids = vec![501];
        assert!(f.matches_process(&make_proc(1, 501, 1, "a")));
        assert!(!f.matches_process(&make_proc(1, 0, 1, "b")));
    }

    #[test]
    fn uid_exclude_filter() {
        let mut f = empty_filter();
        f.exclude_uids = vec![0];
        assert!(!f.matches_process(&make_proc(1, 0, 1, "root_proc")));
        assert!(f.matches_process(&make_proc(2, 501, 1, "user_proc")));
    }

    #[test]
    fn pgid_filter() {
        let mut f = empty_filter();
        f.pgids = vec![42];
        assert!(f.matches_process(&make_proc(1, 0, 42, "a")));
        assert!(!f.matches_process(&make_proc(1, 0, 99, "b")));
    }

    #[test]
    fn command_prefix_filter() {
        let mut f = empty_filter();
        f.commands = vec!["Chrome".to_string()];
        assert!(f.matches_process(&make_proc(1, 0, 1, "Chrome Helper")));
        assert!(f.matches_process(&make_proc(1, 0, 1, "Chrome")));
        assert!(!f.matches_process(&make_proc(1, 0, 1, "Firefox")));
    }

    #[test]
    fn command_regex_filter() {
        let mut f = empty_filter();
        f.command_regexes = vec![Regex::new("nginx|apache").unwrap()];
        assert!(f.matches_process(&make_proc(1, 0, 1, "nginx")));
        assert!(f.matches_process(&make_proc(1, 0, 1, "apache2")));
        assert!(!f.matches_process(&make_proc(1, 0, 1, "sshd")));
    }

    #[test]
    fn or_mode_any_match() {
        let mut f = empty_filter();
        f.pids = vec![100];
        f.commands = vec!["vim".to_string()];
        // OR mode: either PID or command matches
        assert!(f.matches_process(&make_proc(100, 0, 1, "bash"))); // pid match
        assert!(f.matches_process(&make_proc(999, 0, 1, "vim"))); // cmd match
        assert!(!f.matches_process(&make_proc(999, 0, 1, "bash"))); // neither
    }

    #[test]
    fn and_mode_all_must_match() {
        let mut f = empty_filter();
        f.and_mode = true;
        f.pids = vec![100];
        f.commands = vec!["vim".to_string()];
        assert!(f.matches_process(&make_proc(100, 0, 1, "vim"))); // both
        assert!(!f.matches_process(&make_proc(100, 0, 1, "bash"))); // pid only
        assert!(!f.matches_process(&make_proc(999, 0, 1, "vim"))); // cmd only
    }

    #[test]
    fn exclude_overrides_include() {
        let mut f = empty_filter();
        f.pids = vec![100];
        f.exclude_pids = vec![100];
        assert!(!f.matches_process(&make_proc(100, 0, 1, "a")));
    }

    // ── matches_file tests ──────────────────────────────────────────

    #[test]
    fn no_filter_matches_all_files() {
        let f = empty_filter();
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/tmp/x")));
        assert!(f.matches_file(&make_file(5, FileType::IPv4, "*:80")));
    }

    #[test]
    fn fd_filter_range_match() {
        let mut f = empty_filter();
        f.fd_filters = vec![FdFilter::Range(0, 5)];
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/tmp/x")));
        assert!(!f.matches_file(&make_file(10, FileType::Reg, "/tmp/y")));
    }

    #[test]
    fn fd_filter_exclude() {
        let mut f = empty_filter();
        f.fd_filters = vec![FdFilter::Range(0, 2)];
        f.fd_exclude = true;
        assert!(!f.matches_file(&make_file(1, FileType::Reg, "/tmp/x")));
        assert!(f.matches_file(&make_file(5, FileType::Reg, "/tmp/y")));
    }

    #[test]
    fn fd_filter_named_cwd() {
        let mut f = empty_filter();
        f.fd_filters = vec![FdFilter::Name("cwd".to_string())];
        assert!(f.matches_file(&make_cwd_file("/home/user")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp")));
    }

    #[test]
    fn network_filter_blocks_non_network() {
        let mut f = empty_filter();
        f.network = true;
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/x")));
        assert!(f.matches_file(&make_file(3, FileType::IPv4, "*:80")));
        assert!(f.matches_file(&make_file(3, FileType::IPv6, "*:80")));
        assert!(f.matches_file(&make_file(3, FileType::Unix, "/tmp/sock")));
    }

    #[test]
    fn network_type_4_blocks_ipv6() {
        let mut f = empty_filter();
        f.network = true;
        f.network_type = Some(4);
        assert!(f.matches_file(&make_file(3, FileType::IPv4, "*:80")));
        assert!(!f.matches_file(&make_file(3, FileType::IPv6, "*:80")));
    }

    #[test]
    fn network_type_6_blocks_ipv4() {
        let mut f = empty_filter();
        f.network = true;
        f.network_type = Some(6);
        assert!(!f.matches_file(&make_file(3, FileType::IPv4, "*:80")));
        assert!(f.matches_file(&make_file(3, FileType::IPv6, "*:80")));
    }

    #[test]
    fn network_protocol_filter_tcp() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: Some("TCP".to_string()),
            addr_family: None,
            addr: None,
            host: None,
            port_start: None,
            port_end: None,
        }];
        assert!(f.matches_file(&make_tcp_file(3, "TCP", 80, 0)));
        assert!(!f.matches_file(&make_tcp_file(3, "UDP", 53, 0)));
    }

    #[test]
    fn network_protocol_filter_matches_mixed_case_protocol() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: Some("tcp".to_string()),
            addr_family: None,
            addr: None,
            host: None,
            port_start: None,
            port_end: None,
        }];
        assert!(f.matches_file(&make_tcp_file(3, "TCP", 443, 0)));
    }

    #[test]
    fn network_port_filter() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: None,
            addr_family: None,
            addr: None,
            host: None,
            port_start: Some(443),
            port_end: Some(443),
        }];
        assert!(f.matches_file(&make_tcp_file(3, "TCP", 443, 0)));
        assert!(f.matches_file(&make_tcp_file(3, "TCP", 0, 443))); // foreign port
        assert!(!f.matches_file(&make_tcp_file(3, "TCP", 80, 0)));
    }

    #[test]
    fn network_host_filter() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: None,
            addr_family: None,
            addr: None,
            host: Some("10.0.0.1".to_string()),
            port_start: None,
            port_end: None,
        }];
        let mut file = make_tcp_file(3, "TCP", 80, 0);
        file.socket_info.as_mut().unwrap().local.addr =
            Some(IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert!(f.matches_file(&file));

        let file2 = make_tcp_file(3, "TCP", 80, 0); // 0.0.0.0
        assert!(!f.matches_file(&file2));
    }

    #[test]
    fn network_host_filter_matches_socket_name_substring() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: None,
            addr_family: None,
            addr: None,
            host: Some("example.com".to_string()),
            port_start: None,
            port_end: None,
        }];
        let mut file = make_tcp_file(3, "TCP", 443, 0);
        file.socket_info.as_mut().unwrap().local.addr = None;
        file.socket_info.as_mut().unwrap().foreign.addr = None;
        file.name = "example.com:443".to_string();
        assert!(f.matches_file(&file));
    }

    #[test]
    fn network_protocol_and_port_combined() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: Some("TCP".to_string()),
            addr_family: None,
            addr: None,
            host: None,
            port_start: Some(80),
            port_end: Some(80),
        }];
        assert!(f.matches_file(&make_tcp_file(3, "TCP", 80, 0)));
        assert!(!f.matches_file(&make_tcp_file(3, "UDP", 80, 0)));
        assert!(!f.matches_file(&make_tcp_file(3, "TCP", 443, 0)));
    }

    #[test]
    fn nfs_filter() {
        let mut f = empty_filter();
        f.nfs_only = true;
        let mut nfs_file = make_file(3, FileType::Reg, "/mnt/nfs/data");
        nfs_file.is_nfs = true;
        assert!(f.matches_file(&nfs_file));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/local")));
    }

    #[test]
    fn unix_socket_filter() {
        let mut f = empty_filter();
        f.unix_socket = true;
        assert!(f.matches_file(&make_file(3, FileType::Unix, "/tmp/sock")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/x")));
    }

    #[test]
    fn file_path_filter() {
        let mut f = empty_filter();
        f.files = vec!["/var/log/syslog".to_string()];
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/syslog")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/other")));
    }

    #[test]
    fn file_path_dir_prefix() {
        let mut f = empty_filter();
        f.files = vec!["/var/log".to_string()];
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/syslog")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/var/logs/other")));
    }

    // ── from_args parsing tests ─────────────────────────────────────

    #[test]
    fn from_args_pid_parsing() {
        let args = Args::parse_from(["lsofrs", "-p", "100,200,^300"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.pids, vec![100, 200]);
        assert_eq!(f.exclude_pids, vec![300]);
    }

    #[test]
    fn from_args_user_parsing() {
        let args = Args::parse_from(["lsofrs", "-u", "root,^nobody,501"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.usernames, vec!["root".to_string()]);
        assert_eq!(f.exclude_usernames, vec!["nobody".to_string()]);
        assert_eq!(f.uids, vec![501]);
    }

    #[test]
    fn from_args_pgid_parsing() {
        let args = Args::parse_from(["lsofrs", "-g", "10,20"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.pgids, vec![10, 20]);
    }

    #[test]
    fn from_args_command_prefix() {
        let args = Args::parse_from(["lsofrs", "-c", "nginx"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.commands, vec!["nginx".to_string()]);
    }

    #[test]
    fn from_args_command_regex() {
        let args = Args::parse_from(["lsofrs", "-c", "/nginx|apache/"]);
        let f = Filter::from_args(&args);
        assert!(f.commands.is_empty());
        assert_eq!(f.command_regexes.len(), 1);
    }

    #[test]
    fn from_args_fd_range() {
        let args = Args::parse_from(["lsofrs", "-d", "0-10,cwd"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.fd_filters.len(), 2);
    }

    #[test]
    fn from_args_fd_exclude() {
        let args = Args::parse_from(["lsofrs", "-d", "^0-2"]);
        let f = Filter::from_args(&args);
        assert!(f.fd_exclude);
    }

    #[test]
    fn from_args_inet_bare() {
        let args = Args::parse_from(["lsofrs", "-i"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert!(f.network_filters.is_empty());
    }

    #[test]
    fn from_args_inet_tcp() {
        let args = Args::parse_from(["lsofrs", "-i", "TCP"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn from_args_inet_port() {
        let args = Args::parse_from(["lsofrs", "-i", ":8080"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_filters[0].port_start, Some(8080));
    }

    #[test]
    fn from_args_and_mode() {
        let args = Args::parse_from(["lsofrs", "-a", "-p", "1", "-i", "TCP"]);
        let f = Filter::from_args(&args);
        assert!(f.and_mode);
    }

    #[test]
    fn from_args_nfs_flag() {
        let args = Args::parse_from(["lsofrs", "-N"]);
        let f = Filter::from_args(&args);
        assert!(f.nfs_only);
    }

    #[test]
    fn from_args_unix_flag() {
        let args = Args::parse_from(["lsofrs", "-U"]);
        let f = Filter::from_args(&args);
        assert!(f.unix_socket);
    }

    #[test]
    fn from_args_file_args() {
        let args = Args::parse_from(["lsofrs", "/tmp/foo", "/var/log/bar"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.files, vec!["/tmp/foo", "/var/log/bar"]);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn multiple_pid_exclusions() {
        let mut f = empty_filter();
        f.exclude_pids = vec![1, 2, 3];
        assert!(!f.matches_process(&make_proc(1, 0, 1, "a")));
        assert!(!f.matches_process(&make_proc(2, 0, 1, "b")));
        assert!(!f.matches_process(&make_proc(3, 0, 1, "c")));
        assert!(f.matches_process(&make_proc(4, 0, 1, "d")));
    }

    #[test]
    fn command_prefix_is_not_substring() {
        let mut f = empty_filter();
        f.commands = vec!["ssh".to_string()];
        assert!(f.matches_process(&make_proc(1, 0, 1, "sshd")));
        assert!(f.matches_process(&make_proc(1, 0, 1, "ssh")));
        // "bssh" does not start with "ssh"
        assert!(!f.matches_process(&make_proc(1, 0, 1, "bssh")));
    }

    #[test]
    fn multiple_commands_or() {
        let mut f = empty_filter();
        f.commands = vec!["nginx".to_string(), "apache".to_string()];
        assert!(f.matches_process(&make_proc(1, 0, 1, "nginx")));
        assert!(f.matches_process(&make_proc(1, 0, 1, "apache2")));
        assert!(!f.matches_process(&make_proc(1, 0, 1, "sshd")));
    }

    #[test]
    fn fd_range_boundary() {
        let mut f = empty_filter();
        f.fd_filters = vec![FdFilter::Range(5, 10)];
        assert!(!f.matches_file(&make_file(4, FileType::Reg, "/x")));
        assert!(f.matches_file(&make_file(5, FileType::Reg, "/x")));
        assert!(f.matches_file(&make_file(10, FileType::Reg, "/x")));
        assert!(!f.matches_file(&make_file(11, FileType::Reg, "/x")));
    }

    #[test]
    fn fd_single_number_is_range_to_self() {
        let mut filters = vec![];
        parse_fd_filter("7", &mut filters);
        assert!(matches!(&filters[0], FdFilter::Range(7, 7)));
    }

    #[test]
    fn network_allows_sock_type() {
        let mut f = empty_filter();
        f.network = true;
        assert!(f.matches_file(&make_file(3, FileType::Sock, "sock")));
    }

    #[test]
    fn network_with_file_filter_allows_non_network() {
        let mut f = empty_filter();
        f.network = true;
        f.files = vec!["/tmp/x".to_string()];
        // non-network file matching file filter should pass
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/tmp/x")));
    }

    #[test]
    fn protocol_filter_case_insensitive() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: Some("TCP".to_string()),
            addr_family: None,
            addr: None,
            host: None,
            port_start: None,
            port_end: None,
        }];
        // lowercase "tcp" in socket info should match "TCP" filter
        assert!(f.matches_file(&make_tcp_file(3, "tcp", 80, 0)));
    }

    #[test]
    fn network_filter_no_socket_info_rejected() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: Some("TCP".to_string()),
            addr_family: None,
            addr: None,
            host: None,
            port_start: None,
            port_end: None,
        }];
        // IPv4 file without socket_info should be rejected by protocol filter
        let file = make_file(3, FileType::IPv4, "*:80");
        assert!(!f.matches_file(&file));
    }

    #[test]
    fn host_matches_in_name() {
        let mut f = empty_filter();
        f.network = true;
        f.network_filters = vec![NetworkFilter {
            protocol: None,
            addr_family: None,
            addr: None,
            host: Some("example.com".to_string()),
            port_start: None,
            port_end: None,
        }];
        let mut file = make_tcp_file(3, "TCP", 80, 0);
        file.name = "10.0.0.1:80->example.com:443".to_string();
        assert!(f.matches_file(&file));
    }

    #[test]
    fn inet_filter_whitespace_trimmed() {
        let mut f = empty_filter();
        parse_inet_filter("  TCP  ", &mut f);
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn from_args_multiple_exclude_uids() {
        let args = Args::parse_from(["lsofrs", "-u", "^0,^65534"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.exclude_uids, vec![0, 65534]);
    }

    #[test]
    fn from_args_mixed_uid_and_username() {
        let args = Args::parse_from(["lsofrs", "-u", "root,0,^nobody"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.usernames, vec!["root".to_string()]);
        assert_eq!(f.uids, vec![0]);
        assert_eq!(f.exclude_usernames, vec!["nobody".to_string()]);
    }

    #[test]
    fn from_args_multiple_commands() {
        let args = Args::parse_from(["lsofrs", "-c", "nginx,apache,/sshd.*/"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.commands, vec!["nginx".to_string(), "apache".to_string()]);
        assert_eq!(f.command_regexes.len(), 1);
    }

    #[test]
    fn from_args_inet_4() {
        let args = Args::parse_from(["lsofrs", "-i", "4"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_type, Some(4));
        assert!(f.network_filters.is_empty());
    }

    #[test]
    fn from_args_inet_6tcp() {
        let args = Args::parse_from(["lsofrs", "-i", "6TCP"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_type, Some(6));
        assert_eq!(f.network_filters[0].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn from_args_inet_6_only_addr_family() {
        let args = Args::parse_from(["lsofrs", "-i", "6"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_type, Some(6));
        assert!(f.network_filters.is_empty());
    }

    #[test]
    fn and_mode_with_uid_and_pgid() {
        let mut f = empty_filter();
        f.and_mode = true;
        f.uids = vec![501];
        f.pgids = vec![42];
        assert!(f.matches_process(&make_proc(1, 501, 42, "x")));
        assert!(!f.matches_process(&make_proc(1, 501, 99, "x"))); // pgid mismatch
        assert!(!f.matches_process(&make_proc(1, 0, 42, "x"))); // uid mismatch
    }

    #[test]
    fn and_mode_pid_and_username_both_required() {
        let mut f = empty_filter();
        f.and_mode = true;
        f.pids = vec![100];
        f.usernames = vec!["root".to_string()];
        assert!(f.matches_process(&make_proc(100, 0, 1, "bash")));
        assert!(!f.matches_process(&make_proc(100, 501, 1, "bash")));
    }

    // ── +d / +D directory filter tests ──────────────────────────────

    #[test]
    fn dir_filter_one_level() {
        let mut f = empty_filter();
        f.dir = Some("/var/log".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/syslog")));
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/auth.log")));
        // Subdirectory should NOT match (one level only)
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/var/log/nginx/access.log")));
        // Different directory
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/other")));
        // Partial name match
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/var/logs/x")));
    }

    #[test]
    fn dir_filter_trailing_slash() {
        let mut f = empty_filter();
        f.dir = Some("/var/log/".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/syslog")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/var/log/nginx/access.log")));
    }

    #[test]
    fn dir_recurse_filter() {
        let mut f = empty_filter();
        f.dir_recurse = Some("/var/log".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/syslog")));
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/nginx/access.log")));
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/var/log/a/b/c/d.log")));
        // Different directory
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/tmp/other")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/var/logs/x")));
    }

    #[test]
    fn dir_recurse_matches_dir_itself() {
        let mut f = empty_filter();
        f.dir_recurse = Some("/var/log".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Dir, "/var/log")));
    }

    #[test]
    fn dir_filter_root_one_level() {
        let mut f = empty_filter();
        f.dir = Some("/".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/foo")));
        assert!(!f.matches_file(&make_file(3, FileType::Reg, "/foo/bar")));
    }

    #[test]
    fn dir_recurse_root_matches_nested_paths() {
        let mut f = empty_filter();
        f.dir_recurse = Some("/".to_string());
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/foo")));
        assert!(f.matches_file(&make_file(3, FileType::Reg, "/a/b/c/d")));
    }

    #[test]
    fn from_args_dir_flag() {
        let args = Args::parse_from(["lsofrs", "--dir", "/var/log"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.dir.as_deref(), Some("/var/log"));
    }

    #[test]
    fn from_args_dir_recurse_flag() {
        let args = Args::parse_from(["lsofrs", "--dir-recurse", "/var/log"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.dir_recurse.as_deref(), Some("/var/log"));
    }

    #[test]
    fn from_args_terse_propagates() {
        let args = Args::parse_from(["lsofrs", "-t"]);
        let f = Filter::from_args(&args);
        assert!(f.terse);
    }

    #[test]
    fn from_args_and_mode_propagates() {
        let args = Args::parse_from(["lsofrs", "-a"]);
        let f = Filter::from_args(&args);
        assert!(f.and_mode);
    }

    #[test]
    fn from_args_nfs_and_unix_socket() {
        let args = Args::parse_from(["lsofrs", "-N", "-U"]);
        let f = Filter::from_args(&args);
        assert!(f.nfs_only);
        assert!(f.unix_socket);
    }

    #[test]
    fn from_args_file_operands() {
        let args = Args::parse_from(["lsofrs", "/tmp/a", "/tmp/b"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.files, vec!["/tmp/a".to_string(), "/tmp/b".to_string()]);
    }

    #[test]
    fn from_args_csv_output_not_in_filter() {
        let args = Args::parse_from(["lsofrs", "--csv"]);
        let f = Filter::from_args(&args);
        assert!(f.files.is_empty());
    }

    #[test]
    fn from_args_pgids_list() {
        let args = Args::parse_from(["lsofrs", "-g", "10,20,30"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.pgids, vec![10, 20, 30]);
    }

    #[test]
    fn from_args_exclude_pid_caret() {
        let args = Args::parse_from(["lsofrs", "-p", "^1,^2,^3"]);
        let f = Filter::from_args(&args);
        assert_eq!(f.exclude_pids, vec![1, 2, 3]);
        assert!(f.pids.is_empty());
    }

    #[test]
    fn from_args_field_output_not_in_filter() {
        let args = Args::parse_from(["lsofrs", "-F", "pcfn"]);
        let f = Filter::from_args(&args);
        assert!(f.files.is_empty());
        assert!(f.pids.is_empty());
    }

    #[test]
    fn from_args_inet_udp_sets_protocol_filter() {
        let args = Args::parse_from(["lsofrs", "-i", "UDP"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert!(
            f.network_filters
                .iter()
                .any(|nf| nf.protocol.as_deref() == Some("UDP"))
        );
    }

    #[test]
    fn from_args_inet_host_only_propagates() {
        let args = Args::parse_from(["lsofrs", "-i", "@203.0.113.5"]);
        let f = Filter::from_args(&args);
        assert!(f.network);
        assert_eq!(f.network_filters[0].host.as_deref(), Some("203.0.113.5"));
        assert!(f.network_filters[0].port_start.is_none());
    }

    #[test]
    fn from_args_pid_trims_each_token() {
        let args = Args::parse_from(["lsofrs", "-p", " 42 , 43 "]);
        let f = Filter::from_args(&args);
        assert_eq!(f.pids, vec![42, 43]);
    }

    #[test]
    fn from_args_exclude_fd_range() {
        let args = Args::parse_from(["lsofrs", "-d", "^0-7"]);
        let f = Filter::from_args(&args);
        assert!(f.fd_exclude);
        assert!(
            f.fd_filters
                .iter()
                .any(|x| matches!(x, FdFilter::Range(0, 7)))
        );
    }

    #[test]
    fn from_args_two_command_regexes() {
        let args = Args::parse_from(["lsofrs", "-c", "/foo/,/bar/"]);
        let f = Filter::from_args(&args);
        assert!(f.commands.is_empty());
        assert_eq!(f.command_regexes.len(), 2);
    }

    #[test]
    fn from_args_exclude_uid_zero_only() {
        let args = Args::parse_from(["lsofrs", "-u", "^0"]);
        let f = Filter::from_args(&args);
        assert!(f.usernames.is_empty());
        assert_eq!(f.exclude_uids, vec![0]);
    }
}
