//! Selection and filtering logic

use regex::Regex;

use crate::cli::Args;
use crate::types::*;

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
        } else if args.inet_flag {
            f.network = true;
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
            matches.push(self.usernames.iter().any(|n| *n == uname));
        }
        if !self.pgids.is_empty() {
            matches.push(self.pgids.contains(&proc.pgid));
        }
        if !self.commands.is_empty() {
            matches.push(self.commands.iter().any(|c| proc.command.starts_with(c)));
        }
        if !self.command_regexes.is_empty() {
            matches.push(self.command_regexes.iter().any(|re| re.is_match(&proc.command)));
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
                FdName::Number(n) => {
                    self.fd_filters.iter().any(|f| match f {
                        FdFilter::Range(lo, hi) => *n >= *lo && *n <= *hi,
                        FdFilter::Name(s) => n.to_string() == *s,
                    })
                }
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
                if self.and_mode || (!self.files.is_empty() || self.nfs_only) {
                    // Allow non-network files through if other file filters exist
                } else {
                    return false;
                }
            }
            if let Some(net_type) = self.network_type {
                if net_type == 4 && file.file_type != FileType::IPv4 {
                    if !matches!(file.file_type, FileType::IPv6 | FileType::Unix | FileType::Sock) {
                        return false;
                    }
                    if file.file_type != FileType::IPv4 {
                        return false;
                    }
                }
                if net_type == 6 && file.file_type != FileType::IPv6 {
                    return false;
                }
            }
        }

        // NFS filter
        if self.nfs_only && !file.is_nfs {
            return false;
        }

        // Unix socket filter
        if self.unix_socket && !matches!(file.file_type, FileType::Unix) {
            if !self.network && self.files.is_empty() {
                return false;
            }
        }

        // File name filter
        if !self.files.is_empty() {
            let file_match = self.files.iter().any(|path| {
                file.name == *path || file.name.starts_with(&format!("{path}/"))
            });
            if !file_match && !self.network && !self.nfs_only && !self.unix_socket {
                return false;
            }
        }

        true
    }
}

fn parse_fd_filter(s: &str, filters: &mut Vec<FdFilter>) {
    if let Some(dash_pos) = s.find('-') {
        if let (Ok(lo), Ok(hi)) = (
            s[..dash_pos].parse::<i32>(),
            s[dash_pos + 1..].parse::<i32>(),
        ) {
            filters.push(FdFilter::Range(lo, hi));
            return;
        }
    }
    if let Ok(n) = s.parse::<i32>() {
        filters.push(FdFilter::Range(n, n));
    } else {
        filters.push(FdFilter::Name(s.to_string()));
    }
}

fn parse_inet_filter(spec: &str, filter: &mut Filter) {
    let spec = spec.trim();

    // Check for 4 or 6 prefix
    if spec == "4" {
        filter.network_type = Some(4);
        return;
    }
    if spec == "6" {
        filter.network_type = Some(6);
        return;
    }

    // Parse protocol@host:port format
    let mut nf = NetworkFilter {
        protocol: None,
        addr_family: None,
        addr: None,
        host: None,
        port_start: None,
        port_end: None,
    };

    let mut remaining = spec;

    // Check protocol prefix (TCP/UDP)
    for proto in &["TCP@", "tcp@", "UDP@", "udp@", "TCP:", "tcp:", "UDP:", "udp:"] {
        if let Some(rest) = remaining.strip_prefix(proto) {
            nf.protocol = Some(proto[..3].to_uppercase());
            remaining = rest;
            break;
        }
    }

    // Check for @host
    if let Some(at_pos) = remaining.find('@') {
        let host = &remaining[at_pos + 1..];
        if let Some(colon) = host.rfind(':') {
            nf.host = Some(host[..colon].to_string());
            if let Ok(port) = host[colon + 1..].parse::<u16>() {
                nf.port_start = Some(port);
                nf.port_end = Some(port);
            }
        } else {
            nf.host = Some(host.to_string());
        }
    } else if let Some(colon) = remaining.find(':') {
        if let Ok(port) = remaining[colon + 1..].parse::<u16>() {
            nf.port_start = Some(port);
            nf.port_end = Some(port);
        }
    }

    filter.network_filters.push(nf);
}
