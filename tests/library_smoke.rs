//! Integration tests against the `lsofrs` library crate (public API stability).

use std::net::{IpAddr, Ipv4Addr};

use lsofrs::cli::Args;
use lsofrs::filter::{Filter, parse_inet_filter};
use lsofrs::strutil::truncate_max_bytes;
use lsofrs::types::{Access, FdName, FileType, InetAddr, OpenFile, Process, SocketInfo, TcpState};

#[test]
fn strutil_truncates_ascii() {
    assert_eq!(truncate_max_bytes("abcdef", 3), "abc");
}

#[test]
fn filter_from_args_comma_separated_pids() {
    let args = Args::parse_from(["lsofrs", "-p", "1,2, 3"]);
    let f = Filter::from_args(&args);
    assert_eq!(f.pids, vec![1, 2, 3]);
}

#[test]
fn filter_from_args_mixed_include_exclude_pid() {
    let args = Args::parse_from(["lsofrs", "-p", "100,^200,300"]);
    let f = Filter::from_args(&args);
    assert_eq!(f.pids, vec![100, 300]);
    assert_eq!(f.exclude_pids, vec![200]);
}

#[test]
fn filter_from_args_numeric_uid() {
    let args = Args::parse_from(["lsofrs", "-u", "0,65534"]);
    let f = Filter::from_args(&args);
    assert_eq!(f.uids, vec![0, 65534]);
}

#[test]
fn filter_from_args_exclude_username() {
    let args = Args::parse_from(["lsofrs", "-u", "^nobody,^nogroup"]);
    let f = Filter::from_args(&args);
    assert_eq!(f.exclude_usernames, vec!["nobody", "nogroup"]);
}

#[test]
fn filter_matches_process_exclude_pid_wins() {
    let args = Args::parse_from(["lsofrs", "-p", "^42"]);
    let f = Filter::from_args(&args);
    let p = Process::new(42, 1, 1, 0, "x".to_string(), vec![]);
    assert!(!f.matches_process(&p));
}

#[test]
fn filter_matches_process_pid_include() {
    let args = Args::parse_from(["lsofrs", "-p", "7"]);
    let f = Filter::from_args(&args);
    let hit = Process::new(7, 1, 1, 0, "a".to_string(), vec![]);
    let miss = Process::new(8, 1, 1, 0, "b".to_string(), vec![]);
    assert!(f.matches_process(&hit));
    assert!(!f.matches_process(&miss));
}

#[test]
fn filter_matches_process_and_mode_requires_all_predicates() {
    let args = Args::parse_from(["lsofrs", "-a", "-p", "5", "-u", "99999"]);
    let f = Filter::from_args(&args);
    let p = Process::new(5, 1, 1, 0, "cmd".to_string(), vec![]);
    assert!(!f.matches_process(&p));
}

#[test]
fn filter_matches_file_fd_numeric_range() {
    let args = Args::parse_from(["lsofrs", "-d", "2-4"]);
    let f = Filter::from_args(&args);
    let hit = OpenFile {
        fd: FdName::Number(3),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/x".to_string(),
        ..Default::default()
    };
    let miss = OpenFile {
        fd: FdName::Number(9),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/y".to_string(),
        ..Default::default()
    };
    assert!(f.matches_file(&hit));
    assert!(!f.matches_file(&miss));
}

#[test]
fn filter_matches_file_fd_exclude_inverts() {
    let args = Args::parse_from(["lsofrs", "-d", "^0-2"]);
    let f = Filter::from_args(&args);
    assert!(f.fd_exclude);
    let inside = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/a".to_string(),
        ..Default::default()
    };
    let outside = OpenFile {
        fd: FdName::Number(10),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/b".to_string(),
        ..Default::default()
    };
    assert!(!f.matches_file(&inside));
    assert!(f.matches_file(&outside));
}

#[test]
fn filter_matches_file_cwd_name_filter() {
    let args = Args::parse_from(["lsofrs", "-d", "cwd"]);
    let f = Filter::from_args(&args);
    let cwd = OpenFile {
        fd: FdName::Cwd,
        access: Access::Read,
        file_type: FileType::Dir,
        name: "/tmp".to_string(),
        ..Default::default()
    };
    assert!(f.matches_file(&cwd));
}

#[test]
fn filter_set_files_prefix_match() {
    let mut f = Filter::default();
    f.set_files(vec!["/var/log".to_string()]);
    let hit = OpenFile {
        fd: FdName::Number(3),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/var/log/syslog".to_string(),
        ..Default::default()
    };
    let miss = OpenFile {
        fd: FdName::Number(3),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/etc/passwd".to_string(),
        ..Default::default()
    };
    assert!(f.matches_file(&hit));
    assert!(!f.matches_file(&miss));
}

#[test]
fn filter_dir_one_level_rejects_nested() {
    let mut f = Filter::default();
    f.set_dir(Some("/tmp".to_string()));
    let direct = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/foo".to_string(),
        ..Default::default()
    };
    let nested = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/sub/file".to_string(),
        ..Default::default()
    };
    assert!(f.matches_file(&direct));
    assert!(!f.matches_file(&nested));
}

#[test]
fn filter_dir_recurse_allows_nested() {
    let mut f = Filter::default();
    f.set_dir_recurse(Some("/tmp".to_string()));
    let nested = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/a/b/c".to_string(),
        ..Default::default()
    };
    assert!(f.matches_file(&nested));
}

#[test]
fn filter_network_flag_rejects_plain_reg_file_without_other_filters() {
    let mut f = Filter::default();
    f.network = true;
    let reg = OpenFile {
        fd: FdName::Number(0),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/etc/hosts".to_string(),
        ..Default::default()
    };
    let tcp = OpenFile {
        fd: FdName::Number(5),
        access: Access::ReadWrite,
        file_type: FileType::IPv4,
        name: "*:443".to_string(),
        ..Default::default()
    };
    assert!(!f.matches_file(&reg));
    assert!(f.matches_file(&tcp));
}

fn tcp_socket_file(port: u16, state: TcpState) -> OpenFile {
    OpenFile {
        fd: FdName::Number(3),
        access: Access::ReadWrite,
        file_type: FileType::IPv4,
        name: format!("*:{port}"),
        socket_info: Some(SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(state),
            local: InetAddr {
                addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port,
            },
            foreign: InetAddr {
                addr: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                port: 0,
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn parse_inet_filter_sets_network_type_and_port() {
    let mut f = Filter::default();
    parse_inet_filter("6UDP:5353", &mut f);
    assert_eq!(f.network_type, Some(6));
    assert!(
        f.network_filters
            .iter()
            .any(|nf| nf.protocol.as_deref() == Some("UDP") && nf.port_start == Some(5353))
    );
}

#[test]
fn filter_from_args_inet_tcp_port_matches_listening_socket() {
    let args = Args::parse_from(["lsofrs", "-i", "TCP:443"]);
    let f = Filter::from_args(&args);
    let hit = tcp_socket_file(443, TcpState::Listen);
    let miss_port = tcp_socket_file(80, TcpState::Listen);
    assert!(f.matches_file(&hit));
    assert!(!f.matches_file(&miss_port));
}

#[test]
fn filter_from_args_inet_port_only_matches_either_local_or_foreign_port() {
    let args = Args::parse_from(["lsofrs", "-i", ":9000"]);
    let f = Filter::from_args(&args);
    let local = tcp_socket_file(9000, TcpState::Listen);
    let mut foreign_match = tcp_socket_file(1, TcpState::Established);
    if let Some(ref mut si) = foreign_match.socket_info {
        si.local.port = 1;
        si.foreign.port = 9000;
    }
    let miss = tcp_socket_file(9001, TcpState::Listen);
    assert!(f.matches_file(&local));
    assert!(f.matches_file(&foreign_match));
    assert!(!f.matches_file(&miss));
}

#[test]
fn filter_matches_process_username_root_uid_zero() {
    let args = Args::parse_from(["lsofrs", "-u", "root"]);
    let f = Filter::from_args(&args);
    let rootish = Process::new(1, 0, 1, 0, "kthreadd".to_string(), vec![]);
    let other = Process::new(2, 1, 2, 65534, "nobody".to_string(), vec![]);
    assert!(f.matches_process(&rootish));
    assert!(!f.matches_process(&other));
}

#[test]
fn filter_matches_process_command_regex_from_args() {
    let args = Args::parse_from(["lsofrs", "-c", "/^nginx$/"]);
    let f = Filter::from_args(&args);
    assert!(f.matches_process(&Process::new(1, 0, 1, 0, "nginx".into(), vec![])));
    assert!(!f.matches_process(&Process::new(1, 0, 1, 0, "nginx-master".into(), vec![])));
}

#[test]
fn filter_matches_process_or_mode_pid_or_command() {
    let args = Args::parse_from(["lsofrs", "-p", "99", "-c", "sshd"]);
    let f = Filter::from_args(&args);
    assert!(f.matches_process(&Process::new(99, 1, 99, 0, "other".into(), vec![])));
    assert!(f.matches_process(&Process::new(1, 0, 1, 0, "sshd".into(), vec![])));
    assert!(!f.matches_process(&Process::new(1, 0, 1, 0, "bash".into(), vec![])));
}

#[test]
fn filter_network_with_nfs_only_allows_nfs_non_network() {
    let mut f = Filter::default();
    f.network = true;
    f.nfs_only = true;
    let mut nfs = OpenFile {
        fd: FdName::Number(1),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/mnt/nfs/a".into(),
        is_nfs: true,
        ..Default::default()
    };
    assert!(f.matches_file(&nfs));
    nfs.is_nfs = false;
    assert!(!f.matches_file(&nfs));
}

#[test]
fn filter_unix_socket_flag_alone_blocks_regular_file() {
    let args = Args::parse_from(["lsofrs", "-U"]);
    let f = Filter::from_args(&args);
    let unix = OpenFile {
        fd: FdName::Number(3),
        access: Access::ReadWrite,
        file_type: FileType::Unix,
        name: "/run/sock".into(),
        ..Default::default()
    };
    let reg = OpenFile {
        fd: FdName::Number(3),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/x".into(),
        ..Default::default()
    };
    assert!(f.matches_file(&unix));
    assert!(!f.matches_file(&reg));
}

#[test]
fn filter_exclude_username_drops_matching_user() {
    let args = Args::parse_from(["lsofrs", "-u", "^root"]);
    let f = Filter::from_args(&args);
    let root_proc = Process::new(1, 0, 1, 0, "systemd".into(), vec![]);
    assert!(!f.matches_process(&root_proc));
}

#[test]
fn filter_matches_process_pgid_list() {
    let args = Args::parse_from(["lsofrs", "-g", "42,99"]);
    let f = Filter::from_args(&args);
    assert!(f.matches_process(&Process::new(1, 0, 42, 0, "a".into(), vec![])));
    assert!(f.matches_process(&Process::new(2, 0, 99, 0, "b".into(), vec![])));
    assert!(!f.matches_process(&Process::new(3, 0, 7, 0, "c".into(), vec![])));
}

#[test]
fn filter_matches_process_command_regex() {
    let args = Args::parse_from(["lsofrs", "-c", "/^nginx$/"]);
    let f = Filter::from_args(&args);
    assert!(f.matches_process(&Process::new(1, 0, 1, 0, "nginx".into(), vec![])));
    assert!(!f.matches_process(&Process::new(1, 0, 1, 0, "nginx-master".into(), vec![])));
}

#[test]
fn parse_inet_filter_tcp_host_sets_parsed_ipv4() {
    let mut f = Filter::default();
    parse_inet_filter("TCP@192.0.2.1:22", &mut f);
    assert_eq!(f.network_filters.len(), 1);
    let nf = &f.network_filters[0];
    assert_eq!(nf.protocol.as_deref(), Some("TCP"));
    assert_eq!(nf.port_start, Some(22));
    assert!(nf.parsed_host.is_some());
}

#[test]
fn filter_set_dir_trailing_slash_normalized_via_matches() {
    let mut f = Filter::default();
    f.set_dir(Some("/tmp/".to_string()));
    let ok = OpenFile {
        fd: FdName::Number(0),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/file".into(),
        ..Default::default()
    };
    let bad = OpenFile {
        fd: FdName::Number(0),
        access: Access::Read,
        file_type: FileType::Reg,
        name: "/tmp/sub/x".into(),
        ..Default::default()
    };
    assert!(f.matches_file(&ok));
    assert!(!f.matches_file(&bad));
}
