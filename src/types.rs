use std::fmt;
use std::net::IpAddr;

use serde::Serialize;

/// Selection flags matching the C implementation
pub const SEL_CMD: u16 = 0x0001;
pub const SEL_FD: u16 = 0x0004;
pub const SEL_NA: u16 = 0x0008;
pub const SEL_NET: u16 = 0x0010;
pub const SEL_NFS: u16 = 0x0020;
pub const SEL_NLINK: u16 = 0x0040;
pub const SEL_NM: u16 = 0x0080;
pub const SEL_PGID: u16 = 0x0100;
pub const SEL_PID: u16 = 0x0200;
pub const SEL_UID: u16 = 0x0400;
pub const SEL_UNX: u16 = 0x0800;
pub const SEL_EXCL_F: u16 = 0x2000;

pub const SEL_PROC: u16 = SEL_CMD | SEL_PGID | SEL_PID | SEL_UID;
pub const SEL_FILE: u16 = SEL_FD | SEL_NFS | SEL_NLINK | SEL_NM;
pub const SEL_NW: u16 = SEL_NA | SEL_NET | SEL_UNX;

/// File type enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum FileType {
    Reg,
    Dir,
    Chr,
    Blk,
    Fifo,
    Sock,
    Link,
    Pipe,
    Kqueue,
    Unix,
    IPv4,
    IPv6,
    Systm,
    Psem,
    Pshm,
    Atalk,
    Fsevents,
    Unknown(String),
}

impl FileType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Reg => "REG",
            Self::Dir => "DIR",
            Self::Chr => "CHR",
            Self::Blk => "BLK",
            Self::Fifo => "FIFO",
            Self::Sock => "sock",
            Self::Link => "LINK",
            Self::Pipe => "PIPE",
            Self::Kqueue => "KQUE",
            Self::Unix => "unix",
            Self::IPv4 => "IPv4",
            Self::IPv6 => "IPv6",
            Self::Systm => "systm",
            Self::Psem => "PSEM",
            Self::Pshm => "PSHM",
            Self::Atalk => "ATALK",
            Self::Fsevents => "FSEV",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Access mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    None,
}

impl Access {
    pub fn as_char(&self) -> char {
        match self {
            Self::Read => 'r',
            Self::Write => 'w',
            Self::ReadWrite => 'u',
            Self::None => ' ',
        }
    }
}

/// Internet address info for a socket endpoint
#[derive(Debug, Clone, Default)]
pub struct InetAddr {
    pub addr: Option<IpAddr>,
    pub port: u16,
}

/// TCP state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRecv,
    Established,
    CloseWait,
    FinWait1,
    Closing,
    LastAck,
    FinWait2,
    TimeWait,
    Unknown(i32),
}

impl TcpState {
    pub fn from_raw(state: i32) -> Self {
        match state {
            0 => Self::Closed,
            1 => Self::Listen,
            2 => Self::SynSent,
            3 => Self::SynRecv,
            4 => Self::Established,
            5 => Self::CloseWait,
            6 => Self::FinWait1,
            7 => Self::Closing,
            8 => Self::LastAck,
            9 => Self::FinWait2,
            10 => Self::TimeWait,
            n => Self::Unknown(n),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynRecv => "SYN_RCVD",
            Self::Established => "ESTABLISHED",
            Self::CloseWait => "CLOSE_WAIT",
            Self::FinWait1 => "FIN_WAIT_1",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::FinWait2 => "FIN_WAIT_2",
            Self::TimeWait => "TIME_WAIT",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Socket-specific info
#[derive(Debug, Clone, Default)]
pub struct SocketInfo {
    pub local: InetAddr,
    pub foreign: InetAddr,
    pub protocol: String,
    pub tcp_state: Option<TcpState>,
    pub recv_queue: Option<u64>,
    pub send_queue: Option<u64>,
    pub recv_buf_size: Option<u64>,
    pub send_buf_size: Option<u64>,
    pub socket_options: Option<u32>,
    pub socket_state: Option<u32>,
}

/// FD descriptor name
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FdName {
    Cwd,
    Rtd,
    Txt,
    Mem,
    Err,
    Number(i32),
    Other(String),
}

impl FdName {
    pub fn as_display(&self) -> String {
        match self {
            Self::Cwd => "cwd".to_string(),
            Self::Rtd => "rtd".to_string(),
            Self::Txt => "txt".to_string(),
            Self::Mem => "mem".to_string(),
            Self::Err => "err".to_string(),
            Self::Number(n) => format!("{n}"),
            Self::Other(s) => s.clone(),
        }
    }

    pub fn with_access(&self, access: Access) -> String {
        match self {
            Self::Number(n) => {
                let suffix = match access {
                    Access::Read => "r",
                    Access::Write => "w",
                    Access::ReadWrite => "u",
                    Access::None => "",
                };
                format!("{n}{suffix}")
            }
            _ => self.as_display(),
        }
    }
}

/// A single open file entry
#[derive(Debug, Clone)]
pub struct OpenFile {
    pub fd: FdName,
    pub access: Access,
    pub lock: char,
    pub file_type: FileType,
    pub device: Option<(u32, u32)>,
    pub size: Option<u64>,
    pub offset: Option<u64>,
    pub inode: Option<u64>,
    pub nlink: Option<u64>,
    pub name: String,
    pub name_append: Option<String>,
    pub socket_info: Option<SocketInfo>,
    pub sel_flags: u16,
    pub is_nfs: bool,
    pub rdev: Option<(u32, u32)>,
    pub file_flags: Option<i64>,
    pub file_struct_addr: Option<u64>,
}

impl Default for OpenFile {
    fn default() -> Self {
        Self {
            fd: FdName::Other(String::new()),
            access: Access::None,
            lock: ' ',
            file_type: FileType::Unknown(String::new()),
            device: None,
            size: None,
            offset: None,
            inode: None,
            nlink: None,
            name: String::new(),
            name_append: None,
            socket_info: None,
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            file_flags: None,
            file_struct_addr: None,
        }
    }
}

impl OpenFile {
    pub fn full_name(&self) -> String {
        match &self.name_append {
            Some(extra) => format!("{} {extra}", self.name),
            None => self.name.clone(),
        }
    }

    pub fn size_or_offset_str(&self) -> String {
        if let Some(sz) = self.size {
            format!("{sz}")
        } else if let Some(off) = self.offset {
            format!("0t{off}")
        } else {
            String::new()
        }
    }

    pub fn device_str(&self) -> String {
        match self.device {
            Some((maj, min)) => format!("{maj},{min}"),
            None => String::new(),
        }
    }

    pub fn node_str(&self) -> String {
        match self.inode {
            Some(ino) => format!("{ino}"),
            None => match &self.socket_info {
                Some(si) if !si.protocol.is_empty() => si.protocol.clone(),
                _ => String::new(),
            },
        }
    }
}

/// A process entry
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: i32,
    pub ppid: i32,
    pub pgid: i32,
    pub uid: u32,
    pub command: String,
    pub files: Vec<OpenFile>,
    pub sel_flags: u16,
    pub sel_state: u8,
}

impl Process {
    pub fn username(&self) -> String {
        users::get_user_by_uid(self.uid)
            .map(|u| u.name().to_string_lossy().into_owned())
            .unwrap_or_else(|| self.uid.to_string())
    }
}

/// Network address filter for -i option
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    pub protocol: Option<String>,
    pub addr_family: Option<u8>,
    pub addr: Option<IpAddr>,
    pub host: Option<String>,
    pub port_start: Option<u16>,
    pub port_end: Option<u16>,
}

/// FD range filter
#[derive(Debug, Clone)]
pub enum FdFilter {
    Name(String),
    Range(i32, i32),
}

/// Delta status for change highlighting
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaStatus {
    Unchanged,
    New,
    Gone,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── FileType ────────────────────────────────────────────────────

    #[test]
    fn file_type_unknown_empty_string_display() {
        let ft = FileType::Unknown(String::new());
        assert_eq!(ft.as_str(), "");
        assert_eq!(format!("{ft}"), "");
    }

    #[test]
    fn file_type_as_str_all_variants() {
        assert_eq!(FileType::Reg.as_str(), "REG");
        assert_eq!(FileType::Dir.as_str(), "DIR");
        assert_eq!(FileType::Chr.as_str(), "CHR");
        assert_eq!(FileType::Blk.as_str(), "BLK");
        assert_eq!(FileType::Fifo.as_str(), "FIFO");
        assert_eq!(FileType::Sock.as_str(), "sock");
        assert_eq!(FileType::Link.as_str(), "LINK");
        assert_eq!(FileType::Pipe.as_str(), "PIPE");
        assert_eq!(FileType::Kqueue.as_str(), "KQUE");
        assert_eq!(FileType::Unix.as_str(), "unix");
        assert_eq!(FileType::IPv4.as_str(), "IPv4");
        assert_eq!(FileType::IPv6.as_str(), "IPv6");
        assert_eq!(FileType::Systm.as_str(), "systm");
        assert_eq!(FileType::Psem.as_str(), "PSEM");
        assert_eq!(FileType::Pshm.as_str(), "PSHM");
        assert_eq!(FileType::Atalk.as_str(), "ATALK");
        assert_eq!(FileType::Fsevents.as_str(), "FSEV");
        assert_eq!(FileType::Unknown("0014".to_string()).as_str(), "0014");
    }

    // ── FdName ────────────────────────────────────────────────────────

    #[test]
    fn fd_name_as_display_special_fds() {
        assert_eq!(FdName::Cwd.as_display(), "cwd");
        assert_eq!(FdName::Rtd.as_display(), "rtd");
        assert_eq!(FdName::Txt.as_display(), "txt");
        assert_eq!(FdName::Mem.as_display(), "mem");
        assert_eq!(FdName::Err.as_display(), "err");
        assert_eq!(FdName::Other("foo".into()).as_display(), "foo");
    }

    #[test]
    fn fd_name_with_access_number_suffixes() {
        assert_eq!(FdName::Number(3).with_access(Access::Read), "3r");
        assert_eq!(FdName::Number(3).with_access(Access::Write), "3w");
        assert_eq!(FdName::Number(3).with_access(Access::ReadWrite), "3u");
        assert_eq!(FdName::Number(3).with_access(Access::None), "3");
    }

    #[test]
    fn fd_name_with_access_non_numeric_ignores_access() {
        assert_eq!(FdName::Cwd.with_access(Access::ReadWrite), "cwd");
        assert_eq!(FdName::Mem.with_access(Access::Write), "mem");
    }

    // ── TcpState ──────────────────────────────────────────────────────

    #[test]
    fn tcp_state_from_raw_maps_kernel_codes() {
        assert_eq!(TcpState::from_raw(0).as_str(), "CLOSED");
        assert_eq!(TcpState::from_raw(1).as_str(), "LISTEN");
        assert_eq!(TcpState::from_raw(4).as_str(), "ESTABLISHED");
        assert_eq!(TcpState::from_raw(10).as_str(), "TIME_WAIT");
    }

    #[test]
    fn tcp_state_from_raw_unknown_numeric() {
        let s = TcpState::from_raw(99);
        assert!(matches!(s, TcpState::Unknown(99)));
        assert_eq!(s.as_str(), "UNKNOWN");
    }

    #[test]
    fn tcp_state_display_matches_as_str() {
        let s = TcpState::Established;
        assert_eq!(format!("{s}"), s.as_str());
    }

    // ── DeltaStatus ───────────────────────────────────────────────────

    #[test]
    fn delta_status_equality() {
        assert_eq!(DeltaStatus::New, DeltaStatus::New);
        assert_ne!(DeltaStatus::New, DeltaStatus::Unchanged);
        assert_ne!(DeltaStatus::Gone, DeltaStatus::Unchanged);
    }

    #[test]
    fn file_type_display() {
        assert_eq!(format!("{}", FileType::Reg), "REG");
        assert_eq!(format!("{}", FileType::IPv4), "IPv4");
    }

    // ── Access ──────────────────────────────────────────────────────

    #[test]
    fn access_as_char() {
        assert_eq!(Access::Read.as_char(), 'r');
        assert_eq!(Access::Write.as_char(), 'w');
        assert_eq!(Access::ReadWrite.as_char(), 'u');
        assert_eq!(Access::None.as_char(), ' ');
    }

    // ── TcpState ────────────────────────────────────────────────────

    #[test]
    fn tcp_state_from_raw_unknown_low_code() {
        assert_eq!(TcpState::from_raw(11), TcpState::Unknown(11));
    }

    #[test]
    fn tcp_state_from_raw_all() {
        assert_eq!(TcpState::from_raw(0), TcpState::Closed);
        assert_eq!(TcpState::from_raw(1), TcpState::Listen);
        assert_eq!(TcpState::from_raw(2), TcpState::SynSent);
        assert_eq!(TcpState::from_raw(3), TcpState::SynRecv);
        assert_eq!(TcpState::from_raw(4), TcpState::Established);
        assert_eq!(TcpState::from_raw(5), TcpState::CloseWait);
        assert_eq!(TcpState::from_raw(6), TcpState::FinWait1);
        assert_eq!(TcpState::from_raw(7), TcpState::Closing);
        assert_eq!(TcpState::from_raw(8), TcpState::LastAck);
        assert_eq!(TcpState::from_raw(9), TcpState::FinWait2);
        assert_eq!(TcpState::from_raw(10), TcpState::TimeWait);
        assert_eq!(TcpState::from_raw(99), TcpState::Unknown(99));
    }

    #[test]
    fn tcp_state_as_str() {
        assert_eq!(TcpState::Listen.as_str(), "LISTEN");
        assert_eq!(TcpState::Established.as_str(), "ESTABLISHED");
        assert_eq!(TcpState::Unknown(42).as_str(), "UNKNOWN");
    }

    #[test]
    fn tcp_state_display() {
        assert_eq!(format!("{}", TcpState::Established), "ESTABLISHED");
    }

    // ── FdName ──────────────────────────────────────────────────────

    #[test]
    fn fd_name_as_display() {
        assert_eq!(FdName::Cwd.as_display(), "cwd");
        assert_eq!(FdName::Rtd.as_display(), "rtd");
        assert_eq!(FdName::Txt.as_display(), "txt");
        assert_eq!(FdName::Mem.as_display(), "mem");
        assert_eq!(FdName::Err.as_display(), "err");
        assert_eq!(FdName::Number(42).as_display(), "42");
        assert_eq!(FdName::Other("jld".to_string()).as_display(), "jld");
    }

    #[test]
    fn fd_name_with_access() {
        assert_eq!(FdName::Number(3).with_access(Access::Read), "3r");
        assert_eq!(FdName::Number(3).with_access(Access::Write), "3w");
        assert_eq!(FdName::Number(3).with_access(Access::ReadWrite), "3u");
        assert_eq!(FdName::Number(3).with_access(Access::None), "3");
        assert_eq!(FdName::Cwd.with_access(Access::Read), "cwd");
    }

    // ── InetAddr ────────────────────────────────────────────────────

    #[test]
    fn inet_addr_default() {
        let ia = InetAddr::default();
        assert!(ia.addr.is_none());
        assert_eq!(ia.port, 0);
    }

    // ── OpenFile ────────────────────────────────────────────────────

    #[test]
    fn open_file_full_name_no_append() {
        let f = OpenFile {
            name: "/tmp/test".to_string(),
            ..Default::default()
        };
        assert_eq!(f.full_name(), "/tmp/test");
    }

    #[test]
    fn open_file_full_name_with_append() {
        let f = OpenFile {
            name: "/tmp/test".to_string(),
            name_append: Some("(deleted)".to_string()),
            ..Default::default()
        };
        assert_eq!(f.full_name(), "/tmp/test (deleted)");
    }

    #[test]
    fn open_file_size_or_offset_str() {
        let f1 = OpenFile {
            size: Some(4096),
            ..Default::default()
        };
        assert_eq!(f1.size_or_offset_str(), "4096");

        let f2 = OpenFile {
            offset: Some(0),
            ..Default::default()
        };
        assert_eq!(f2.size_or_offset_str(), "0t0");

        let f3 = OpenFile::default();
        assert_eq!(f3.size_or_offset_str(), "");
    }

    #[test]
    fn open_file_size_prefers_size_over_offset() {
        let f = OpenFile {
            size: Some(100),
            offset: Some(50),
            ..Default::default()
        };
        assert_eq!(f.size_or_offset_str(), "100");
    }

    #[test]
    fn open_file_device_str() {
        let f1 = OpenFile {
            device: Some((1, 16)),
            ..Default::default()
        };
        assert_eq!(f1.device_str(), "1,16");

        let f2 = OpenFile::default();
        assert_eq!(f2.device_str(), "");
    }

    #[test]
    fn open_file_node_str_inode() {
        let f = OpenFile {
            inode: Some(12345),
            ..Default::default()
        };
        assert_eq!(f.node_str(), "12345");
    }

    #[test]
    fn open_file_node_str_protocol() {
        let f = OpenFile {
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(f.node_str(), "TCP");
    }

    #[test]
    fn open_file_node_str_empty() {
        let f = OpenFile::default();
        assert_eq!(f.node_str(), "");
    }

    // ── Process ─────────────────────────────────────────────────────

    #[test]
    fn process_username_for_root() {
        let p = Process {
            pid: 1,
            ppid: 0,
            pgid: 1,
            uid: 0,
            command: "launchd".to_string(),
            files: vec![],
            sel_flags: 0,
            sel_state: 0,
        };
        assert_eq!(p.username(), "root");
    }

    #[test]
    fn process_username_unknown_uid() {
        let p = Process {
            pid: 1,
            ppid: 0,
            pgid: 1,
            uid: 99999,
            command: "test".to_string(),
            files: vec![],
            sel_flags: 0,
            sel_state: 0,
        };
        // Unknown UID falls back to numeric string
        assert_eq!(p.username(), "99999");
    }
}
