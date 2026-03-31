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
#[derive(Debug, Clone)]
pub struct InetAddr {
    pub addr: Option<IpAddr>,
    pub port: u16,
}

impl Default for InetAddr {
    fn default() -> Self {
        Self {
            addr: None,
            port: 0,
        }
    }
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
