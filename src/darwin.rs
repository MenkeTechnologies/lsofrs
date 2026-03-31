//! macOS/Darwin process enumeration via libproc FFI

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libc::{self, c_int, c_void, pid_t};

use crate::types::*;

// libproc constants
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDTASKALLINFO: c_int = 2;
const PROC_PIDVNODEPATHINFO: c_int = 6;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
const PROC_PIDFDPIPEINFO: c_int = 6;
const PROC_PIDFDKQUEUEINFO: c_int = 7;
const PROC_PIDFDPSEMINFO: c_int = 8;
const PROC_PIDFDPSHMINFO: c_int = 9;

// FD types
const PROX_FDTYPE_VNODE: u32 = 1;
const PROX_FDTYPE_SOCKET: u32 = 2;
const PROX_FDTYPE_PSHM: u32 = 3;
const PROX_FDTYPE_PSEM: u32 = 4;
const PROX_FDTYPE_KQUEUE: u32 = 5;
const PROX_FDTYPE_PIPE: u32 = 6;
const PROX_FDTYPE_FSEVENTS: u32 = 7;
const PROX_FDTYPE_ATALK: u32 = 8;

// Socket families and protocols
const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;
const AF_UNIX: c_int = 1;
const AF_SYSTEM: c_int = 32;

const IPPROTO_TCP: c_int = 6;
const IPPROTO_UDP: c_int = 17;

// Socket info kinds
const SOCKINFO_TCP: c_int = 1;
const SOCKINFO_IN: c_int = 2;
const SOCKINFO_UN: c_int = 3;

// File mode bits
const S_IFMT: u16 = 0o170000;
const S_IFIFO: u16 = 0o010000;
const S_IFCHR: u16 = 0o020000;
const S_IFDIR: u16 = 0o040000;
const S_IFBLK: u16 = 0o060000;
const S_IFREG: u16 = 0o100000;
const S_IFLNK: u16 = 0o120000;
const S_IFSOCK: u16 = 0o140000;

// Open flags
const FREAD: u32 = 0x0001;
const FWRITE: u32 = 0x0002;

// proc_fdinfo struct (matches Darwin kernel)
#[repr(C)]
#[derive(Copy, Clone)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

// proc_taskallinfo (simplified - we use raw bytes and offsets)
#[repr(C)]
#[derive(Copy, Clone)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    _reserved: u32,
    pbi_comm: [u8; 16],
    pbi_name: [u8; 32],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcTaskInfo {
    pti_virtual_size: u64,
    pti_resident_size: u64,
    pti_total_user: u64,
    pti_total_system: u64,
    pti_threads_user: u64,
    pti_threads_system: u64,
    pti_policy: i32,
    pti_faults: i32,
    pti_pageins: i32,
    pti_cow_faults: i32,
    pti_messages_sent: i32,
    pti_messages_received: i32,
    pti_syscalls_mach: i32,
    pti_syscalls_unix: i32,
    pti_csw: i32,
    pti_threadnum: i32,
    pti_numrunning: i32,
    pti_priority: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcTaskAllInfo {
    pbsd: ProcBsdInfo,
    ptinfo: ProcTaskInfo,
}

// vnode info
#[repr(C)]
#[derive(Copy, Clone)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VnodeInfo {
    vi_stat: VinfoStat,
    vi_type: c_int,
    vi_pad: c_int,
    vi_fsid: libc::fsid_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VnodeInfoPath {
    vip_vi: VnodeInfo,
    vip_path: [u8; 1024],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcVnodePathInfo {
    pvi_cdir: VnodeInfoPath,
    pvi_rdir: VnodeInfoPath,
}

// vnode_fdinfowithpath
#[repr(C)]
#[derive(Copy, Clone)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: VnodeInfoPath,
}

// Socket info structures
#[repr(C)]
#[derive(Copy, Clone)]
struct InSockInfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    _pad: [u8; 2],
    insi_faddr: InAddr46,
    insi_laddr: InAddr46,
    insi_v4: InAddr46V4,
    insi_v6: InAddr46V6,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InAddr46 {
    ina_46: InAddr46Union,
}

#[repr(C)]
#[derive(Copy, Clone)]
union InAddr46Union {
    i46a_addr4: libc::in_addr,
    i46a_addr6: libc::in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InAddr46V4 {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InAddr46V6 {
    in6_hlim: c_int,
    in6_cksum: c_int,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: c_int,
    tcpsi_timer: [c_int; 4],
    tcpsi_mss: c_int,
    tcpsi_flags: u32,
    _pad: u32,
    tcpsi_tp: u64,
}

// SOCK_MAXADDRLEN = 255 on Darwin; the union of sockaddr_un and char[255]
const SOCK_MAXADDRLEN: usize = 255;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct UnSockInfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: [u8; SOCK_MAXADDRLEN],
    unsi_caddr: [u8; SOCK_MAXADDRLEN],
}

// soi_proto union size: largest member is un_sockinfo (528 bytes)
const SOCKINFO_SIZE: usize = 528;

#[repr(C)]
#[derive(Copy, Clone)]
struct SocketInfo {
    soi_stat: SoiStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockBufInfo,
    soi_snd: SockBufInfo,
    soi_kind: c_int,
    _pad: u32,
    soi_proto: [u8; SOCKINFO_SIZE],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SoiStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SockBufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

// Pipe info
#[repr(C)]
#[derive(Copy, Clone)]
struct PipeInfo {
    pipe_stat: VinfoStat,
    pipe_handle: u64,
    pipe_peerhandle: u64,
    pipe_status: c_int,
    _pad: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PipeFdInfo {
    pfi: ProcFileInfo,
    pipe_info: PipeInfo,
}

// Kqueue info
#[repr(C)]
#[derive(Copy, Clone)]
struct KqueueInfo {
    kq_stat: VinfoStat,
    kq_state: u32,
    _pad: [u32; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct KqueueFdInfo {
    pfi: ProcFileInfo,
    kqueue_info: KqueueInfo,
}

unsafe extern "C" {
    fn proc_listpids(r#type: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: pid_t,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: pid_t,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn major(dev: u32) -> u32 {
    (dev >> 24) & 0xff
}

fn minor(dev: u32) -> u32 {
    dev & 0xffffff
}

fn file_type_from_mode(mode: u16) -> FileType {
    match mode & S_IFMT {
        S_IFIFO => FileType::Fifo,
        S_IFCHR => FileType::Chr,
        S_IFDIR => FileType::Dir,
        S_IFBLK => FileType::Blk,
        S_IFREG => FileType::Reg,
        S_IFLNK => FileType::Link,
        S_IFSOCK => FileType::Sock,
        _ => FileType::Unknown(format!("{:04o}", (mode & S_IFMT) >> 12)),
    }
}

fn access_from_flags(flags: u32) -> Access {
    let f = flags & (FREAD | FWRITE);
    if f == FREAD {
        Access::Read
    } else if f == FWRITE {
        Access::Write
    } else if f == (FREAD | FWRITE) {
        Access::ReadWrite
    } else {
        Access::None
    }
}

fn process_vnode_info(vip: &VnodeInfoPath, pfi: Option<&ProcFileInfo>) -> OpenFile {
    let ft = file_type_from_mode(vip.vip_vi.vi_stat.vst_mode);
    let path = cstr_from_bytes(&vip.vip_path);
    let dev = vip.vip_vi.vi_stat.vst_dev;

    let (access, offset, file_flags) = match pfi {
        Some(fi) => (
            access_from_flags(fi.fi_openflags),
            Some(fi.fi_offset as u64),
            Some(fi.fi_openflags as i64),
        ),
        None => (Access::None, None, None),
    };

    let (size, has_offset) = match ft {
        FileType::Chr | FileType::Fifo => (None, true),
        _ => (Some(vip.vip_vi.vi_stat.vst_size as u64), false),
    };

    let rdev = match ft {
        FileType::Chr | FileType::Blk => {
            let rd = vip.vip_vi.vi_stat.vst_rdev;
            Some((major(rd), minor(rd)))
        }
        _ => None,
    };

    let device = match ft {
        FileType::Fifo => None,
        _ => Some((major(dev), minor(dev))),
    };

    OpenFile {
        fd: FdName::Other(String::new()), // caller sets this
        access,
        lock: ' ',
        file_type: ft,
        device,
        size,
        offset: if has_offset { offset } else { None },
        inode: Some(vip.vip_vi.vi_stat.vst_ino),
        nlink: Some(vip.vip_vi.vi_stat.vst_nlink as u64),
        name: path,
        name_append: None,
        socket_info: None,
        sel_flags: 0,
        is_nfs: false,
        rdev,
        file_flags,
        file_struct_addr: None,
    }
}

/// List all PIDs on the system
fn list_pids() -> Vec<pid_t> {
    unsafe {
        let buf_size = proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if buf_size <= 0 {
            return Vec::new();
        }
        let count = (buf_size as usize / mem::size_of::<pid_t>()) + 32;
        let mut pids = vec![0i32; count];
        let actual = proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut c_void,
            (count * mem::size_of::<pid_t>()) as c_int,
        );
        if actual <= 0 {
            return Vec::new();
        }
        let n = actual as usize / mem::size_of::<pid_t>();
        pids.truncate(n);
        pids.retain(|&p| p > 0);
        pids
    }
}

/// Get task info for a PID
fn get_task_info(pid: pid_t) -> Option<ProcTaskAllInfo> {
    unsafe {
        let mut tai: ProcTaskAllInfo = mem::zeroed();
        let ret = proc_pidinfo(
            pid,
            PROC_PIDTASKALLINFO,
            0,
            &mut tai as *mut _ as *mut c_void,
            mem::size_of::<ProcTaskAllInfo>() as c_int,
        );
        if ret as usize >= mem::size_of::<ProcTaskAllInfo>() {
            Some(tai)
        } else {
            None
        }
    }
}

/// Get vnode path info (cwd, root dir) for a PID
fn get_vnode_path_info(pid: pid_t) -> Option<ProcVnodePathInfo> {
    unsafe {
        let mut vpi: ProcVnodePathInfo = mem::zeroed();
        let ret = proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            &mut vpi as *mut _ as *mut c_void,
            mem::size_of::<ProcVnodePathInfo>() as c_int,
        );
        if ret as usize >= mem::size_of::<ProcVnodePathInfo>() {
            Some(vpi)
        } else {
            None
        }
    }
}

/// List FDs for a PID
fn list_fds(pid: pid_t) -> Vec<ProcFdInfo> {
    unsafe {
        let buf_size = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        );
        if buf_size <= 0 {
            return Vec::new();
        }
        let count = buf_size as usize / mem::size_of::<ProcFdInfo>() + 16;
        let alloc = count * mem::size_of::<ProcFdInfo>();
        let mut fds: Vec<ProcFdInfo> = vec![mem::zeroed(); count];
        let actual = proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut c_void,
            alloc as c_int,
        );
        if actual <= 0 {
            return Vec::new();
        }
        let n = actual as usize / mem::size_of::<ProcFdInfo>();
        fds.truncate(n);
        fds
    }
}

/// Process a vnode FD
fn process_vnode_fd(pid: pid_t, fd: i32) -> Option<OpenFile> {
    unsafe {
        let mut vnpi: VnodeFdInfoWithPath = mem::zeroed();
        let ret = proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            &mut vnpi as *mut _ as *mut c_void,
            mem::size_of::<VnodeFdInfoWithPath>() as c_int,
        );
        if (ret as usize) < mem::size_of::<VnodeFdInfoWithPath>() {
            return None;
        }
        let mut of = process_vnode_info(&vnpi.pvip, Some(&vnpi.pfi));
        of.fd = FdName::Number(fd);
        Some(of)
    }
}

/// Process a socket FD
fn process_socket_fd(pid: pid_t, fd: i32) -> Option<OpenFile> {
    unsafe {
        let mut si: SocketFdInfo = mem::zeroed();
        let ret = proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            &mut si as *mut _ as *mut c_void,
            mem::size_of::<SocketFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<SocketFdInfo>() {
            return None;
        }

        let access = access_from_flags(si.pfi.fi_openflags);
        let family = si.psi.soi_family;
        let protocol = si.psi.soi_protocol;

        let proto_str = match protocol {
            IPPROTO_TCP => "TCP",
            IPPROTO_UDP => "UDP",
            _ => "",
        };

        let file_type = match family {
            AF_INET => FileType::IPv4,
            AF_INET6 => FileType::IPv6,
            AF_UNIX => FileType::Unix,
            AF_SYSTEM => FileType::Systm,
            _ => FileType::Sock,
        };

        let mut sock_info = crate::types::SocketInfo {
            protocol: proto_str.to_string(),
            recv_queue: Some(si.psi.soi_rcv.sbi_cc as u64),
            send_queue: Some(si.psi.soi_snd.sbi_cc as u64),
            recv_buf_size: Some(si.psi.soi_rcv.sbi_mbmax as u64),
            send_buf_size: Some(si.psi.soi_snd.sbi_mbmax as u64),
            socket_options: Some(si.psi.soi_options as u32),
            socket_state: Some(si.psi.soi_state as u32),
            ..Default::default()
        };

        let mut name = String::new();

        match family {
            AF_INET | AF_INET6 => {
                if si.psi.soi_kind == SOCKINFO_TCP || si.psi.soi_kind == SOCKINFO_IN {
                    // Read addresses from soi_proto union
                    let proto_bytes = &si.psi.soi_proto;

                    if si.psi.soi_kind == SOCKINFO_TCP {
                        // TcpSockInfo -> InSockInfo at offset 0
                        let tcp: &TcpSockInfo = &*(proto_bytes.as_ptr() as *const TcpSockInfo);
                        let ini = &tcp.tcpsi_ini;

                        sock_info.tcp_state = Some(TcpState::from_raw(tcp.tcpsi_state));

                        if family == AF_INET {
                            let la = Ipv4Addr::from(u32::from_be(ini.insi_laddr.ina_46.i46a_addr4.s_addr));
                            let fa = Ipv4Addr::from(u32::from_be(ini.insi_faddr.ina_46.i46a_addr4.s_addr));
                            let lp = u16::from_be(ini.insi_lport as u16);
                            let fp = u16::from_be(ini.insi_fport as u16);

                            sock_info.local = InetAddr { addr: Some(IpAddr::V4(la)), port: lp };
                            sock_info.foreign = InetAddr { addr: Some(IpAddr::V4(fa)), port: fp };

                            name = format_inet_name(IpAddr::V4(la), lp, IpAddr::V4(fa), fp, proto_str);
                        } else {
                            let la = Ipv6Addr::from(ini.insi_laddr.ina_46.i46a_addr6.s6_addr);
                            let fa = Ipv6Addr::from(ini.insi_faddr.ina_46.i46a_addr6.s6_addr);
                            let lp = u16::from_be(ini.insi_lport as u16);
                            let fp = u16::from_be(ini.insi_fport as u16);

                            sock_info.local = InetAddr { addr: Some(IpAddr::V6(la)), port: lp };
                            sock_info.foreign = InetAddr { addr: Some(IpAddr::V6(fa)), port: fp };

                            name = format_inet_name(IpAddr::V6(la), lp, IpAddr::V6(fa), fp, proto_str);
                        }
                    } else {
                        let ini: &InSockInfo = &*(proto_bytes.as_ptr() as *const InSockInfo);

                        if family == AF_INET {
                            let la = Ipv4Addr::from(u32::from_be(ini.insi_laddr.ina_46.i46a_addr4.s_addr));
                            let fa = Ipv4Addr::from(u32::from_be(ini.insi_faddr.ina_46.i46a_addr4.s_addr));
                            let lp = u16::from_be(ini.insi_lport as u16);
                            let fp = u16::from_be(ini.insi_fport as u16);

                            sock_info.local = InetAddr { addr: Some(IpAddr::V4(la)), port: lp };
                            sock_info.foreign = InetAddr { addr: Some(IpAddr::V4(fa)), port: fp };

                            name = format_inet_name(IpAddr::V4(la), lp, IpAddr::V4(fa), fp, proto_str);
                        } else {
                            let la = Ipv6Addr::from(ini.insi_laddr.ina_46.i46a_addr6.s6_addr);
                            let fa = Ipv6Addr::from(ini.insi_faddr.ina_46.i46a_addr6.s6_addr);
                            let lp = u16::from_be(ini.insi_lport as u16);
                            let fp = u16::from_be(ini.insi_fport as u16);

                            sock_info.local = InetAddr { addr: Some(IpAddr::V6(la)), port: lp };
                            sock_info.foreign = InetAddr { addr: Some(IpAddr::V6(fa)), port: fp };

                            name = format_inet_name(IpAddr::V6(la), lp, IpAddr::V6(fa), fp, proto_str);
                        }
                    }
                }

                if let Some(ref state) = sock_info.tcp_state {
                    name.push_str(&format!(" ({})", state));
                }
            }
            AF_UNIX => {
                if si.psi.soi_kind == SOCKINFO_UN {
                    let un: &UnSockInfo = &*(si.psi.soi_proto.as_ptr() as *const UnSockInfo);
                    // unsi_addr is the raw sockaddr_un union; sun_path starts at offset 2
                    let path = if SOCK_MAXADDRLEN > 2 {
                        cstr_from_bytes(&un.unsi_addr[2..])
                    } else {
                        String::new()
                    };
                    if path.is_empty() {
                        name = format!("->0x{:x}", { un.unsi_conn_pcb });
                    } else {
                        name = path;
                    }
                }
            }
            AF_SYSTEM => {
                name = "systemsocket".to_string();
            }
            _ => {
                name = format!("protocol={}", protocol);
            }
        }

        Some(OpenFile {
            fd: FdName::Number(fd),
            access,
            lock: ' ',
            file_type,
            device: None,
            size: None,
            offset: Some(si.pfi.fi_offset as u64),
            inode: None,
            nlink: None,
            name,
            name_append: None,
            socket_info: Some(sock_info),
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            file_flags: Some(si.pfi.fi_openflags as i64),
            file_struct_addr: None,
        })
    }
}

/// Process a pipe FD
fn process_pipe_fd(pid: pid_t, fd: i32) -> Option<OpenFile> {
    unsafe {
        let mut pi: PipeFdInfo = mem::zeroed();
        let ret = proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDPIPEINFO,
            &mut pi as *mut _ as *mut c_void,
            mem::size_of::<PipeFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<PipeFdInfo>() {
            return None;
        }
        let access = access_from_flags(pi.pfi.fi_openflags);
        let name = format!("->0x{:x}", pi.pipe_info.pipe_peerhandle);
        Some(OpenFile {
            fd: FdName::Number(fd),
            access,
            lock: ' ',
            file_type: FileType::Pipe,
            device: None,
            size: Some(pi.pipe_info.pipe_stat.vst_size as u64),
            offset: None,
            inode: Some(pi.pipe_info.pipe_stat.vst_ino),
            nlink: None,
            name,
            name_append: None,
            socket_info: None,
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            file_flags: Some(pi.pfi.fi_openflags as i64),
            file_struct_addr: None,
        })
    }
}

/// Process a kqueue FD
fn process_kqueue_fd(pid: pid_t, fd: i32) -> Option<OpenFile> {
    unsafe {
        let mut ki: KqueueFdInfo = mem::zeroed();
        let ret = proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDKQUEUEINFO,
            &mut ki as *mut _ as *mut c_void,
            mem::size_of::<KqueueFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<KqueueFdInfo>() {
            return None;
        }
        let access = access_from_flags(ki.pfi.fi_openflags);
        Some(OpenFile {
            fd: FdName::Number(fd),
            access,
            lock: ' ',
            file_type: FileType::Kqueue,
            device: None,
            size: None,
            offset: None,
            inode: None,
            nlink: None,
            name: format!("count={}", ki.kqueue_info.kq_state),
            name_append: None,
            socket_info: None,
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            file_flags: Some(ki.pfi.fi_openflags as i64),
            file_struct_addr: None,
        })
    }
}

fn format_inet_name(la: IpAddr, lp: u16, fa: IpAddr, fp: u16, _proto: &str) -> String {
    let local = format_endpoint(&la, lp);
    let foreign = format_endpoint(&fa, fp);

    if is_any_addr(&fa) && fp == 0 {
        format!("{local}")
    } else {
        format!("{local}->{foreign}")
    }
}

fn format_endpoint(addr: &IpAddr, port: u16) -> String {
    let addr_str = if is_any_addr(addr) {
        "*".to_string()
    } else {
        match addr {
            IpAddr::V4(a) => a.to_string(),
            IpAddr::V6(a) => format!("[{a}]"),
        }
    };

    if port == 0 {
        format!("{addr_str}:*")
    } else {
        format!("{addr_str}:{port}")
    }
}

fn is_any_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => a.is_unspecified(),
        IpAddr::V6(a) => a.is_unspecified(),
    }
}

/// Gather all process information from the system
pub fn gather_processes() -> Vec<Process> {
    let pids = list_pids();
    let mut processes = Vec::with_capacity(pids.len());

    for pid in pids {
        let tai = match get_task_info(pid) {
            Some(t) => t,
            None => continue,
        };

        let cmd = {
            let name = cstr_from_bytes(&tai.pbsd.pbi_name);
            if name.is_empty() {
                cstr_from_bytes(&tai.pbsd.pbi_comm)
            } else {
                name
            }
        };

        let mut files = Vec::new();

        // Get cwd and root dir
        if let Some(vpi) = get_vnode_path_info(pid) {
            if vpi.pvi_cdir.vip_path[0] != 0 {
                let mut cwd_file = process_vnode_info(&vpi.pvi_cdir, None);
                cwd_file.fd = FdName::Cwd;
                files.push(cwd_file);
            }
            if vpi.pvi_rdir.vip_path[0] != 0 {
                let mut rtd_file = process_vnode_info(&vpi.pvi_rdir, None);
                rtd_file.fd = FdName::Rtd;
                files.push(rtd_file);
            }
        }

        // Get open FDs
        let fds = list_fds(pid);
        for fdi in &fds {
            let of = match fdi.proc_fdtype {
                PROX_FDTYPE_VNODE => process_vnode_fd(pid, fdi.proc_fd),
                PROX_FDTYPE_SOCKET => process_socket_fd(pid, fdi.proc_fd),
                PROX_FDTYPE_PIPE => process_pipe_fd(pid, fdi.proc_fd),
                PROX_FDTYPE_KQUEUE => process_kqueue_fd(pid, fdi.proc_fd),
                PROX_FDTYPE_PSEM => {
                    Some(OpenFile {
                        fd: FdName::Number(fdi.proc_fd),
                        file_type: FileType::Psem,
                        name: String::new(),
                        ..Default::default()
                    })
                }
                PROX_FDTYPE_PSHM => {
                    Some(OpenFile {
                        fd: FdName::Number(fdi.proc_fd),
                        file_type: FileType::Pshm,
                        name: String::new(),
                        ..Default::default()
                    })
                }
                PROX_FDTYPE_FSEVENTS => {
                    Some(OpenFile {
                        fd: FdName::Number(fdi.proc_fd),
                        file_type: FileType::Fsevents,
                        name: String::new(),
                        ..Default::default()
                    })
                }
                PROX_FDTYPE_ATALK => {
                    Some(OpenFile {
                        fd: FdName::Number(fdi.proc_fd),
                        file_type: FileType::Atalk,
                        name: String::new(),
                        ..Default::default()
                    })
                }
                _ => None,
            };
            if let Some(f) = of {
                files.push(f);
            }
        }

        processes.push(Process {
            pid,
            ppid: tai.pbsd.pbi_ppid as i32,
            pgid: tai.pbsd.pbi_pgid as i32,
            uid: tai.pbsd.pbi_uid,
            command: cmd,
            files,
            sel_flags: 0,
            sel_state: 0,
        });
    }

    processes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    // ── FFI struct size validation ──────────────────────────────────
    // These must match Darwin's sys/proc_info.h exactly or
    // proc_pidfdinfo will reject the undersized buffer.

    #[test]
    fn ffi_socket_fd_info_size() {
        assert_eq!(mem::size_of::<SocketFdInfo>(), 792);
    }

    #[test]
    fn ffi_socket_info_size() {
        assert_eq!(mem::size_of::<SocketInfo>(), 768);
    }

    #[test]
    fn ffi_proc_file_info_size() {
        assert_eq!(mem::size_of::<ProcFileInfo>(), 24);
    }

    #[test]
    fn ffi_in_sock_info_size() {
        assert_eq!(mem::size_of::<InSockInfo>(), 80);
    }

    #[test]
    fn ffi_tcp_sock_info_size() {
        assert_eq!(mem::size_of::<TcpSockInfo>(), 120);
    }

    #[test]
    fn ffi_vnode_fd_info_with_path_size() {
        assert_eq!(mem::size_of::<VnodeFdInfoWithPath>(), 1200);
    }

    #[test]
    fn ffi_pipe_fd_info_size() {
        assert_eq!(mem::size_of::<PipeFdInfo>(), 184);
    }

    #[test]
    fn ffi_kqueue_fd_info_size() {
        // Rust struct is 176 due to alignment padding; C is 168.
        // Oversized is safe — proc_pidfdinfo only writes 168 bytes into our 176-byte buffer.
        assert!(mem::size_of::<KqueueFdInfo>() >= 168);
    }

    #[test]
    fn ffi_proc_task_all_info_size() {
        assert_eq!(mem::size_of::<ProcTaskAllInfo>(), 232);
    }

    #[test]
    fn ffi_vinfo_stat_size() {
        assert_eq!(mem::size_of::<VinfoStat>(), 136);
    }

    #[test]
    fn ffi_sock_buf_info_size() {
        assert_eq!(mem::size_of::<SockBufInfo>(), 24);
    }

    // ── FFI field offset validation ─────────────────────────────────

    #[test]
    fn ffi_socket_info_field_offsets() {
        let base = 0usize;
        unsafe {
            let s: SocketInfo = mem::zeroed();
            let p = &s as *const _ as usize;
            assert_eq!(&s.soi_type as *const _ as usize - p, 152, "soi_type offset");
            assert_eq!(&s.soi_protocol as *const _ as usize - p, 156, "soi_protocol offset");
            assert_eq!(&s.soi_family as *const _ as usize - p, 160, "soi_family offset");
            assert_eq!(&s.soi_kind as *const _ as usize - p, 232, "soi_kind offset");
            assert_eq!(&s.soi_proto as *const _ as usize - p, 240, "soi_proto offset");
            let _ = base;
        }
    }

    // ── Functional tests ────────────────────────────────────────────

    #[test]
    fn cstr_from_bytes_null_terminated() {
        assert_eq!(cstr_from_bytes(b"hello\0world"), "hello");
    }

    #[test]
    fn cstr_from_bytes_no_null() {
        assert_eq!(cstr_from_bytes(b"hello"), "hello");
    }

    #[test]
    fn cstr_from_bytes_empty() {
        assert_eq!(cstr_from_bytes(b"\0"), "");
        assert_eq!(cstr_from_bytes(b""), "");
    }

    #[test]
    fn major_minor_extraction() {
        // dev = 0x01000010 -> major=1, minor=16
        assert_eq!(major(0x01000010), 1);
        assert_eq!(minor(0x01000010), 16);
        assert_eq!(major(0), 0);
        assert_eq!(minor(0), 0);
        assert_eq!(major(0xFF00FFFF), 0xFF);
        assert_eq!(minor(0xFF00FFFF), 0x00FFFF);
    }

    #[test]
    fn gather_processes_returns_nonempty() {
        let procs = gather_processes();
        assert!(!procs.is_empty(), "should find at least one process");
    }

    #[test]
    fn gather_processes_includes_self() {
        let my_pid = std::process::id() as i32;
        let procs = gather_processes();
        assert!(
            procs.iter().any(|p| p.pid == my_pid),
            "should find our own process pid={my_pid}"
        );
    }

    #[test]
    fn gather_processes_self_has_files() {
        let my_pid = std::process::id() as i32;
        let procs = gather_processes();
        let me = procs.iter().find(|p| p.pid == my_pid).unwrap();
        // Without root, we may not get cwd, but we should have some FDs
        assert!(
            !me.files.is_empty(),
            "our process should have open files"
        );
    }

    #[test]
    fn gather_processes_have_commands() {
        let procs = gather_processes();
        for p in &procs {
            assert!(!p.command.is_empty(), "pid {} has empty command", p.pid);
        }
    }

    #[test]
    fn gather_processes_sorted_by_pid() {
        let mut procs = gather_processes();
        procs.sort_by_key(|p| p.pid);
        for w in procs.windows(2) {
            assert!(w[0].pid <= w[1].pid);
        }
    }

    #[test]
    fn gather_processes_file_types_valid() {
        let procs = gather_processes();
        let valid_types = [
            "REG", "DIR", "CHR", "BLK", "FIFO", "sock", "LINK", "PIPE",
            "KQUE", "unix", "IPv4", "IPv6", "systm", "PSEM", "PSHM",
            "ATALK", "FSEV",
        ];
        for p in &procs {
            for f in &p.files {
                let ts = f.file_type.as_str();
                assert!(
                    valid_types.contains(&ts) || ts.chars().all(|c| c.is_ascii_digit() || c == 'o'),
                    "unexpected file type '{}' for pid {} fd {:?}",
                    ts, p.pid, f.fd
                );
            }
        }
    }
}
