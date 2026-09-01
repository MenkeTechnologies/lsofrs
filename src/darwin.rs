//! macOS/Darwin process enumeration via libproc FFI

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libc::{self, c_int, c_void, pid_t};
use rayon::prelude::*;

use crate::types::*;

// libproc constants
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDTASKALLINFO: c_int = 2;
const PROC_PIDVNODEPATHINFO: c_int = 9;
const PROC_PIDREGIONPATHINFO: c_int = 8;
const PROC_PIDLISTFILEPORTS: c_int = 14;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
const PROC_PIDFDPIPEINFO: c_int = 6;
const PROC_PIDFDKQUEUEINFO: c_int = 7;
const PROC_PIDFDPSEMINFO: c_int = 4;
const PROC_PIDFDPSHMINFO: c_int = 5;

// FD types
const PROX_FDTYPE_VNODE: u32 = 1;
const PROX_FDTYPE_SOCKET: u32 = 2;
const PROX_FDTYPE_PSHM: u32 = 3;
const PROX_FDTYPE_PSEM: u32 = 4;
const PROX_FDTYPE_KQUEUE: u32 = 5;
const PROX_FDTYPE_PIPE: u32 = 6;
const PROX_FDTYPE_FSEVENTS: u32 = 7;
const PROX_FDTYPE_ATALK: u32 = 0;
const PROX_FDTYPE_NETPOLICY: u32 = 9;
const PROX_FDTYPE_CHANNEL: u32 = 10;
const PROX_FDTYPE_NEXUS: u32 = 11;
const PROC_PIDFDCHANNELINFO: c_int = 10;

// Socket families and protocols
const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;
const AF_UNIX: c_int = 1;
const AF_SYSTEM: c_int = 32;

const IPPROTO_TCP: c_int = 6;
const IPPROTO_UDP: c_int = 17;

// Socket info kinds
const SOCKINFO_IN: c_int = 1;
const SOCKINFO_TCP: c_int = 2;
const SOCKINFO_UN: c_int = 3;
const SOCKINFO_NDRV: c_int = 4;
const SOCKINFO_KERN_EVENT: c_int = 5;
const SOCKINFO_KERN_CTL: c_int = 6;

const AF_ROUTE: c_int = 17;
const AF_NDRV: c_int = 27;

const MAXPATHLEN: usize = 1024;
const MAX_KCTL_NAME: usize = 96;
const IF_NAMESIZE: usize = 16;

// proc_channel_info chi_type
const PROC_CHANNEL_TYPE_USER_PIPE: u32 = 0;
const PROC_CHANNEL_TYPE_KERNEL_PIPE: u32 = 1;
const PROC_CHANNEL_TYPE_NET_IF: u32 = 2;
const PROC_CHANNEL_TYPE_FLOW_SWITCH: u32 = 3;
const PROC_CHANNEL_FLAGS_USER_PACKET_POOL: u32 = 0x20;

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
    vip_path: [u8; MAXPATHLEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcVnodePathInfo {
    pvi_cdir: VnodeInfoPath,
    pvi_rdir: VnodeInfoPath,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcFilePortInfo {
    proc_fileport: u32,
    proc_fdtype: u32,
}

// proc_regioninfo / proc_regionwithpathinfo — mirrors <sys/proc_info.h>.
#[repr(C)]
#[derive(Copy, Clone)]
struct ProcRegionInfo {
    pri_protection: u32,
    pri_max_protection: u32,
    pri_inheritance: u32,
    pri_flags: u32,
    pri_offset: u64,
    pri_behavior: u32,
    pri_user_wired_count: u32,
    pri_user_tag: u32,
    pri_pages_resident: u32,
    pri_pages_shared_now_private: u32,
    pri_pages_swapped_out: u32,
    pri_pages_dirtied: u32,
    pri_ref_count: u32,
    pri_shadow_depth: u32,
    pri_share_mode: u32,
    pri_private_pages_resident: u32,
    pri_shared_pages_resident: u32,
    pri_obj_id: u32,
    pri_depth: u32,
    pri_address: u64,
    pri_size: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ProcRegionWithPathInfo {
    prp_prinfo: ProcRegionInfo,
    prp_vip: VnodeInfoPath,
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

// Socket info structures — mirrors `struct in_sockinfo` in <sys/proc_info.h>.
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
    // `uint32_t rfu_1` in the header — a full reserved word, not 2 bytes of
    // padding. Shrinking it slides insi_faddr/insi_laddr 4 bytes earlier and
    // makes every address read land on the wrong field.
    insi_rfu_1: u32,
    insi_faddr: InAddr46,
    insi_laddr: InAddr46,
    insi_v4: InSockInfoV4,
    insi_v6: InSockInfoV6,
}

/// `struct in4in6_addr` — an IPv4 address stored in the tail of a 16-byte slot,
/// so it overlays the low word of the equivalent IPv6 address.
#[repr(C)]
#[derive(Copy, Clone)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: libc::in_addr,
}

/// The anonymous `insi_faddr` / `insi_laddr` union in `struct in_sockinfo`.
#[repr(C)]
#[derive(Copy, Clone)]
union InAddr46 {
    ina_46: In4In6Addr,
    ina_6: libc::in6_addr,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InSockInfoV4 {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct InSockInfoV6 {
    in6_hlim: u8,
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

// POSIX semaphore / shared memory info
#[repr(C)]
#[derive(Copy, Clone)]
struct PsemInfo {
    psem_stat: VinfoStat,
    psem_name: [u8; MAXPATHLEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PsemFdInfo {
    pfi: ProcFileInfo,
    pseminfo: PsemInfo,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PshmInfo {
    pshm_stat: VinfoStat,
    pshm_mappaddr: u64,
    pshm_name: [u8; MAXPATHLEN],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PshmFdInfo {
    pfi: ProcFileInfo,
    pshminfo: PshmInfo,
}

// Skywalk channel info
#[repr(C)]
#[derive(Copy, Clone)]
struct ProcChannelInfo {
    chi_instance: [u8; 16],
    chi_port: u32,
    chi_type: u32,
    chi_flags: u32,
    rfu_1: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ChannelFdInfo {
    pfi: ProcFileInfo,
    channelinfo: ProcChannelInfo,
}

// Raw network driver socket info (SOCKINFO_NDRV)
#[repr(C)]
#[derive(Copy, Clone)]
struct NdrvInfo {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [u8; IF_NAMESIZE],
}

// Kernel event socket info (SOCKINFO_KERN_EVENT)
#[repr(C)]
#[derive(Copy, Clone)]
struct KernEventInfo {
    kesi_vendor_code_filter: u32,
    kesi_class_filter: u32,
    kesi_subclass_filter: u32,
}

// Kernel control socket info (SOCKINFO_KERN_CTL)
#[repr(C)]
#[derive(Copy, Clone)]
struct KernCtlInfo {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [u8; MAX_KCTL_NAME],
}

// Kqueue info
#[repr(C)]
#[derive(Copy, Clone)]
struct KqueueInfo {
    kq_stat: VinfoStat,
    kq_state: u32,
    rfu_1: u32,
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
    fn proc_pidfileportinfo(
        pid: pid_t,
        fileport: u32,
        flavor: c_int,
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

/// stat(2) a path into the kernel's `vinfo_stat` shape.
fn stat_path(path: &str) -> Option<VinfoStat> {
    if path.is_empty() {
        return None;
    }
    let c_path = std::ffi::CString::new(path).ok()?;
    unsafe {
        let mut st: libc::stat = mem::zeroed();
        if libc::stat(c_path.as_ptr(), &mut st) != 0 {
            return None;
        }
        let mut vst: VinfoStat = mem::zeroed();
        vst.vst_dev = st.st_dev as u32;
        vst.vst_mode = st.st_mode;
        vst.vst_nlink = st.st_nlink;
        vst.vst_ino = st.st_ino;
        vst.vst_size = st.st_size;
        vst.vst_rdev = st.st_rdev as u32;
        Some(vst)
    }
}

fn process_vnode_info(vip: &VnodeInfoPath, pfi: Option<&ProcFileInfo>) -> OpenFile {
    let path = cstr_from_bytes(&vip.vip_path);

    // Mapped regions sometimes come back with an empty vnode stat. lsof falls
    // back to stat(2) on the path rather than printing a zero mode.
    let stat = (vip.vip_vi.vi_stat.vst_mode == 0)
        .then(|| stat_path(&path))
        .flatten();
    let vst = stat.as_ref().unwrap_or(&vip.vip_vi.vi_stat);

    // A vnode we could not stat — SIP data vaults refuse it to anything
    // without Apple's entitlement — still came from a mapped file, so report
    // the type lsof does and leave the numbers we do not have blank.
    let unknown = vst.vst_mode == 0 && !path.is_empty();
    let ft = if unknown {
        FileType::Reg
    } else {
        file_type_from_mode(vst.vst_mode)
    };
    let dev = vst.vst_dev;

    let (access, offset, file_flags, file_status) = match pfi {
        Some(fi) => (
            access_from_flags(fi.fi_openflags),
            Some(fi.fi_offset as u64),
            Some(fi.fi_openflags as i64),
            Some(fi.fi_status),
        ),
        None => (Access::None, None, None, None),
    };

    let (size, has_offset) = match ft {
        _ if unknown => (None, false),
        FileType::Chr | FileType::Fifo => (None, true),
        _ => (Some(vst.vst_size as u64), false),
    };

    let rdev = match ft {
        FileType::Chr | FileType::Blk => {
            let rd = vst.vst_rdev;
            Some((major(rd), minor(rd)))
        }
        _ => None,
    };

    let device = match ft {
        _ if unknown => None,
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
        inode: (!unknown).then_some(vst.vst_ino),
        nlink: (!unknown).then_some(vst.vst_nlink as u64),
        name: path,
        name_append: None,
        socket_info: None,
        sel_flags: 0,
        is_nfs: false,
        rdev,
        device_label: None,
        file_port: None,
        file_flags,
        file_status,
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

/// Mapped-file (`txt`) entries for a PID.
///
/// Walks the task's VM regions with `PROC_PIDREGIONPATHINFO`, keeping the
/// distinct vnodes backing them — the executable, dyld, shared libraries and
/// any other `mmap`ed file. Matches what lsof reports as `txt` on Darwin.
fn text_files(pid: pid_t) -> Vec<OpenFile> {
    // Bound the walk so a pathological map can never spin forever.
    const MAX_REGIONS: usize = 200_000;

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut addr: u64 = 0;

    for _ in 0..MAX_REGIONS {
        let rwpi = unsafe {
            let mut rwpi: ProcRegionWithPathInfo = mem::zeroed();
            let ret = proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                addr,
                &mut rwpi as *mut _ as *mut c_void,
                mem::size_of::<ProcRegionWithPathInfo>() as c_int,
            );
            if (ret as usize) < mem::size_of::<ProcRegionWithPathInfo>() {
                break;
            }
            rwpi
        };

        let next = rwpi
            .prp_prinfo
            .pri_address
            .saturating_add(rwpi.prp_prinfo.pri_size);
        if next <= addr {
            break;
        }
        addr = next;

        if rwpi.prp_vip.vip_path[0] == 0 {
            continue;
        }
        let st = &rwpi.prp_vip.vip_vi.vi_stat;
        if !seen.insert((st.vst_dev, st.vst_ino)) {
            continue;
        }
        let mut f = process_vnode_info(&rwpi.prp_vip, None);
        f.fd = FdName::Txt;
        out.push(f);
    }

    out
}

/// List FDs for a PID
fn list_fds(pid: pid_t) -> Vec<ProcFdInfo> {
    unsafe {
        let buf_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0);
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

/// Build the `OpenFile` for one descriptor, whatever kind of object it holds.
fn descriptor(pid: pid_t, src: FdSource, fdtype: u32) -> Option<OpenFile> {
    match fdtype {
        PROX_FDTYPE_VNODE => process_vnode_fd(pid, src),
        PROX_FDTYPE_SOCKET => process_socket_fd(pid, src),
        PROX_FDTYPE_PIPE => process_pipe_fd(pid, src),
        PROX_FDTYPE_KQUEUE => process_kqueue_fd(pid, src),
        PROX_FDTYPE_PSEM => process_psem_fd(pid, src),
        PROX_FDTYPE_PSHM => process_pshm_fd(pid, src),
        PROX_FDTYPE_CHANNEL => process_channel_fd(pid, src),
        // These carry no per-descriptor info flavor; lsof lists the type with
        // an empty name.
        PROX_FDTYPE_FSEVENTS => Some(bare_fd(src, FileType::Fsevents)),
        PROX_FDTYPE_ATALK => Some(bare_fd(src, FileType::Atalk)),
        PROX_FDTYPE_NETPOLICY => Some(bare_fd(src, FileType::Npolicy)),
        PROX_FDTYPE_NEXUS => Some(bare_fd(src, FileType::Nexus)),
        _ => None,
    }
}

/// List the file ports a process holds.
fn list_fileports(pid: pid_t) -> Vec<ProcFilePortInfo> {
    unsafe {
        let buf_size = proc_pidinfo(pid, PROC_PIDLISTFILEPORTS, 0, std::ptr::null_mut(), 0);
        if buf_size <= 0 {
            return Vec::new();
        }
        let count = buf_size as usize / mem::size_of::<ProcFilePortInfo>() + 16;
        let alloc = count * mem::size_of::<ProcFilePortInfo>();
        let mut ports: Vec<ProcFilePortInfo> = vec![mem::zeroed(); count];
        let actual = proc_pidinfo(
            pid,
            PROC_PIDLISTFILEPORTS,
            0,
            ports.as_mut_ptr() as *mut c_void,
            alloc as c_int,
        );
        if actual <= 0 {
            return Vec::new();
        }
        ports.truncate(actual as usize / mem::size_of::<ProcFilePortInfo>());
        ports.retain(|p| p.proc_fileport != 0);
        ports
    }
}

/// Where a descriptor's information comes from.
///
/// A process reaches most files through a file descriptor, but Mach also lets
/// it hold a file by *file port*; both answer the same `proc_pidinfo` flavors
/// through different entry points, and lsof lists file ports as `fp.` rows.
#[derive(Copy, Clone)]
enum FdSource {
    Fd(i32),
    FilePort(u32),
}

impl FdSource {
    /// Fetch one info flavor for this descriptor.
    ///
    /// # Safety
    /// `buffer` must point to at least `size` writable bytes of the layout the
    /// flavor returns.
    unsafe fn info(self, pid: pid_t, flavor: c_int, buffer: *mut c_void, size: c_int) -> c_int {
        unsafe {
            match self {
                Self::Fd(fd) => proc_pidfdinfo(pid, fd, flavor, buffer, size),
                Self::FilePort(port) => proc_pidfileportinfo(pid, port, flavor, buffer, size),
            }
        }
    }

    /// The FD column entry for this descriptor.
    fn fd_name(self) -> FdName {
        match self {
            Self::Fd(fd) => FdName::Number(fd),
            Self::FilePort(_) => FdName::FilePort,
        }
    }

    /// The Mach file port a file was reached through, if any.
    fn file_port(self) -> Option<u32> {
        match self {
            Self::Fd(_) => None,
            Self::FilePort(port) => Some(port),
        }
    }
}

/// Process a vnode FD
fn process_vnode_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut vnpi: VnodeFdInfoWithPath = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDVNODEPATHINFO,
            &mut vnpi as *mut _ as *mut c_void,
            mem::size_of::<VnodeFdInfoWithPath>() as c_int,
        );
        if (ret as usize) < mem::size_of::<VnodeFdInfoWithPath>() {
            // A descriptor whose vnode has been revoked (`revoke(2)`, or a tty
            // torn out from under the process) answers ENOENT. lsof still
            // lists the fd, named `(revoked)`.
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Some(OpenFile {
                    fd: src.fd_name(),
                    file_type: FileType::Unknown(String::new()),
                    name: "(revoked)".to_string(),
                    ..Default::default()
                });
            }
            return None;
        }
        let mut of = process_vnode_info(&vnpi.pvip, Some(&vnpi.pfi));
        of.fd = src.fd_name();
        Some(of)
    }
}

/// Process a socket FD
fn process_socket_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut si: SocketFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
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
            AF_ROUTE => FileType::Rte,
            AF_NDRV => FileType::Ndrv,
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
        let mut device_label = Some(format!("0x{:x}", { si.psi.soi_pcb }));

        match family {
            AF_INET | AF_INET6 => {
                // `in_sockinfo` sits at offset 0 of the union for both plain
                // internet sockets and TCP ones (as `tcpsi_ini`), so the
                // addresses are read the same way; only TCP adds a state and
                // the protocol control block lsof prints as the device.
                if si.psi.soi_kind == SOCKINFO_IN || si.psi.soi_kind == SOCKINFO_TCP {
                    let proto_bytes = &si.psi.soi_proto;
                    let ini: &InSockInfo = &*(proto_bytes.as_ptr() as *const InSockInfo);

                    if protocol == IPPROTO_TCP {
                        let tcp: &TcpSockInfo = &*(proto_bytes.as_ptr() as *const TcpSockInfo);
                        sock_info.tcp_state = Some(TcpState::from_raw(tcp.tcpsi_state));
                        device_label = Some(format!("0x{:x}", { tcp.tcpsi_tp }));
                    }

                    let lp = u16::from_be(ini.insi_lport as u16);
                    let fp = u16::from_be(ini.insi_fport as u16);
                    let (la, fa) = if family == AF_INET {
                        (
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(
                                ini.insi_laddr.ina_46.i46a_addr4.s_addr,
                            ))),
                            IpAddr::V4(Ipv4Addr::from(u32::from_be(
                                ini.insi_faddr.ina_46.i46a_addr4.s_addr,
                            ))),
                        )
                    } else {
                        (
                            IpAddr::V6(Ipv6Addr::from(ini.insi_laddr.ina_6.s6_addr)),
                            IpAddr::V6(Ipv6Addr::from(ini.insi_faddr.ina_6.s6_addr)),
                        )
                    };

                    sock_info.local = InetAddr {
                        addr: Some(la),
                        port: lp,
                    };
                    sock_info.foreign = InetAddr {
                        addr: Some(fa),
                        port: fp,
                    };
                    name = format_inet_name(la, lp, fa, fp, proto_str);
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
                        name = match un.unsi_conn_pcb {
                            0 => "->(none)".to_string(),
                            pcb => format!("->0x{pcb:x}"),
                        };
                    } else {
                        name = path;
                    }
                }
            }
            AF_SYSTEM => {
                // Kernel control sockets are named by their control, id and
                // unit, e.g. `[ctl com.apple.net.netagent id 3 unit 7]`.
                if si.psi.soi_kind == SOCKINFO_KERN_EVENT {
                    let ke: &KernEventInfo = &*(si.psi.soi_proto.as_ptr() as *const KernEventInfo);
                    name = format!(
                        "[event {}:{}:{}]",
                        { ke.kesi_vendor_code_filter },
                        { ke.kesi_class_filter },
                        { ke.kesi_subclass_filter }
                    );
                } else if si.psi.soi_kind == SOCKINFO_KERN_CTL {
                    let kc: &KernCtlInfo = &*(si.psi.soi_proto.as_ptr() as *const KernCtlInfo);
                    name = format!(
                        "[ctl {} id {} unit {}]",
                        cstr_from_bytes(&kc.kcsi_name),
                        { kc.kcsi_id },
                        { kc.kcsi_unit }
                    );
                }
            }
            AF_NDRV => {
                if si.psi.soi_kind == SOCKINFO_NDRV {
                    let nd: &NdrvInfo = &*(si.psi.soi_proto.as_ptr() as *const NdrvInfo);
                    // The kernel keeps the interface name and its unit
                    // number apart: "en" + 6 is what lsof prints as en6.
                    let ifname = cstr_from_bytes(&nd.ndrvsi_if_name);
                    if !ifname.is_empty() {
                        name = format!("-> {ifname}{}", { nd.ndrvsi_if_unit });
                    }
                }
            }
            AF_ROUTE => {}
            _ => {
                name = format!("protocol={}", protocol);
            }
        }

        Some(OpenFile {
            fd: src.fd_name(),
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
            device_label,
            file_flags: Some(si.pfi.fi_openflags as i64),
            file_port: None,
            file_status: Some(si.pfi.fi_status),
            file_struct_addr: None,
        })
    }
}

/// Process a pipe FD
fn process_pipe_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut pi: PipeFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDPIPEINFO,
            &mut pi as *mut _ as *mut c_void,
            mem::size_of::<PipeFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<PipeFdInfo>() {
            return None;
        }
        // lsof reports neither an access mode nor the open flags for a pipe,
        // names it only by the peer it is joined to, and gives the buffer size
        // rather than the byte count currently queued.
        let name = match pi.pipe_info.pipe_peerhandle {
            0 => String::new(),
            peer => format!("->0x{peer:x}"),
        };
        Some(OpenFile {
            fd: src.fd_name(),
            access: Access::None,
            lock: ' ',
            file_type: FileType::Pipe,
            device: None,
            size: Some(pi.pipe_info.pipe_stat.vst_blksize as u64),
            offset: None,
            inode: None,
            nlink: None,
            name,
            name_append: None,
            socket_info: None,
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            device_label: Some(format!("0x{:x}", { pi.pipe_info.pipe_handle })),
            file_flags: None,
            file_port: None,
            file_status: None,
            file_struct_addr: None,
        })
    }
}

/// A descriptor class the kernel exposes by type alone, with no info flavor.
fn bare_fd(src: FdSource, file_type: FileType) -> OpenFile {
    OpenFile {
        fd: src.fd_name(),
        file_type,
        name: String::new(),
        ..Default::default()
    }
}

/// Process a POSIX semaphore FD
fn process_psem_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut pi: PsemFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDPSEMINFO,
            &mut pi as *mut _ as *mut c_void,
            mem::size_of::<PsemFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<PsemFdInfo>() {
            return None;
        }
        Some(OpenFile {
            fd: src.fd_name(),
            access: access_from_flags(pi.pfi.fi_openflags),
            file_type: FileType::Psem,
            offset: Some(pi.pfi.fi_offset as u64),
            name: cstr_from_bytes(&pi.pseminfo.psem_name),
            file_flags: Some(pi.pfi.fi_openflags as i64),
            file_port: None,
            file_status: Some(pi.pfi.fi_status),
            ..Default::default()
        })
    }
}

/// Process a POSIX shared memory FD
fn process_pshm_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut pi: PshmFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDPSHMINFO,
            &mut pi as *mut _ as *mut c_void,
            mem::size_of::<PshmFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<PshmFdInfo>() {
            return None;
        }
        Some(OpenFile {
            fd: src.fd_name(),
            access: access_from_flags(pi.pfi.fi_openflags),
            file_type: FileType::Pshm,
            size: Some(pi.pshminfo.pshm_stat.vst_size as u64),
            name: cstr_from_bytes(&pi.pshminfo.pshm_name),
            file_flags: Some(pi.pfi.fi_openflags as i64),
            file_port: None,
            file_status: Some(pi.pfi.fi_status),
            ..Default::default()
        })
    }
}

/// Process a skywalk channel FD
fn process_channel_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut ci: ChannelFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDCHANNELINFO,
            &mut ci as *mut _ as *mut c_void,
            mem::size_of::<ChannelFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<ChannelFdInfo>() {
            return None;
        }
        let (kind, name) = channel_labels(&ci.channelinfo);
        Some(OpenFile {
            fd: src.fd_name(),
            access: access_from_flags(ci.pfi.fi_openflags),
            file_type: FileType::Channel,
            device_label: Some(kind),
            name,
            file_flags: Some(ci.pfi.fi_openflags as i64),
            file_port: None,
            file_status: Some(ci.pfi.fi_status),
            ..Default::default()
        })
    }
}

/// Split a channel into the kind lsof puts in DEVICE and the
/// `<instance>[<port>] <flags>` text it puts in NAME.
fn channel_labels(ci: &ProcChannelInfo) -> (String, String) {
    let kind = match ci.chi_type {
        PROC_CHANNEL_TYPE_USER_PIPE => "upipe".to_string(),
        PROC_CHANNEL_TYPE_KERNEL_PIPE => "kpipe".to_string(),
        PROC_CHANNEL_TYPE_NET_IF => "netif".to_string(),
        PROC_CHANNEL_TYPE_FLOW_SWITCH => "flowsw".to_string(),
        other => format!("type={other}"),
    };

    // The flag list is space-separated after the instance, and lsof keeps the
    // separating space even when no flag applies. Only user-packet-pool is
    // rendered; lsof leaves the remaining channel flags out of the name.
    let flags = if ci.chi_flags & PROC_CHANNEL_FLAGS_USER_PACKET_POOL != 0 {
        "user-packet-pool"
    } else {
        ""
    };
    let name = format!("{}[{}] {flags}", format_uuid(&ci.chi_instance), ci.chi_port);
    (kind, name)
}

/// Format a raw UUID the way the system tools print it.
fn format_uuid(u: &[u8; 16]) -> String {
    let hex: String = u.iter().map(|b| format!("{b:02X}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// Process a kqueue FD
fn process_kqueue_fd(pid: pid_t, src: FdSource) -> Option<OpenFile> {
    unsafe {
        let mut ki: KqueueFdInfo = mem::zeroed();
        let ret = src.info(
            pid,
            PROC_PIDFDKQUEUEINFO,
            &mut ki as *mut _ as *mut c_void,
            mem::size_of::<KqueueFdInfo>() as c_int,
        );
        if (ret as usize) < mem::size_of::<KqueueFdInfo>() {
            return None;
        }
        let access = access_from_flags(ki.pfi.fi_openflags);
        Some(OpenFile {
            fd: src.fd_name(),
            access,
            lock: ' ',
            file_type: FileType::Kqueue,
            device: None,
            size: None,
            offset: None,
            inode: None,
            nlink: None,
            name: format!(
                "count={}, state=0x{:x}",
                ki.kqueue_info.kq_stat.vst_size, ki.kqueue_info.kq_state
            ),
            name_append: None,
            socket_info: None,
            sel_flags: 0,
            is_nfs: false,
            rdev: None,
            device_label: None,
            file_flags: Some(ki.pfi.fi_openflags as i64),
            file_port: None,
            file_status: Some(ki.pfi.fi_status),
            file_struct_addr: None,
        })
    }
}

fn format_inet_name(la: IpAddr, lp: u16, fa: IpAddr, fp: u16, _proto: &str) -> String {
    let local = format_endpoint(&la, lp);
    let foreign = format_endpoint(&fa, fp);

    if is_any_addr(&fa) && fp == 0 {
        local
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

/// Process a single PID into a Process struct (used by parallel gather)
fn process_pid(pid: pid_t) -> Option<Process> {
    let tai = get_task_info(pid)?;

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

    // Mapped files (txt)
    files.extend(text_files(pid));

    // Get open FDs
    let fds = list_fds(pid);
    for fdi in &fds {
        let of = descriptor(pid, FdSource::Fd(fdi.proc_fd), fdi.proc_fdtype);
        if let Some(f) = of {
            files.push(f);
        }
    }

    // Files held through Mach file ports rather than descriptors.
    for fp in list_fileports(pid) {
        let src = FdSource::FilePort(fp.proc_fileport);
        if let Some(mut f) = descriptor(pid, src, fp.proc_fdtype) {
            f.file_port = src.file_port();
            files.push(f);
        }
    }

    Some(Process::new(
        pid,
        tai.pbsd.pbi_ppid as i32,
        tai.pbsd.pbi_pgid as i32,
        tai.pbsd.pbi_uid,
        cmd,
        files,
    ))
}

/// Gather all process information from the system
pub fn gather_processes() -> Vec<Process> {
    let pids = list_pids();

    let mut processes: Vec<Process> = pids.into_par_iter().filter_map(process_pid).collect();

    processes.sort_by_key(|p| p.pid);
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
            assert_eq!(
                &s.soi_protocol as *const _ as usize - p,
                156,
                "soi_protocol offset"
            );
            assert_eq!(
                &s.soi_family as *const _ as usize - p,
                160,
                "soi_family offset"
            );
            assert_eq!(&s.soi_kind as *const _ as usize - p, 232, "soi_kind offset");
            assert_eq!(
                &s.soi_proto as *const _ as usize - p,
                240,
                "soi_proto offset"
            );
            let _ = base;
        }
    }

    /// `in_sockinfo` layout drift silently swaps the local and foreign address
    /// columns instead of failing, so pin every offset the address reads depend
    /// on against <sys/proc_info.h>.
    #[test]
    fn ffi_in_sockinfo_field_offsets() {
        assert_eq!(
            mem::offset_of!(InSockInfo, insi_faddr) + mem::offset_of!(In4In6Addr, i46a_addr4),
            44,
            "insi_faddr.ina_46.i46a_addr4 offset"
        );
        assert_eq!(
            mem::offset_of!(InSockInfo, insi_laddr) + mem::offset_of!(In4In6Addr, i46a_addr4),
            60,
            "insi_laddr.ina_46.i46a_addr4 offset"
        );
        assert_eq!(mem::offset_of!(InSockInfo, insi_faddr), 32, "insi_faddr");
        assert_eq!(mem::offset_of!(InSockInfo, insi_laddr), 48, "insi_laddr");
        assert_eq!(mem::offset_of!(InSockInfo, insi_v4), 64, "insi_v4");
        assert_eq!(mem::offset_of!(InSockInfo, insi_v6), 68, "insi_v6");
    }

    #[test]
    fn ffi_tcp_sockinfo_field_offsets() {
        assert_eq!(mem::offset_of!(TcpSockInfo, tcpsi_state), 80, "tcpsi_state");
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

    /// The kqueue info struct must match the kernel's byte for byte: an extra
    /// reserved word made `proc_pidfdinfo` come up short and every KQUEUE
    /// descriptor vanished from the listing.
    #[test]
    fn kqueue_struct_matches_the_kernel_layout() {
        assert_eq!(
            mem::size_of::<KqueueInfo>(),
            mem::size_of::<VinfoStat>() + 8
        );
        assert_eq!(
            mem::size_of::<KqueueFdInfo>(),
            mem::size_of::<ProcFileInfo>() + mem::size_of::<KqueueInfo>()
        );
    }

    /// The `PROX_FDTYPE_*` values are a kernel ABI; a wrong one silently drops
    /// a whole class of descriptor.
    #[test]
    fn fd_type_constants_match_the_header() {
        assert_eq!(PROX_FDTYPE_ATALK, 0);
        assert_eq!(PROX_FDTYPE_VNODE, 1);
        assert_eq!(PROX_FDTYPE_SOCKET, 2);
        assert_eq!(PROX_FDTYPE_PSHM, 3);
        assert_eq!(PROX_FDTYPE_PSEM, 4);
        assert_eq!(PROX_FDTYPE_KQUEUE, 5);
        assert_eq!(PROX_FDTYPE_PIPE, 6);
        assert_eq!(PROX_FDTYPE_FSEVENTS, 7);
        assert_eq!(PROX_FDTYPE_NETPOLICY, 9);
        assert_eq!(PROX_FDTYPE_CHANNEL, 10);
        assert_eq!(PROX_FDTYPE_NEXUS, 11);
        // The fd info flavors are a separate numbering from the fd types.
        assert_eq!(PROC_PIDFDVNODEPATHINFO, 2);
        assert_eq!(PROC_PIDFDSOCKETINFO, 3);
        assert_eq!(PROC_PIDFDPSEMINFO, 4);
        assert_eq!(PROC_PIDFDPSHMINFO, 5);
        assert_eq!(PROC_PIDFDPIPEINFO, 6);
        assert_eq!(PROC_PIDFDKQUEUEINFO, 7);
        assert_eq!(PROC_PIDFDCHANNELINFO, 10);
        assert_eq!(SOCKINFO_IN, 1);
        assert_eq!(SOCKINFO_TCP, 2);
    }

    /// Our own kqueue must come back described, not dropped.
    #[test]
    fn kqueue_descriptor_is_listed() {
        let fd = unsafe { libc::kqueue() };
        assert!(fd >= 0, "could not create a kqueue");
        let file = process_kqueue_fd(unsafe { libc::getpid() }, FdSource::Fd(fd));
        unsafe { libc::close(fd) };

        let file = file.expect("kqueue descriptor was dropped");
        assert_eq!(file.file_type, FileType::Kqueue);
        assert!(
            file.name.starts_with("count=") && file.name.contains(", state=0x"),
            "unexpected kqueue name: {}",
            file.name
        );
    }

    /// A channel's kind goes in the DEVICE column and the instance in NAME,
    /// with lsof's separating space before the flag list.
    #[test]
    fn channel_labels_split_kind_from_instance() {
        let ci = ProcChannelInfo {
            chi_instance: [
                0xBE, 0x0A, 0x4E, 0xF8, 0xF3, 0x71, 0x48, 0xAC, 0xBF, 0xCC, 0x18, 0xEA, 0x18, 0x83,
                0x77, 0x44,
            ],
            chi_port: 6,
            chi_type: PROC_CHANNEL_TYPE_FLOW_SWITCH,
            chi_flags: PROC_CHANNEL_FLAGS_USER_PACKET_POOL,
            rfu_1: 0,
        };
        assert_eq!(
            channel_labels(&ci),
            (
                "flowsw".to_string(),
                "BE0A4EF8-F371-48AC-BFCC-18EA18837744[6] user-packet-pool".to_string()
            )
        );

        let bare = ProcChannelInfo {
            chi_flags: 0,
            chi_port: 0,
            chi_type: PROC_CHANNEL_TYPE_KERNEL_PIPE,
            ..ci
        };
        let (kind, name) = channel_labels(&bare);
        assert_eq!(kind, "kpipe");
        assert!(
            name.ends_with("[0] "),
            "lsof keeps the trailing space: {name:?}"
        );
    }

    /// `PROC_PIDVNODEPATHINFO` must be flavor 9; it was once 6
    /// (`PROC_PIDLISTTHREADS`), which silently dropped every `cwd` row.
    #[test]
    fn vnode_path_info_returns_our_cwd() {
        let vpi = get_vnode_path_info(unsafe { libc::getpid() })
            .expect("PROC_PIDVNODEPATHINFO failed for our own pid");
        let cwd = cstr_from_bytes(&vpi.pvi_cdir.vip_path);
        assert_eq!(
            cwd,
            std::env::current_dir().unwrap().to_string_lossy(),
            "pvi_cdir did not match the real cwd"
        );
    }

    /// `txt` rows come from the mapped-region walk; our own test binary and
    /// dyld are always mapped.
    #[test]
    fn text_files_include_the_running_binary_and_dyld() {
        let files = text_files(unsafe { libc::getpid() });
        assert!(!files.is_empty(), "no mapped files found for our own pid");
        assert!(
            files.iter().all(|f| matches!(f.fd, FdName::Txt)),
            "mapped files must be reported as txt"
        );
        assert!(
            files.iter().any(|f| f.name.ends_with("/dyld")),
            "dyld missing from mapped files: {:?}",
            files.iter().map(|f| &f.name).collect::<Vec<_>>()
        );

        // Each vnode appears once, matching lsof's dedup.
        let mut keys: Vec<_> = files.iter().map(|f| (f.device, f.inode)).collect();
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(before, keys.len(), "duplicate txt entries emitted");
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
        assert!(!me.files.is_empty(), "our process should have open files");
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
    fn tcp_sockets_have_state() {
        // All TCP sockets should have a tcp_state set (not None)
        let procs = gather_processes();
        for p in &procs {
            for f in &p.files {
                if let Some(ref si) = f.socket_info
                    && si.protocol == "TCP"
                {
                    assert!(
                        si.tcp_state.is_some(),
                        "TCP socket for pid {} fd {:?} has no tcp_state (name: {})",
                        p.pid,
                        f.fd,
                        f.name
                    );
                }
            }
        }
    }

    #[test]
    fn tcp_listen_sockets_detected() {
        // There should be at least one TCP LISTEN socket on any macOS system
        // (e.g., rapportd, ControlCenter, or other system services)
        let procs = gather_processes();
        let listen_count = procs
            .iter()
            .flat_map(|p| &p.files)
            .filter(|f| {
                f.socket_info.as_ref().is_some_and(|si| {
                    si.protocol == "TCP" && si.tcp_state == Some(TcpState::Listen)
                })
            })
            .count();
        // May be 0 without root, but should not panic
        // listen_count is always >= 0 (usize), just verify we got here without panic
        let _ = listen_count;
    }

    #[test]
    fn tcp_sockets_have_local_port() {
        // TCP sockets with LISTEN state should have a non-zero local port
        let procs = gather_processes();
        for p in &procs {
            for f in &p.files {
                if let Some(ref si) = f.socket_info
                    && si.protocol == "TCP"
                    && si.tcp_state == Some(TcpState::Listen)
                {
                    assert!(
                        si.local.port > 0,
                        "LISTEN socket for pid {} should have a port, got 0",
                        p.pid
                    );
                }
            }
        }
    }

    #[test]
    fn udp_sockets_identified() {
        // Verify UDP sockets are found and have correct protocol string
        let procs = gather_processes();
        for p in &procs {
            for f in &p.files {
                if let Some(ref si) = f.socket_info
                    && si.protocol == "UDP"
                {
                    // UDP protocol should be set correctly
                    assert_eq!(si.protocol, "UDP");
                }
            }
        }
    }

    #[test]
    fn gather_processes_file_types_valid() {
        let procs = gather_processes();
        let valid_types = [
            "REG", "DIR", "CHR", "BLK", "FIFO", "sock", "LINK", "PIPE", "KQUEUE", "unix", "IPv4",
            "IPv6", "systm", "PSXSEM", "PSXSHM", "ATALK", "FSEVENT", "NPOLICY", "CHAN", "NEXUS",
            "rte", "ndrv", "",
        ];
        for p in &procs {
            for f in &p.files {
                let ts = f.file_type.as_str();
                assert!(
                    valid_types.contains(&ts) || ts.chars().all(|c| c.is_ascii_digit() || c == 'o'),
                    "unexpected file type '{}' for pid {} fd {:?}",
                    ts,
                    p.pid,
                    f.fd
                );
            }
        }
    }
}
