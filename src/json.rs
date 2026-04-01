//! JSON output module

use serde::Serialize;
use std::io::{self, Write};

use crate::types::*;

#[derive(Serialize)]
struct JsonProcess {
    command: String,
    pid: i32,
    uid: u32,
    pgid: i32,
    ppid: i32,
    files: Vec<JsonFile>,
}

#[derive(Serialize)]
struct JsonFile {
    fd: String,
    r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_off: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lock: Option<String>,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tcp_state: Option<String>,
}

pub fn print_json(procs: &[Process]) {
    let json_procs: Vec<JsonProcess> = procs
        .iter()
        .map(|p| JsonProcess {
            command: p.command.clone(),
            pid: p.pid,
            uid: p.uid,
            pgid: p.pgid,
            ppid: p.ppid,
            files: p
                .files
                .iter()
                .map(|f| {
                    let access = match f.access {
                        Access::None => None,
                        a => Some(a.as_char().to_string()),
                    };
                    let lock = if f.lock != ' ' {
                        Some(f.lock.to_string())
                    } else {
                        None
                    };
                    let size_off = f.size.or(f.offset);
                    let device = f.device.map(|(maj, min)| format!("{maj},{min}"));
                    let protocol = f
                        .socket_info
                        .as_ref()
                        .filter(|si| !si.protocol.is_empty())
                        .map(|si| si.protocol.clone());
                    let tcp_state = f
                        .socket_info
                        .as_ref()
                        .and_then(|si| si.tcp_state.as_ref())
                        .map(|s| s.to_string());

                    JsonFile {
                        fd: f.fd.with_access(f.access),
                        r#type: f.file_type.as_str().to_string(),
                        device,
                        size_off,
                        node: f.inode,
                        access,
                        lock,
                        name: f.full_name(),
                        protocol,
                        tcp_state,
                    }
                })
                .collect(),
        })
        .collect();

    let out = io::stdout();
    let mut out = out.lock();
    let _ = serde_json::to_writer_pretty(&mut out, &json_procs);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgid: pid,
            uid: 501,
            command: cmd.to_string(),
            files,
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

    #[test]
    fn print_json_empty() {
        print_json(&[]);
    }

    #[test]
    fn print_json_single_proc() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_json(&procs);
    }

    #[test]
    fn print_json_with_socket() {
        let mut f = make_file(5, FileType::IPv4, "*:80");
        f.socket_info = Some(SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(TcpState::Listen),
            ..Default::default()
        });
        let procs = vec![make_proc(1, "nginx", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_with_device_and_inode() {
        let mut f = make_file(3, FileType::Reg, "/tmp/x");
        f.device = Some((1, 16));
        f.inode = Some(12345);
        f.size = Some(4096);
        let procs = vec![make_proc(1, "cat", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_access_none_omitted() {
        let mut f = make_file(3, FileType::Reg, "/tmp/x");
        f.access = Access::None;
        let procs = vec![make_proc(1, "test", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_lock_char() {
        let mut f = make_file(3, FileType::Reg, "/tmp/x");
        f.lock = 'R';
        let procs = vec![make_proc(1, "test", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_multiple_procs() {
        let procs = vec![
            make_proc(1, "init", vec![make_file(0, FileType::Chr, "/dev/null")]),
            make_proc(
                2,
                "bash",
                vec![
                    make_file(0, FileType::Chr, "/dev/pts/0"),
                    make_file(1, FileType::Chr, "/dev/pts/0"),
                ],
            ),
        ];
        print_json(&procs);
    }

    #[test]
    fn print_json_offset_used_when_no_size() {
        let mut f = make_file(3, FileType::Reg, "/tmp/x");
        f.offset = Some(100);
        let procs = vec![make_proc(1, "test", vec![f])];
        print_json(&procs);
    }
}
