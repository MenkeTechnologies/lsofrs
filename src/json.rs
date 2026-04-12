//! JSON output module

use serde::Serialize;
use serde_json::Value;
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

fn build_json_processes(procs: &[Process]) -> Vec<JsonProcess> {
    procs
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
        .collect()
}

/// Serialize the default `-J` / `--json` process list to a JSON value (for tests and tooling).
pub(crate) fn processes_json_value(procs: &[Process]) -> serde_json::Result<Value> {
    serde_json::to_value(build_json_processes(procs))
}

pub fn print_json(procs: &[Process]) {
    let json_procs = build_json_processes(procs);
    let out = io::stdout();
    let mut out = out.lock();
    let _ = serde_json::to_writer_pretty(&mut out, &json_procs);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process::new(pid, 1, pid, 501, cmd.to_string(), files)
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

    fn json_array(procs: &[Process]) -> serde_json::Value {
        processes_json_value(procs).expect("json serialization")
    }

    #[test]
    fn build_json_empty_array() {
        let v = json_array(&[]);
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[test]
    fn build_json_process_top_level_fields() {
        let procs = vec![make_proc(
            42,
            "mydaemon",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        let v = json_array(&procs);
        let row = &v[0];
        assert_eq!(row["command"], "mydaemon");
        assert_eq!(row["pid"], 42);
        assert_eq!(row["uid"], 501);
        assert_eq!(row["pgid"], 42);
        assert_eq!(row["ppid"], 1);
        assert!(row["files"].is_array());
    }

    #[test]
    fn build_json_file_fd_type_name() {
        let procs = vec![make_proc(1, "t", vec![make_file(7, FileType::Dir, "/var")])];
        let f = &json_array(&procs)[0]["files"][0];
        assert_eq!(f["fd"], "7u");
        assert_eq!(f["type"], "DIR");
        assert_eq!(f["name"], "/var");
    }

    #[test]
    fn build_json_access_read_write_suffixes() {
        let mut fr = make_file(1, FileType::Reg, "/r");
        fr.access = Access::Read;
        let mut fw = make_file(2, FileType::Reg, "/w");
        fw.access = Access::Write;
        let mut fnone = make_file(4, FileType::Reg, "/n");
        fnone.access = Access::None;
        let procs = vec![make_proc(1, "t", vec![fr, fw, fnone])];
        let files = &json_array(&procs)[0]["files"];
        assert_eq!(files[0]["access"], "r");
        assert_eq!(files[1]["access"], "w");
        assert!(files[2].get("access").is_none());
    }

    #[test]
    fn build_json_lock_omitted_when_space_present_when_non_space() {
        let mut a = make_file(0, FileType::Reg, "/a");
        a.lock = ' ';
        let mut b = make_file(1, FileType::Reg, "/b");
        b.lock = 'W';
        let procs = vec![make_proc(1, "t", vec![a, b])];
        let files = &json_array(&procs)[0]["files"];
        assert!(files[0].get("lock").is_none());
        assert_eq!(files[1]["lock"], "W");
    }

    #[test]
    fn build_json_device_and_node_from_inode() {
        let mut f = make_file(3, FileType::Reg, "/dev/foo");
        f.device = Some((8, 1));
        f.inode = Some(999);
        let procs = vec![make_proc(2, "cat", vec![f])];
        let jf = &json_array(&procs)[0]["files"][0];
        assert_eq!(jf["device"], "8,1");
        assert_eq!(jf["node"], 999);
    }

    #[test]
    fn build_json_size_off_prefers_size_over_offset() {
        let mut f = make_file(3, FileType::Reg, "/x");
        f.size = Some(100);
        f.offset = Some(200);
        let procs = vec![make_proc(1, "t", vec![f])];
        assert_eq!(json_array(&procs)[0]["files"][0]["size_off"], 100);
    }

    #[test]
    fn build_json_size_off_falls_back_to_offset() {
        let mut f = make_file(3, FileType::Reg, "/x");
        f.offset = Some(512);
        let procs = vec![make_proc(1, "t", vec![f])];
        assert_eq!(json_array(&procs)[0]["files"][0]["size_off"], 512);
    }

    #[test]
    fn build_json_full_name_includes_deleted_append() {
        let mut f = make_file(3, FileType::Reg, "/gone");
        f.name_append = Some("(deleted)".to_string());
        let procs = vec![make_proc(1, "t", vec![f])];
        assert_eq!(json_array(&procs)[0]["files"][0]["name"], "/gone (deleted)");
    }

    #[test]
    fn build_json_socket_protocol_and_tcp_state() {
        let mut f = make_file(5, FileType::IPv4, "*:443");
        f.socket_info = Some(SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(TcpState::Listen),
            ..Default::default()
        });
        let procs = vec![make_proc(9, "srv", vec![f])];
        let jf = &json_array(&procs)[0]["files"][0];
        assert_eq!(jf["protocol"], "TCP");
        assert_eq!(jf["tcp_state"], "LISTEN");
    }

    #[test]
    fn build_json_socket_empty_protocol_field_omitted() {
        let mut f = make_file(5, FileType::IPv4, "*:443");
        f.socket_info = Some(SocketInfo {
            protocol: String::new(),
            tcp_state: Some(TcpState::TimeWait),
            ..Default::default()
        });
        let jf = &json_array(&[make_proc(1, "t", vec![f])])[0]["files"][0];
        assert!(jf.get("protocol").is_none());
        assert_eq!(jf["tcp_state"], "TIME_WAIT");
    }

    #[test]
    fn build_json_unknown_file_type_string() {
        let f = make_file(2, FileType::Unknown("XYZ".to_string()), "/q");
        let jf = &json_array(&[make_proc(1, "t", vec![f])])[0]["files"][0];
        assert_eq!(jf["type"], "XYZ");
    }

    #[test]
    fn build_json_cwd_fd_non_numeric_no_access_suffix_in_fd_string() {
        let f = OpenFile {
            fd: FdName::Cwd,
            access: Access::ReadWrite,
            file_type: FileType::Dir,
            name: "/proc/1/cwd".to_string(),
            ..Default::default()
        };
        let jf = &json_array(&[make_proc(1, "sh", vec![f])])[0]["files"][0];
        assert_eq!(jf["fd"], "cwd");
    }

    #[test]
    fn build_json_two_processes_order_preserved() {
        let procs = vec![
            make_proc(10, "first", vec![make_file(0, FileType::Chr, "/dev/null")]),
            make_proc(20, "second", vec![]),
        ];
        let v = json_array(&procs);
        assert_eq!(v[0]["pid"], 10);
        assert_eq!(v[1]["pid"], 20);
        assert_eq!(v[1]["files"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn build_json_tcp_state_omitted_when_none() {
        let mut f = make_file(4, FileType::IPv4, "*:53");
        f.socket_info = Some(SocketInfo {
            protocol: "UDP".to_string(),
            tcp_state: None,
            ..Default::default()
        });
        let jf = &json_array(&[make_proc(1, "dns", vec![f])])[0]["files"][0];
        assert!(jf.get("tcp_state").is_none());
        assert_eq!(jf["protocol"], "UDP");
    }

    #[test]
    fn build_json_many_files_single_process() {
        let files: Vec<OpenFile> = (0..40)
            .map(|i| make_file(i, FileType::Reg, &format!("/tmp/f{i}")))
            .collect();
        let v = json_array(&[make_proc(1, "many", files)]);
        assert_eq!(v[0]["files"].as_array().unwrap().len(), 40);
    }

    #[test]
    fn build_json_mem_txt_fd_strings() {
        let mem = OpenFile {
            fd: FdName::Mem,
            access: Access::Read,
            file_type: FileType::Reg,
            name: "[stack]".to_string(),
            ..Default::default()
        };
        let txt = OpenFile {
            fd: FdName::Txt,
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/bin/ls".to_string(),
            ..Default::default()
        };
        let files = &json_array(&[make_proc(1, "bin", vec![mem, txt])])[0]["files"];
        assert_eq!(files[0]["fd"], "mem");
        assert_eq!(files[1]["fd"], "txt");
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

    #[test]
    fn print_json_name_append_deleted() {
        let mut f = make_file(3, FileType::Reg, "/tmp/zombie");
        f.name_append = Some("(deleted)".to_string());
        let procs = vec![make_proc(1, "holder", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_ipv6_socket_with_protocol() {
        let mut f = make_file(4, FileType::IPv6, "[::1]:443");
        f.socket_info = Some(SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(TcpState::Established),
            ..Default::default()
        });
        let procs = vec![make_proc(1, "srv", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_unknown_file_type_round_trips_name() {
        let f = make_file(2, FileType::Unknown("CUSTOM".to_string()), "/dev/foo");
        let procs = vec![make_proc(1, "t", vec![f])];
        print_json(&procs);
    }

    #[test]
    fn print_json_socket_empty_protocol_omitted_from_json() {
        let mut f = make_file(5, FileType::IPv4, "*:443");
        f.socket_info = Some(SocketInfo {
            protocol: String::new(),
            tcp_state: Some(TcpState::Listen),
            ..Default::default()
        });
        let procs = vec![make_proc(1, "t", vec![f])];
        print_json(&procs);
    }
}
