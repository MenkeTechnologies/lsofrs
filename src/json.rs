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
