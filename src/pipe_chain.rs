//! Trace pipe/socket pairs between processes, show IPC topology

use std::collections::HashMap;
use std::io::{self, Write};

use serde::Serialize;

use crate::output::Theme;
use crate::types::*;

#[derive(Serialize)]
struct PipeConnection {
    kind: String,
    identifier: String,
    endpoints: Vec<PipeEndpoint>,
}

#[derive(Serialize)]
struct PipeEndpoint {
    pid: i32,
    command: String,
    fd: String,
}

/// Extract a pipe/socket identifier from an open file name.
/// On macOS, pipes look like `->0xabcdef1234` — the hex address is the key.
/// On Linux, pipes look like `pipe:[12345]` — the inode is the key.
/// Unix sockets on Linux: `socket:[12345]`.
fn pipe_identifier(file: &OpenFile) -> Option<(String, String)> {
    let name = &file.name;

    // macOS: pipe names contain "->0x..." hex addresses
    if file.file_type == FileType::Pipe {
        // macOS style: look for hex address in name
        if let Some(pos) = name.find("0x") {
            let hex = name[pos..]
                .split_whitespace()
                .next()
                .unwrap_or(&name[pos..]);
            return Some(("pipe".to_string(), hex.to_string()));
        }
        // Linux style: pipe:[12345]
        if let Some(start) = name.find("pipe:[") {
            let rest = &name[start + 6..];
            if let Some(end) = rest.find(']') {
                return Some(("pipe".to_string(), rest[..end].to_string()));
            }
        }
        // Fallback: use the whole name as identifier if it's a pipe
        return Some(("pipe".to_string(), name.clone()));
    }

    // Unix domain sockets
    if file.file_type == FileType::Unix {
        // Linux: socket:[12345]
        if let Some(start) = name.find("socket:[") {
            let rest = &name[start + 8..];
            if let Some(end) = rest.find(']') {
                return Some(("unix".to_string(), rest[..end].to_string()));
            }
        }
        // macOS: unix sockets with ->0x... addresses
        if let Some(pos) = name.find("0x") {
            let hex = name[pos..]
                .split_whitespace()
                .next()
                .unwrap_or(&name[pos..]);
            return Some(("unix".to_string(), hex.to_string()));
        }
    }

    None
}

pub fn print_pipe_chain(procs: &[Process], theme: &Theme, json: bool) {
    // Group endpoints by identifier
    let mut groups: HashMap<(String, String), Vec<PipeEndpoint>> = HashMap::new();

    for p in procs {
        for f in &p.files {
            if let Some((kind, id)) = pipe_identifier(f) {
                groups.entry((kind, id)).or_default().push(PipeEndpoint {
                    pid: p.pid,
                    command: p.command.clone(),
                    fd: f.fd.with_access(f.access),
                });
            }
        }
    }

    // Only keep groups that connect multiple processes (or multiple FDs)
    let mut connections: Vec<PipeConnection> = groups
        .into_iter()
        .filter(|(_, endpoints)| endpoints.len() >= 2)
        .map(|((kind, id), endpoints)| PipeConnection {
            kind,
            identifier: id,
            endpoints,
        })
        .collect();

    // Sort by first endpoint PID for stable output
    connections.sort_by_key(|c| c.endpoints.first().map(|e| e.pid).unwrap_or(0));

    if json {
        print_pipe_chain_json(&connections);
    } else {
        print_pipe_chain_text(&connections, theme);
    }
}

fn print_pipe_chain_text(connections: &[PipeConnection], theme: &Theme) {
    let out = io::stdout();
    let mut out = out.lock();

    if connections.is_empty() {
        let _ = writeln!(out, "No pipe/socket IPC connections found.");
        return;
    }

    let _ = writeln!(
        out,
        "\n{bold}═══ Pipe/Socket IPC Topology ═══{reset}\n",
        bold = theme.bold(),
        reset = theme.reset(),
    );

    for conn in connections {
        let _ = write!(
            out,
            "{dim}[{kind}:{id}]{reset} ",
            dim = theme.dim(),
            kind = conn.kind,
            id = conn.identifier,
            reset = theme.reset(),
        );

        for (i, ep) in conn.endpoints.iter().enumerate() {
            if i > 0 {
                let _ = write!(
                    out,
                    " {cyan}──{kind}──>{reset} ",
                    cyan = theme.cyan(),
                    kind = conn.kind,
                    reset = theme.reset(),
                );
            }
            let _ = write!(
                out,
                "{mag}{pid}{reset}/{bold}{cmd}{reset}({green}{fd}{reset})",
                mag = theme.magenta(),
                pid = ep.pid,
                reset = theme.reset(),
                bold = theme.bold(),
                cmd = ep.command,
                green = theme.green(),
                fd = ep.fd,
            );
        }
        let _ = writeln!(out);
    }

    let _ = writeln!(
        out,
        "\n{dim}  {} IPC connection(s) found{reset}\n",
        connections.len(),
        dim = theme.dim(),
        reset = theme.reset(),
    );
}

fn print_pipe_chain_json(connections: &[PipeConnection]) {
    let out = io::stdout();
    let mut out = out.lock();
    let wrapper = serde_json::json!({ "pipe_chains": connections });
    let _ = serde_json::to_writer_pretty(&mut out, &wrapper);
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
            uid: 0,
            command: cmd.to_string(),
            files,
            sel_flags: 0,
            sel_state: 0,
        }
    }

    fn make_pipe(fd: i32, name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::Pipe,
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn make_unix(fd: i32, name: &str) -> OpenFile {
        OpenFile {
            fd: FdName::Number(fd),
            access: Access::ReadWrite,
            file_type: FileType::Unix,
            name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn pipe_identifier_macos_pipe() {
        let f = make_pipe(3, "->0xabcdef1234");
        let result = pipe_identifier(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "pipe");
        assert_eq!(id, "0xabcdef1234");
    }

    #[test]
    fn pipe_identifier_linux_pipe() {
        let f = make_pipe(3, "pipe:[12345]");
        let result = pipe_identifier(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "pipe");
        assert_eq!(id, "12345");
    }

    #[test]
    fn pipe_identifier_linux_unix_socket() {
        let f = make_unix(3, "socket:[67890]");
        let result = pipe_identifier(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "unix");
        assert_eq!(id, "67890");
    }

    #[test]
    fn pipe_identifier_macos_unix_socket() {
        let f = make_unix(3, "->0xdeadbeef");
        let result = pipe_identifier(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "unix");
        assert_eq!(id, "0xdeadbeef");
    }

    #[test]
    fn pipe_identifier_regular_file_none() {
        let f = OpenFile {
            fd: FdName::Number(3),
            access: Access::Read,
            file_type: FileType::Reg,
            name: "/tmp/foo".to_string(),
            ..Default::default()
        };
        assert!(pipe_identifier(&f).is_none());
    }

    #[test]
    fn pipe_identifier_generic_sock_none() {
        let f = OpenFile {
            fd: FdName::Number(3),
            access: Access::ReadWrite,
            file_type: FileType::Sock,
            name: "socket".to_string(),
            ..Default::default()
        };
        assert!(pipe_identifier(&f).is_none());
    }

    #[test]
    fn pipe_identifier_pipe_fallback_name() {
        let f = make_pipe(3, "some-pipe-name");
        let result = pipe_identifier(&f);
        assert!(result.is_some());
        let (kind, id) = result.unwrap();
        assert_eq!(kind, "pipe");
        assert_eq!(id, "some-pipe-name");
    }

    #[test]
    fn print_pipe_chain_empty_no_panic() {
        let theme = Theme::new(false);
        print_pipe_chain(&[], &theme, false);
    }

    #[test]
    fn print_pipe_chain_connected_processes() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(100, "writer", vec![make_pipe(1, "->0xabc123")]),
            make_proc(200, "reader", vec![make_pipe(0, "->0xabc123")]),
        ];
        print_pipe_chain(&procs, &theme, false);
    }

    #[test]
    fn print_pipe_chain_json_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(100, "writer", vec![make_pipe(1, "->0xabc123")]),
            make_proc(200, "reader", vec![make_pipe(0, "->0xabc123")]),
        ];
        print_pipe_chain(&procs, &theme, true);
    }

    #[test]
    fn print_pipe_chain_single_endpoint_filtered() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(100, "solo", vec![make_pipe(1, "->0xunique")])];
        // Single endpoint should not appear as a connection
        print_pipe_chain(&procs, &theme, false);
    }

    #[test]
    fn print_pipe_chain_unix_sockets() {
        let theme = Theme::new(false);
        let procs = vec![
            make_proc(100, "server", vec![make_unix(3, "socket:[99999]")]),
            make_proc(200, "client", vec![make_unix(4, "socket:[99999]")]),
        ];
        print_pipe_chain(&procs, &theme, false);
    }
}
