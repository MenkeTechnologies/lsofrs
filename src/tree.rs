//! Process tree view — show parent/child relationships with FD counts

use std::collections::HashMap;
use std::io::{self, Write};

use crate::output::Theme;
use crate::strutil::truncate_max_bytes;
use crate::types::*;

struct TreeNode {
    pid: i32,
    ppid: i32,
    command: String,
    uid: u32,
    files: Vec<OpenFile>,
    children: Vec<i32>,
}

pub fn print_tree(procs: &[Process], theme: &Theme, json: bool) {
    if json {
        print_tree_json(procs);
        return;
    }

    let mut nodes: HashMap<i32, TreeNode> = HashMap::new();

    for p in procs {
        nodes.insert(
            p.pid,
            TreeNode {
                pid: p.pid,
                ppid: p.ppid,
                command: p.command.clone(),
                uid: p.uid,
                files: p.files.clone(),
                children: Vec::new(),
            },
        );
    }

    // Build parent→children map
    let pids: Vec<i32> = nodes.keys().copied().collect();
    for &pid in &pids {
        let ppid = nodes[&pid].ppid;
        if ppid != pid
            && let Some(parent) = nodes.get_mut(&ppid)
        {
            parent.children.push(pid);
        }
    }

    // Sort children by PID
    for node in nodes.values_mut() {
        node.children.sort();
    }

    // Find roots: processes whose parent is not in the set
    let mut roots: Vec<i32> = nodes
        .values()
        .filter(|n| !nodes.contains_key(&n.ppid) || n.ppid == n.pid)
        .map(|n| n.pid)
        .collect();
    roots.sort();

    let out = io::stdout();
    let mut out = out.lock();

    // Header
    let _ = writeln!(
        out,
        "{bold}{hdr}  PID   USER     FDs  CMD  ──  OPEN FILES{reset}",
        bold = theme.bold(),
        hdr = theme.hdr_bg(),
        reset = theme.reset(),
    );

    for (i, &root) in roots.iter().enumerate() {
        let is_last_root = i == roots.len() - 1;
        print_node(&nodes, root, "", is_last_root, theme, &mut out);
    }
}

fn print_node(
    nodes: &HashMap<i32, TreeNode>,
    pid: i32,
    prefix: &str,
    is_last: bool,
    theme: &Theme,
    out: &mut impl Write,
) {
    let node = match nodes.get(&pid) {
        Some(n) => n,
        None => return,
    };

    let connector = if prefix.is_empty() {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let username = users::get_user_by_uid(node.uid)
        .map(|u| u.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| node.uid.to_string());
    let user_display = truncate_max_bytes(&username, 8);

    let fd_count = node.files.len();
    let cmd = truncate_max_bytes(&node.command, 20);

    // FD type breakdown
    let mut type_counts: HashMap<&str, usize> = HashMap::new();
    for f in &node.files {
        *type_counts.entry(f.file_type.as_str()).or_insert(0) += 1;
    }
    let mut type_parts: Vec<String> = type_counts
        .iter()
        .map(|(t, c)| format!("{t}:{c}"))
        .collect();
    type_parts.sort();
    let type_summary = type_parts.join(" ");

    // Network connections summary
    let net_count: usize = node
        .files
        .iter()
        .filter(|f| matches!(f.file_type, FileType::IPv4 | FileType::IPv6))
        .count();

    let _ = write!(
        out,
        "{prefix}{dim}{connector}{reset}{mag}{pid:>5}{reset} {yellow}{user:<8}{reset} {cyan}{fds:>4}{reset}  {bold}{cmd}{reset}",
        prefix = prefix,
        dim = theme.dim(),
        connector = connector,
        reset = theme.reset(),
        mag = theme.magenta(),
        pid = node.pid,
        yellow = theme.yellow(),
        user = user_display,
        cyan = theme.cyan(),
        fds = fd_count,
        bold = theme.bold(),
        cmd = cmd,
    );

    if !type_summary.is_empty() {
        let _ = write!(
            out,
            "  {dim}[{types}]{reset}",
            dim = theme.dim(),
            types = type_summary,
            reset = theme.reset(),
        );
    }

    if net_count > 0 {
        let _ = write!(
            out,
            "  {green}{net}net{reset}",
            green = theme.green(),
            net = net_count,
            reset = theme.reset(),
        );
    }

    let _ = writeln!(out);

    // Print notable files: sockets, pipes with connections
    let child_prefix = if prefix.is_empty() {
        String::new()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    let notable: Vec<&OpenFile> = node
        .files
        .iter()
        .filter(|f| {
            matches!(
                f.file_type,
                FileType::IPv4 | FileType::IPv6 | FileType::Pipe
            )
        })
        .collect();

    for f in notable.iter().take(5) {
        let fd_str = f.fd.with_access(f.access);
        let pipe_connector = if node.children.is_empty() { " " } else { "│" };
        let _ = writeln!(
            out,
            "{file_prefix}{pipe}{dim}    {fd:<5} {type_:<5} {name}{reset}",
            file_prefix = child_prefix,
            pipe = pipe_connector,
            dim = theme.dim(),
            fd = fd_str,
            type_ = f.file_type.as_str(),
            name = f.full_name(),
            reset = theme.reset(),
        );
    }
    if notable.len() > 5 {
        let pipe_connector = if node.children.is_empty() { " " } else { "│" };
        let _ = writeln!(
            out,
            "{file_prefix}{pipe}{dim}    ... +{} more{reset}",
            notable.len() - 5,
            file_prefix = child_prefix,
            pipe = pipe_connector,
            dim = theme.dim(),
            reset = theme.reset(),
        );
    }

    // Recurse into children
    for (i, &child_pid) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1;
        print_node(nodes, child_pid, &child_prefix, child_is_last, theme, out);
    }
}

fn print_tree_json(procs: &[Process]) {
    use serde::Serialize;

    #[derive(Serialize)]
    struct JsonTreeNode {
        pid: i32,
        ppid: i32,
        command: String,
        uid: u32,
        fd_count: usize,
        net_count: usize,
        children: Vec<JsonTreeNode>,
    }

    let mut nodes: HashMap<i32, (i32, String, u32, usize, usize)> = HashMap::new();
    let mut children_map: HashMap<i32, Vec<i32>> = HashMap::new();

    for p in procs {
        let net = p
            .files
            .iter()
            .filter(|f| matches!(f.file_type, FileType::IPv4 | FileType::IPv6))
            .count();
        nodes.insert(
            p.pid,
            (p.ppid, p.command.clone(), p.uid, p.files.len(), net),
        );
        children_map.entry(p.ppid).or_default().push(p.pid);
    }

    for v in children_map.values_mut() {
        v.sort();
    }

    fn build(
        pid: i32,
        nodes: &HashMap<i32, (i32, String, u32, usize, usize)>,
        children_map: &HashMap<i32, Vec<i32>>,
    ) -> JsonTreeNode {
        let (ppid, cmd, uid, fds, net) = nodes.get(&pid).cloned().unwrap_or_default();
        let children = children_map
            .get(&pid)
            .map(|kids| {
                kids.iter()
                    .filter(|&&k| k != pid)
                    .map(|&k| build(k, nodes, children_map))
                    .collect()
            })
            .unwrap_or_default();
        JsonTreeNode {
            pid,
            ppid,
            command: cmd,
            uid,
            fd_count: fds,
            net_count: net,
            children,
        }
    }

    let roots: Vec<i32> = nodes
        .iter()
        .filter(|&(&pid, &(ppid, ..))| !nodes.contains_key(&ppid) || ppid == pid)
        .map(|(&pid, _)| pid)
        .collect();

    let tree: Vec<JsonTreeNode> = {
        let mut r: Vec<_> = roots
            .iter()
            .map(|&pid| build(pid, &nodes, &children_map))
            .collect();
        r.sort_by_key(|n| n.pid);
        r
    };

    let out = io::stdout();
    let mut out = out.lock();
    let _ = serde_json::to_writer_pretty(&mut out, &tree);
    let _ = writeln!(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proc(pid: i32, ppid: i32, cmd: &str, n_files: usize) -> Process {
        Process {
            pid,
            ppid,
            pgid: pid,
            uid: 501,
            command: cmd.to_string(),
            files: (0..n_files)
                .map(|i| OpenFile {
                    fd: FdName::Number(i as i32),
                    access: Access::Read,
                    file_type: FileType::Reg,
                    name: format!("/tmp/f{i}"),
                    ..Default::default()
                })
                .collect(),
            sel_flags: 0,
            sel_state: 0,
        }
    }

    #[test]
    fn tree_single_root() {
        let procs = vec![make_proc(1, 0, "init", 3)];
        let theme = Theme::new(false);
        // Should not panic
        print_tree(&procs, &theme, false);
    }

    #[test]
    fn tree_parent_child() {
        let procs = vec![
            make_proc(1, 0, "init", 2),
            make_proc(100, 1, "bash", 5),
            make_proc(200, 1, "sshd", 3),
            make_proc(201, 200, "sshd-child", 1),
        ];
        let theme = Theme::new(false);
        print_tree(&procs, &theme, false);
    }

    #[test]
    fn tree_deep_nesting() {
        let procs = vec![
            make_proc(1, 0, "init", 1),
            make_proc(2, 1, "level1", 1),
            make_proc(3, 2, "level2", 1),
            make_proc(4, 3, "level3", 1),
            make_proc(5, 4, "level4", 1),
        ];
        let theme = Theme::new(false);
        print_tree(&procs, &theme, false);
    }

    #[test]
    fn tree_multiple_roots() {
        let procs = vec![
            make_proc(1, 0, "init", 2),
            make_proc(100, 99, "orphan", 3), // parent 99 not in set
        ];
        let theme = Theme::new(false);
        print_tree(&procs, &theme, false);
    }

    #[test]
    fn tree_json_output() {
        let procs = vec![make_proc(1, 0, "init", 2), make_proc(100, 1, "bash", 5)];
        // Should not panic
        print_tree_json(&procs);
    }

    #[test]
    fn tree_json_valid() {
        // Just verify the function doesn't panic with empty input
        print_tree_json(&[]);
    }

    #[test]
    fn print_tree_empty_no_panic() {
        let theme = Theme::new(false);
        print_tree(&[], &theme, false);
    }

    #[test]
    fn tree_json_multiple_roots_no_panic() {
        let procs = vec![
            make_proc(1, 0, "init", 1),
            make_proc(500, 49_999, "orphan", 1),
        ];
        print_tree_json(&procs);
    }

    #[test]
    fn tree_with_network_files() {
        let mut p = make_proc(1, 0, "nginx", 0);
        p.files.push(OpenFile {
            fd: FdName::Number(3),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: "*:80".to_string(),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        p.files.push(OpenFile {
            fd: FdName::Number(4),
            access: Access::ReadWrite,
            file_type: FileType::IPv4,
            name: "*:443".to_string(),
            socket_info: Some(SocketInfo {
                protocol: "TCP".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let theme = Theme::new(false);
        print_tree(&[p], &theme, false);
    }

    #[test]
    fn tree_self_parent_no_infinite_loop() {
        // PID 1 with ppid=1 should not infinite-loop
        let procs = vec![make_proc(1, 1, "init", 2)];
        let theme = Theme::new(false);
        print_tree(&procs, &theme, false);
    }

    #[test]
    fn tree_truncates_notable_socket_lines_after_five() {
        let mut p = make_proc(1, 0, "many_socks", 0);
        for i in 0..6i32 {
            p.files.push(OpenFile {
                fd: FdName::Number(i),
                access: Access::ReadWrite,
                file_type: FileType::IPv4,
                name: format!("*:{}", 8000 + i as u16),
                socket_info: Some(SocketInfo {
                    protocol: "TCP".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        let theme = Theme::new(false);
        print_tree(&[p], &theme, false);
    }
}
