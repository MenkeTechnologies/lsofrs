//! Columnar and field output formatting

use std::io::{self, Write};

use crate::strutil::truncate_max_bytes;
use crate::types::*;

/// Delta status callback: (pid, fd, name) -> DeltaStatus
pub type DeltaFn<'a> = Option<&'a dyn Fn(i32, &str, &str) -> DeltaStatus>;

/// ANSI color codes for cyberpunk theme
pub struct Theme {
    pub is_tty: bool,
}

impl Theme {
    pub fn new(is_tty: bool) -> Self {
        Self { is_tty }
    }

    pub fn reset(&self) -> &str {
        if self.is_tty { "\x1b[0m" } else { "" }
    }
    pub fn cyan(&self) -> &str {
        if self.is_tty { "\x1b[1;96m" } else { "" }
    }
    pub fn magenta(&self) -> &str {
        if self.is_tty { "\x1b[1;95m" } else { "" }
    }
    pub fn green(&self) -> &str {
        if self.is_tty { "\x1b[1;92m" } else { "" }
    }
    pub fn yellow(&self) -> &str {
        if self.is_tty { "\x1b[1;93m" } else { "" }
    }
    pub fn red(&self) -> &str {
        if self.is_tty { "\x1b[1;91m" } else { "" }
    }
    pub fn blue(&self) -> &str {
        if self.is_tty { "\x1b[1;94m" } else { "" }
    }
    pub fn dim(&self) -> &str {
        if self.is_tty { "\x1b[2m" } else { "" }
    }
    pub fn bold(&self) -> &str {
        if self.is_tty { "\x1b[1m" } else { "" }
    }
    pub fn hdr_bg(&self) -> &str {
        if self.is_tty { "\x1b[48;5;234m" } else { "" }
    }
    pub fn row_alt(&self) -> &str {
        if self.is_tty { "\x1b[48;5;233m" } else { "" }
    }

    // Column titles — cyberpunk when TTY, plain when piped
    pub fn cmd_title(&self) -> &str {
        if self.is_tty { "PROCESS" } else { "COMMAND" }
    }
    pub fn dev_title(&self) -> &str {
        if self.is_tty { "DEV/ICE" } else { "DEVICE" }
    }
    pub fn fd_title(&self) -> &str {
        "FD"
    }
    pub fn name_title(&self) -> &str {
        if self.is_tty { "T4RGET" } else { "NAME" }
    }
    pub fn node_title(&self) -> &str {
        if self.is_tty { "N0DE" } else { "NODE" }
    }
    pub fn pid_title(&self) -> &str {
        if self.is_tty { "PRC" } else { "PID" }
    }
    pub fn size_off_title(&self) -> &str {
        if self.is_tty { "BYT3/0FF" } else { "SIZE/OFF" }
    }
    pub fn type_title(&self) -> &str {
        if self.is_tty { "CL4SS" } else { "TYPE" }
    }
    pub fn user_title(&self) -> &str {
        if self.is_tty { "H4XOR" } else { "USER" }
    }
    pub fn pgid_title(&self) -> &str {
        "PGID"
    }
    pub fn ppid_title(&self) -> &str {
        if self.is_tty { "PPRC" } else { "PPID" }
    }
}

/// Column widths computed from data
struct ColWidths {
    cmd: usize,
    pid: usize,
    user: usize,
    fd: usize,
    type_: usize,
    device: usize,
    size_off: usize,
    node: usize,
    pgid: usize,
    ppid: usize,
}

impl ColWidths {
    fn compute(procs: &[Process], show_pgid: bool, show_ppid: bool) -> Self {
        let mut w = ColWidths {
            cmd: 7,      // "COMMAND" or "PROCESS"
            pid: 3,      // "PID" or "PRC"
            user: 4,     // "USER" or "H4XOR"
            fd: 2,       // "FD"
            type_: 4,    // "TYPE" or "CL4SS"
            device: 6,   // "DEVICE" or "DEV/ICE"
            size_off: 8, // "SIZE/OFF"
            node: 4,     // "NODE"
            pgid: 4,     // "PGID"
            ppid: 4,     // "PPID"
        };

        for p in procs {
            w.cmd = w.cmd.max(p.command.len().min(15));
            w.pid = w.pid.max(p.pid.to_string().len());
            w.user = w.user.max(p.username().len().min(8));
            if show_pgid {
                w.pgid = w.pgid.max(p.pgid.to_string().len());
            }
            if show_ppid {
                w.ppid = w.ppid.max(p.ppid.to_string().len());
            }

            for f in &p.files {
                let fd_str = f.fd.with_access(f.access);
                w.fd = w.fd.max(fd_str.len());
                w.type_ = w.type_.max(f.file_type.as_str().len());
                w.device = w.device.max(f.device_str().len());
                w.size_off = w.size_off.max(f.size_or_offset_str().len());
                w.node = w.node.max(f.node_str().len());
            }
        }

        w
    }
}

pub fn print_processes(
    procs: &[Process],
    theme: &Theme,
    show_pgid: bool,
    show_ppid: bool,
    delta_status: DeltaFn<'_>,
) {
    let w = ColWidths::compute(procs, show_pgid, show_ppid);
    let out = io::stdout();
    let mut out = out.lock();

    // Print header
    let _ = write!(
        out,
        "{bg}{bold}{cmd:<cw$} {pid:>pw$} ",
        bg = theme.hdr_bg(),
        bold = theme.bold(),
        cmd = theme.cmd_title(),
        cw = w.cmd,
        pid = theme.pid_title(),
        pw = w.pid,
    );
    if show_pgid {
        let _ = write!(out, "{:>gw$} ", theme.pgid_title(), gw = w.pgid);
    }
    if show_ppid {
        let _ = write!(out, "{:>rw$} ", theme.ppid_title(), rw = w.ppid);
    }
    let _ = writeln!(
        out,
        "{user:<uw$} {fd:<fw$} {type_:<tw$} {dev:<dw$} {szoff:>sw$} {node:<nw$} {name}{reset}",
        user = theme.user_title(),
        uw = w.user,
        fd = theme.fd_title(),
        fw = w.fd,
        type_ = theme.type_title(),
        tw = w.type_,
        dev = theme.dev_title(),
        dw = w.device,
        szoff = theme.size_off_title(),
        sw = w.size_off,
        node = theme.node_title(),
        nw = w.node,
        name = theme.name_title(),
        reset = theme.reset(),
    );

    let mut row = 0usize;
    for p in procs {
        let username = p.username();
        let user_display = truncate_max_bytes(username, 8);
        let cmd_display = truncate_max_bytes(&p.command, 15);

        let mut first = true;
        for f in &p.files {
            let alt = if row % 2 == 1 { theme.row_alt() } else { "" };
            let fd_str = f.fd.with_access(f.access);
            let type_str = f.file_type.as_str();
            let dev_str = f.device_str();
            let szoff_str = f.size_or_offset_str();
            let node_str = f.node_str();
            let name_str = f.full_name();

            // Delta coloring
            let (prefix, suffix) = if let Some(ref classify) = delta_status {
                let ds = classify(p.pid, &fd_str, &f.name);
                match ds {
                    DeltaStatus::New => (theme.green(), theme.reset()),
                    DeltaStatus::Gone => (theme.red(), theme.reset()),
                    DeltaStatus::Unchanged => ("", ""),
                }
            } else {
                ("", "")
            };

            let _ = write!(out, "{prefix}{alt}");

            if first {
                let _ = write!(
                    out,
                    "{cyan}{cmd:<cw$}{reset} {mag}{pid:>pw$}{reset} ",
                    cyan = theme.cyan(),
                    cmd = cmd_display,
                    cw = w.cmd,
                    reset = theme.reset(),
                    mag = theme.magenta(),
                    pid = p.pid,
                    pw = w.pid,
                );
                if show_pgid {
                    let _ = write!(out, "{:>gw$} ", p.pgid, gw = w.pgid);
                }
                if show_ppid {
                    let _ = write!(out, "{:>rw$} ", p.ppid, rw = w.ppid);
                }
                let _ = write!(
                    out,
                    "{yellow}{user:<uw$}{reset} ",
                    yellow = theme.yellow(),
                    user = user_display,
                    uw = w.user,
                    reset = theme.reset(),
                );
                first = false;
            } else {
                let _ = write!(out, "{:<cw$} {:>pw$} ", "", "", cw = w.cmd, pw = w.pid,);
                if show_pgid {
                    let _ = write!(out, "{:>gw$} ", "", gw = w.pgid);
                }
                if show_ppid {
                    let _ = write!(out, "{:>rw$} ", "", rw = w.ppid);
                }
                let _ = write!(out, "{:<uw$} ", "", uw = w.user);
            }

            let _ = writeln!(
                out,
                "{green}{fd:<fw$}{reset} {blue}{type_:<tw$}{reset} {dim}{dev:<dw$}{reset} {szoff:>sw$} {node:<nw$} {name}{suffix}{reset}",
                green = theme.green(),
                fd = fd_str,
                fw = w.fd,
                reset = theme.reset(),
                blue = theme.blue(),
                type_ = type_str,
                tw = w.type_,
                dim = theme.dim(),
                dev = dev_str,
                dw = w.device,
                szoff = szoff_str,
                sw = w.size_off,
                node = node_str,
                nw = w.node,
                name = name_str,
                suffix = suffix,
            );

            row += 1;
        }
    }
}

/// Print processes in terse mode (PIDs only)
pub fn print_terse(procs: &[Process]) {
    let out = io::stdout();
    let mut out = out.lock();
    for p in procs {
        let _ = writeln!(out, "{}", p.pid);
    }
}

/// Print field output (-F format)
pub fn print_field_output(procs: &[Process], fields: &str, terminator: char) {
    let out = io::stdout();
    let mut out = out.lock();

    let field_chars: Vec<char> = if fields.is_empty() {
        vec!['p', 'f', 'n'] // default fields
    } else {
        fields.chars().collect()
    };

    for p in procs {
        // Process-level fields
        for &fc in &field_chars {
            match fc {
                'p' => {
                    let _ = write!(out, "p{}{}", p.pid, terminator);
                }
                'c' => {
                    let _ = write!(out, "c{}{}", p.command, terminator);
                }
                'g' => {
                    let _ = write!(out, "g{}{}", p.pgid, terminator);
                }
                'R' => {
                    let _ = write!(out, "R{}{}", p.ppid, terminator);
                }
                'u' => {
                    let _ = write!(out, "u{}{}", p.uid, terminator);
                }
                'L' => {
                    let _ = write!(out, "L{}{}", p.username(), terminator);
                }
                _ => {}
            }
        }

        // File-level fields
        for f in &p.files {
            for &fc in &field_chars {
                match fc {
                    'f' => {
                        let _ = write!(out, "f{}{}", f.fd.with_access(f.access), terminator);
                    }
                    'a' => {
                        if f.access != Access::None {
                            let _ = write!(out, "a{}{}", f.access.as_char(), terminator);
                        }
                    }
                    't' => {
                        let _ = write!(out, "t{}{}", f.file_type.as_str(), terminator);
                    }
                    'D' => {
                        if let Some((maj, min)) = f.device {
                            let _ = write!(out, "D0x{:x}{:02x}{}", maj, min, terminator);
                        }
                    }
                    's' => {
                        if let Some(sz) = f.size {
                            let _ = write!(out, "s{}{}", sz, terminator);
                        }
                    }
                    'o' => {
                        if let Some(off) = f.offset {
                            let _ = write!(out, "o0t{}{}", off, terminator);
                        }
                    }
                    'i' => {
                        if let Some(ino) = f.inode {
                            let _ = write!(out, "i{}{}", ino, terminator);
                        }
                    }
                    'n' => {
                        let _ = write!(out, "n{}{}", f.full_name(), terminator);
                    }
                    'P' => {
                        if let Some(ref si) = f.socket_info
                            && !si.protocol.is_empty()
                        {
                            let _ = write!(out, "P{}{}", si.protocol, terminator);
                        }
                    }
                    'T' => {
                        if let Some(ref si) = f.socket_info
                            && let Some(ref state) = si.tcp_state
                        {
                            let _ = write!(out, "TST={}{}", state, terminator);
                        }
                    }
                    _ => {}
                }
            }
        }

        if terminator == '\0' {
            let _ = writeln!(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Theme tests ─────────────────────────────────────────────────

    #[test]
    fn theme_tty_has_ansi_codes() {
        let t = Theme::new(true);
        assert!(t.reset().contains("\x1b["));
        assert!(t.cyan().contains("\x1b["));
        assert!(t.magenta().contains("\x1b["));
        assert!(t.green().contains("\x1b["));
        assert!(t.yellow().contains("\x1b["));
        assert!(t.red().contains("\x1b["));
        assert!(t.blue().contains("\x1b["));
        assert!(t.dim().contains("\x1b["));
        assert!(t.bold().contains("\x1b["));
        assert!(t.hdr_bg().contains("\x1b["));
        assert!(t.row_alt().contains("\x1b["));
    }

    #[test]
    fn theme_no_tty_empty_strings() {
        let t = Theme::new(false);
        assert_eq!(t.reset(), "");
        assert_eq!(t.cyan(), "");
        assert_eq!(t.magenta(), "");
        assert_eq!(t.green(), "");
        assert_eq!(t.yellow(), "");
        assert_eq!(t.red(), "");
        assert_eq!(t.blue(), "");
        assert_eq!(t.dim(), "");
        assert_eq!(t.bold(), "");
        assert_eq!(t.hdr_bg(), "");
        assert_eq!(t.row_alt(), "");
    }

    #[test]
    fn theme_tty_cyberpunk_titles() {
        let t = Theme::new(true);
        assert_eq!(t.cmd_title(), "PROCESS");
        assert_eq!(t.pid_title(), "PRC");
        assert_eq!(t.user_title(), "H4XOR");
        assert_eq!(t.type_title(), "CL4SS");
        assert_eq!(t.dev_title(), "DEV/ICE");
        assert_eq!(t.size_off_title(), "BYT3/0FF");
        assert_eq!(t.node_title(), "N0DE");
        assert_eq!(t.name_title(), "T4RGET");
        assert_eq!(t.ppid_title(), "PPRC");
    }

    #[test]
    fn theme_pipe_plain_titles() {
        let t = Theme::new(false);
        assert_eq!(t.cmd_title(), "COMMAND");
        assert_eq!(t.pid_title(), "PID");
        assert_eq!(t.user_title(), "USER");
        assert_eq!(t.type_title(), "TYPE");
        assert_eq!(t.dev_title(), "DEVICE");
        assert_eq!(t.size_off_title(), "SIZE/OFF");
        assert_eq!(t.node_title(), "NODE");
        assert_eq!(t.name_title(), "NAME");
        assert_eq!(t.ppid_title(), "PPID");
    }

    #[test]
    fn theme_fd_and_pgid_titles_same() {
        let tty = Theme::new(true);
        let pipe = Theme::new(false);
        assert_eq!(tty.fd_title(), "FD");
        assert_eq!(pipe.fd_title(), "FD");
        assert_eq!(tty.pgid_title(), "PGID");
        assert_eq!(pipe.pgid_title(), "PGID");
    }

    // ── ColWidths tests ─────────────────────────────────────────────

    fn make_proc(pid: i32, cmd: &str, files: Vec<OpenFile>) -> Process {
        Process::new(pid, 1, pid, 0, cmd.to_string(), files)
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
    fn col_widths_defaults_on_empty() {
        let w = ColWidths::compute(&[], false, false);
        assert!(w.cmd >= 7);
        assert!(w.pid >= 3);
    }

    #[test]
    fn col_widths_grows_for_long_pid() {
        let p = make_proc(1234567, "test", vec![make_file(3, FileType::Reg, "/x")]);
        let w = ColWidths::compute(&[p], false, false);
        assert!(w.pid >= 7); // "1234567" is 7 chars
    }

    #[test]
    fn col_widths_cmd_capped_at_15() {
        let p = make_proc(1, "a_very_long_command_name_here", vec![]);
        let w = ColWidths::compute(&[p], false, false);
        assert!(w.cmd <= 15);
    }

    #[test]
    fn col_widths_pgid_only_with_flag() {
        let p = make_proc(1, "test", vec![]);
        let w_no = ColWidths::compute(std::slice::from_ref(&p), false, false);
        let w_yes = ColWidths::compute(std::slice::from_ref(&p), true, false);
        // pgid width should only grow when show_pgid is true
        assert_eq!(w_no.pgid, 4); // default
        assert!(w_yes.pgid >= 1);
    }

    #[test]
    fn col_widths_ppid_only_with_flag() {
        let p = Process::new(1, 123456, 1, 0, "x".to_string(), vec![]);
        let w_no = ColWidths::compute(std::slice::from_ref(&p), false, false);
        let w_yes = ColWidths::compute(std::slice::from_ref(&p), false, true);
        assert_eq!(w_no.ppid, 4);
        assert!(w_yes.ppid >= 6);
    }

    #[test]
    fn col_widths_fd_grows_for_cwd_token() {
        let f = OpenFile {
            fd: FdName::Cwd,
            access: Access::ReadWrite,
            file_type: FileType::Dir,
            name: "/".to_string(),
            ..Default::default()
        };
        let p = make_proc(1, "x", vec![f]);
        let w = ColWidths::compute(std::slice::from_ref(&p), false, false);
        assert!(w.fd >= "cwd".len());
    }

    #[test]
    fn col_widths_type_grows_for_unknown_long_label() {
        let f = OpenFile {
            fd: FdName::Number(0),
            access: Access::Read,
            file_type: FileType::Unknown("VERYLONGTYPE".to_string()),
            name: "/x".to_string(),
            ..Default::default()
        };
        let p = make_proc(1, "x", vec![f]);
        let w = ColWidths::compute(std::slice::from_ref(&p), false, false);
        assert!(w.type_ >= "VERYLONGTYPE".len());
    }

    #[test]
    fn col_widths_size_off_includes_0t_prefix_for_offset() {
        let mut f = make_file(1, FileType::Reg, "/x");
        f.offset = Some(4096);
        let p = make_proc(1, "x", vec![f]);
        let w = ColWidths::compute(std::slice::from_ref(&p), false, false);
        assert!(w.size_off >= "0t4096".len());
    }

    #[test]
    fn col_widths_node_from_protocol_when_no_inode() {
        let mut f = make_file(5, FileType::IPv4, "*:80");
        f.socket_info = Some(crate::types::SocketInfo {
            protocol: "TCP".to_string(),
            ..Default::default()
        });
        let p = make_proc(1, "x", vec![f]);
        let w = ColWidths::compute(std::slice::from_ref(&p), false, false);
        assert!(w.node >= "TCP".len());
    }

    // ── print_processes smoke tests ─────────────────────────────────

    #[test]
    fn print_processes_empty_no_panic() {
        let theme = Theme::new(false);
        print_processes(&[], &theme, false, false, None);
    }

    #[test]
    fn print_processes_with_data_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_processes(&procs, &theme, false, false, None);
    }

    #[test]
    fn print_processes_tty_theme_no_panic() {
        let theme = Theme::new(true);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_processes(&procs, &theme, false, false, None);
    }

    #[test]
    fn print_processes_with_pgid_ppid_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_processes(&procs, &theme, true, true, None);
    }

    #[test]
    fn print_processes_with_delta_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        let delta = |_pid: i32, _fd: &str, _name: &str| DeltaStatus::New;
        print_processes(&procs, &theme, false, false, Some(&delta));
    }

    #[test]
    fn print_processes_with_delta_gone_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        let delta = |_pid: i32, _fd: &str, _name: &str| DeltaStatus::Gone;
        print_processes(&procs, &theme, false, false, Some(&delta));
    }

    #[test]
    fn print_processes_with_delta_unchanged_no_panic() {
        let theme = Theme::new(false);
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        let delta = |_pid: i32, _fd: &str, _name: &str| DeltaStatus::Unchanged;
        print_processes(&procs, &theme, false, false, Some(&delta));
    }

    #[test]
    fn print_terse_no_panic() {
        let procs = vec![make_proc(1, "a", vec![]), make_proc(2, "b", vec![])];
        print_terse(&procs);
    }

    #[test]
    fn print_terse_duplicate_pid_no_panic() {
        let procs = vec![make_proc(42, "x", vec![]), make_proc(42, "y", vec![])];
        print_terse(&procs);
    }

    #[test]
    fn print_field_output_no_panic() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_field_output(&procs, "pcfnta", '\n');
    }

    #[test]
    fn print_field_output_empty_fields_uses_defaults() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        // empty string should use defaults (p, f, n)
        print_field_output(&procs, "", '\n');
    }

    #[test]
    fn print_field_output_all_fields_no_panic() {
        let mut f = make_file(3, FileType::Reg, "/tmp/x");
        f.device = Some((1, 16));
        f.size = Some(4096);
        f.offset = Some(0);
        f.inode = Some(12345);
        f.socket_info = Some(crate::types::SocketInfo {
            protocol: "TCP".to_string(),
            tcp_state: Some(TcpState::Established),
            ..Default::default()
        });
        let procs = vec![make_proc(42, "test", vec![f])];
        print_field_output(&procs, "pcfntaDsoiPTguRL", '\n');
    }

    #[test]
    fn print_field_output_nul_terminator_no_panic() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_field_output(&procs, "pfn", '\0');
    }

    #[test]
    fn print_field_output_unknown_chars_ignored_no_panic() {
        let procs = vec![make_proc(
            42,
            "test",
            vec![make_file(3, FileType::Reg, "/tmp/x")],
        )];
        print_field_output(&procs, "pfx!z", '\n');
    }

    #[test]
    fn print_field_output_pgid_ppid_username_no_panic() {
        let mut p = make_proc(7, "cmd", vec![make_file(3, FileType::Reg, "/x")]);
        p.pgid = 99;
        p.ppid = 100;
        p.uid = 501;
        print_field_output(std::slice::from_ref(&p), "pgRuL", '\n');
    }

    #[test]
    fn theme_plain_column_titles_when_not_tty() {
        let t = Theme::new(false);
        assert_eq!(t.cmd_title(), "COMMAND");
        assert_eq!(t.name_title(), "NAME");
        assert_eq!(t.pid_title(), "PID");
    }

    #[test]
    fn theme_tty_column_titles() {
        let t = Theme::new(true);
        assert_eq!(t.cmd_title(), "PROCESS");
        assert_eq!(t.name_title(), "T4RGET");
        assert_eq!(t.pid_title(), "PRC");
    }

    #[test]
    fn theme_hdr_bg_empty_when_not_tty() {
        let t = Theme::new(false);
        assert_eq!(t.hdr_bg(), "");
    }

    #[test]
    fn theme_row_alt_empty_when_not_tty() {
        let t = Theme::new(false);
        assert_eq!(t.row_alt(), "");
    }

    #[test]
    fn theme_color_codes_empty_when_not_tty() {
        let t = Theme::new(false);
        assert_eq!(t.reset(), "");
        assert_eq!(t.cyan(), "");
        assert_eq!(t.magenta(), "");
        assert_eq!(t.green(), "");
        assert_eq!(t.yellow(), "");
        assert_eq!(t.red(), "");
        assert_eq!(t.blue(), "");
        assert_eq!(t.dim(), "");
        assert_eq!(t.bold(), "");
    }
}
