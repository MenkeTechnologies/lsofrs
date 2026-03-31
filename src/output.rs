//! Columnar and field output formatting

use std::io::{self, Write};

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
        let user_display = if username.len() > 8 {
            &username[..8]
        } else {
            &username
        };
        let cmd_display = if p.command.len() > 15 {
            &p.command[..15]
        } else {
            &p.command
        };

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
