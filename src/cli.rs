//! Command-line argument parsing

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "lsofrs",
    version = env!("CARGO_PKG_VERSION"),
    about = "List System Open Files — modern Rust implementation",
    author = "MenkeTechnologies",
    long_about = "lsofrs maps the relationship between processes and the files they hold open.\n\
                  Supports regular files, directories, sockets, pipes, devices, and streams.",
    disable_help_flag = true,
    disable_version_flag = true
)]
/// `Args` — see fields for layout.
pub struct Args {
    /// Display help
    #[arg(short = 'h', long = "help", action = clap::ArgAction::SetTrue)]
    pub help: bool,
    /// Select processes by PID (comma-separated, ^PID to exclude)
    #[arg(short = 'p', long = "pid")]
    pub pid: Option<String>,

    /// Select by user ID or name (comma-separated, ^user to exclude)
    #[arg(short = 'u', long = "user")]
    pub user: Option<String>,

    /// Select by process group ID (comma-separated)
    #[arg(short = 'g', long = "pgid")]
    pub pgid: Option<String>,

    /// Select by command name (comma-separated, /regex/)
    #[arg(short = 'c', long = "command")]
    pub command: Option<String>,

    /// Select internet connections `[4|6|protocol[@host[:port]]]`
    #[arg(short = 'i', num_args = 0..=1, default_missing_value = "")]
    pub inet: Option<String>,

    /// Select file descriptors (comma-separated, N-M ranges, ^FD to exclude)
    #[arg(short = 'd')]
    pub fd: Option<String>,

    /// AND selection (all filters must match)
    #[arg(short = 'a')]
    pub and_mode: bool,

    /// NFS files only
    #[arg(short = 'N')]
    pub nfs: bool,

    /// UNIX domain sockets
    #[arg(short = 'U')]
    pub unix_socket: bool,

    /// Terse output (PIDs only)
    #[arg(short = 't')]
    pub terse: bool,

    /// Field output format (chars: p=pid, c=cmd, f=fd, n=name, t=type, etc.)
    #[arg(short = 'F')]
    pub field_output: Option<String>,

    /// Repeat every N seconds
    #[arg(short = 'r')]
    pub repeat: Option<u64>,

    /// Inhibit hostname lookup
    #[arg(short = 'n')]
    pub no_host_lookup: bool,

    /// Inhibit port name lookup
    #[arg(short = 'P')]
    pub no_port_lookup: bool,

    /// Suppress warnings
    #[arg(short = 'w')]
    pub suppress_warnings: bool,

    /// Show process group IDs
    #[arg(long = "pgid-show")]
    pub show_pgid: bool,

    /// Show parent PIDs
    #[arg(short = 'R')]
    pub show_ppid: bool,

    /// JSON output
    #[arg(short = 'J', long = "json")]
    pub json: bool,

    /// Live full-screen monitor mode
    #[arg(short = 'W', long = "monitor")]
    pub monitor: bool,

    /// Aggregate FD summary/statistics
    #[arg(long = "summary", alias = "stats")]
    pub summary: bool,

    /// Follow a single process's FDs in real-time
    #[arg(long = "follow")]
    pub follow: Option<i32>,

    /// FD leak detection `[interval,threshold]`
    #[arg(long = "leak-detect")]
    pub leak_detect: Option<Option<String>>,

    /// Process tree view with FD inheritance
    #[arg(long = "tree")]
    pub tree: bool,

    /// Watch who opens/closes a specific file over time
    #[arg(long = "watch")]
    pub watch: Option<String>,

    /// Live top-N processes by FD count
    #[arg(long = "top")]
    pub top: Option<Option<usize>>,

    /// Delta highlighting in repeat mode
    #[arg(long = "delta")]
    pub delta: bool,

    /// Find FDs pointing to deleted files
    #[arg(long = "stale")]
    pub stale: bool,

    /// Show listening ports summary
    #[arg(long = "ports")]
    pub ports: bool,

    /// Trace pipe/socket pairs between processes
    #[arg(long = "pipe-chain")]
    pub pipe_chain: bool,

    /// CSV output format
    #[arg(long = "csv")]
    pub csv_output: bool,

    /// Network connection map grouped by remote host
    #[arg(long = "net-map")]
    pub net_map: bool,

    /// Use NUL field terminator instead of NL
    #[arg(short = '0')]
    pub nul_terminator: bool,

    /// Launch unified TUI mode with tabs
    #[arg(long = "tui")]
    pub tui: bool,

    /// Color theme for TUI modes (neon-sprawl, classic, solar-flare, ice-breaker, matrix)
    #[arg(long = "theme", default_value = "neon-sprawl")]
    pub theme_name: String,

    /// Color output: auto (default), always, never
    #[arg(long = "color", default_value = "auto")]
    pub color: String,

    /// List open files in directory (one level)
    #[arg(long = "dir", alias = "+d")]
    pub dir: Option<String>,

    /// Recursively list open files in directory
    #[arg(long = "dir-recurse", alias = "+D")]
    pub dir_recurse: Option<String>,

    /// List file link counts (NLINK column). Set by `+L` / `+Ln`.
    #[arg(long = "list-nlink")]
    pub list_nlink: bool,

    /// Select only files whose link count is less than N (set by `+Ln`, e.g. `+L1` = unlinked files)
    #[arg(long = "link-count-max")]
    pub link_count_max: Option<u64>,

    /// Display version and exit (lsof `-v`)
    #[arg(short = 'v', long = "version")]
    pub version: bool,

    /// Report search items that were requested but not found (lsof `-V`)
    #[arg(short = 'V')]
    pub report_unfound: bool,

    /// Show numeric UID instead of login name (lsof `-l`)
    #[arg(short = 'l')]
    pub numeric_uid: bool,

    /// Always display file offset instead of size (lsof `-o`)
    #[arg(long = "offset-always")]
    pub offset_always: bool,

    /// Decimal digits to show in offset (lsof `-on`)
    #[arg(long = "offset-digits")]
    pub offset_digits: Option<usize>,

    /// Always display file size, never offset (lsof `-s` without a spec)
    #[arg(long = "size-always")]
    pub size_always: bool,

    /// Select sockets by protocol state, e.g. `TCP:LISTEN` (lsof `-s p:s`)
    #[arg(long = "state-filter")]
    pub state_filter: Vec<String>,

    /// Show TCP/TPI state and queue info (lsof `-T`)
    #[arg(long = "tcp-info")]
    pub tcp_info: bool,

    /// Follow symlinks/mount points while walking `+d`/`+D` (lsof `-x`)
    #[arg(long = "cross-over")]
    pub cross_over: bool,

    /// Command column width; 0 means unlimited (lsof `+c w`)
    #[arg(long = "command-width")]
    pub command_width: Option<usize>,

    /// List tasks/threads of matching processes (lsof `-K`)
    #[arg(long = "list-tasks")]
    pub list_tasks: bool,

    /// Repeat until no output is produced (lsof `+r`)
    #[arg(long = "repeat-until")]
    pub repeat_until: bool,

    /// Files/directories to search
    pub files: Vec<String>,
}

impl Args {
    /// `print_help` — see implementation.
    pub fn print_help() {
        let cyan = "\x1b[1;36m";
        let green = "\x1b[1;32m";
        let magenta = "\x1b[1;35m";
        let yellow = "\x1b[1;33m";
        let dyellow = "\x1b[33m";
        let red = "\x1b[31m";
        let dcyan = "\x1b[36m";
        let dmagenta = "\x1b[35m";
        let reset = "\x1b[0m";
        let version = env!("CARGO_PKG_VERSION");

        println!(
            r#"
{dcyan}  ██▓     ██████  ▒█████    █████▒██████  ██████ {reset}
{dcyan} ▓██▒   ▒██    ▒ ▒██▒  ██▒▓██   ▒██   ▒ ▒██    ▒{reset}
{dmagenta} ▒██░   ░ ▓██▄   ▒██░  ██▒▒████ ░▓██▄    ░ ▓██▄  {reset}
{dmagenta} ░██░     ▒   ██▒▒██   ██░░▓█▒  ░▒   ██▒  ▒   ██▒{reset}
{red} ░██████▒▒██████▒▒░ ████▓▒░░▒█░  ▒██████▒▒██████▒▒{reset}
{red} ░ ▒░▓  ░▒ ▒▓▒ ▒ ░░ ▒░▒░▒░  ▒ ░ ▒ ▒▓▒ ▒ ░ ▒▓▒ ▒ ░{reset}
{dyellow}  ░ ▒  ░░ ░▒  ░ ░  ░ ▒ ▒░  ░   ░ ░▒  ░ ░ ░▒  ░ ░{reset}
{dyellow}    ░ ░  ░ ░  ░    ░ ░ ░ ▒   ░ ░ ░ ░  ░   ░ ░  ░ {reset}
{dyellow}      ░        ░        ░ ░           ░           ░{reset}

{cyan}  >> FILE DESCRIPTOR SCANNER v{version} << {reset}
{magenta}  [ mapping the topology of open files ]{reset}

{yellow}  USAGE:{reset} lsofrs [OPTION]... [FILE]...

{cyan}  ── SELECTION ──────────────────────────────────────{reset}
{green}   -?, -h            {reset}display this transmission
{green}   -a                {reset}AND selections {magenta}(default: OR){reset}
{green}   -c COMMAND        {reset}select by command name {magenta}(prefix, ^exclude, /regex/){reset}
{green}   -d FD             {reset}select by file descriptor set
{green}   -g [PGID]         {reset}exclude(^) or select process group IDs
{green}   -p PID            {reset}select by PID {magenta}(comma-separated, ^excludes){reset}
{green}   -u USER           {reset}select by login name or UID {magenta}(comma-separated, ^excludes){reset}
{green}   -s PROTO:STATE    {reset}select sockets by state {magenta}(e.g. TCP:LISTEN){reset}
{green}   -V                {reset}report search items that matched nothing

{cyan}  ── NETWORK ───────────────────────────────────────{reset}
{green}   -i [ADDR]         {reset}select internet connections
                     {magenta}[4|6][proto][@host|addr][:svc|port]{reset}
{green}   -n                {reset}inhibit host name resolution
{green}   -N                {reset}select NFS files
{green}   -P                {reset}inhibit port number to name conversion
{green}   -U                {reset}select UNIX domain socket files

{cyan}  ── FILES & DIRECTORIES ───────────────────────────{reset}
{green}   FILE...           {reset}list processes using these files
{green}   --dir DIR         {reset}list open files in DIR {magenta}(one level, like +d){reset}
{green}   --dir-recurse DIR {reset}recursively list open files in DIR {magenta}(like +D){reset}

{cyan}  ── DISPLAY ───────────────────────────────────────{reset}
{green}   -F [FIELDS]       {reset}select output fields; -F ? for help
{green}   +L [n]            {reset}list link counts (NLINK); {magenta}+Ln selects link count < n (+L1 = unlinked){reset}
{green}   -l                {reset}show numeric UID instead of login name
{green}   -o [n]            {reset}always show file offset {magenta}(n = decimal digits){reset}
{green}   -s                {reset}always show file size {magenta}(bare; see -s PROTO:STATE to select){reset}
{green}   +c [w]            {reset}command column width {magenta}(0 = unlimited, default 15){reset}
{green}   -T                {reset}TCP/TPI info {magenta}(state shown by default){reset}
{green}   -J, --json        {reset}output in JSON format
{green}   -R                {reset}list parent PID
{green}   --pgid-show       {reset}show process group IDs
{green}   -t                {reset}terse output {magenta}(PID only){reset}
{green}   -0                {reset}use NUL field terminator instead of NL
{green}   +|-w              {reset}enable (+) or suppress (-) warnings {magenta}(default: +){reset}
{green}   --color MODE      {reset}color output: auto, always, never {magenta}(default: auto){reset}

{cyan}  ── SYSTEM ────────────────────────────────────────{reset}
{green}   +|-r [SECONDS]    {reset}repeat mode {magenta}(default: 1; +r repeats until no output){reset}
{green}   --leak-detect[=I[,N]] {reset}detect FD leaks: poll every I secs {magenta}(default: 5,3){reset}
{green}   --delta           {reset}highlight new/gone FDs in repeat mode
{green}   -W, --monitor     {reset}live full-screen refresh mode {magenta}(like top){reset}
{green}   --summary, --stats {reset}aggregate FD summary: type breakdown, top processes, per-user
{green}   --follow PID      {reset}watch a single process's FDs, highlight opens/closes
{green}   --tree            {reset}process tree view with FD counts {magenta}(like pstree + lsof){reset}
{green}   --top [N]         {reset}live top-N processes by FD count {magenta}(default: 20){reset}
{green}   --watch FILE      {reset}watch who opens/closes a file over time
{green}   --stale            {reset}find FDs pointing to deleted files
{green}   --ports            {reset}show listening ports summary {magenta}(like ss -tlnp){reset}
{green}   --pipe-chain       {reset}trace pipe/socket IPC between processes
{green}   --csv              {reset}CSV output format {magenta}(for spreadsheets/pipelines){reset}
{green}   --net-map          {reset}network connections grouped by remote host
{green}   --tui              {reset}unified TUI with tabs for all modes
{green}   -v, --version     {reset}display version information

{cyan}  ── EXAMPLES ──────────────────────────────────────{reset}
{green}   lsofrs -i :8080       {reset}list files using port 8080
{green}   lsofrs -p 1234        {reset}list files opened by PID 1234
{green}   lsofrs -u root        {reset}list files opened by root
{green}   lsofrs --tree -u root {reset}process tree for root's processes
{green}   lsofrs /var/log/syslog{reset}  list processes using this file
{green}   lsofrs -i TCP         {reset}list all TCP connections

{cyan}  ── INFO ──────────────────────────────────────────{reset}
{magenta}  v{version} {reset}// {yellow}(c) lsof contributors{reset}
Anyone can list all files; /dev warnings disabled; kernel ID check enabled.
{magenta}  Every open file tells a story.{reset}"#,
        );
    }
    /// `parse_from` — normalizes lsof `+|-` option grammar, then delegates to clap.
    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::parse_from(normalize_lsof_args(args))
    }
    /// `leak_detect_params` — see implementation.
    pub fn leak_detect_params(&self) -> Option<(u64, usize)> {
        match &self.leak_detect {
            None => None,
            Some(None) => Some((5, 3)),
            Some(Some(spec)) => {
                let parts: Vec<&str> = spec.split(',').collect();
                let interval = parts.first().and_then(|s| s.parse().ok()).unwrap_or(5);
                let threshold = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
                Some((interval, threshold.max(2)))
            }
        }
    }
}

/// Translate the full lsof `+|-` option grammar into clap-parseable tokens.
///
/// clap uses getopt-with-`--`-longs; lsof adds a `+` prefix family and options
/// with optional attached arguments (`-o9`, `-sTCP:LISTEN`, `+L1`). This is the
/// single place that bridges the two: it splits `-`-clusters getopt-style, maps
/// each lsof option to its clap equivalent (a short flag, a `--long`, or nothing
/// for accept-and-ignore compatibility options), and passes anything after `--`
/// through untouched.
fn normalize_lsof_args<I, T>(args: I) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let toks: Vec<std::ffi::OsString> = args.into_iter().map(Into::into).collect();
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut idx = 0;
    let mut after_dashdash = false;

    // Program name passes through verbatim.
    if let Some(first) = toks.first() {
        out.push(first.clone());
        idx = 1;
    }

    while idx < toks.len() {
        let tok = &toks[idx];
        let next = toks.get(idx + 1).and_then(|t| t.to_str());

        if after_dashdash {
            out.push(tok.clone());
            idx += 1;
            continue;
        }

        match tok.to_str() {
            Some("--") => {
                out.push(tok.clone());
                after_dashdash = true;
                idx += 1;
            }
            Some(s) if s.starts_with('+') && s.len() >= 2 => {
                let (mut emitted, consumed_next) = expand_plus_token(s, next);
                out.append(&mut emitted);
                idx += if consumed_next { 2 } else { 1 };
            }
            Some(s) if s.starts_with('-') && !s.starts_with("--") && s.len() >= 2 => {
                let (mut emitted, consumed_next) = expand_dash_cluster(&s[1..], next);
                out.append(&mut emitted);
                idx += if consumed_next { 2 } else { 1 };
            }
            // Non-UTF8, "--", "-", or a bare positional: pass through.
            _ => {
                out.push(tok.clone());
                idx += 1;
            }
        }
    }
    out
}

/// Expand a single `-`-prefixed cluster (getopt-style) into clap tokens.
/// Returns the emitted tokens and whether the following argv token was consumed
/// (only accept-and-ignore options that take a separate arg consume it).
fn expand_dash_cluster(body: &str, next: Option<&str>) -> (Vec<std::ffi::OsString>, bool) {
    let chars: Vec<char> = body.chars().collect();
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let rest: String = chars[i + 1..].iter().collect();
        match c {
            // No-arg flags clap already knows — keep and continue the cluster.
            'a' | 'l' | 'n' | 'N' | 'P' | 'R' | 't' | 'U' | 'v' | 'V' | 'w' => {
                out.push(format!("-{c}").into());
                i += 1;
            }
            'h' | '?' => {
                out.push("-h".into());
                i += 1;
            }
            // Arg-taking flags clap knows: rest (if any) is the value, else clap
            // pairs the next argv token. Either way the cluster ends.
            'c' | 'd' | 'g' | 'i' | 'p' | 'u' | 'F' | 'r' => {
                if rest.is_empty() {
                    out.push(format!("-{c}").into());
                } else {
                    out.push(format!("-{c}{rest}").into());
                }
                break;
            }
            // Accept-and-ignore, no argument — continue the cluster.
            // `-L` disables link-count listing, which is already the default.
            'b' | 'O' | 'C' | 'M' | 'X' | 'E' | 'L' => {
                i += 1;
            }
            // Accept-and-ignore, optional attached arg — drop rest, end cluster.
            'z' | 'Z' | 'S' | 'f' => {
                break;
            }
            // Accept-and-ignore, required arg — drop rest, or the next token.
            'A' | 'k' | 'm' | 'D' | 'e' => {
                let consumed = rest.is_empty() && next.is_some();
                return (out, consumed);
            }
            // -o [n]: always show offset; leading digits set the precision.
            'o' => {
                let digits: String = rest.chars().take_while(|d| d.is_ascii_digit()).collect();
                out.push("--offset-always".into());
                if !digits.is_empty() {
                    out.push("--offset-digits".into());
                    out.push(digits.clone().into());
                }
                let consumed = digits.len();
                if i + 1 + consumed >= chars.len() {
                    break;
                }
                i += 1 + consumed;
            }
            // -s [p:s]: bare -> always size; with a colon spec -> state filter.
            's' => {
                if rest.is_empty() {
                    out.push("--size-always".into());
                    break;
                } else if rest.contains(':') {
                    out.push("--state-filter".into());
                    out.push(rest.into());
                    break;
                } else {
                    out.push("--size-always".into());
                    i += 1;
                }
            }
            // Meaningful lsof-only flags with optional selectors we accept but
            // treat as "show all" / "enable".
            'T' => {
                out.push("--tcp-info".into());
                break;
            }
            'x' => {
                out.push("--cross-over".into());
                break;
            }
            'K' => {
                out.push("--list-tasks".into());
                break;
            }
            // Unknown single-char: keep it and let clap decide.
            _ => {
                out.push(format!("-{c}").into());
                i += 1;
            }
        }
    }
    (out, false)
}

/// Expand a single `+`-prefixed lsof token into clap tokens.
fn expand_plus_token(s: &str, next: Option<&str>) -> (Vec<std::ffi::OsString>, bool) {
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    let rest = &s[2..]; // characters after `+X`
    match &s[1..2] {
        "L" => {
            if rest.is_empty() {
                out.push("--list-nlink".into());
            } else if let Ok(n) = rest.parse::<u64>() {
                out.push("--list-nlink".into());
                out.push("--link-count-max".into());
                out.push(n.to_string().into());
            } else {
                out.push(s.into()); // not a valid +Ln token
            }
        }
        // Directory search — clap pairs the value (attached or next token).
        "d" => {
            out.push("--dir".into());
            if !rest.is_empty() {
                out.push(rest.into());
            }
        }
        "D" => {
            out.push("--dir-recurse".into());
            if !rest.is_empty() {
                out.push(rest.into());
            }
        }
        // Command column width (0 = unlimited).
        "c" => {
            out.push("--command-width".into());
            if !rest.is_empty() {
                out.push(rest.into());
            }
        }
        // Repeat until no output; optional attached interval.
        "r" => {
            out.push("--repeat-until".into());
            out.push("-r".into());
            let interval = if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
                rest
            } else {
                "1"
            };
            out.push(interval.into());
        }
        // Accept-and-ignore `+` options that take a separate arg.
        "e" => {
            let consumed = rest.is_empty() && next.is_some();
            return (out, consumed);
        }
        // Accept-and-ignore `+` toggles.
        "w" | "f" | "E" | "M" | "X" | "m" => {}
        _ => out.push(s.into()),
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_flag_short() {
        let args = Args::parse_from(["lsofrs", "-h"]);
        assert!(args.help);
    }

    #[test]
    fn parse_help_flag_long() {
        let args = Args::parse_from(["lsofrs", "--help"]);
        assert!(args.help);
    }

    #[test]
    fn parse_pid() {
        let args = Args::parse_from(["lsofrs", "-p", "1234"]);
        assert_eq!(args.pid.as_deref(), Some("1234"));
    }

    #[test]
    fn parse_user() {
        let args = Args::parse_from(["lsofrs", "-u", "root"]);
        assert_eq!(args.user.as_deref(), Some("root"));
    }

    #[test]
    fn parse_command() {
        let args = Args::parse_from(["lsofrs", "-c", "nginx"]);
        assert_eq!(args.command.as_deref(), Some("nginx"));
    }

    #[test]
    fn parse_inet_with_value() {
        let args = Args::parse_from(["lsofrs", "-i", "TCP"]);
        assert_eq!(args.inet.as_deref(), Some("TCP"));
    }

    #[test]
    fn parse_inet_no_value() {
        let args = Args::parse_from(["lsofrs", "-i"]);
        assert_eq!(args.inet.as_deref(), Some(""));
    }

    #[test]
    fn parse_fd() {
        let args = Args::parse_from(["lsofrs", "-d", "0-10"]);
        assert_eq!(args.fd.as_deref(), Some("0-10"));
    }

    #[test]
    fn parse_and_mode() {
        let args = Args::parse_from(["lsofrs", "-a"]);
        assert!(args.and_mode);
    }

    #[test]
    fn parse_terse() {
        let args = Args::parse_from(["lsofrs", "-t"]);
        assert!(args.terse);
    }

    #[test]
    fn parse_json_short() {
        let args = Args::parse_from(["lsofrs", "-J"]);
        assert!(args.json);
    }

    #[test]
    fn parse_json_long() {
        let args = Args::parse_from(["lsofrs", "--json"]);
        assert!(args.json);
    }

    #[test]
    fn parse_monitor_short() {
        let args = Args::parse_from(["lsofrs", "-W"]);
        assert!(args.monitor);
    }

    #[test]
    fn parse_monitor_long() {
        let args = Args::parse_from(["lsofrs", "--monitor"]);
        assert!(args.monitor);
    }

    #[test]
    fn parse_summary() {
        let args = Args::parse_from(["lsofrs", "--summary"]);
        assert!(args.summary);
    }

    #[test]
    fn parse_stats_alias() {
        let args = Args::parse_from(["lsofrs", "--stats"]);
        assert!(args.summary);
    }

    #[test]
    fn parse_follow() {
        let args = Args::parse_from(["lsofrs", "--follow", "1234"]);
        assert_eq!(args.follow, Some(1234));
    }

    #[test]
    fn parse_delta() {
        let args = Args::parse_from(["lsofrs", "--delta"]);
        assert!(args.delta);
    }

    #[test]
    fn parse_nul_terminator() {
        let args = Args::parse_from(["lsofrs", "-0"]);
        assert!(args.nul_terminator);
    }

    #[test]
    fn parse_repeat() {
        let args = Args::parse_from(["lsofrs", "-r", "5"]);
        assert_eq!(args.repeat, Some(5));
    }

    #[test]
    fn parse_boolean_flags() {
        let args = Args::parse_from(["lsofrs", "-n", "-P", "-w", "-N", "-U", "-R"]);
        assert!(args.no_host_lookup);
        assert!(args.no_port_lookup);
        assert!(args.suppress_warnings);
        assert!(args.nfs);
        assert!(args.unix_socket);
        assert!(args.show_ppid);
    }

    #[test]
    fn parse_pgid_show() {
        let args = Args::parse_from(["lsofrs", "--pgid-show"]);
        assert!(args.show_pgid);
    }

    #[test]
    fn parse_field_output() {
        let args = Args::parse_from(["lsofrs", "-F", "pcfn"]);
        assert_eq!(args.field_output.as_deref(), Some("pcfn"));
    }

    #[test]
    fn parse_file_args() {
        let args = Args::parse_from(["lsofrs", "/tmp/foo", "/var/bar"]);
        assert_eq!(args.files, vec!["/tmp/foo", "/var/bar"]);
    }

    #[test]
    fn parse_combined_flags() {
        let args = Args::parse_from(["lsofrs", "-a", "-p", "1", "-i", "TCP", "-t"]);
        assert!(args.and_mode);
        assert_eq!(args.pid.as_deref(), Some("1"));
        assert_eq!(args.inet.as_deref(), Some("TCP"));
        assert!(args.terse);
    }

    #[test]
    fn leak_detect_params_none() {
        let args = Args::parse_from(["lsofrs"]);
        assert!(args.leak_detect_params().is_none());
    }

    #[test]
    fn leak_detect_params_defaults() {
        let args = Args {
            leak_detect: Some(None),
            ..Args::parse_from(["lsofrs"])
        };
        assert_eq!(args.leak_detect_params(), Some((5, 3)));
    }

    #[test]
    fn leak_detect_params_custom() {
        let args = Args {
            leak_detect: Some(Some("10,5".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        assert_eq!(args.leak_detect_params(), Some((10, 5)));
    }

    #[test]
    fn leak_detect_params_threshold_min_2() {
        let args = Args {
            leak_detect: Some(Some("3,1".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (_, threshold) = args.leak_detect_params().unwrap();
        assert_eq!(threshold, 2);
    }

    #[test]
    fn parse_tree() {
        let args = Args::parse_from(["lsofrs", "--tree"]);
        assert!(args.tree);
    }

    #[test]
    fn parse_tree_with_json() {
        let args = Args::parse_from(["lsofrs", "--tree", "--json"]);
        assert!(args.tree);
        assert!(args.json);
    }

    #[test]
    fn parse_tree_and_summary_flags() {
        let args = Args::parse_from(["lsofrs", "--tree", "--summary"]);
        assert!(args.tree);
        assert!(args.summary);
    }

    #[test]
    fn parse_stale_and_csv_flags() {
        let args = Args::parse_from(["lsofrs", "--stale", "--csv"]);
        assert!(args.stale);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_tree_with_filters() {
        let args = Args::parse_from(["lsofrs", "--tree", "-u", "root", "-c", "sshd"]);
        assert!(args.tree);
        assert_eq!(args.user.as_deref(), Some("root"));
        assert_eq!(args.command.as_deref(), Some("sshd"));
    }

    #[test]
    fn parse_no_flags_defaults() {
        let args = Args::parse_from(["lsofrs"]);
        assert!(!args.help);
        assert!(!args.tree);
        assert!(!args.json);
        assert!(!args.terse);
        assert!(!args.and_mode);
        assert!(!args.nfs);
        assert!(!args.unix_socket);
        assert!(!args.monitor);
        assert!(!args.summary);
        assert!(!args.delta);
        assert!(!args.show_pgid);
        assert!(!args.show_ppid);
        assert!(!args.no_host_lookup);
        assert!(!args.no_port_lookup);
        assert!(!args.suppress_warnings);
        assert!(!args.nul_terminator);
        assert!(!args.stale);
        assert!(!args.ports);
        assert!(!args.pipe_chain);
        assert!(!args.csv_output);
        assert!(!args.net_map);
        assert!(!args.tui);
        assert!(args.pid.is_none());
        assert!(args.user.is_none());
        assert!(args.pgid.is_none());
        assert!(args.command.is_none());
        assert!(args.inet.is_none());
        assert!(args.fd.is_none());
        assert!(args.field_output.is_none());
        assert!(args.repeat.is_none());
        assert!(args.follow.is_none());
        assert!(args.leak_detect.is_none());
        assert!(args.files.is_empty());
    }

    #[test]
    fn parse_stale() {
        let args = Args::parse_from(["lsofrs", "--stale"]);
        assert!(args.stale);
    }

    #[test]
    fn parse_ports() {
        let args = Args::parse_from(["lsofrs", "--ports"]);
        assert!(args.ports);
    }

    #[test]
    fn parse_stale_with_json() {
        let args = Args::parse_from(["lsofrs", "--stale", "--json"]);
        assert!(args.stale);
        assert!(args.json);
    }

    #[test]
    fn parse_ports_with_json() {
        let args = Args::parse_from(["lsofrs", "--ports", "--json"]);
        assert!(args.ports);
        assert!(args.json);
    }

    #[test]
    fn leak_detect_params_interval_only() {
        let args = Args {
            leak_detect: Some(Some("15".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (interval, threshold) = args.leak_detect_params().unwrap();
        assert_eq!(interval, 15);
        assert_eq!(threshold, 3); // default
    }

    #[test]
    fn leak_detect_params_invalid_input() {
        let args = Args {
            leak_detect: Some(Some("abc,xyz".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (interval, threshold) = args.leak_detect_params().unwrap();
        assert_eq!(interval, 5); // fallback
        assert_eq!(threshold, 3); // fallback
    }

    #[test]
    fn parse_pipe_chain() {
        let args = Args::parse_from(["lsofrs", "--pipe-chain"]);
        assert!(args.pipe_chain);
    }

    #[test]
    fn parse_csv_output() {
        let args = Args::parse_from(["lsofrs", "--csv"]);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_net_map() {
        let args = Args::parse_from(["lsofrs", "--net-map"]);
        assert!(args.net_map);
    }

    #[test]
    fn parse_pgid_filter_comma_separated() {
        let args = Args::parse_from(["lsofrs", "-g", "42,99"]);
        assert_eq!(args.pgid.as_deref(), Some("42,99"));
    }

    #[test]
    fn parse_show_ppid_short_uppercase_r_flag() {
        let args = Args::parse_from(["lsofrs", "-R"]);
        assert!(args.show_ppid);
    }

    #[test]
    fn parse_pipe_chain_with_json() {
        let args = Args::parse_from(["lsofrs", "--pipe-chain", "--json"]);
        assert!(args.pipe_chain);
        assert!(args.json);
    }

    #[test]
    fn parse_net_map_with_json() {
        let args = Args::parse_from(["lsofrs", "--net-map", "--json"]);
        assert!(args.net_map);
        assert!(args.json);
    }

    #[test]
    fn parse_watch_path() {
        let args = Args::parse_from(["lsofrs", "--watch", "/tmp/lsofrs-watch"]);
        assert_eq!(args.watch.as_deref(), Some("/tmp/lsofrs-watch"));
    }

    #[test]
    fn parse_top_bare() {
        let args = Args::parse_from(["lsofrs", "--top"]);
        assert_eq!(args.top, Some(None));
    }

    #[test]
    fn parse_top_with_limit() {
        let args = Args::parse_from(["lsofrs", "--top", "7"]);
        assert_eq!(args.top, Some(Some(7)));
    }

    #[test]
    fn parse_top_bare_with_monitor_short() {
        let args = Args::parse_from(["lsofrs", "--top", "-W"]);
        assert_eq!(args.top, Some(None));
        assert!(args.monitor);
    }

    #[test]
    fn parse_top_with_limit_and_monitor_short() {
        let args = Args::parse_from(["lsofrs", "--top", "5", "-W"]);
        assert_eq!(args.top, Some(Some(5)));
        assert!(args.monitor);
    }

    #[test]
    fn parse_top_with_limit_and_monitor_long() {
        let args = Args::parse_from(["lsofrs", "--top", "5", "--monitor"]);
        assert_eq!(args.top, Some(Some(5)));
        assert!(args.monitor);
    }

    #[test]
    fn parse_tui() {
        let args = Args::parse_from(["lsofrs", "--tui"]);
        assert!(args.tui);
    }

    #[test]
    fn parse_theme_override() {
        let args = Args::parse_from(["lsofrs", "--tui", "--theme", "matrix"]);
        assert_eq!(args.theme_name, "matrix");
    }

    #[test]
    fn parse_color_always() {
        let args = Args::parse_from(["lsofrs", "--color", "always"]);
        assert_eq!(args.color, "always");
    }

    #[test]
    fn parse_color_never() {
        let args = Args::parse_from(["lsofrs", "--color", "never"]);
        assert_eq!(args.color, "never");
    }

    #[test]
    fn parse_dir_long_form() {
        let args = Args::parse_from(["lsofrs", "--dir", "/var/tmp"]);
        assert_eq!(args.dir.as_deref(), Some("/var/tmp"));
    }

    #[test]
    fn parse_dir_plus_d_long_alias() {
        let args = Args::parse_from(["lsofrs", "--+d", "/var/tmp"]);
        assert_eq!(args.dir.as_deref(), Some("/var/tmp"));
    }

    #[test]
    fn parse_dir_recurse_plus_upper_d_alias() {
        let args = Args::parse_from(["lsofrs", "--+D", "/var/log"]);
        assert_eq!(args.dir_recurse.as_deref(), Some("/var/log"));
    }

    #[test]
    fn parse_stats_alias_with_json() {
        let args = Args::parse_from(["lsofrs", "--stats", "-J"]);
        assert!(args.summary);
        assert!(args.json);
    }

    #[test]
    fn parse_suppress_warnings_with_json() {
        let args = Args::parse_from(["lsofrs", "-w", "-J", "-p", "1"]);
        assert!(args.suppress_warnings);
        assert!(args.json);
        assert_eq!(args.pid.as_deref(), Some("1"));
    }

    #[test]
    fn parse_leak_detect_from_cli_with_spec() {
        let args = Args::parse_from(["lsofrs", "--leak-detect", "12,6"]);
        assert_eq!(args.leak_detect, Some(Some("12,6".to_string())));
        assert_eq!(args.leak_detect_params(), Some((12, 6)));
    }

    #[test]
    fn parse_leak_detect_from_cli_flag_only() {
        let args = Args::parse_from(["lsofrs", "--leak-detect"]);
        assert_eq!(args.leak_detect, Some(None));
        assert_eq!(args.leak_detect_params(), Some((5, 3)));
    }

    #[test]
    fn parse_monitor_with_theme_and_color() {
        let args = Args::parse_from(["lsofrs", "-W", "--theme", "ice-breaker", "--color", "never"]);
        assert!(args.monitor);
        assert_eq!(args.theme_name, "ice-breaker");
        assert_eq!(args.color, "never");
    }

    #[test]
    fn parse_summary_with_csv_is_valid_args() {
        let args = Args::parse_from(["lsofrs", "--summary", "--csv"]);
        assert!(args.summary);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_follow_pid() {
        let args = Args::parse_from(["lsofrs", "--follow", "4242"]);
        assert_eq!(args.follow, Some(4242));
    }

    #[test]
    fn parse_inet_udp_value() {
        let args = Args::parse_from(["lsofrs", "-i", "UDP"]);
        assert_eq!(args.inet.as_deref(), Some("UDP"));
    }

    #[test]
    fn parse_inet_4tcp_combined_token() {
        let args = Args::parse_from(["lsofrs", "-i", "4TCP:22"]);
        assert_eq!(args.inet.as_deref(), Some("4TCP:22"));
    }

    #[test]
    fn parse_repeat_delta_json_combo() {
        let args = Args::parse_from(["lsofrs", "-r", "2", "--delta", "-J"]);
        assert_eq!(args.repeat, Some(2));
        assert!(args.delta);
        assert!(args.json);
    }

    #[test]
    fn parse_watch_with_json_flags() {
        let args = Args::parse_from(["lsofrs", "--watch", "/tmp/x", "--json"]);
        assert_eq!(args.watch.as_deref(), Some("/tmp/x"));
        assert!(args.json);
    }

    #[test]
    fn parse_watch_and_follow_flags_together() {
        let args = Args::parse_from(["lsofrs", "--watch", "/tmp/x", "--follow", "42"]);
        assert_eq!(args.watch.as_deref(), Some("/tmp/x"));
        assert_eq!(args.follow, Some(42));
    }

    #[test]
    fn parse_nul_terminator_with_json() {
        let args = Args::parse_from(["lsofrs", "-0", "-J"]);
        assert!(args.nul_terminator);
        assert!(args.json);
    }

    #[test]
    fn parse_tree_with_csv_flags() {
        let args = Args::parse_from(["lsofrs", "--tree", "--csv"]);
        assert!(args.tree);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_stale_with_csv() {
        let args = Args::parse_from(["lsofrs", "--stale", "--csv"]);
        assert!(args.stale);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_ports_with_csv() {
        let args = Args::parse_from(["lsofrs", "--ports", "--csv"]);
        assert!(args.ports);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_net_map_json_csv_combo() {
        let args = Args::parse_from(["lsofrs", "--net-map", "-J", "--csv"]);
        assert!(args.net_map);
        assert!(args.json);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_top_with_json() {
        let args = Args::parse_from(["lsofrs", "--top", "12", "-J"]);
        assert_eq!(args.top, Some(Some(12)));
        assert!(args.json);
    }

    #[test]
    fn parse_top_with_json_and_pid() {
        let args = Args::parse_from(["lsofrs", "--top", "12", "-J", "-p", "1"]);
        assert_eq!(args.top, Some(Some(12)));
        assert!(args.json);
        assert_eq!(args.pid.as_deref(), Some("1"));
    }

    #[test]
    fn parse_pipe_chain_with_csv() {
        let args = Args::parse_from(["lsofrs", "--pipe-chain", "--csv"]);
        assert!(args.pipe_chain);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_leak_detect_params_with_json() {
        let args = Args::parse_from(["lsofrs", "--leak-detect", "8,4", "-J"]);
        assert_eq!(args.leak_detect_params(), Some((8, 4)));
        assert!(args.json);
    }

    #[test]
    fn parse_summary_json_and_delta() {
        let args = Args::parse_from(["lsofrs", "--summary", "--json", "--delta"]);
        assert!(args.summary);
        assert!(args.json);
        assert!(args.delta);
    }

    #[test]
    fn parse_tui_with_csv() {
        let args = Args::parse_from(["lsofrs", "--tui", "--csv"]);
        assert!(args.tui);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_monitor_with_json() {
        let args = Args::parse_from(["lsofrs", "-W", "-J"]);
        assert!(args.monitor);
        assert!(args.json);
    }

    #[test]
    fn parse_follow_with_csv() {
        let args = Args::parse_from(["lsofrs", "--follow", "999", "--csv"]);
        assert_eq!(args.follow, Some(999));
        assert!(args.csv_output);
    }

    #[test]
    fn parse_json_and_mode_and_pid() {
        let args = Args::parse_from(["lsofrs", "-J", "-a", "-p", "7"]);
        assert!(args.json);
        assert!(args.and_mode);
        assert_eq!(args.pid.as_deref(), Some("7"));
    }

    #[test]
    fn parse_tree_json_csv_combo() {
        let args = Args::parse_from(["lsofrs", "--tree", "-J", "--csv"]);
        assert!(args.tree);
        assert!(args.json);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_json_long_and_summary_together() {
        let args = Args::parse_from(["lsofrs", "--json", "--summary"]);
        assert!(args.json);
        assert!(args.summary);
    }

    #[test]
    fn parse_stale_and_net_map_flags() {
        let args = Args::parse_from(["lsofrs", "--stale", "--net-map"]);
        assert!(args.stale);
        assert!(args.net_map);
    }

    #[test]
    fn parse_ports_and_pipe_chain_flags() {
        let args = Args::parse_from(["lsofrs", "--ports", "--pipe-chain"]);
        assert!(args.ports);
        assert!(args.pipe_chain);
    }

    #[test]
    fn parse_stale_and_pipe_chain_flags() {
        let args = Args::parse_from(["lsofrs", "--stale", "--pipe-chain"]);
        assert!(args.stale);
        assert!(args.pipe_chain);
    }

    #[test]
    fn parse_net_map_and_summary_flags() {
        let args = Args::parse_from(["lsofrs", "--net-map", "--summary"]);
        assert!(args.net_map);
        assert!(args.summary);
    }

    #[test]
    fn parse_stale_and_tree_flags() {
        let args = Args::parse_from(["lsofrs", "--stale", "--tree"]);
        assert!(args.stale);
        assert!(args.tree);
    }

    #[test]
    fn parse_ports_and_summary_flags() {
        let args = Args::parse_from(["lsofrs", "--ports", "--summary"]);
        assert!(args.ports);
        assert!(args.summary);
    }

    #[test]
    fn parse_pipe_chain_and_tree_flags() {
        let args = Args::parse_from(["lsofrs", "--pipe-chain", "--tree"]);
        assert!(args.pipe_chain);
        assert!(args.tree);
    }

    #[test]
    fn parse_net_map_summary_and_terse_flags() {
        let args = Args::parse_from(["lsofrs", "--net-map", "--summary", "-t"]);
        assert!(args.net_map);
        assert!(args.summary);
        assert!(args.terse);
    }

    #[test]
    fn parse_tree_and_terse_flags() {
        let args = Args::parse_from(["lsofrs", "--tree", "-t"]);
        assert!(args.tree);
        assert!(args.terse);
    }

    #[test]
    fn parse_stale_json_and_terse_flags() {
        let args = Args::parse_from(["lsofrs", "--stale", "-J", "-t"]);
        assert!(args.stale);
        assert!(args.json);
        assert!(args.terse);
    }

    #[test]
    fn parse_csv_and_field_output() {
        let args = Args::parse_from(["lsofrs", "--csv", "-F", "pn", "-p", "1"]);
        assert!(args.csv_output);
        assert_eq!(args.field_output.as_deref(), Some("pn"));
    }

    #[test]
    fn parse_net_map_and_field_output() {
        let args = Args::parse_from(["lsofrs", "--net-map", "-F", "pfn"]);
        assert!(args.net_map);
        assert_eq!(args.field_output.as_deref(), Some("pfn"));
    }

    #[test]
    fn parse_json_long_before_tree() {
        let args = Args::parse_from(["lsofrs", "--json", "--tree", "-p", "42"]);
        assert!(args.json);
        assert!(args.tree);
        assert_eq!(args.pid.as_deref(), Some("42"));
    }

    #[test]
    fn parse_json_long_before_stale() {
        let args = Args::parse_from(["lsofrs", "--json", "--stale"]);
        assert!(args.json);
        assert!(args.stale);
    }

    #[test]
    fn parse_json_long_before_pipe_chain() {
        let args = Args::parse_from(["lsofrs", "--json", "--pipe-chain"]);
        assert!(args.json);
        assert!(args.pipe_chain);
    }

    #[test]
    fn parse_json_short_before_net_map() {
        let args = Args::parse_from(["lsofrs", "-J", "--net-map"]);
        assert!(args.json);
        assert!(args.net_map);
    }

    #[test]
    fn parse_json_short_before_ports() {
        let args = Args::parse_from(["lsofrs", "-J", "--ports"]);
        assert!(args.json);
        assert!(args.ports);
    }

    #[test]
    fn parse_json_short_before_stale() {
        let args = Args::parse_from(["lsofrs", "-J", "--stale"]);
        assert!(args.json);
        assert!(args.stale);
    }

    #[test]
    fn parse_json_short_before_tree() {
        let args = Args::parse_from(["lsofrs", "-J", "--tree", "-p", "42"]);
        assert!(args.json);
        assert!(args.tree);
        assert_eq!(args.pid.as_deref(), Some("42"));
    }

    #[test]
    fn parse_json_short_before_pipe_chain() {
        let args = Args::parse_from(["lsofrs", "-J", "--pipe-chain"]);
        assert!(args.json);
        assert!(args.pipe_chain);
    }

    #[test]
    fn parse_json_short_before_summary() {
        let args = Args::parse_from(["lsofrs", "-J", "--summary"]);
        assert!(args.json);
        assert!(args.summary);
    }

    #[test]
    fn parse_json_long_before_stats() {
        let args = Args::parse_from(["lsofrs", "--json", "--stats"]);
        assert!(args.json);
        assert!(args.summary);
    }

    #[test]
    fn parse_json_short_before_stats() {
        let args = Args::parse_from(["lsofrs", "-J", "--stats"]);
        assert!(args.json);
        assert!(args.summary);
    }

    #[test]
    fn parse_json_and_mode_and_inet() {
        let args = Args::parse_from(["lsofrs", "-J", "-a", "-i", "TCP"]);
        assert!(args.json);
        assert!(args.and_mode);
        assert_eq!(args.inet.as_deref(), Some("TCP"));
    }

    #[test]
    fn parse_watch_csv_combo() {
        let args = Args::parse_from(["lsofrs", "--watch", "/var/log/secure", "--csv"]);
        assert_eq!(args.watch.as_deref(), Some("/var/log/secure"));
        assert!(args.csv_output);
    }

    #[test]
    fn parse_no_lookup_flags_together() {
        let args = Args::parse_from(["lsofrs", "-n", "-P", "-i", "TCP"]);
        assert!(args.no_host_lookup);
        assert!(args.no_port_lookup);
        assert_eq!(args.inet.as_deref(), Some("TCP"));
    }

    #[test]
    fn parse_csv_json_terse_flags() {
        let args = Args::parse_from(["lsofrs", "--csv", "-J", "-t"]);
        assert!(args.csv_output);
        assert!(args.json);
        assert!(args.terse);
    }

    #[test]
    fn parse_repeat_delta_json() {
        let args = Args::parse_from(["lsofrs", "-r", "3", "--delta", "-J"]);
        assert_eq!(args.repeat, Some(3));
        assert!(args.delta);
        assert!(args.json);
    }

    #[test]
    fn parse_stale_net_map_json_combo() {
        let args = Args::parse_from(["lsofrs", "--stale", "--net-map", "-J"]);
        assert!(args.stale);
        assert!(args.net_map);
        assert!(args.json);
    }

    #[test]
    fn parse_monitor_top_and_csv() {
        let args = Args::parse_from(["lsofrs", "-W", "--top", "3", "--csv"]);
        assert!(args.monitor);
        assert_eq!(args.top, Some(Some(3)));
        assert!(args.csv_output);
    }

    #[test]
    fn parse_pipe_chain_stale_json() {
        let args = Args::parse_from(["lsofrs", "--pipe-chain", "--stale", "-J"]);
        assert!(args.pipe_chain);
        assert!(args.stale);
        assert!(args.json);
    }

    #[test]
    fn parse_ports_repeat_csv() {
        let args = Args::parse_from(["lsofrs", "--ports", "-r", "5", "--csv"]);
        assert!(args.ports);
        assert_eq!(args.repeat, Some(5));
        assert!(args.csv_output);
    }

    #[test]
    fn parse_repeat_with_nul_terminator() {
        let args = Args::parse_from(["lsofrs", "-r", "2", "-0"]);
        assert_eq!(args.repeat, Some(2));
        assert!(args.nul_terminator);
    }

    #[test]
    fn parse_nul_terminator_with_csv() {
        let args = Args::parse_from(["lsofrs", "-0", "--csv"]);
        assert!(args.nul_terminator);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_leak_detect_with_monitor_short() {
        let args = Args::parse_from(["lsofrs", "--leak-detect", "6,3", "-W"]);
        assert_eq!(args.leak_detect_params(), Some((6, 3)));
        assert!(args.monitor);
    }

    #[test]
    fn parse_leak_detect_bare_with_top() {
        let args = Args::parse_from(["lsofrs", "--leak-detect", "--top", "4"]);
        assert_eq!(args.leak_detect, Some(None));
        assert_eq!(args.top, Some(Some(4)));
    }

    #[test]
    fn parse_tree_monitor_json() {
        let args = Args::parse_from(["lsofrs", "--tree", "-W", "-J"]);
        assert!(args.tree);
        assert!(args.monitor);
        assert!(args.json);
    }

    #[test]
    fn parse_json_with_field_output() {
        let args = Args::parse_from(["lsofrs", "-J", "-F", "pcfn"]);
        assert!(args.json);
        assert_eq!(args.field_output.as_deref(), Some("pcfn"));
    }

    #[test]
    fn parse_field_output_with_terse() {
        let args = Args::parse_from(["lsofrs", "-F", "pfn", "-t"]);
        assert_eq!(args.field_output.as_deref(), Some("pfn"));
        assert!(args.terse);
    }

    #[test]
    fn parse_summary_net_map_csv() {
        let args = Args::parse_from(["lsofrs", "--summary", "--net-map", "--csv"]);
        assert!(args.summary);
        assert!(args.net_map);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_inet_colon_port_only() {
        let args = Args::parse_from(["lsofrs", "-i", ":443"]);
        assert_eq!(args.inet.as_deref(), Some(":443"));
    }

    #[test]
    fn parse_positional_after_double_dash() {
        let args = Args::parse_from(["lsofrs", "--", "/tmp/after-dd"]);
        assert_eq!(args.files, vec!["/tmp/after-dd"]);
    }

    #[test]
    fn parse_json_terse_both_set() {
        let args = Args::parse_from(["lsofrs", "-J", "-t", "-p", "1"]);
        assert!(args.json);
        assert!(args.terse);
        assert_eq!(args.pid.as_deref(), Some("1"));
    }

    #[test]
    fn parse_csv_json_both_set() {
        let args = Args::parse_from(["lsofrs", "--csv", "-J", "-p", "2"]);
        assert!(args.csv_output);
        assert!(args.json);
        assert_eq!(args.pid.as_deref(), Some("2"));
    }

    #[test]
    fn parse_show_pgid_ppid_with_json() {
        let args = Args::parse_from(["lsofrs", "-J", "--pgid-show", "-R", "-p", "1"]);
        assert!(args.json);
        assert!(args.show_pgid);
        assert!(args.show_ppid);
    }

    #[test]
    fn parse_net_map_delta_json() {
        let args = Args::parse_from(["lsofrs", "--net-map", "--delta", "-J"]);
        assert!(args.net_map);
        assert!(args.delta);
        assert!(args.json);
    }

    #[test]
    fn parse_stale_ports_csv() {
        let args = Args::parse_from(["lsofrs", "--stale", "--ports", "--csv"]);
        assert!(args.stale);
        assert!(args.ports);
        assert!(args.csv_output);
    }

    #[test]
    fn parse_tree_net_map_json() {
        let args = Args::parse_from(["lsofrs", "--tree", "--net-map", "-J"]);
        assert!(args.tree);
        assert!(args.net_map);
        assert!(args.json);
    }

    #[test]
    fn leak_detect_params_trailing_comma_uses_default_threshold() {
        let args = Args {
            leak_detect: Some(Some("12,".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (i, t) = args.leak_detect_params().unwrap();
        assert_eq!(i, 12);
        assert_eq!(t, 3);
    }

    #[test]
    fn leak_detect_params_leading_comma_interval_defaults_threshold_parsed() {
        let args = Args {
            leak_detect: Some(Some(",9".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (i, t) = args.leak_detect_params().unwrap();
        assert_eq!(i, 5);
        assert_eq!(t, 9);
    }

    #[test]
    fn leak_detect_params_invalid_interval_valid_threshold() {
        let args = Args {
            leak_detect: Some(Some("oops,7".to_string())),
            ..Args::parse_from(["lsofrs"])
        };
        let (i, t) = args.leak_detect_params().unwrap();
        assert_eq!(i, 5);
        assert_eq!(t, 7);
    }

    #[test]
    fn parse_top_limit_10() {
        let args = Args::parse_from(["lsofrs", "--top", "10"]);
        assert_eq!(args.top, Some(Some(10)));
    }

    #[test]
    fn parse_color_auto() {
        let args = Args::parse_from(["lsofrs", "--color", "auto"]);
        assert_eq!(args.color, "auto");
    }

    #[test]
    fn parse_delta_repeat_combo() {
        let args = Args::parse_from(["lsofrs", "--delta", "-r", "3"]);
        assert!(args.delta);
        assert_eq!(args.repeat, Some(3));
    }

    #[test]
    fn parse_command_comma_separated_literals() {
        let args = Args::parse_from(["lsofrs", "-c", "sshd,nginx"]);
        assert_eq!(args.command.as_deref(), Some("sshd,nginx"));
    }

    #[test]
    fn parse_plus_l_bare_enables_nlink_listing_no_filter() {
        let args = Args::parse_from(["lsofrs", "+L"]);
        assert!(args.list_nlink);
        assert_eq!(args.link_count_max, None);
    }

    #[test]
    fn parse_plus_l1_selects_unlinked_files() {
        let args = Args::parse_from(["lsofrs", "+L1"]);
        assert!(args.list_nlink);
        assert_eq!(args.link_count_max, Some(1));
    }

    #[test]
    fn parse_plus_ln_arbitrary_number() {
        let args = Args::parse_from(["lsofrs", "+L5"]);
        assert!(args.list_nlink);
        assert_eq!(args.link_count_max, Some(5));
    }

    #[test]
    fn parse_minus_l_is_default_no_listing() {
        let args = Args::parse_from(["lsofrs", "-L"]);
        assert!(!args.list_nlink);
        assert_eq!(args.link_count_max, None);
    }

    #[test]
    fn parse_plus_l1_with_pid_filter() {
        let args = Args::parse_from(["lsofrs", "+L1", "-p", "1234"]);
        assert!(args.list_nlink);
        assert_eq!(args.link_count_max, Some(1));
        assert_eq!(args.pid.as_deref(), Some("1234"));
    }

    #[test]
    fn parse_plus_l_nonnumeric_suffix_is_positional() {
        // `+Lx` isn't a valid link-count token; it must not be swallowed.
        let args = Args::parse_from(["lsofrs", "+Lx"]);
        assert!(!args.list_nlink);
        assert_eq!(args.link_count_max, None);
        assert_eq!(args.files, vec!["+Lx"]);
    }

    #[test]
    fn normalize_leaves_unrelated_args_untouched() {
        let out = normalize_lsof_args(["lsofrs", "-p", "1", "/tmp/x"]);
        let strs: Vec<String> = out.iter().map(|s| s.to_string_lossy().into()).collect();
        assert_eq!(strs, vec!["lsofrs", "-p", "1", "/tmp/x"]);
    }

    // Helper: run the normalizer and return the emitted tokens as Strings.
    fn norm(args: &[&str]) -> Vec<String> {
        normalize_lsof_args(args.iter().copied())
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn normalize_splits_grouped_short_flags() {
        assert_eq!(norm(&["lsofrs", "-nP"]), vec!["lsofrs", "-n", "-P"]);
        assert_eq!(norm(&["lsofrs", "-aNP"]), vec!["lsofrs", "-a", "-N", "-P"]);
    }

    #[test]
    fn normalize_cluster_ends_at_arg_taking_flag() {
        // `-nPi4TCP` → -n -P -i with attached value 4TCP.
        assert_eq!(
            norm(&["lsofrs", "-nPi4TCP"]),
            vec!["lsofrs", "-n", "-P", "-i4TCP"]
        );
    }

    #[test]
    fn normalize_bare_arg_option_lets_clap_pair_next() {
        assert_eq!(norm(&["lsofrs", "-p", "123"]), vec!["lsofrs", "-p", "123"]);
        assert_eq!(norm(&["lsofrs", "-i", "TCP"]), vec!["lsofrs", "-i", "TCP"]);
    }

    #[test]
    fn normalize_offset_option() {
        assert_eq!(norm(&["lsofrs", "-o"]), vec!["lsofrs", "--offset-always"]);
        assert_eq!(
            norm(&["lsofrs", "-o9"]),
            vec!["lsofrs", "--offset-always", "--offset-digits", "9"]
        );
    }

    #[test]
    fn normalize_size_and_state_filter() {
        assert_eq!(norm(&["lsofrs", "-s"]), vec!["lsofrs", "--size-always"]);
        assert_eq!(
            norm(&["lsofrs", "-sTCP:LISTEN"]),
            vec!["lsofrs", "--state-filter", "TCP:LISTEN"]
        );
    }

    #[test]
    fn normalize_accept_ignore_no_arg_flags_dropped() {
        // -b -O -C -M -X -E carry no behavior; they must not reach clap or leak.
        assert_eq!(
            norm(&["lsofrs", "-bOC", "-p", "1"]),
            vec!["lsofrs", "-p", "1"]
        );
    }

    #[test]
    fn normalize_accept_ignore_arg_option_consumes_value() {
        // -A takes a device-cache path; both the flag and its value are dropped.
        assert_eq!(
            norm(&["lsofrs", "-A", "/dev/cache", "-p", "1"]),
            vec!["lsofrs", "-p", "1"]
        );
        assert_eq!(
            norm(&["lsofrs", "-k/vmunix", "-p", "1"]),
            vec!["lsofrs", "-p", "1"]
        );
    }

    #[test]
    fn normalize_tcp_info_and_cross_over_ignore_selectors() {
        assert_eq!(norm(&["lsofrs", "-Tqs"]), vec!["lsofrs", "--tcp-info"]);
        assert_eq!(norm(&["lsofrs", "-xl"]), vec!["lsofrs", "--cross-over"]);
    }

    #[test]
    fn normalize_plus_c_command_width() {
        assert_eq!(
            norm(&["lsofrs", "+c0"]),
            vec!["lsofrs", "--command-width", "0"]
        );
        assert_eq!(
            norm(&["lsofrs", "+c", "20"]),
            vec!["lsofrs", "--command-width", "20"]
        );
    }

    #[test]
    fn normalize_plus_d_dir_forms() {
        assert_eq!(
            norm(&["lsofrs", "+d", "/tmp"]),
            vec!["lsofrs", "--dir", "/tmp"]
        );
        assert_eq!(
            norm(&["lsofrs", "+D/var"]),
            vec!["lsofrs", "--dir-recurse", "/var"]
        );
    }

    #[test]
    fn normalize_stops_transforming_after_double_dash() {
        assert_eq!(
            norm(&["lsofrs", "--", "-o", "+L1"]),
            vec!["lsofrs", "--", "-o", "+L1"]
        );
    }

    #[test]
    fn parse_lowercase_v_is_version() {
        let args = Args::parse_from(["lsofrs", "-v"]);
        assert!(args.version);
        assert!(!args.report_unfound);
    }

    #[test]
    fn parse_uppercase_v_is_report_unfound() {
        let args = Args::parse_from(["lsofrs", "-V", "-p", "1"]);
        assert!(args.report_unfound);
        assert!(!args.version);
    }

    #[test]
    fn parse_numeric_uid_flag() {
        let args = Args::parse_from(["lsofrs", "-l"]);
        assert!(args.numeric_uid);
    }

    #[test]
    fn parse_offset_always_and_digits() {
        let bare = Args::parse_from(["lsofrs", "-o"]);
        assert!(bare.offset_always);
        assert_eq!(bare.offset_digits, None);
        let padded = Args::parse_from(["lsofrs", "-o9"]);
        assert!(padded.offset_always);
        assert_eq!(padded.offset_digits, Some(9));
    }

    #[test]
    fn parse_size_always_and_state_filter() {
        let size = Args::parse_from(["lsofrs", "-s"]);
        assert!(size.size_always);
        let state = Args::parse_from(["lsofrs", "-sTCP:LISTEN"]);
        assert_eq!(state.state_filter, vec!["TCP:LISTEN"]);
    }

    #[test]
    fn parse_command_width_via_plus_c() {
        let args = Args::parse_from(["lsofrs", "+c0"]);
        assert_eq!(args.command_width, Some(0));
    }

    #[test]
    fn parse_tcp_info_and_cross_over_and_tasks() {
        let args = Args::parse_from(["lsofrs", "-T", "-x", "-K"]);
        assert!(args.tcp_info);
        assert!(args.cross_over);
        assert!(args.list_tasks);
    }

    #[test]
    fn parse_accept_ignore_options_do_not_error() {
        // These legacy/platform options must parse cleanly and select nothing.
        let args = Args::parse_from(["lsofrs", "-b", "-O", "-C", "-A", "/dev/x", "-p", "1"]);
        assert_eq!(args.pid.as_deref(), Some("1"));
    }

    #[test]
    fn normalize_plus_r_repeat_until() {
        // +r bare -> repeat-until with default 1s interval; +r5 keeps the interval.
        assert_eq!(
            norm(&["lsofrs", "+r"]),
            vec!["lsofrs", "--repeat-until", "-r", "1"]
        );
        assert_eq!(
            norm(&["lsofrs", "+r5"]),
            vec!["lsofrs", "--repeat-until", "-r", "5"]
        );
    }

    #[test]
    fn normalize_offset_with_trailing_flag_letter() {
        // -o9a: offset(9 digits) then a separate -a flag — the digit run must not
        // swallow the trailing 'a'.
        assert_eq!(
            norm(&["lsofrs", "-o9a"]),
            vec!["lsofrs", "--offset-always", "--offset-digits", "9", "-a"]
        );
    }

    #[test]
    fn normalize_optional_arg_ignores_do_not_consume_next() {
        // -z/-Z/-S have optional args; a following positional must survive.
        assert_eq!(norm(&["lsofrs", "-z", "/tmp/x"]), vec!["lsofrs", "/tmp/x"]);
        assert_eq!(norm(&["lsofrs", "-S", "/tmp/x"]), vec!["lsofrs", "/tmp/x"]);
    }

    #[test]
    fn normalize_plus_toggles_dropped() {
        assert_eq!(
            norm(&["lsofrs", "+w", "+f", "+E", "+M", "+X", "-p", "1"]),
            vec!["lsofrs", "-p", "1"]
        );
    }

    #[test]
    fn normalize_plus_e_consumes_separate_arg() {
        // +e takes a filesystem path; both are dropped, positional survives.
        assert_eq!(
            norm(&["lsofrs", "+e", "/mnt", "/tmp/x"]),
            vec!["lsofrs", "/tmp/x"]
        );
    }

    #[test]
    fn normalize_plus_lx_invalid_passes_through() {
        // +Lx is not a valid +Ln token and must reach clap unchanged (positional).
        assert_eq!(norm(&["lsofrs", "+Lx"]), vec!["lsofrs", "+Lx"]);
    }

    #[test]
    fn normalize_standalone_meaningful_lsof_only_flags() {
        assert_eq!(norm(&["lsofrs", "-K"]), vec!["lsofrs", "--list-tasks"]);
        assert_eq!(norm(&["lsofrs", "-x"]), vec!["lsofrs", "--cross-over"]);
    }

    #[test]
    fn normalize_bare_dash_and_program_name_preserved() {
        // A lone "-" (stdin convention) and argv[0] pass through untouched.
        assert_eq!(norm(&["lsofrs", "-"]), vec!["lsofrs", "-"]);
        assert_eq!(norm(&["lsofrs"]), vec!["lsofrs"]);
    }
}
