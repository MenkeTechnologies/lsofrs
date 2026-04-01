//! Command-line argument parsing

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "lsofrs",
    version = "4.1.0",
    about = "List System Open Files — modern Rust implementation",
    author = "Jacob Menke",
    long_about = "lsofrs maps the relationship between processes and the files they hold open.\n\
                  Supports regular files, directories, sockets, pipes, devices, and streams.",
    disable_help_flag = true
)]
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

    /// List open files in directory (one level)
    #[arg(long = "dir", alias = "+d")]
    pub dir: Option<String>,

    /// Recursively list open files in directory
    #[arg(long = "dir-recurse", alias = "+D")]
    pub dir_recurse: Option<String>,

    /// Files/directories to search
    pub files: Vec<String>,
}

impl Args {
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

{cyan}  >> FILE DESCRIPTOR SCANNER v4.1 << {reset}
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
{green}   -J, --json        {reset}output in JSON format
{green}   -R                {reset}list parent PID
{green}   --pgid-show       {reset}show process group IDs
{green}   -t                {reset}terse output {magenta}(PID only){reset}
{green}   -0                {reset}use NUL field terminator instead of NL
{green}   +|-w              {reset}enable (+) or suppress (-) warnings {magenta}(default: +){reset}

{cyan}  ── SYSTEM ────────────────────────────────────────{reset}
{green}   +|-r [SECONDS]    {reset}repeat mode {magenta}(default: 1){reset}
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
{green}   -V, --version     {reset}display version information

{cyan}  ── EXAMPLES ──────────────────────────────────────{reset}
{green}   lsofrs -i :8080       {reset}list files using port 8080
{green}   lsofrs -p 1234        {reset}list files opened by PID 1234
{green}   lsofrs -u root        {reset}list files opened by root
{green}   lsofrs --tree -u root {reset}process tree for root's processes
{green}   lsofrs /var/log/syslog{reset}  list processes using this file
{green}   lsofrs -i TCP         {reset}list all TCP connections

{cyan}  ── INFO ──────────────────────────────────────────{reset}
{magenta}  v4.1.0 {reset}// {yellow}(c) lsof contributors{reset}
Anyone can list all files; /dev warnings disabled; kernel ID check enabled.
{magenta}  Every open file tells a story.{reset}"#,
        );
    }

    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        <Self as Parser>::parse_from(args)
    }

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
}
