//! Command-line argument parsing

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "lsofrs",
    version = "6.3.0",
    about = "List System Open Files — modern Rust implementation",
    author = "Jacob Menke",
    long_about = "lsofrs maps the relationship between processes and the files they hold open.\n\
                  Supports regular files, directories, sockets, pipes, devices, and streams.",
)]
pub struct Args {
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

    /// Select internet connections [4|6|protocol[@host[:port]]]
    #[arg(short = 'i')]
    pub inet: Option<String>,

    /// Enable internet selection with no filter (equivalent to -i with no arg)
    #[arg(long = "inet", hide = true)]
    pub inet_flag: bool,

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

    /// FD leak detection [interval,threshold]
    #[arg(long = "leak-detect")]
    pub leak_detect: Option<Option<String>>,

    /// Delta highlighting in repeat mode
    #[arg(long = "delta")]
    pub delta: bool,

    /// Use NUL field terminator instead of NL
    #[arg(short = '0')]
    pub nul_terminator: bool,

    /// Files/directories to search
    pub files: Vec<String>,
}

impl Args {
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
