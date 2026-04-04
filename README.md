```
 ██▓      ██████  ▒█████    █████▒██████  ██████
▓██▒    ▒██    ▒ ▒██▒  ██▒▓██   ▒██   ▒ ▒██    ▒
▒██░    ░ ▓██▄   ▒██░  ██▒▒████ ░▓██▄    ░ ▓██▄
▒██░      ▒   ██▒▒██   ██░░▓█▒  ░▒   ██▒  ▒   ██▒
░██████▒▒██████▒▒░ ████▓▒░░▒█░  ▒██████▒▒██████▒▒
░ ▒░▓  ░▒ ▒▓▒ ▒ ░░ ▒░▒░▒░  ▒ ░ ▒ ▒▓▒ ▒ ░ ▒▓▒ ▒ ░
░ ░ ▒  ░░ ░▒  ░ ░  ░ ▒ ▒░  ░   ░ ░▒  ░ ░ ░▒  ░ ░
  ░ ░  ░ ░  ░    ░ ░ ░ ▒   ░ ░ ░ ░  ░   ░ ░  ░
    ░        ░        ░ ░           ░           ░
```

<p align="center">
  <a href="https://github.com/MenkeTechnologies/lsofrs/actions/workflows/ci.yml"><img src="https://github.com/MenkeTechnologies/lsofrs/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/lsofrs"><img src="https://img.shields.io/crates/v/lsofrs.svg" alt="crates.io"></a>
  <a href="https://crates.io/crates/lsofrs"><img src="https://img.shields.io/crates/d/lsofrs.svg" alt="downloads"></a>
  <a href="https://docs.rs/lsofrs"><img src="https://docs.rs/lsofrs/badge.svg" alt="docs.rs"></a>
  <a href="https://github.com/MenkeTechnologies/lsofrs/blob/main/LICENSE"><img src="https://img.shields.io/crates/l/lsofrs.svg" alt="license"></a>
</p>

> *"Rewritten in Rust. Faster. Safer. The same cyberpunk soul."*

---

## // WHAT IS THIS

**lsofrs** — **L**ist **S**ystem **O**pen **F**iles in **R**u**s**t — v4.7.0

A Rust rewrite of [lsofng](https://github.com/MenkeTechnologies/lsofng), the modernized lsof diagnostic tool. Maps the invisible topology between processes and the files they hold open: regular files, directories, sockets, pipes, devices, kqueues — anything the kernel touches.

If a process has a file descriptor, `lsofrs` sees it.

---

![lsofrs --help](screenshots/help.png)

---

## // JACK IN — BUILD FROM SOURCE

```bash
cargo build --release
sudo cp target/release/lsofrs /usr/local/sbin/
```

Or install directly:

```bash
cargo install --path .
```

Install the man page:

```bash
sudo cp lsofrs.1 /usr/local/share/man/man1/
man lsofrs
```

---

## // USAGE

```bash
lsofrs                           # list all open files
lsofrs -p 1234                   # files for PID 1234
lsofrs -c Chrome                 # files for Chrome processes
lsofrs -u root                   # files for root user
lsofrs -i                        # network connections only
lsofrs -i :8080                  # who's listening on port 8080
lsofrs /path/to/file             # who has this file open
lsofrs -t -c nginx               # just PIDs (for scripting)
```

### Network Filters

```bash
lsofrs -i                        # all network files
lsofrs -i 4                      # IPv4 only
lsofrs -i 6                      # IPv6 only
lsofrs -i TCP                    # TCP only
lsofrs -i :443                   # port 443
lsofrs -i TCP:443                # TCP port 443
```

### Output Formats

```bash
lsofrs                           # columnar (default, cyberpunk-themed on TTY)
lsofrs --json                    # JSON array output
lsofrs -J                        # JSON (short form)
lsofrs -F pcfn                   # field output (p=pid, c=cmd, f=fd, n=name)
lsofrs -t                        # terse (PIDs only)
```

### Selection Combinators

```bash
lsofrs -p 1234,5678              # multiple PIDs
lsofrs -u root,wizard            # multiple users
lsofrs -p ^1234                  # exclude PID 1234
lsofrs -u ^root                  # exclude root
lsofrs -a -p 1234 -i             # AND: PID 1234 AND network
lsofrs -d 0-10                   # FD range 0-10
lsofrs -c '/nginx|apache/'       # regex command match
```

---

## // ADVANCED MODES

### Unified TUI (`--tui`)

Full-screen tabbed dashboard with all modes in one interface. 7 clickable tabs, 31 color themes, mouse support, hover/right-click tooltips, theme chooser + editor, config persistence.

```bash
lsofrs --tui                     # launch TUI (restores last tab/theme)
lsofrs --tui --theme matrix      # launch with Matrix theme
sudo lsofrs --tui                # full visibility (all processes)
```

**Tabs**: TOP | SUMMARY | PORTS | TREE | NET-MAP | PIPES | STALE — click or press Tab/1-7 to switch.

**Bottom bar**: `▶▶▶ LSOFRS ◀◀◀ │ procs:N │ files:N │ tcp:N udp:N unix:N pipe:N │ rate:Ns │ theme:Name │ paused:no │ h=help │ HH:MM:SS` — each `│` segment is a hover zone with verbose tooltips.

**Mouse**: click tabs, scroll rows, right-click for detailed tooltips (PID, FD breakdown, kill hints, copy hints), hover 1s for auto-tooltips.

**Theme chooser** (`c`): browse 31 themes with color swatches, live preview as you scroll, Enter to apply + save.

**Theme editor** (`C`): create custom 6-color palettes, adjust values 0-255, name and save to `~/.lsofrs.conf`.

### Top-N Dashboard (`--top`)

Live auto-refreshing dashboard of the top processes sorted by FD count. Like `iotop` for file descriptors — shows FD type distribution bars, delta tracking, and per-process breakdowns.

```bash
lsofrs --top                     # top 20 processes by FD count
lsofrs --top 10                  # top 10 only
lsofrs --top -r 5                # refresh every 5 seconds
lsofrs --top -u root             # top FD consumers for root
```

**Top-specific keys**: `s` cycle sort, `r` reverse, `+`/`-` show more/fewer, `b` toggle bar, `d` toggle delta. See [Interactive Controls](#-interactive-controls) for common keys.

### File Watch (`--watch FILE`)

Monitor who opens and closes a specific file over time. Prints timestamped `+OPEN`/`-CLOSE` events as they happen — like a lightweight `inotifywait` / `fs_usage` for a single path.

```bash
lsofrs --watch /var/log/syslog          # watch syslog
lsofrs --watch /tmp/myapp.sock          # watch a socket file
lsofrs --watch /dev/null -r 2           # poll every 2 seconds
```

Each event shows timestamp, open/close tag, PID, user, FD, and command. When piped, prints a single snapshot and exits.

### Stale FDs (`--stale`)

Find file descriptors pointing to deleted files — a common source of disk space leaks, zombie file handles, and security issues.

```bash
lsofrs --stale                   # find all deleted-file FDs
lsofrs --stale -u www-data       # deleted files held by www-data
lsofrs --stale --json            # JSON output
```

### Listening Ports (`--ports`)

Quick "what's listening where" summary — like `ss -tlnp` but cross-platform (macOS + Linux).

```bash
lsofrs --ports                   # show all listening TCP/UDP ports
lsofrs --ports --json            # JSON output
lsofrs --ports -u root           # ports opened by root only
```

### Pipe Chain (`--pipe-chain`)

Trace pipe and unix socket pairs between processes — visualize the IPC topology.

```bash
lsofrs --pipe-chain              # show all inter-process pipe/socket connections
lsofrs --pipe-chain --json       # JSON output
lsofrs --pipe-chain -c Chrome    # pipes within Chrome process tree
```

### Network Map (`--net-map`)

Group network connections by remote host — see which servers your system talks to and how many connections each has.

```bash
lsofrs --net-map                 # connections grouped by remote host
lsofrs --net-map --json          # JSON output
lsofrs --net-map -u wizard       # only wizard's connections
```

### CSV Export (`--csv`)

Pure CSV output for pipelines, spreadsheets, and data analysis. RFC 4180-compliant quoting.

```bash
lsofrs --csv                     # full CSV dump
lsofrs --csv -i TCP              # CSV of TCP connections only
lsofrs --csv -p 1234 > out.csv   # export PID 1234 to file
```

### Process Tree (`--tree`)

Hierarchical process tree view with FD counts, type breakdowns, and network connection counts. Like `pstree` meets `lsof`.

```bash
lsofrs --tree                    # full process tree with FD stats
lsofrs --tree -u root            # tree for root's processes
lsofrs --tree -c Chrome          # tree for Chrome and helpers
lsofrs --tree --json             # JSON tree with nested children
```

Each node shows: PID, user, FD count, command name, type breakdown (`[REG:12 IPv4:3 PIPE:2]`), and network connection count. Notable files (sockets, pipes) are listed inline under each process.

### Live Monitor (`--monitor` / `-W`)

Full-screen alternate-buffer display like `top(1)`. Auto-refreshes with interactive controls.

```bash
lsofrs --monitor                 # full-screen monitor
lsofrs -W -r 2                   # refresh every 2 seconds
lsofrs -W -c Chrome              # monitor Chrome only
```

**Controls**: `s`=sort, `r`=reverse, `f`=filter, `p`=pause, `?`=help, `q`=quit

### Follow Mode (`--follow PID`)

Watch a single process's FDs in real-time. New opens highlighted `+NEW` in green, closes `-DEL` in red.

```bash
lsofrs --follow 1234             # watch PID 1234
lsofrs --follow 1234 -r 2        # 2-second refresh
```

### FD Leak Detection (`--leak-detect`)

Monitors per-process FD counts over time. Flags processes with monotonically increasing FD counts.

```bash
lsofrs --leak-detect             # default: 5s interval, 3 increase threshold
lsofrs --leak-detect=10,5        # 10s interval, flag after 5 consecutive increases
lsofrs --leak-detect -u wizard   # monitor only wizard's processes
```

### Summary / Statistics (`--summary`)

Aggregate FD breakdown with bar charts, top processes, per-user totals. Add `-r N` for live auto-refreshing TUI mode.

```bash
lsofrs --summary                 # text report (single-shot)
lsofrs --summary -r 2            # live TUI, refresh every 2s
lsofrs --summary --json          # JSON report
lsofrs --summary -i              # network-only summary
```

### Delta Highlighting (`--delta`)

Color-code changes between repeat iterations. New FDs in green, gone in red.

```bash
lsofrs --delta -r 2              # repeat every 2s with change highlighting
lsofrs --delta -r 1 -c myapp     # watch myapp changes
```

---

## // CYBERPUNK THEME

When output goes to a TTY, lsofrs activates cyberpunk-themed column headers and ANSI coloring:

| Piped | TTY |
|-------|-----|
| COMMAND | PROCESS |
| PID | PRC |
| USER | H4XOR |
| TYPE | CL4SS |
| DEVICE | DEV/ICE |
| SIZE/OFF | BYT3/0FF |
| NODE | N0DE |
| NAME | T4RGET |

When piped or redirected, plain headers and no colors are used — safe for scripts.

---

## // INTERACTIVE CONTROLS

All live TUI modes (`--tui`, `--top`, `--summary -r`) share common keybindings.

**Common keys**:

| Key | Action |
|-----|--------|
| `1`-`9` | Set refresh interval (seconds) |
| `<`/`>` | Fine-adjust refresh interval (±1s) |
| `p` | Pause/resume data collection |
| `?`/`h` | Toggle help overlay |
| `c` | Open theme chooser (31 themes with swatches) |
| `C` | Open theme editor (custom 6-color palettes) |
| `T` | Toggle hover tooltips (right-click still works) |
| `x` | Toggle border |
| `t` | Toggle compact/expanded view |
| `o` | Freeze/unfreeze sort order |
| `/` | Filter popup (regex search) |
| `0` | Clear filter |
| `j`/`k`/`↑`/`↓` | Navigate rows |
| `F` | Pin/unpin selected row |
| `y` | Copy selected row to clipboard |
| `e` | Export current tab to file |
| `q`/`Esc`/`Ctrl-C` | Quit |

**`--tui` additional keys**:

| Key | Action |
|-----|--------|
| `Tab`/`→` | Next tab |
| `BackTab`/`←` | Previous tab |
| `1`-`7` | Jump to tab by number |
| Click tab | Switch to clicked tab |
| Right-click row | Verbose tooltip (PID, FDs, kill hints) |
| Hover 1s | Auto-tooltip (disappears on mouse move) |

**`--top` additional keys**:

| Key | Action |
|-----|--------|
| `s` | Cycle sort column (FDs→PID→USER→REG→SOCK→PIPE→OTHER→DELTA→CMD) |
| `r` | Reverse sort order |
| `+`/`-` | Show more/fewer processes (±5) |
| `b` | Toggle distribution bar column |
| `d` | Toggle delta column |

Non-TTY (piped) output always does a single-shot print and exits — no TUI, no key handling.

---

## // ARCHITECTURE

```
src/
├── main.rs      # CLI entry point, dispatch, repeat/leak-detect loops
├── cli.rs       # clap argument definitions + custom help display
├── types.rs     # Core data structures (Process, OpenFile, SocketInfo, etc.)
├── darwin.rs    # macOS libproc FFI — process/FD enumeration (rayon parallel)
├── linux.rs     # Linux /proc filesystem — process/FD enumeration (rayon parallel)
├── freebsd.rs   # FreeBSD sysctl + procfs — process/FD enumeration
├── filter.rs    # Selection & filtering (PID, user, command, FD, network)
├── output.rs    # Columnar & field output formatting, ANSI theming
├── json.rs      # JSON serialization via serde
├── monitor.rs   # Live full-screen mode (crossterm alternate screen)
├── follow.rs    # Single-process FD tracking with status transitions
├── leak.rs      # Circular-buffer leak detector
├── delta.rs     # Iteration-diff engine for change highlighting
├── summary.rs   # Aggregate statistics with bar charts
├── tree.rs      # Process tree view with FD inheritance
├── tui_app.rs   # Shared TUI framework (TuiMode trait, ratatui)
├── tui_tabs.rs  # Unified tabbed TUI (--tui) with 7 tabs, mouse, tooltips
├── theme.rs     # 31 color themes + custom theme support
├── config.rs    # TOML config persistence (~/.lsofrs.conf)
├── top.rs       # Live top-N FD dashboard (TuiMode)
├── watch.rs     # File watch — monitor opens/closes over time
├── stale.rs     # Stale FD finder — deleted files still held open
├── ports.rs     # Listening ports summary (like ss -tlnp)
├── pipe_chain.rs # Pipe/socket IPC topology between processes
├── csv_out.rs   # CSV export (RFC 4180)
└── net_map.rs   # Network connections grouped by remote host
lsofrs.1         # Man page (roff)
completions/
└── _lsofrs      # Zsh completion function
```

### Shell Completions

Zsh completions are provided in `completions/_lsofrs`. To install:

```bash
cp completions/_lsofrs /usr/local/share/zsh/site-functions/
# or symlink into your fpath
ln -sf "$PWD/completions/_lsofrs" /usr/local/share/zsh/site-functions/_lsofrs
# then reload
autoload -Uz compinit && compinit
```

### Platform Support

Supports **macOS/Darwin** (libproc FFI), **Linux** (`/proc` filesystem), and **FreeBSD** (sysctl + procfs). Platform modules are gated behind `#[cfg(target_os)]`. Process gathering is parallelized with rayon.

### Development and CI

The repo includes `rust-toolchain.toml` (stable + `rustfmt` / `clippy`) so local builds and GitHub Actions agree on the compiler and edition. Run `cargo test` for unit tests (`src/**`, including broad CLI flag coverage in `cli.rs` (e.g. `-R` for parent PID column) plus module tests such as `filter.rs` (network, FD, AND/OR process matching, user/command filters, and directory filters including `--+d` / `--+D` aliases; `parse_inet_filter` covers forms such as `TCP@host:port` and `UDP@host:port`, IPv6 bracket hosts (`TCP[::1]:port`, `UDP@[2001:db8::1]:port`), trimmed `-i` specs, invalid `host:port` suffixes (host-only fallback), `TCP@` host without port, `matches_file` network port ranges, and `Filter::from_args` wiring for those; `parse_fd_filter` covers numeric FDs (including `0`), ranges, degenerate ranges such as `N-N`, multi-dash tokens that are not valid ranges, reversed ranges, negative singleton FDs, and `from_args` for `-d` including comma-separated tokens (e.g. `0,5,cwd`, `mem,txt`) and multi-dash tokens; `matches_file` includes `-a` (AND) with network plus path filters, combined `-U` / `-i` with file operands, multiple command regexes, `Filter::from_args` for `4UDP:port`, three `/regex/` command terms, comma-separated command name literals, and mixed literals with `/regex/` terms; trimmed `-g` / `-u` comma tokens; `Filter::from_args` for `-i :port` port-only inet specs, `UDP@host:port` and `TCP@host:port` IPv4 forms (including RFC 5737 `192.0.2.0/24` TEST-NET-1 addresses in `from_args` for both `UDP@…` and `TCP@…`), `TCP@` / `UDP@` IPv6 documentation-prefix bracket hosts with port (e.g. `TCP@[2001:db8::1]:443`), `-i TCP@` / `-i UDP@` dotted-IPv4 host-only (no port), `-i TCP[::1]` / `-i UDP[::1]` bracket IPv6 host without port, `-i TCP[::1]:port` / `-i UDP[::1]:port` bracket host with port, `4TCP:port` / `4UDP:port` with IPv4 address-family prefix, bare `4TCP` / `4UDP` / `6UDP` with address-family prefix and protocol in `from_args`, and `6TCP:port` / `6UDP:port` with IPv6 address-family prefix, and `Filter::from_args` for `TCP:1`, `TCP:2`, `TCP:3`, `TCP:53`, `TCP:22`, `UDP:1`, `UDP:2`, `UDP:3`, `UDP:53`, `UDP:67`, `UDP:80`, `UDP:443`, `UDP:65535`, `TCP:80`, `TCP:65535`, `4TCP:1`, `4TCP:2`, `4TCP:3`, `4TCP:53`, `4TCP:80`, `4TCP:67`, `4TCP:123`, `4TCP:65535`, `4TCP:443`, `4UDP:443`, `4UDP:80`, `4UDP:67`, `4UDP:1`, `4UDP:2`, `4UDP:3`, `4UDP:123`, `4UDP:65535`, `6TCP:1`, `6TCP:2`, `6TCP:3`, `6TCP:53`, `6TCP:22`, `6TCP:67`, `6TCP:123`, `6TCP:80`, `6TCP:65535`, `6UDP:1`, `6UDP:2`, `6UDP:3`, `6UDP:67`, `6UDP:80`, `6UDP:123`, `6UDP:65535`, and `6UDP:443`), `types.rs` (including `FileType::as_str` for less common variants and `Display` matching `as_str` for variants such as `REG`, `DIR`, and `Sock`, `TcpState` string forms and `Display` for unknown numeric states, `SocketInfo::default`, `OpenFile::full_name` with an empty base path plus `name_append`, non-default `OpenFile.lock` when not space, and `InetAddr` with IPv4 or IPv6 addresses), `delta.rs` (delta keys include the FD access suffix from `FdName::with_access`, so the same numeric FD and path with different access modes are distinct; duplicate identical keys in one `record` replace the map entry; second and third iterations with an identical snapshot yield zero new and zero gone; first iteration with a process that has no open files yields zero new and zero gone; when a process drops all FDs and later reopens the same FD path, gone-then-new counting applies; when the same numeric FD number changes path between iterations, the previous path counts as gone and the new path as new; when two PIDs are tracked and one disappears from a later snapshot, the missing PID's keys count as gone; when three PIDs are tracked and one disappears from a later snapshot, exactly one PID's keys count as gone; when the current snapshot records no processes but the previous snapshot had keys, all previous keys count as gone), `output.rs` (including `Theme` ANSI helpers empty when not a TTY), `net_map.rs` (including IPv6 `print_net_map` smoke tests), `pipe_chain.rs` (including `pipe_identifier` for Unix paths without `socket:[` / `0x` patterns), `config.rs` (including TOML roundtrip when only `theme` is set), `json.rs` (binary-only unit tests; empty socket `protocol` is skipped in JSON), `csv_out.rs` (including RFC 4180 quoting with comma plus non-ASCII/emoji payload, and ASCII fields without special characters left unquoted, embedded ASCII double quotes doubled per RFC 4180, lone carriage-return and tab without commas left unquoted, U+001C (file separator) without commas left unquoted, zero-width joiner sequences without commas left unquoted, vertical tab and form-feed in a field without commas left unquoted, Unicode line separator (U+2028) including a U+2028-only field, paragraph separator (U+2029) including a U+2029-only field, narrow no-break space (U+202F) including a U+202F-only field, and word joiner (U+2060) including a U+2060-only field, and object replacement (U+FFFC) including a U+FFFC-only field, and soft hyphen (U+00AD) including a soft-hyphen-only field, UTF-8 BOM (U+FEFF), and fullwidth comma (U+FF0C) left unquoted by the current escaper, a NUL byte in a field left unquoted by the current escaper, and a newline-only field quoted per RFC 4180, and a lone CRLF pair without commas quoted per RFC 4180), `stale.rs` (binary-only `is_deleted` tests, including append without a `(deleted)` marker), `summary.rs` (binary-only `compute_stats` aggregation tests), `theme.rs` (binary-only `ThemeName::from_str_loose`, including kebab-case names such as `plasma-core` / `night-city`), `ports.rs` (binary-only `is_listening`, including UDP protocol case-insensitivity), `tree.rs` (binary-only `print_tree_json` multi-root and empty `print_tree` / `print_tree_json` smoke tests), `watch.rs` (binary-only `file_matches` path-prefix rules and matching the original file operand when canonical paths differ), and `leak.rs` (binary-only `LeakDetector::report` smoke tests)) and integration tests (several crates under `tests/`, for example `integration.rs` (help and `-V` / `--version`), `filters_and_paths.rs`, `cli_combinations.rs`, `json_and_csv_contracts.rs` (including JSON array contracts for `TCP@…`, `UDP@…`, bare `UDP`, `4TCP:port` / `4UDP:port`, bare `4UDP` stderr-empty, `6UDP:port`, `TCP@` host without port, `--pipe-chain` with `--csv` on argv (pipe-chain wins) stderr-empty, `TCP[::1]:port` / `UDP[::1]:port` bracket IPv6 host with port, `TCP[::1]` / `UDP[::1]` host-only JSON (and CSV for TCP and UDP) stderr-empty, bare `4TCP` / `6TCP` stderr-empty, `4TCP:port` / `4UDP:port` JSON, `6TCP:443` JSON, `4UDP:53` JSON, `4TCP:22` / `4UDP:53` / `6TCP:443` CSV stderr-empty, bare `4UDP` CSV stderr-empty, `6TCP` CSV stderr-empty, `TCP@192.0.2.1:443` CSV stderr-empty, `6UDP:53` CSV stderr-empty, `TCP@` IPv4 host:port CSV, `TCP@` / `UDP@` IPv4 host-only JSON and CSV stderr-empty, `UDP@192.0.2.1:53` JSON and CSV stderr-empty, `TCP@192.0.2.1:443` JSON stderr-empty, JSON/CSV `TCP:1`, `TCP:2`, `TCP:3`, `TCP:53`, `TCP:22`, `UDP:1`, `UDP:2`, `UDP:3`, `UDP:53`, `UDP:67`, `UDP:80`, `UDP:443`, `UDP:65535`, `TCP:80`, `TCP:65535`, `4TCP:1`, `4TCP:2`, `4TCP:3`, `4TCP:53`, `4TCP:80`, `4TCP:67`, `4TCP:123`, `4TCP:65535`, `4TCP:443`, `4UDP:443`, `4UDP:80`, `4UDP:67`, `4UDP:1`, `4UDP:2`, `4UDP:3`, `4UDP:123`, `4UDP:65535`, `6TCP:1`, `6TCP:2`, `6TCP:3`, `6TCP:53`, `6TCP:22`, `6TCP:67`, `6TCP:123`, `6TCP:80`, `6TCP:65535`, `6UDP:1`, `6UDP:2`, `6UDP:3`, `6UDP:67`, `6UDP:80`, `6UDP:123`, `6UDP:65535`, and `6UDP:443` stderr-empty, bare `4TCP` CSV stderr-empty, CSV `--csv -i 4` / `--csv -i 6` stderr-empty, bare `6UDP` CSV stderr-empty, `UDP@[2001:db8::1]:5353` JSON and CSV stderr-empty, `TCP@[2001:db8::1]:443` JSON and CSV stderr-empty, `UDP[::1]:53` JSON stderr-empty, CSV `TCP[::1]:443`, CSV `UDP[::1]:port`, CSV `-i :443` port-only stderr-empty, `-d` exclude with `-p`, degenerate FD range with `-p`, `-p` with `^pid` combined with self, `-R` with `-p`, `-g`, `--pgid-show` with `-R` and `-p`, `-i 4` stderr-empty, CSV with `-i TCP`, `--pipe-chain` JSON, `--stats --json` wrapper, `/dev/null` file operand, `--delta` with `-J`, `6TCP:port`, `--csv --delta`, `--stale --json` with `-p`, `--color never` with `-i TCP`, and `-N` / `-U` with JSON, `6UDP:port`, `-w` with `-J`, `-d cwd` with `-p`, `-n`/`-P` with `-J`, `--pipe-chain` with `-p`, `--csv -0` NUL-terminated rows, `-a` with `-i TCP` and `-p`, bare `-i 6`, and `-c` literal with `-p`, `--ports --json` / `--net-map --json` with `-p`, `--csv -i UDP` / `6TCP`, `-d txt` / `mem` / `err` / `rtd` with `-p`, `-d ^0-10` exclude range with `-p`, `-J --dir /tmp`, `-J --dir-recurse /tmp`, `--csv --dir /tmp`, `-J -i @127.0.0.1`, `-i 6UDP`, `-a` with `-i UDP` and `-p`, `-J -w` alone, `-J --theme classic` / `matrix`, `-J --stale --color never`, `-F` with `--color never`), `json_shape.rs`, `json_wrappers.rs`, `dispatch_contracts.rs` (which single-shot output mode wins when several are set, including `csv` vs `tree` / `summary`, `ports` vs `pipe-chain` / `tree`, `stale` / `ports` / `pipe-chain` / `net-map` vs `summary` or `tree`, `stale` vs `csv`, and `stale` / `ports` / `pipe-chain` / `net-map` chains), `color_output.rs`). The `lsofrs` library (`src/lib.rs`) runs unit tests only for modules it exports; the binary target runs unit tests for every `mod` under `src/main.rs`, including modules not linked into the library (for example `stale`, `leak`, `summary`, `ports`, `tree`, `watch`, `json`). Any module that is both in `lib.rs` and `main.rs` runs its unit tests twice; integration tests in `tests/` run once each. CI runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo doc` with warnings denied, and `cargo test` on Linux and macOS runners.

On macOS and other non-Linux hosts, `cargo clippy` does not type-check `#[cfg(target_os = "linux")]` code. To catch Linux-only issues before push, install the Linux target and run `cargo clippy --target x86_64-unknown-linux-gnu --all-targets -- -D warnings` (same flags as CI). Integration tests in `json_and_csv_contracts` and `cli_combinations` also assert empty `stderr` on successful runs for terse (`-t`), field (`-F`), `--summary` / `--stats` with `--color never`, columnar `--color always` with `-p`, bare long `--json` with `-i`, columnar `--pgid-show` with `-p`, `--csv --delta`, NFS-only (`-N`) and UNIX-socket (`-U`) filters with JSON (including `-N` and `-U` together), `-J` with `-n`/`-P`, `-c` command-name literals with `-p`, and several single-shot modes (`--ports`, `--net-map`, `--pipe-chain`, `--stale`, `--tree` with `-p`, `--tree` / `--net-map` with `--color never`, `--ports` / `--pipe-chain` with `--color never`, `--ports --json` / `--net-map --json` with `--color never`, `--ports` / `--net-map` with `--csv` and `--color never` (ports wins over CSV; CSV wins over net-map), `--csv` with `--net-map` and `--color never` when `--csv` is first on argv (CSV wins over net-map), `--csv` with `--net-map` and `--tree` and `--color never` when `--csv` is first on argv (CSV wins over net-map and tree), `--csv` with `--pipe-chain` and `--color never` when `--csv` is first on argv (pipe-chain wins over CSV), `--csv` with `--pipe-chain` and `--tree` and `--color never` when `--csv` is first on argv (pipe-chain wins over csv and tree), `--csv` with `--ports` and `--color never` when `--csv` is first on argv (ports wins over CSV), `--csv` with `--ports` and `--tree` and `--color never` when `--csv` is first on argv (ports wins over csv and tree), `--ports` with `--summary` and `--color never` (ports wins), `--summary` with `--ports` and `--color never` when `--summary` is first on argv (ports wins), `--ports` with `--net-map` and `--color never` (ports wins), `--net-map` with `--ports` and `--color never` when `--net-map` is first on argv (ports wins), `--tree` with `--net-map` and `--color never` (net-map wins), `--stale` with `--ports` and `--color never` (stale wins), `--ports` with `--stale` and `--color never` when `--ports` is first on argv (stale wins), `--stale` with `--pipe-chain` and `--color never` (stale wins), `--net-map` with `--summary` and `--color never` (net-map wins), `--summary` with `--net-map` and `--color never` when `--summary` is first on argv (net-map wins), `--pipe-chain` with `--tree` and `--color never` (pipe-chain wins), `--ports` with `--pipe-chain` and `--color never` (ports wins), `--tree` with `--stale` and `--color never` (stale wins), `--csv` with `--tree` and `--stale` and `--color never` when `--csv` is first on argv (stale wins over csv and tree), `--tree` with `--summary` and `--color never` (tree wins), `--net-map` with `--pipe-chain` and `--color never` (pipe-chain wins), `--pipe-chain --json` / `--tree --json` with `--color never` (including `-p` self-PID for tree), `--tree` with `--csv` and `--color never` (CSV wins), `--csv` with `--tree` and `--color never` when `--csv` is first on argv (CSV wins), `--stale` with `--net-map` and `--color never` (stale wins), `--stale` with `--csv` and `--color never` (stale wins), `--csv` with `--stale` and `--color never` when `--csv` is first on argv (stale wins), `--summary` with `--csv` and `--color never` (CSV wins), `--csv` with `--summary` and `--color never` when `--csv` is first on argv (CSV wins), `--pipe-chain` with `--net-map` and `--color never` (pipe-chain wins), `--stale` with `--color never`, `--stale` with `--summary` and `--color never` (stale wins), `--summary` with `--stale` and `--color never` when `--summary` is first on argv (stale wins), `--pipe-chain` with `--summary` and `--color never` (pipe-chain wins), `--summary` with `--pipe-chain` and `--color never` when `--summary` is first on argv (pipe-chain wins), `--ports` with `--tree` and `--color never` (ports wins), `--tree` with `--ports` and `--color never` (ports wins), `--summary` with `--json` and `--color never`, `--stats` with `--json` and `--color never`, `--summary` with `--color always`) alongside the JSON/CSV cases; `cli_combinations` also smoke-tests excluding two comma-separated `^user` terms.

To see how many test cases `cargo test` executes (library + binary harnesses + each file under `tests/`), run `cargo test` and read the `test result` lines, or use `cargo test 2>&1 | grep 'test result:'`. The number of distinct `#[test]` functions in the tree is lower because modules linked from both `src/lib.rs` and the binary run their unit tests twice.

Columnar header lines include padding derived from live FD data, so integration tests that check `--color` compare title substrings (for example `COMMAND` vs `PROCESS`), not full header string equality across two process spawns.

Dispatch order matters when multiple output modes are set: for example `--stale` runs before `--ports` and `--net-map` (and before `--pipe-chain`); `--ports` runs before `--pipe-chain` and `--net-map`; `--pipe-chain` runs before `--net-map`; `--net-map` runs before `--tree` and `--summary`; `--csv` runs before `--net-map`, `--tree`, and `--summary` (and before default `--json` output); the winning mode is determined by that fixed order in `main`, not by the order of flags on the command line (integration `dispatch_contracts` includes cases such as `--csv` before `--net-map`, `--summary` before `--tree`, `--ports` before `--stale`, `--tree` before `--ports`, `--pipe-chain` / `--net-map` before `--stale`, `--csv` before `--pipe-chain`, and argv-order mirrors where the lower-priority mode appears first — for example `--summary` before `--net-map` / `--ports` / `--pipe-chain`, `--tree` before `--net-map` / `--csv`, and `--csv` before `--stale`); `--summary` / `--stats` with `--json` use the summary JSON wrapper, not the default process array; `--tree -J` emits tree nodes (`children`, etc.), not the default lsof JSON rows with `files`; `-J` / `--json` can be placed before or after mode flags on the command line — dispatch in `main` picks the output serializer, not argv order (integration `json_wrappers` tests cover `--json` and `-J` before `--net-map`, `--ports`, `--stale`, `--tree`, `--pipe-chain`, and `--summary` / `--stats`); `--json` runs before `-t` terse, which runs before `-F` field output (so `-F` is last among the standard output modes). Integration `integration.rs` also asserts argv order among `-J`, `-t`, `-F`, and `--csv` (for example `-t` before `-J`, `-F` before `-J`, `-F` before `-t`, `-F` before `--csv`), and the same fixed dispatch when `-t` is placed before `--csv`, `--json`, `--stale`, `--ports`, `--pipe-chain`, `--net-map`, `--summary`, or `--tree`. It also checks that `--csv` wins over default JSON when both `-J` / `--json` and `--csv` are set, regardless of whether the JSON flag appears before `--csv` on the command line. `dispatch_contracts` includes the same CSV-vs-JSON ordering without a PID filter (full scan), and asserts that several text modes (`--net-map`, `--ports`, `--stale`, `--summary`, `--tree` with `-p`, default columnar, `--csv` with `-p`, `-t` with `-p`, `-F` with `-p`) do not emit output whose first line looks like a JSON array. `integration.rs` also covers `--json` / `-J` with `-F` field output, including when `-F` appears before `--json`. Integration tests cover combinations such as `-J` with `-F`, `--csv`/`--stale`/`--ports`/`--pipe-chain`/`--net-map`/`--tree`/`--summary` with `-F`, `--csv` with `-J`, `-J` with `-t`, `--csv` with `-t`, `--stale`/`--ports`/`--pipe-chain` versus `--csv`, pairwise ordering among `--stale`, `--ports`, `--pipe-chain`, and `--net-map`, `--stale`/`--ports`/`--pipe-chain` versus `--tree` or `--summary`, `--csv` versus `--net-map`, `--net-map` versus `--tree` and versus `--summary`, `--tree` versus `--summary`, `--summary --json`, `-t` with `-F`, `--stale` with `-t`, `--net-map`/`--summary`/`--tree`/`--ports`/`--pipe-chain` with `-t` (terse loses to those modes in single-shot dispatch), `--tree`/`--summary`/`--net-map`/`--ports`/`--pipe-chain` with `-J` and `-t`, and `--csv` with `--summary` or `--tree` so the winning mode stays stable.

### Key Design Decisions

- **Zero-copy FFI**: Raw `repr(C)` structs matched to Darwin kernel headers. No intermediate parsing.
- **Parallel gathering**: Per-PID FD enumeration parallelized with rayon.
- **Streaming output**: Processes are gathered, filtered, and printed in a single pass.
- **Shared TUI framework**: `TuiMode` trait — all live modes get common keybindings, alternate screen, and atomic frame rendering.
- **serde for JSON**: Derive-based serialization, no hand-rolled escaping.
- **clap for CLI**: Derive-based argument parsing with full help generation.

---

## // PERFORMANCE

Benchmarked on macOS with `hyperfine` (10 runs, 3 warmup, ~900 processes / ~8000 open files, rayon parallel gathering):

### All Open Files (default)

| Tool | Mean | Min–Max | Speedup |
|------|------|---------|---------|
| **lsofrs** (Rust) | **58 ms** | 40–111 ms | — |
| lsof 4.91 (C) | 5,555 ms | 5,194–8,343 ms | **95x** slower |
| lsofng (C) | 13,202 ms | 11,299–16,336 ms | **226x** slower |

### Network Connections (`-i TCP`)

| Tool | Mean | Min–Max | Speedup |
|------|------|---------|---------|
| **lsofrs** | **9 ms** | 9–10 ms | — |
| lsof 4.91 | 5,117 ms | 5,098–5,229 ms | **555x** slower |
| lsofng | 10,520 ms | 10,097–13,792 ms | **1,141x** slower |

### Terse Output (`-t`, PIDs only)

| Tool | Mean | Min–Max | Speedup |
|------|------|---------|---------|
| **lsofrs** | **14 ms** | 12–16 ms | — |
| lsofng | 149 ms | 133–216 ms | **10x** slower |
| lsof 4.91 | 273 ms | 249–298 ms | **19x** slower |

### Structured Output (`-J` JSON / `-F` field)

| Tool | Mean | Min–Max | Speedup |
|------|------|---------|---------|
| **lsofrs** `-J` | **41 ms** | 40–42 ms | — |
| lsofng `-J` | 164 ms | 142–336 ms | **4x** slower |
| lsof `-F pcfn` | 5,552 ms | 5,171–7,391 ms | **134x** slower |

The rayon-parallelized per-PID FD enumeration combined with zero-copy FFI structs gives lsofrs a **95–1,141x** advantage over traditional lsof implementations.

---

## // LICENSE

MIT License — Jacob Menke

---

## // CREDITS

Rust rewrite of [lsofng](https://github.com/MenkeTechnologies/lsofng) by Jacob Menke, which itself is a modernized fork of the original [lsof](https://github.com/lsof-org/lsof) by Vic Abell.
