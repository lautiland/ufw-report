# Current State of ufw-report

> **Version:** 0.1.0 | **Updated:** 2026-11-16

## What it is

`ufw-report` is a Rust CLI that reads UFW logs (`/var/log/ufw.log`), analyzes blocked traffic within a date range, and presents an interactive terminal report (TUI). It also exports the parsed entries to CSV or JSON.

## Stack

Rust | ratatui + crossterm | clap | chrono | serde | regex | tracing

## Current features

### Parser and data

- UFW log parsing for IPv4 and IPv6 (syslog and ISO timestamps)
- Protocol normalization from numeric values to names using a hardcoded table
- Traffic direction detection (`IN=` / `OUT=`)
- Configurable date range (default: last 7 days)
- Zero-filled days with no data
- Range-safe JSON parse cache
- Unique source IP counters, split into IPv4 and IPv6

### CLI

- `--log-file <PATH>` — path to the log (default: `/var/log/ufw.log`)
- `--from <DATE>` / `--to <DATE>` — date range (`YYYY-MM-DD`)
- `--csv` — export CSV and exit
- `-o, --output <PATH>` — export CSV or JSON to a file
- `-o -` — export to stdout (JSON unless `--csv` is also set)
- `--no-cache` — disable reading and writing the parse cache
- `-v, --verbose` — detailed logging

### Output format precedence

- No `--csv` and no `-o`: TUI.
- `--csv`: CSV, to stdout or to the `-o` path.
- `--csv -o report.json`: error, because the flag and the extension contradict each other.
- `-o report.csv`: CSV.
- `-o report.json` or a path without an extension: JSON.

### TUI (terminal interface)

- **Overview** — summary cards (Total, Incoming, Outgoing, Unique IPs with v4/v6 split), protocol distribution with scrolling, Top IPs, and Top Ports
- **Daily** — bar chart per day; `←`/`→` selects a day, `Enter` opens it in Hourly
- **Hourly** — bars for the selected day; `←`/`→` changes the day, `↑`/`↓` changes the hour, `PgUp`/`PgDn` scrolls the log table
- **Raw** — paginated table with every record (Date, Hour, Src IP, Dst IP, Port, Protocol, Direction)

## TUI controls

| Key | Action |
|-----|--------|
| `1`-`4` | Switch tabs (Overview, Daily, Hourly, Raw) |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `←` `→` | Previous / next day in Daily and Hourly |
| `↑` `↓` | Scroll protocols (Overview), previous / next hour (Hourly), scroll rows (Raw) |
| `Shift+↑` `Shift+↓` | Fast scroll in Overview and Raw |
| `PgUp` `PgDn` | Page scroll in Overview, Raw, and the Hourly log table |
| `Shift+PgUp` `Shift+PgDn` | Fast page scroll |
| `Enter` | In Daily: open the selected day in Hourly |
| `q` / `Esc` | Quit |

## Cache

- Default location: `$XDG_CACHE_HOME/ufw-report/<hash>.json`, falling back to `~/.cache/ufw-report/` and then the system temporary directory.
- The cache stores all parsed entries, not only the entries from the requested range, so later queries with a wider range remain correct.
- Invalidation checks the cache version, parser version, log size, and log modification time.
- Writes are atomic (temporary file plus rename).
- `--no-cache` disables the cache completely.
- Write failures are reported as warnings and do not stop the analysis.

## Quality

- 91 tests covering parser, date ranges, cache invalidation, aggregation, output formats, CLI behavior, and TUI navigation
- GitHub Actions CI with `fmt`, `clippy` pedantic, `test`, and `build`, running on every branch and on pull requests to `main`
- Panic hook that restores the terminal on crash and reinstalls the original hook afterwards

## Security

- Read-only: it never modifies firewall rules
- No network dependencies and no HTTP servers
- Cache files are written under the user's cache directory

## Dependencies

- clap (4): CLI parsing
- ratatui (0.30): TUI rendering
- crossterm (0.29): terminal backend
- serde (1): serialization/deserialization
- serde_json (1): JSON serialization/deserialization
- chrono (0.4): date/time parsing
- regex (1): regular expressions
- anyhow (1): error handling
- thiserror (2): error definitions
- tracing (0.1): logging
- tracing-subscriber (0.3): logging backend

## Other notes

- **No async.** The analysis pipeline is synchronous.
- The parser reads the raw UFW log every time the tool runs, unless a valid cache is available.
- Entries are kept in memory to drive the TUI; very large logs require memory proportional to the number of blocked entries.
- **IPv4 + IPv6 support**; protocol normalization uses a built-in table (it does not read `/etc/protocols`).
- **Default range** = last 7 calendar days. Missing days are zero-filled.
- **CSV/JSON columns**: `date, hour, src_ip, dst_ip, src_port, dst_port, protocol, direction`
- **Terminal safety**: the panic hook restores the terminal on crash.
- Without `--csv` or `--output`, the tool enters interactive TUI mode.
- The TUI takes over the terminal (alternate screen). Press `q` or `Esc` to exit.
