# ufw-report

A Rust CLI that reads UFW logs, analyzes blocked traffic, and presents an interactive terminal report (TUI). It can also export the parsed entries to CSV or JSON.

## What it is

`ufw-report` turns the noisy output of `/var/log/ufw.log` into an aggregated view of blocked traffic by day, hour, source IP, destination port, and protocol. Instead of using `grep`/`tail` or deploying a heavy stack such as ELK or Splunk, it gives you an interactive dashboard directly in the terminal.

It is lightweight, offline, and read-only: it never changes firewall rules, opens ports, or depends on external services. That makes it a good fit for sysadmins, DevOps engineers, auditors, and homelabbers working over SSH on small servers, VPS instances, or Raspberry Pis.

## Requirements

- Linux with UFW
- Read access to the UFW log (`sudo`, or membership in the `adm` group)
- Rust 1.82 or newer to build from source

## Installation

```bash
git clone https://github.com/lautiland/ufw-report.git
cd ufw-report
cargo build --release
```

The binary is written to `target/release/ufw-report`.

## Usage

```bash
# Interactive TUI (default range: last 7 days)
ufw-report

# Custom date range
ufw-report --from 2026-06-01 --to 2026-06-30

# Custom log path
ufw-report --log-file /var/log/ufw.log

# Export CSV to stdout
ufw-report --csv > report.csv

# Export CSV to a file
ufw-report --csv -o report.csv

# Export JSON to a file
ufw-report -o report.json

# Export JSON to stdout (pipeable)
ufw-report -o -

# Disable the parse cache
ufw-report --no-cache
```

### Output format precedence

The format is resolved in one place and never inferred silently:

- No `--csv` and no `-o`: interactive TUI.
- `--csv`: CSV, to stdout or to the `-o` path.
- `--csv -o report.json`: error, because the flag and the extension contradict each other.
- `-o report.csv`: CSV.
- `-o report.json`: JSON.
- `-o report` (no extension): JSON.
- `-o -`: CSV with `--csv`, JSON otherwise.

## Cache

The parser cache is enabled by default and is stored per user:

- `$XDG_CACHE_HOME/ufw-report/<hash>.json`
- `~/.cache/ufw-report/<hash>.json` when `XDG_CACHE_HOME` is not set
- A temporary directory as a last resort

The cache stores all parsed entries together with the log size and modification time, plus cache and parser version numbers. It is invalidated automatically when the log changes or when the cache format changes, and it can serve any date range because the filtering happens after loading.

Use `--no-cache` to disable both reading and writing. Cache write failures are non-fatal and reported as warnings.

## Features

- UFW log parsing for IPv4 and IPv6, including syslog and ISO timestamps
- Protocol normalization (numeric values to names)
- Traffic direction detection (`IN=` / `OUT=`)
- Configurable date range (default: last 7 days)
- Zero-filled days with no data
- Range-safe JSON parse cache
- Four TUI views: Overview, Daily, Hourly, and Raw
- CSV and JSON export, including stdout pipelines

## TUI controls

| Key | Action |
|-----|--------|
| `1`-`4` | Switch to Overview, Daily, Hourly, or Raw |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `←` `→` | Previous / next day (Daily and Hourly) |
| `↑` `↓` | Scroll protocols (Overview), previous / next hour (Hourly), scroll rows (Raw) |
| `Shift+↑` `Shift+↓` | Fast scroll in Overview and Raw |
| `PgUp` `PgDn` | Page scroll in Overview, Raw, and the Hourly log table |
| `Shift+PgUp` `Shift+PgDn` | Fast page scroll |
| `Enter` | Open the selected day in Hourly |
| `q` / `Esc` | Quit |

## Tests

```bash
cargo test
```

The suite covers the parser, date range handling, cache invalidation, aggregation, output formats, CLI behavior, and TUI navigation.

## License

MIT - Copyright (c) 2026 Lautaro Matias Jovanovics
