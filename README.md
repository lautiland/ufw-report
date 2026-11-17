# ufw-report

A Rust CLI that reads UFW logs, analyzes blocked traffic, and presents an interactive terminal report (TUI). It detects attacker profiles, subnets, scans, and brute-force bursts, and can export the parsed entries to CSV or JSON or the threat findings to JSON or Markdown.

## What it is

`ufw-report` turns the noisy output of `/var/log/ufw.log` into an aggregated view of blocked traffic by day, hour, source IP, destination port, and protocol. Instead of using `grep`/`tail` or deploying a heavy stack such as ELK or Splunk, it gives you an interactive dashboard directly in the terminal.

It is lightweight, offline, and read-only: it never changes firewall rules, opens ports, or depends on external services. That makes it a good fit for sysadmins, DevOps engineers, auditors, and homelabbers working over SSH on small servers, VPS instances, or Raspberry Pis.

## Requirements

- Linux with UFW
- Read access to the UFW log (`sudo`, or membership in the `adm` group)
- No Rust toolchain is required with the precompiled binaries. Building from
  source needs Rust 1.82 or newer.

## Installation

Precompiled binaries are published on
[GitHub Releases](https://github.com/lautiland/ufw-report/releases).

| Target | Use it for |
|--------|------------|
| `x86_64-unknown-linux-gnu` | Most desktops, VPS instances, and servers |
| `aarch64-unknown-linux-gnu` | ARM64 servers and Raspberry Pi boards |
| `x86_64-unknown-linux-musl` | Static build; recommended for old glibc or air-gapped systems |

```bash
VERSION=0.2.0
TARGET=x86_64-unknown-linux-musl
BASE="https://github.com/lautiland/ufw-report/releases/download/v${VERSION}"

# Download the tarball and its checksum
curl -LO "${BASE}/ufw-report-v${VERSION}-${TARGET}.tar.gz"
curl -LO "${BASE}/ufw-report-v${VERSION}-${TARGET}.tar.gz.sha256"

# Verify the download
sha256sum -c "ufw-report-v${VERSION}-${TARGET}.tar.gz.sha256"

# Extract and install
tar -xzf "ufw-report-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 "ufw-report-v${VERSION}-${TARGET}/ufw-report" /usr/local/bin/ufw-report
```

Pick the musl build when the target system has an older glibc, or when it cannot
reach the network to install libraries. The GNU builds are built on Ubuntu
22.04 and need a compatible or newer glibc.

### Build from source

```bash
git clone https://github.com/lautiland/ufw-report.git
cd ufw-report
cargo build --release --locked
```

The binary is written to `target/release/ufw-report`.

## Status

`0.2.0` is the first release with precompiled binaries. The threat analysis
(TUI tab, scoring, and findings export) is feature-complete for its first
iteration; smaller improvements and packaging are tracked in
[`docs/roadmap.md`](docs/roadmap.md). The project is pre-1.0, so CLI flags and
output formats may still change between minor versions.

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

# Export threat findings as JSON or Markdown
ufw-report --findings findings.json
ufw-report --findings findings.md

# Use an explicit analysis config file
ufw-report --config analysis.toml

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

## Threat analysis

The analysis is offline and read-only. It never runs `ufw`, opens network
connections, or changes firewall rules.

For every source IP, `ufw-report` builds a profile with volume, first/last
seen, active days, distinct destination ports and hosts, administrative port
hits, and top ports/protocols. Profiles receive a 0-100 risk score built from
capped volume, port diversity, administrative hits, persistence, and findings.
Severity bands are Low (0-24), Medium (25-49), High (50-74), and Critical
(75-100).

The heuristics use one-hour buckets:

- **Port scan** — at least `scan_ports_per_hour` distinct destination ports
  from one source in one hour.
- **Host sweep** — at least `scan_hosts_per_hour` distinct destination hosts
  from one source in one hour.
- **Brute force** — at least `bruteforce_attempts_per_hour` attempts against
  administrative ports in one hour, or `bruteforce_attempts_per_day` in one
  day.
- **Distributed brute force** — at least `distributed_sources_per_hour`
  distinct sources against the same host and port in one hour.
- **Persistent source** — at least `persistence_min_days` active days and
  `persistence_min_blocks` blocks.

Sources are also grouped by IPv4 `/24` and IPv6 `/64` prefixes. The coverage
section reports how many hours in the requested range had data, the longest gap,
and parser counters such as unparsed block lines, out-of-order lines, and
future-dated entries, so "no findings" can be told apart from "no usable log".

CIDRs in `allowlist.cidrs` are excluded from findings and risk scores, but not
from the raw data or coverage counters. Profiles below `min_score` are left out
of the ranking; findings are kept even when their source falls below it.

### Configuration

Analysis thresholds use built-in defaults and are only loaded from an explicit
`--config <PATH>` file (automatic discovery is intentionally not supported).
Every section and key is optional. A complete example lives in
[`docs/analysis-config.example.toml`](docs/analysis-config.example.toml).

```toml
[thresholds]
scan_ports_per_hour = 10
min_score = 25

[allowlist]
cidrs = ["192.0.2.0/24"]

[scoring]
finding_weight = 10
```

### Findings export

`--findings <PATH>` writes the full report (summary, coverage, findings,
profiles, and network groups):

- Paths ending in `.md` produce Markdown.
- Any other path produces pretty-printed JSON.
- `-` writes to stdout.
- `--findings -` cannot be combined with an entry export that also writes to
  stdout (`-o -`, or `--csv` without `-o`).

When `--findings` is used the tool writes the file and exits, unless an entry
export (`--csv` or `-o`) is also requested, in which case both files are written.

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
- Threat analysis: attacker profiles, subnet groups, scan and brute-force heuristics
- 0-100 risk score with Low/Medium/High/Critical bands
- Log coverage and parser quality counters
- Five TUI views: Overview, Daily, Hourly, Raw, and Threats
- CSV and JSON export, including stdout pipelines
- JSON and Markdown findings export

## TUI controls

| Key | Action |
|-----|--------|
| `1`-`5` | Switch to Overview, Daily, Hourly, Raw, or Threats |
| `Tab` / `Shift+Tab` | Next / previous tab |
| `←` `→` | Previous / next day (Daily and Hourly) |
| `↑` `↓` | Scroll protocols (Overview), previous / next hour (Hourly), scroll rows (Raw), select a row (Threats) |
| `Shift+↑` `Shift+↓` | Fast scroll in Overview, Raw, and Threats |
| `PgUp` `PgDn` | Page scroll in Overview, Raw, the Hourly log table, and Threats |
| `Shift+PgUp` `Shift+PgDn` | Fast page scroll |
| `v` | Toggle Sources / Networks in Threats |
| `Enter` | Open the selected day in Hourly |
| `q` / `Esc` | Quit |

## Limitations

- Linux only: UFW and its log format are Linux-specific.
- The parser expects the standard UFW log layout. Unknown formats are reported
  through parser counters instead of crashing, but those lines are skipped.
- Analysis is synchronous and keeps parsed entries in memory. Very large logs
  need memory proportional to the number of blocked entries and delay the UI
  while they are parsed.
- Heuristics use one-hour buckets because entries store only date and hour, so
  sub-hour bursts are aggregated into their hour.
- There is no GeoIP, ASN, or external reputation data: findings come only from
  the local log.
- Only GitHub Releases are supported today. `.deb` packages, PPAs, and
  crates.io publication are not available yet.

## Tests

```bash
cargo test
```

The suite covers the parser, date range handling, cache invalidation, aggregation, output formats, threat heuristics, findings export, CLI behavior, and TUI navigation.

## License

MIT - Copyright (c) 2026 Lautaro Matias Jovanovics
