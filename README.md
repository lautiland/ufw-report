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
VERSION=0.2.1
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

`0.2.1` is the latest published release. `main` targets the complete v0.3.0
forensic-triage milestone: rotated/compressed ingestion with SHA-256,
second-precision timestamps, configurable sliding-window detection, a
chain-of-custody block in the findings exports, MITRE ATT&CK mapping, and
evidence-integrity findings. The work is specified in
[`specs/001-forensic-triage/spec.md`](specs/001-forensic-triage/spec.md) and the
backlog is indexed in [`docs/roadmap.md`](docs/roadmap.md). The project is
pre-1.0, so CLI flags and output formats may still change between minor versions.

## Usage

```bash
# Interactive TUI (default range: last 7 days)
ufw-report

# Custom date range
ufw-report --from 2026-06-01 --to 2026-06-30

# Custom log path
ufw-report --log-file /var/log/ufw.log

# Analyze several files explicitly
ufw-report -l /var/log/ufw.log -l /var/log/ufw.log.1

# Discover rotated siblings, including .gz
ufw-report --include-rotated

# Lower the decompressed-size limit per .gz input (bytes)
ufw-report --include-rotated --max-decompressed-bytes 1073741824

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

The heuristics evaluate configurable moving windows, 60 minutes wide by default,
so bursts that cross an hour boundary are detected as one event:

- **Port scan** — at least `scan_ports_per_hour` distinct destination ports
  from one source within `scan_window_minutes`.
- **Host sweep** — at least `scan_hosts_per_hour` distinct destination hosts
  from one source within `scan_window_minutes`.
- **Brute force** — at least `bruteforce_attempts_per_hour` attempts against
  administrative ports within `bruteforce_window_minutes`, or
  `bruteforce_attempts_per_day` in one day.
- **Distributed brute force** — at least `distributed_sources_per_hour`
  distinct sources against the same host and port within
  `distributed_window_minutes`.
- **Persistent source** — at least `persistence_min_days` active days and
  `persistence_min_blocks` blocks.

The legacy `*_per_hour` key names are retained; they mean "per configured
window". Every finding carries exact first/last timestamps, the ports,
protocols, and sources involved, and a MITRE ATT&CK technique where the mapping
is defensible: `T1046` (port scan), `T1018` (host sweep), and `T1110` (brute
force and distributed brute force). Persistence and integrity findings leave the
technique empty.

Sources are also grouped by IPv4 `/24` and IPv6 `/64` prefixes. The coverage
section reports how many hours in the requested range had data, the longest gap,
and parser counters such as unparsed block lines, out-of-order lines, and
future-dated entries, so "no findings" can be told apart from "no usable log".
When those anomalies exceed the `[integrity]` thresholds, they also appear as
findings (`MissingHours`, `OutOfOrderEntries`, `FutureDatedEntries`), as does
every input that could not be read completely (`InputError`).

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
scan_window_minutes = 60
min_score = 25

[integrity]
missing_hours = 24
future_entries = 1

[allowlist]
cidrs = ["192.0.2.0/24"]

[scoring]
finding_weight = 10
```

### Findings export

`--findings <PATH>` writes the full report (summary, coverage, findings,
profiles, network groups, and custody manifest):

- Paths ending in `.md` produce Markdown.
- Any other path produces pretty-printed JSON.
- `-` writes to stdout.
- `--findings -` cannot be combined with an entry export that also writes to
  stdout (`-o -`, or `--csv` without `-o`).

When `--findings` is used the tool writes the file and exits, unless an entry
export (`--csv` or `-o`) is also requested, in which case both files are written.

Both formats include a **chain-of-custody** block: execution timestamp in UTC,
best-effort hostname, tool version, SHA-256 of the effective configuration, the
effective configuration itself (window widths, thresholds, allowlist), and one
row per input file with its path, size, SHA-256, parsed-block counters, and read
status (including failures). The digest always covers the raw bytes on disk
(compressed bytes for `.gz`), so it can be reproduced with `sha256sum`. Both
formats also state the disclaimer: findings are heuristic triage indicators, the
hashes certify only the bytes read during that execution, and the report is not
a full forensic investigation.

## Cache

The parser cache is enabled by default and is stored per user:

- `$XDG_CACHE_HOME/ufw-report/<hash>.json`
- `~/.cache/ufw-report/<hash>.json` when `XDG_CACHE_HOME` is not set
- A temporary directory as a last resort

The cache stores all parsed entries together with the log size and modification time, plus cache and parser version numbers. It is invalidated automatically when the log changes or when the cache format changes, and it can serve any date range because the filtering happens after loading.

Each input file has its own cache entry, keyed by canonical path, size,
modification time, and cache/parser versions, and revalidated against the file's
SHA-256. Adding, removing, or modifying a rotated sibling therefore cannot
produce a stale combined result: unchanged files are reused and the new or
changed file is read again.

Use `--no-cache` to disable both reading and writing. Cache write failures are non-fatal and reported as warnings.

## Features

- UFW log parsing for IPv4 and IPv6, including syslog and ISO timestamps
- Second-precision timestamps preserved through parsing, cache, and export
- Multi-file and rotated `.gz` ingestion with per-file SHA-256 and parse
  counters
- Configurable sliding-window detection for scans, sweeps, brute force, and
  distributed brute force
- Chain-of-custody manifest and disclaimer in JSON and Markdown findings exports
- MITRE ATT&CK mapping (`T1046`, `T1018`, `T1110`) where defensible
- Evidence-integrity findings for coverage gaps, out-of-order lines,
  future-dated entries, and unreadable inputs
- Protocol normalization (numeric values to names)
- Traffic direction detection (`IN=` / `OUT=`)
- Configurable date range (default: last 7 days)
- Zero-filled days with no data
- Range-safe JSON parse cache
- Threat analysis: attacker profiles, subnet groups, scan and brute-force heuristics
- 0-100 risk score with Low/Medium/High/Critical bands
- Log coverage and parser quality counters
- Five TUI views: Overview, Daily, Hourly, Raw, and Threats
- Per-file provenance view in Threats (Sources / Networks / Inputs)
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
| `v` | Toggle Sources / Networks / Inputs in Threats |
| `Enter` | Open the selected day in Hourly |
| `q` / `Esc` | Quit |

## Limitations

- Linux only: UFW and its log format are Linux-specific.
- The parser expects the standard UFW log layout. Unknown formats are reported
  through parser counters instead of crashing, but those lines are skipped.
- Analysis is synchronous and keeps parsed entries in memory. Very large logs
  need memory proportional to the number of blocked entries and delay the UI
  while they are parsed. Asynchronous parsing is specified in
  [`specs/003-async-streaming-parsing/spec.md`](specs/003-async-streaming-parsing/spec.md).
- Detection uses configurable sliding windows that default to 60 minutes. A burst
  longer than the configured window is reported as separate occurrences; widen
  the window when investigating slow, low-rate activity.
- There is no GeoIP, ASN, or external reputation data: findings come only from
  the local log.
- Only GitHub Releases are supported today. `.deb` packages, PPAs, and
  crates.io publication are specified in
  [`specs/004-distribution-expansion/spec.md`](specs/004-distribution-expansion/spec.md)
  but are not available yet.

## Technical notes

- Rust 1.82 or newer; single binary; Linux only.
- The TUI uses `ratatui` + `crossterm`. There is no async runtime; the analysis
  is synchronous and in-memory.
- IPv4 and IPv6 are supported. Protocol normalization uses a built-in table, not
  `/etc/protocols`.
- CSV/JSON columns: `date, hour, src_ip, dst_ip, src_port, dst_port, protocol,
  direction, timestamp`.
- Findings JSON adds exact `first_timestamp`/`last_timestamp`, `sources`,
  `ports`, `protocols`, `technique`, and a run-level `custody` object. Existing
  keys keep their meaning; the CSV/JSON entry schema is unchanged.
- Dependency versions live in `Cargo.toml`; they are not duplicated here.
- The panic hook restores the terminal if the TUI crashes.

## Security

- Read-only: the tool never modifies firewall rules or writes to UFW logs.
- Never runs `ufw` or any other privileged command.
- No network dependencies, HTTP servers, telemetry, or remote lookups.
- Cache files are written under the user's cache directory; exports go only to
  the paths the user selects.

## Development workflow

This repository uses [GitHub Spec Kit](https://github.github.com/spec-kit/) for
spec-driven development. The project constitution lives in
[`.specify/memory/constitution.md`](.specify/memory/constitution.md), and
change-level specifications, plans, and tasks live under `specs/`.

- New behavior starts with `/speckit.specify` and follows the cycle documented
  in [`docs/spec-kit.md`](docs/spec-kit.md).
- The Spec Kit git extension commits each phase automatically; finish a change
  with `/speckit.git.pr`, which commits any remaining work, pushes the branch,
  and opens the pull request (with a REST fallback if GitHub's GraphQL API
  fails).
- Product direction and scope are in [`docs/roadmap.md`](docs/roadmap.md).
- Cross-cutting risks are in [`docs/risk-analysis.md`](docs/risk-analysis.md).

The required local gates are `cargo fmt`, pedantic `cargo clippy`, `cargo test`,
and a locked release build. See [`docs/releasing.md`](docs/releasing.md).

## Tests

```bash
cargo test
```

The suite has 206 tests covering the parser, date range handling, cache
invalidation, multi-file ingestion, sliding-window heuristics, custody
metadata, integrity findings, aggregation, output formats, threat heuristics,
findings export, CLI behavior, and TUI navigation. CI also runs formatting,
pedantic Clippy, and a locked release build.

## License

MIT - Copyright (c) 2026 Lautaro Matias Jovanovics
