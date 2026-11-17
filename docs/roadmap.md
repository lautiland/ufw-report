# Roadmap

This document is the single source of truth for the future of `ufw-report`.
It lists what is already shipped, what is planned next, and what is explicitly
out of scope. For the current behavior of the tool, see
[`actual-state.md`](actual-state.md).

## Shipped

### Log analysis

- UFW log parsing for IPv4 and IPv6, with syslog and ISO timestamps
- Protocol normalization, direction detection, and configurable date ranges
- Zero-filled days, per-day and per-hour aggregates, and unique IP counts
- Range-safe JSON parse cache with atomic writes and a `--no-cache` escape hatch
- Parser quality counters (unparsed blocks, out-of-order lines, future-dated
  entries) and a coverage summary

### Threat analysis

- Per-source profiles: volume, first/last seen, active days, distinct ports and
  hosts, administrative hits, and top ports/protocols
- Capped 0-100 risk score with Low/Medium/High/Critical bands
- Hourly heuristics: port scan, host sweep, brute force, distributed brute
  force, and persistent source
- IPv4 `/24` and IPv6 `/64` network grouping
- CIDR allowlist that excludes findings and scores without hiding raw data
- Explicit TOML configuration with built-in defaults and no autoload

### Interfaces and output

- Five-view TUI: Overview, Daily, Hourly, Raw, and Threats
- Sources/Networks toggle and full keyboard navigation in Threats
- CSV and JSON entry exports, including stdout pipelines
- JSON and Markdown findings export
- Offline and read-only operation: no network access, no `ufw` execution, no
  rule changes

### Quality and distribution

- 159 automated tests across parser, cache, models, output, CLI, TUI, and
  threat analysis
- GitHub Actions CI: `fmt`, pedantic `clippy`, tests, and a locked build
- Precompiled release binaries for `x86_64`/`aarch64` GNU Linux and `x86_64`
  musl, published as tarballs with SHA256 checksums
- Documented release process in [`releasing.md`](releasing.md)

## Next

Candidates are ordered by expected value, not by commitment. None of them is
scheduled.

### Distribution

- `.deb` packages for Ubuntu/Debian, built from the existing tarballs
- PPA/Launchpad publication once the manual `.deb` flow is stable
- `cargo install ufw-report` via crates.io

### Analysis depth

- Volume-based anomaly detection (possible DoS) on top of the current heuristics
- Configurable scoring weights per finding type
- Sub-hour time resolution, which requires extending the `LogEntry` schema
- Optional TCP flags and TTL parsing for offline fingerprinting

### Interface

- Isolate an incident directly from the Daily chart and open it in a filtered
  Raw/Threats view
- Export blocking suggestions (`ufw deny` lines) for the user to review and run
  manually; the tool itself stays read-only
- Threat tags on the Overview and Raw tabs

### Performance

- Asynchronous or multithreaded parsing so the TUI never blocks on very large
  logs
- Streaming aggregation to reduce peak memory on multi-gigabyte logs

## Out of scope

- Executing `ufw` commands, modifying rules, or opening network connections
- Contacting reputation feeds, GeoIP/ASN services, or any remote API
- Acting as a long-running daemon, IDS, or log shipper
- Being a replacement for a SIEM or a full packet-level analysis stack
- Snap, Flatpak, or Docker as a primary distribution channel

## How to propose work

Open an issue describing the problem, the affected workflow, and how it fits the
offline, read-only constraint. Proposals that require network access or rule
changes are out of scope by design.
