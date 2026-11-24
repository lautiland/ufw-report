# Roadmap

This document is the single source of truth for the product direction of
`ufw-report`. It lists what is already shipped, what is planned next, and what
is explicitly out of scope. For the current behavior of the tool, see
[`actual-state.md`](actual-state.md).

> **Spec Kit:** change-level specifications, plans, and tasks live under
> `specs/` (see [`spec-kit.md`](spec-kit.md)). This roadmap remains the
> authority for direction, scope, and sequencing; it should link to the spec
> once a roadmap item becomes active work.

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

The next committed milestone is **v0.3.0 — Forensic Triage**. It narrows the
product around rotated logs, sub-hour resolution, chain of custody, and MITRE
ATT&CK mapping. The user-facing behavior is specified in
[`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md). The
technical work packages remain in [`wbs-v0.3.0.md`](wbs-v0.3.0.md) as planning
input for the Spec Kit plan and tasks.

### v0.3.0 — Forensic Triage (committed)

**Specification:**
[`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md)

**Goal:** make `ufw-report` a credible first-response triage kit for UFW logs,
without turning it into a SIEM or a packet-level forensic suite.

#### Multi-file ingestion and `.gz`

- Ingest `ufw.log`, `ufw.log.1`, and `ufw.log.*.gz` as one chronological stream
- Add `--include-rotated` or repeated input paths to discover rotated files
- Decompress `.gz` in streaming mode, with configurable size limits
- Record per-file parse counters and coverage gaps

#### Sub-hour resolution

- Store full timestamps with second precision in `LogEntry`
- Replace fixed one-hour buckets with configurable sliding windows
- Detect short scans, sweeps, and brute-force bursts that cross an hour boundary

#### Chain of custody and integrity

- Compute SHA-256 for every raw file read
- Record execution metadata: UTC timestamp, hostname, tool version, and TOML hash
- Promote severe coverage anomalies (`missing_hours`, `out_of_order`,
  `future_dated`) to integrity findings in the report

#### MITRE ATT&CK and evidence

- Map findings to their technique where applicable (`T1046`, `T1018`, `T1110`);
  leave the field empty for generic persistence and integrity findings
- Include the exact start/end timestamp range, plus key ports/protocols when
  applicable, for manual verification
- Keep the report explicitly framed as heuristic triage, not legal proof

### Backlog (v0.4.0+)

Specs ready for planning:

- Incident isolation and filtered evidence export —
  [`specs/002-incident-isolation/spec.md`](../specs/002-incident-isolation/spec.md)
- Asynchronous and streaming parsing for large log sets —
  [`specs/003-async-streaming-parsing/spec.md`](../specs/003-async-streaming-parsing/spec.md)
- Distribution through `.deb`, a Launchpad PPA, and crates.io —
  [`specs/004-distribution-expansion/spec.md`](../specs/004-distribution-expansion/spec.md)
- Signed releases and offline provenance verification —
  [`specs/005-signed-releases/spec.md`](../specs/005-signed-releases/spec.md)

Still unspecced:

- Optional passive fingerprinting (TCP flags and TTL) to enrich `T1046`; keep in
  the backlog until 001–003 are implemented.
- Generator of `ufw deny` commands for manual review (deprioritized on this
  branch; the tool stays read-only)

## Out of scope

- Executing `ufw` commands, modifying rules, or opening network connections
- Contacting reputation feeds, GeoIP/ASN services, or any remote API
- Acting as a long-running daemon, IDS, or log shipper
- Being a replacement for a SIEM or a full packet-level analysis stack
- Deep egress (`OUT=`) threat analysis or C2 beaconing detection. `OUT=` remains
  in counters and the Raw view, but the heuristic engine focuses exclusively on
  inbound perimeter traffic to keep one coherent data model.
- Snap, Flatpak, or Docker as a primary distribution channel

## How to propose work

Open an issue describing the problem, the affected workflow, and how it fits the
offline, read-only constraint. Proposals that require network access or rule
changes are out of scope by design.
