# Roadmap

This document is the single source of truth for the product direction of
`ufw-report`. It lists what is already shipped, what is planned next, and what
is explicitly out of scope. For the current behavior of the tool, see
[`../README.md`](../README.md).

> **Spec Kit:** change-level specifications, plans, and tasks live under
> `specs/` (see [`spec-kit.md`](spec-kit.md)). This roadmap remains the
> authority for direction, scope, and sequencing; it links to the spec once a
> roadmap item becomes active work.

## Product context

`ufw-report` exists because raw UFW logs are noisy and heavy SIEM stacks are a
poor fit for small servers, VPS instances, and Raspberry Pis. The primary users
are blue-teamers, incident responders, and security auditors who need offline
triage and evidence preservation on the host itself. Sysadmins, DevOps, and
homelabbers benefit from the terminal UI but do not drive the roadmap.

The value proposition is instant forensic triage in the terminal: offline
heuristics, precise chronological reconstruction, and a verifiable chain of
custody without touching the firewall. The unfair advantage is the same
constraint that limits the tool: it is offline, local, read-only, and
cryptographically proves which files it read.

The primary channel today is GitHub Releases. Planned channels are `.deb`, a
Launchpad PPA, and crates.io. Key indicators are downloads, processing time and
memory per 100k lines, rotated-file coverage, detection precision on
sliding-window fixtures, evidence-integrity completeness, and recurring
community issues or pull requests. Sustainability is reputation and portfolio
value first; donations and a future commercial tier are optional, not roadmap
drivers.

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
- Sliding-window heuristics: port scan, host sweep, brute force, distributed
  brute force, and persistent source, with exact finding intervals
- Evidence-integrity findings for coverage gaps and unreadable inputs
- MITRE ATT&CK mapping where defensible
- IPv4 `/24` and IPv6 `/64` network grouping
- CIDR allowlist that excludes findings and scores without hiding raw data
- Explicit TOML configuration with built-in defaults and no autoload

### Interfaces and output

- Five-view TUI: Overview, Daily, Hourly, Raw, and Threats
- Sources/Networks/Inputs switch and full keyboard navigation in Threats
- Chain-of-custody manifest and disclaimer in the findings exports
- CSV and JSON entry exports, including stdout pipelines
- JSON and Markdown findings export
- Offline and read-only operation: no network access, no `ufw` execution, no
  rule changes

### Quality and distribution

- 206 automated tests across parser, cache, models, output, CLI, TUI,
  multi-file ingestion, sliding windows, custody, and threat analysis
- GitHub Actions CI: `fmt`, pedantic `clippy`, tests, and a locked build
- Precompiled release binaries for `x86_64`/`aarch64` GNU Linux and `x86_64`
  musl, published as tarballs with SHA256 checksums
- Documented release process in [`releasing.md`](releasing.md)

> `main` also includes the complete v0.3.0 forensic-triage work: second-precision
> timestamps, multi-file/rotated ingestion with SHA-256, sliding-window
> detection, custody metadata, MITRE ATT&CK mapping, and integrity findings. It
> is not part of a published release yet; see
> [`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md).

## Next

### v0.3.0 — Forensic Triage (complete on `main`, pending release)

**Specification:**
[`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md) ·
**Plan:** [`plan.md`](../specs/001-forensic-triage/plan.md) ·
**Tasks:** [`tasks.md`](../specs/001-forensic-triage/tasks.md)

**Goal:** make `ufw-report` a credible first-response triage kit for UFW logs,
without turning it into a SIEM or a packet-level forensic suite.

Delivered on `main`:

- Multi-file and `.gz` ingestion with per-file SHA-256 and parse counters
- Second-precision timestamps end to end
- Configurable sliding-window heuristics with exact finding intervals
- Chain-of-custody manifest and disclaimer in JSON and Markdown exports
- MITRE ATT&CK mapping where defensible
- Evidence-integrity findings for coverage anomalies and unreadable inputs
- Per-file provenance in the TUI Threats tab

The next committed milestone after v0.3.0 is **v0.4.0**, starting with incident
isolation and filtered evidence export.

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
changes are out of scope by design. Significant changes become a specification
under `specs/` through `/speckit.specify`; small fixes can go straight to a pull
request with tests and documentation.
