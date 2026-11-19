# Work Breakdown Structure — v0.3.0 (Forensic Triage)

> **Status:** Planned | **Target version:** 0.3.0 | **Roadmap:**
> [`roadmap.md`](roadmap.md)

This document breaks the v0.3.0 milestone into work packages. It is the
implementation reference for the forensic triage branch and the checklist used
to decide when the release is ready.

## Goal

Turn `ufw-report` into an offline forensic triage kit for rotated UFW logs:
multi-file ingestion (including `.gz`), second-precision timestamps,
sliding-window heuristics, a verifiable chain of custody, and MITRE ATT&CK
mapping. The tool remains read-only: it never writes to the logs, changes firewall
state, or modifies the host configuration.

## Scope

**In scope**

- Rotated and compressed UFW logs as first-class inputs
- Sub-hour heuristics with configurable sliding windows
- SHA-256 evidence hashes and execution metadata in the findings report
- MITRE ATT&CK identifiers attached to findings where applicable
- Integrity alerts derived from coverage anomalies
- Tests, fixtures, and documentation for all of the above

**Out of scope**

- Deep egress (`OUT=`) threat analysis or C2 beaconing detection
- Passive fingerprinting (TCP flags and TTL); tracked in the v0.4.0+ backlog
- `ufw deny` command generation; deprioritized on this branch
- Full packet capture, SIEM replacement, or legal expert reporting

## Work packages

| ID | Work package | Concrete deliverables |
| --- | --- | --- |
| **1.0** | **Temporal schema and cache** | Second-resolution timestamps and a multi-file-safe cache. |
| 1.1 | `LogEntry` update | Replace `(date, hour)` with `NaiveDateTime` / `DateTime` at second resolution while keeping CSV/JSON compatibility or documenting the change. |
| 1.2 | Cache migration | Bump `cache_version` and adapt invalidation to support multiple source files without collisions or duplicated entries. |
| **2.0** | **Multi-file ingestion and hashing** | Read, hash, merge, and deduplicate rotated inputs at the file level. |
| 2.1 | Rotated file discovery | CLI flag (`--include-rotated` or multiple paths) to detect `ufw.log`, `.1`, `.2.gz`, and similar rotated names. |
| 2.2 | `.gz` reader and streaming SHA-256 | Integrate `flate2` and `sha2`, computing the hash over the raw bytes while reading each file in a single pass. |
| 2.3 | Unification and input deduplication | Sort the combined entries chronologically, deduplicate only at the input-file level (canonical path or inode, to avoid reading the same file twice when paths overlap), and update `ParseStats` counters per file. Never collapse repeated log lines with identical source/destination fields: they are distinct evidence. |
| **3.0** | **Sub-hour heuristic engine** | Sliding-window detection with optional MITRE IDs and integrity findings. |
| 3.1 | Sliding windows | Migrate port scan, host sweep, and brute force from fixed buckets to configurable moving windows in the TOML file. |
| 3.2 | MITRE ATT&CK mapping | Attach the technique ID (`T1046`, `T1018`, `T1110`) where it maps cleanly. Keep the field optional (`None`) for generic persistence findings and integrity findings that have no defensible ATT&CK technique. |
| 3.3 | Integrity alerts | Promote anomalous gaps (`missing_hours`), `out_of_order`, and `future_dated` entries to evidence-integrity findings. |
| **4.0** | **Forensic report (`--findings`)** | A verifiable report with custody metadata and evidence samples. |
| 4.1 | Chain-of-custody block | Add to JSON and Markdown: file list with SHA-256, UTC timestamp, hostname, tool version, and TOML hash. |
| 4.2 | Evidence samples | Include, for every finding, the exact timestamp range (start/end to the second), plus the key ports/protocols when the finding describes network behavior. |
| **5.0** | **Quality and documentation** | Tests, fixtures, and documentation aligned with the release. |
| 5.1 | Test suite | Add `.gz` fixtures (including a corrupt file), burst tests that cross an hour boundary, a fixture that preserves identical packets in the same second, and `--findings` format tests. |
| 5.2 | Documentation update | Update `actual-state.md`, `roadmap.md`, `risk-analysis.md`, `CHANGELOG.md`, `README.md`, the config example, and this WBS. |

### MITRE ATT&CK mapping policy

| Finding | ATT&CK ID | Rationale |
| --- | --- | --- |
| Port scan | `T1046` | Network Service Discovery |
| Host sweep | `T1018` | Remote System Discovery |
| Brute force and distributed brute force | `T1110` | Brute Force |
| Persistent source | None (optional) | Generic persistence has no single defensible technique; keep the finding as a heuristic without forcing an ID. |
| Integrity findings (`missing_hours`, `out_of_order`, `future_dated`) | None | They describe evidence quality, not adversary behavior. |

## Dependencies

```text
1.0 ──► 2.0 ──► 3.0 ──► 4.0
5.0 runs alongside every package
```

- **1.0 before 2.0:** the cache and timestamp schema must support multiple files
  before ingestion is wired in.
- **2.0 before 3.0:** sliding windows operate on the unified entry stream produced
  after input-file deduplication.
- **3.0 before 4.0:** the report needs stable finding variants and a settled MITRE
  mapping policy.
- **5.0 runs alongside every package,** with final verification before the
  release.

## Acceptance criteria

### 1.0 — Temporal schema and cache

- `LogEntry` stores a full timestamp with second precision.
- CSV and JSON exports keep their documented columns, or the breaking change is
  documented in the README and CHANGELOG.
- The cache key covers every input file, and `cache_version` is bumped.
- Rotation, addition, removal, and modification of an input invalidate the cache
  correctly.

### 2.0 — Multi-file ingestion and hashing

- `--include-rotated` (or repeated input paths) ingests `ufw.log`, `.1`, and
  `.2.gz`.
- `.gz` files are decompressed in streaming mode, and SHA-256 is computed in the
  same pass.
- Combined entries are sorted chronologically.
- Deduplication happens only at the input-file level (canonical path or inode),
  not by collapsing repeated `LogEntry` values. A fixture with two identical
  blocked packets in the same second must keep both entries.
- A corrupt `.gz` is reported in the coverage counters without aborting the
  analysis of the remaining files.

### 3.0 — Sub-hour heuristic engine

- Port scan, host sweep, brute force, and distributed brute force use
  configurable sliding windows.
- Findings that map to a technique (`T1046`, `T1018`, `T1110`) carry that ID.
- Generic persistence findings and integrity findings leave the MITRE field
  empty instead of forcing an incorrect technique.
- `missing_hours`, `out_of_order`, and `future_dated` become integrity findings
  in the report.

### 4.0 — Forensic report

- `--findings` includes the chain-of-custody block in both JSON and Markdown:
  files and SHA-256, UTC timestamp, hostname, tool version, and TOML hash.
- Each finding includes its exact start/end timestamps, plus key ports/protocols
  when applicable.
- Both formats include the disclaimer that findings are heuristic triage
  indicators and that the hash only certifies the input read during that run.

### 5.0 — Quality and documentation

- Fixtures cover `.gz`, corrupt `.gz`, bursts crossing an hour or DST boundary,
  and both findings formats.
- `actual-state.md`, `README.md`, `CHANGELOG.md`, `roadmap.md`,
  `risk-analysis.md`, the config example, and this WBS match the shipped
  behavior.
- `cargo fmt --all -- --check`, pedantic `clippy`, `cargo test --all-targets`,
  and `cargo build --release --locked` pass.

## Traceability

| Work package | Roadmap section | Primary risks |
| --- | --- | --- |
| 1.1, 3.1 | Sub-hour resolution | Risk 4 |
| 1.2 | Cache migration | Risk 10 |
| 2.0 | Multi-file ingestion and `.gz` | Risks 2, 7, 9 |
| 3.3 | Chain of custody and integrity | Risk 11 |
| 4.1, 4.2 | Forensic report and evidence | Risk 11 |

## Definition of done

- Every acceptance criterion above is met.
- Existing v0.2.1 behavior does not regress.
- CLI and output changes are documented as pre-1.0 changes when they break
  compatibility.
- The version is bumped to `0.3.0`, and `CHANGELOG.md` and `actual-state.md`
  describe the shipped behavior, not the plan.
- The release checklist in [`releasing.md`](releasing.md) is followed.
