# Implementation Plan: Module Refactor and Consistency Pass

## Executive Summary

Reorganize the codebase into feature modules, keep the analysis pipeline data-driven, and close the consistency gaps between code, tests, CLI behavior, TUI hints, and documentation. The threat heuristics engine and the findings export are implemented in Phases 4-8.

**Core rule:** modules communicate through data (`models/`), not through cross-module references.

## Target Structure

```
src/
├── main.rs
├── lib.rs
├── cli/
│   ├── mod.rs
│   ├── args.rs          # CliArgs (clap)
│   └── config.rs        # AppConfig
├── core/
│   ├── mod.rs
│   ├── parser.rs        # parse_log_line(), regexes
│   ├── range.rs         # parse_ufw_log_range(), ParseOptions
│   └── cache.rs         # Range-safe JSON cache
├── models/
│   ├── mod.rs
│   ├── entry.rs         # LogEntry, Direction
│   ├── report.rs        # DailyReport, HourBreak, IpEntry, PortEntry
│   ├── stats.rs         # ParseStats
│   ├── threat.rs        # ThreatReport, SourceProfile, findings, coverage
│   └── aggregate.rs     # AggregatedData, build_aggregated()
├── output/
│   ├── mod.rs           # OutputFormat, write_output()
│   ├── csv.rs           # write_csv()
│   ├── json.rs          # write_json()
│   └── findings.rs      # FindingsFormat, JSON/Markdown findings export
├── threat/
│   ├── mod.rs           # analyze() pipeline
│   ├── config.rs        # AnalysisConfig and defaults
│   ├── allowlist.rs     # CIDR exclusions
│   ├── offenders.rs     # SourceProfile builder
│   ├── subnets.rs       # IPv4 /24 and IPv6 /64 groups
│   ├── coverage.rs      # Hourly coverage and ParseStats
│   ├── scan.rs          # Port scan and host sweep
│   ├── bruteforce.rs    # Brute force and distributed brute force
│   ├── scoring.rs       # 0-100 risk score
│   ├── aggregate.rs     # Shared finding accumulator
│   └── util.rs          # Deterministic ranking helpers
├── tui/
│   ├── mod.rs           # Event loop, key handling
│   ├── app.rs           # App, Tab, ThreatsView
│   ├── tabs/
│   │   ├── mod.rs
│   │   ├── overview.rs
│   │   ├── daily.rs
│   │   ├── hourly.rs
│   │   ├── raw.rs
│   │   └── threats.rs
│   └── widgets/
│       ├── mod.rs
│       └── bar_chart.rs
├── error.rs
└── logging.rs
```

## Module Dependencies

```
main.rs → cli, core, models, output, threat, tui
cli/    → error
core/   → models, error
models/ → (none)
output/ → models
threat/ → models
tui/    → models
```

## Phase 1: Reorganize Existing Code (Complete)

**Goal:** Move code into the new directories without changing behavior.

- [x] Create `src/cli/`, `src/core/`, `src/models/`, `src/output/`, `src/tui/`
- [x] Move configuration and CLI arguments into `cli/`
- [x] Split parsing, range handling, and caching into `core/`
- [x] Split entries, reports, and aggregation into `models/`
- [x] Split CSV and JSON output into `output/`
- [x] Extract the TUI app and tabs into `tui/`
- [x] Re-export modules from `lib.rs`
- [x] Verify with `fmt`, `clippy`, and `test`

## Phase 2: Separate the TUI into Subcomponents (Complete)

**Goal:** One file per tab and reusable widgets.

- [x] Extract each tab into `tui/tabs/`
- [x] Extract bar-chart builders into `tui/widgets/bar_chart.rs`
- [x] Introduce `Tab` enum and remove magic tab indexes
- [x] Make status hints and navigation behavior share one source of truth
- [x] Verify with `fmt`, `clippy`, and `test`

## Phase 3: Consistency Pass (Complete)

- [x] Fix the clippy lint that left CI red
- [x] Run CI on every branch and on pull requests to `main`
- [x] Track `Cargo.lock`
- [x] Make the cache range-safe: store all entries plus log fingerprint and format version
- [x] Move the cache to `$XDG_CACHE_HOME` and add `--no-cache`
- [x] Make cache writes atomic and non-fatal
- [x] Report real unique IP counts with a v4/v6 split
- [x] Use the Overview scroll state instead of leaving it dead
- [x] Remove the 20-row cap from the Raw view
- [x] Unify keyboard navigation: `←`/`→` selects days, `↑`/`↓` selects hours in Hourly
- [x] Resolve the output format in one place; make `--csv` win and reject a contradictory `.json` path
- [x] Make date resolution deterministic by injecting the reference date
- [x] Add fixture, cache, CLI, and App-navigation tests
- [x] Translate the CLI, TUI, and documentation to English
- [x] Add package metadata and an MSRV

## Phase 4: Threat Foundations (Complete)

**Goal:** Add the data model, parse quality counters, and explicit configuration
that the heuristics need.

- [x] Add `threat/` with `AnalysisConfig`, defaults, validation, and TOML loading
- [x] Add `--config <PATH>` with no autoload
- [x] Add `models/stats.rs` with `ParseStats` and line classification
- [x] Collect block/allow/audit/other lines, unparsed blocks, out-of-order lines, and future-dated entries
- [x] Persist `ParseStats` in cache version 3
- [x] Add `models/threat.rs`: profiles, findings, subnet groups, coverage, summary, and report
- [x] Add `--findings <PATH>` to the CLI
- [x] Verify with `fmt`, `clippy`, and `test`

## Phase 5: Profiles, Subnets, and Coverage (Complete)

- [x] Build one `SourceProfile` per source with volume, recurrence, ports, hosts, and protocols
- [x] Group sources by IPv4 `/24` and IPv6 `/64` with a minimum-source filter
- [x] Compute hourly coverage, missing hours, longest gap, and coverage percentage
- [x] Apply CIDR allowlists to profiles and findings only
- [x] Keep ordering deterministic (counts, then stable keys)

## Phase 6: Heuristics and Risk Score (Complete)

- [x] Detect vertical port scans and horizontal host sweeps per hour
- [x] Detect hourly and daily brute-force bursts against administrative ports
- [x] Detect distributed brute force against one host/port
- [x] Detect persistent sources by active days and volume
- [x] Attach findings to profiles and compute the capped 0-100 score
- [x] Filter ranked profiles with `min_score` without dropping findings
- [x] Add unit tests for every heuristic, allowlists, scoring, and the pipeline

## Phase 7: Threats TUI (Complete)

- [x] Add the fifth tab and `ThreatsView` state
- [x] Render summary, source/network tables, and a detail panel
- [x] Add `v` to toggle Sources/Networks and row navigation
- [x] Show a compact risk/coverage line on Overview
- [x] Wire `AnalysisConfig` and `analyze()` through `main.rs`

## Phase 8: Findings Export and Documentation (Complete)

- [x] Add `output/findings.rs` with JSON and Markdown renderers
- [x] Resolve Markdown from the `.md` extension; JSON otherwise
- [x] Support `--findings -` for stdout and reject it together with `-o -`
- [x] Allow findings and entry exports in the same run
- [x] Add scan, brute-force, distributed, persistent, and clean fixtures
- [x] Add end-to-end CLI tests for both formats, config overrides, and conflicts
- [x] Document threat analysis, configuration, and export in English

## Scope Notes

- v1 buckets heuristics by hour because `LogEntry` stores only `date` and
  `hour`; the parser schema is unchanged.
- Out of scope for v1: volume-based DoS detection, historical baselines,
  sub-hour timestamps, TCP flags, TTL, OS fingerprinting, GeoIP/ASN, and
  external reputation feeds.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
cargo test --all-targets
cargo build --release
```

## Acceptance Criteria

1. [x] Phase 1: all files reorganized and tests pass
2. [x] Phase 2: TUI separated into independent tabs and widgets
3. [x] Phase 3: consistency gaps closed and documented
4. [x] Phase 4: threat foundations, stats, and explicit config
5. [x] Phase 5: source profiles, subnet groups, and coverage
6. [x] Phase 6: scan/brute-force heuristics and risk scoring
7. [x] Phase 7: Threats tab with Sources/Networks toggle
8. [x] Phase 8: JSON/Markdown findings export and documentation
9. [x] `cargo clippy` clean on every change
10. [x] `lib.rs` re-exports everything needed by the binary
11. [x] CI green on every branch and on pull requests
