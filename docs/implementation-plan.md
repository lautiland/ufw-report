# Implementation Plan: Module Refactor and Consistency Pass

## Executive Summary

Reorganize the codebase into feature modules, keep the analysis pipeline data-driven, and close the consistency gaps between code, tests, CLI behavior, TUI hints, and documentation. The threat heuristics engine remains a future phase.

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
│   └── aggregate.rs     # AggregatedData, build_aggregated()
├── output/
│   ├── mod.rs           # OutputFormat, write_output()
│   ├── csv.rs           # write_csv()
│   └── json.rs          # write_json()
├── tui/
│   ├── mod.rs           # Event loop, key handling, App
│   ├── app.rs           # App, Tab
│   ├── tabs/
│   │   ├── mod.rs
│   │   ├── overview.rs
│   │   ├── daily.rs
│   │   ├── hourly.rs
│   │   └── raw.rs
│   └── widgets/
│       ├── mod.rs
│       └── bar_chart.rs
├── error.rs
└── logging.rs
```

## Module Dependencies

```
main.rs → cli, core, models, output, tui
cli/    → error
core/   → models, error
models/ → (none)
output/ → models
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

## Phase 4: Prepare the Threat Engine (Pending)

**Goal:** Create the `threat/` module structure with ready interfaces.

- [ ] Create `src/threat/`
- [ ] Define the `ThreatDetector` trait
- [ ] Add stubs for brute force, port scan, anomaly detection, scoring, and fingerprinting
- [ ] Add `ThreatAlert` to `models/`
- [ ] Integrate into the pipeline without real logic

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
4. [ ] Phase 4: `threat/` module created with traits and stub integration
5. [x] `cargo clippy` clean on every change
6. [x] `lib.rs` re-exports everything needed by the binary
7. [x] CI green on every branch and on pull requests
