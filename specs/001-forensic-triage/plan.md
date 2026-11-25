# Implementation Plan: Forensic Triage for Rotated and Compressed UFW Logs

**Branch**: `001-forensic-triage` | **Date**: 2026-11-24 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-forensic-triage/spec.md`

## Summary

Complete the v0.3.0 forensic-triage milestone on top of the already-shipped
multi-file/`.gz` ingestion, second-precision timestamps, per-file SHA-256, and
parser counters. The remaining work is:

1. Replace fixed one-hour heuristic buckets with configurable sliding windows
   anchored on exact entry timestamps.
2. Add a chain-of-custody manifest, execution metadata, configuration hash, and
   disclaimer to both findings exports.
3. Attach MITRE ATT&CK identifiers where defensible and promote severe coverage
   anomalies (and unreadable inputs) to evidence-integrity findings.
4. Surface per-file provenance in the TUI and align docs/version with 0.3.0.

No new dependency is required: the window scan uses `std`, the configuration
hash reuses `sha2`, and hostname discovery is best-effort from local files.

## Technical Context

**Language/Version**: Rust 1.82+, edition 2021

**Primary Dependencies**: `chrono`, `serde`/`serde_json`, `toml`, `sha2`,
`ratatui`/`crossterm`, `flate2` (all already in `Cargo.toml`)

**Storage**: Per-user JSON parse cache (unchanged, per-file keyed); findings
exports to user-selected paths

**Testing**: `cargo test --all-targets --locked`; unit tests in `src/`, integration
tests in `tests/`, CLI fixtures under `tests/fixtures/`

**Target Platform**: Linux (UFW log format), single binary

**Project Type**: CLI + TUI application (library + binary)

**Performance Goals**: Sliding-window detection stays O(n log n) in entries per
detector (sort + two pointers), with no extra copy of the entry set

**Constraints**: Offline, read-only, no `ufw` execution, no network access, no new
daemon or async runtime; keep the public CLI/CSV/JSON entry schema stable

**Scale/Scope**: Existing synchronous, in-memory pipeline; rotation sets of a
few files and up to millions of blocked entries

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Gate | Status |
| --- | --- | --- |
| I. Offline, read-only, least privilege | No network, no `ufw`, no privileged command; hostname read is best-effort from local files | PASS |
| II. Evidence integrity and honest reporting | Custody block states exactly what hashes certify; disclaimer in both formats; corrupt inputs and coverage gaps surfaced | PASS |
| III. Specification before implementation | Spec exists; `plan.md`, `tasks.md`, and implementation trace to it; `/speckit.analyze` run before implementation | PASS |
| IV. Testable quality gates | Unit + integration tests per behavior; `fmt`, pedantic `clippy`, `test`, locked release build | PASS |
| V. Explicit contracts and backward compatibility | New fields are additive; existing keys/flags retained; breaking changes documented | PASS |
| VI. Simplicity and dependency discipline | Reuses existing crates and synchronous architecture; no new dependency | PASS |

No violations; Complexity Tracking is empty.

## Project Structure

### Documentation (this feature)

```text
specs/001-forensic-triage/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── findings-export.md
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
src/
├── core/
│   ├── hash.rs              # add sha256_bytes for the config hash
│   └── inputs.rs, range.rs  # baseline ingestion (unchanged)
├── models/
│   ├── custody.rs           # NEW: CustodyManifest + disclaimer + hostname
│   ├── threat.rs            # findings: exact timestamps, ATT&CK, evidence lists
│   └── mod.rs
├── output/
│   └── findings.rs          # custody + disclaimer + timestamps in JSON/Markdown
├── threat/
│   ├── window.rs            # NEW: sliding-window primitives
│   ├── scan.rs              # sliding windows for scan/sweep
│   ├── bruteforce.rs        # sliding windows for brute force/distributed
│   ├── integrity.rs         # NEW: coverage and input-error findings
│   ├── config.rs            # window minutes + [integrity] thresholds
│   └── mod.rs               # analyze_with_custody, ordering, integrity wiring
├── tui/
│   ├── app.rs               # ThreatsView::Inputs
│   └── tabs/threats.rs      # per-file provenance view
└── main.rs                  # pass EvidenceFile set + tool version to analysis
tests/
├── fixture_tests.rs
├── ingestion_tests.rs
├── threat_tests.rs          # NEW scenarios: window boundary, custody, MITRE
└── fixtures/                # add boundary + integrity fixtures
```

**Structure Decision**: Keep the existing single-crate CLI/TUI layout and module
boundaries (cli → core → models → threat → output/tui). New logic lives in two
small modules (`threat/window.rs`, `threat/integrity.rs`) plus the `CustodyManifest`
model, so the change stays reviewable and each module has one responsibility.

## Phase 0: Research

See [research.md](research.md). Decisions cover the sliding-window algorithm,
configuration surface, identifier attachment, integrity thresholds, custody hash
inputs, and hostname discovery. All `NEEDS CLARIFICATION` items are resolved.

## Phase 1: Design

- [data-model.md](data-model.md) — entity changes and constraints.
- [contracts/findings-export.md](contracts/findings-export.md) — JSON and Markdown
  export contract, including the custody block and disclaimer.
- [quickstart.md](quickstart.md) — end-to-end validation scenarios.

Post-design constitution re-check: PASS. The design adds no network/elevated
operation and keeps all new fields additive.

## Implementation Phases

1. **Configuration and models** — window minutes, `[integrity]` thresholds,
   `ThreatFinding` evidence fields, `CustodyManifest`, `ThreatKind` additions.
2. **Sliding-window engine** — `threat/window.rs` plus scan/sweep and
   brute-force/distributed detectors.
3. **Integrity findings** — coverage anomalies and unreadable inputs.
4. **Custody and exports** — manifest, config hash, disclaimer, JSON/Markdown.
5. **TUI and CLI wiring** — pass files/version, Inputs view.
6. **Docs, tests, gates** — README, CHANGELOG, example config, roadmap, tests,
   `fmt`/`clippy`/`test`/release build.
