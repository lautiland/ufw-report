# Tasks: Forensic Triage for Rotated and Compressed UFW Logs

**Input**: Design documents from `specs/001-forensic-triage/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/findings-export.md

**Tests**: Required by the project constitution. Test tasks precede their
implementation tasks where practical.

**Organization**: Tasks are grouped by user story. US1's ingestion pieces already
exist on `main`; its tasks verify and harden them rather than reimplementing them.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1–US4 from `spec.md`
- Every task names the exact file path

## Phase 1: Setup

- [X] T001 Confirm the baseline in `src/core/inputs.rs`, `src/core/range.rs`, and `src/core/cache.rs`; record any gap against FR-001–FR-007 and FR-014 in `specs/001-forensic-triage/plan.md`
- [X] T002 Add `specs/001-forensic-triage/` design artifacts to the repository (plan.md, research.md, data-model.md, contracts/findings-export.md, quickstart.md, tasks.md)

---

## Phase 2: Foundational (blocking all stories)

**Purpose**: Shared model and configuration changes every story depends on.

- [X] T003 [P] Extend `ThreatKind` with `MissingHours`, `OutOfOrderEntries`, `FutureDatedEntries`, `InputError`, and `ThreatKind::technique()` in `src/models/threat.rs` (see data-model.md `ThreatKind`)
- [X] T004 [P] Add `sources`, `ports`, `protocols`, `first_timestamp`, `last_timestamp`, and `technique` to `ThreatFinding` in `src/models/threat.rs`, keeping `first_seen`/`last_seen` in sync (see data-model.md `ThreatFinding`)
- [X] T005 [P] Create `src/models/custody.rs` with `CustodyManifest`, the fixed `DISCLAIMER`, and best-effort hostname discovery; export it from `src/models/mod.rs` (see data-model.md `CustodyManifest`)
- [X] T006 Add `custody: CustodyManifest` to `ThreatReport` and update `ThreatReport::empty` in `src/models/threat.rs` (see data-model.md `ThreatReport`)
- [X] T007 Add `scan_window_minutes`, `bruteforce_window_minutes`, and `distributed_window_minutes` to `Thresholds` with defaults `60`, and an `[integrity]` section to `AnalysisConfig` in `src/threat/config.rs` (see data-model.md `AnalysisConfig`)
- [X] T008 Validate the new windows (`1..=10080`) and integrity thresholds in `AnalysisConfig::validate`, with key names in the error messages, in `src/threat/config.rs` (FR-019)
- [X] T009 Add `sha256_bytes(&[u8]) -> String` in `src/core/hash.rs` for the effective-configuration digest
- [X] T010 Update all `ThreatFinding` constructors and `Aggregate` in `src/threat/aggregate.rs`, `src/threat/scan.rs`, `src/threat/bruteforce.rs`, and `src/threat/mod.rs` to populate the new fields (compile checkpoint)

**Checkpoint**: `cargo check` succeeds with no behavior change yet.

---

## Phase 3: User Story 1 — Complete rotation set (Priority: P1) 🎯 MVP

**Goal**: Verify that every readable rotated/compressed input is ingested once,
merged chronologically, attributed with its own counters and hash, and that
failures are reported without aborting the run.

**Independent Test**: `cargo test --test ingestion_tests` plus the quickstart
rotation scenario.

- [X] T011 [P] [US1] Add a regression assertion for per-file counts and SHA-256 across base, `.1`, and `.2.gz` in `tests/ingestion_tests.rs`
- [X] T012 [P] [US1] Add a regression assertion that a corrupt `.gz` among healthy inputs produces an `InputError` finding and keeps the healthy entries in `tests/threat_tests.rs`
- [X] T013 [US1] Verify cache invalidation behavior for added/removed/modified rotated files in `src/core/cache.rs`; adjust only if a gap exists (FR-014)

**Checkpoint**: US1 behavior is verified end to end.

---

## Phase 4: User Story 2 — Bursts across an hour boundary (Priority: P2)

**Goal**: Detect scan/sweep/brute-force bursts over configurable moving windows
and report exact second-precision start/end timestamps.

**Independent Test**: Fixture burst from 10:59:30 to 11:01:10 yields one finding
with those exact timestamps; widening the window removes it.

- [X] T014 [P] [US2] Add sliding-window primitives (sort + two pointers, distinct values and plain counts) with unit tests in `src/threat/window.rs`
- [X] T015 [P] [US2] Add a boundary fixture with ten ports from 10:59:30 to 11:01:10 in `tests/fixtures/threat_boundary.log`
- [X] T016 [US2] Rewrite `src/threat/scan.rs` to use the window engine for port scan and host sweep, populating `ports`/`protocols` and exact timestamps
- [X] T017 [US2] Rewrite `src/threat/bruteforce.rs` to use the window engine for brute force and distributed brute force, keeping the daily threshold and populating `sources`/`ports`/`protocols`
- [X] T018 [US2] Validate that `TestEnv` in `tests/threat_tests.rs` checks `first_timestamp`/`last_timestamp` on the boundary fixture and that a 1-minute window suppresses the finding
- [X] T019 [US2] Update the TUI detail and export evidence text to name the configured window instead of "a single hour" in `src/threat/scan.rs`, `src/threat/bruteforce.rs`, and `tests/threat_tests.rs`
- [X] T020 [US2] Add unit tests for window configuration parsing/validation in `src/threat/config.rs`

**Checkpoint**: US2 passes independently; existing hourly fixtures still detect.

---

## Phase 5: User Story 3 — Verifiable custody metadata (Priority: P3)

**Goal**: Both findings exports carry the custody manifest, execution metadata,
configuration hash, exact evidence timestamps, and disclaimer.

**Independent Test**: Export a fixture as JSON and Markdown; compare
`custody.files[*].sha256` with `sha256sum`, and assert the disclaimer and
metadata exist in both.

- [X] T021 [P] [US3] Add unit tests for `CustodyManifest` (disclaimer present, config hash stable, hostname optional) in `src/models/custody.rs`
- [X] T022 [US3] Implement `analyze_with_custody(entries, from, to, stats, config, files, tool_version)` in `src/threat/mod.rs`; keep `analyze` as a wrapper for existing callers
- [X] T023 [US3] Wire `ParseResult::files` and `env!("CARGO_PKG_VERSION")` into analysis in `src/main.rs` (FR-012)
- [X] T024 [US3] Render `## Chain of custody` and `## Disclaimer` in `src/output/findings.rs`, including per-file path, size, SHA-256, and status
- [X] T025 [US3] Extend the findings table with `ATT&CK`, `First`, and `Last` exact timestamps in `src/output/findings.rs` (FR-009)
- [X] T026 [P] [US3] Add integration assertions for custody, disclaimer, and reproducible hashes in `tests/threat_tests.rs` (SC-005, SC-010)
- [X] T027 [US3] Update the findings constructors in `src/output/findings.rs` unit tests for the new fields

**Checkpoint**: JSON and Markdown satisfy the export contract.

---

## Phase 6: User Story 4 — Attribution and evidence quality (Priority: P4)

**Goal**: Attach defensible ATT&CK identifiers, promote severe coverage anomalies
to findings, and expose per-file provenance in the TUI.

**Independent Test**: Fixtures for scan/sweep/brute/persistence/integrity assert
`T1046`, `T1018`, `T1110`, empty technique, and integrity findings.

- [X] T028 [P] [US4] Create `src/threat/integrity.rs` with `MissingHours`, `OutOfOrderEntries`, `FutureDatedEntries`, and `InputError` findings derived from coverage, stats, and `EvidenceFile`s; add unit tests
- [X] T029 [US4] Wire integrity findings into `src/threat/mod.rs` after coverage is computed, before sorting and summary (FR-011)
- [X] T030 [P] [US4] Add ATT&CK assertions for all finding kinds in `src/models/threat.rs` and `tests/threat_tests.rs` (SC-006)
- [X] T031 [US4] Add `ThreatsView::Inputs` to `src/tui/app.rs` (cycle, title, length) and render a per-file table plus hash/error detail in `src/tui/tabs/threats.rs` (FR-018)
- [X] T032 [US4] Update TUI tests and hints for the three-view cycle in `src/tui/app.rs`, `src/tui/mod.rs`, and `src/tui/tabs/threats.rs`
- [X] T033 [US4] Update the clean-traffic test to distinguish attack findings from integrity notes in `tests/threat_tests.rs`

**Checkpoint**: All four user stories are independently functional.

---

## Phase 7: Polish and cross-cutting concerns

- [X] T034 [P] Update `README.md`: sliding windows, `[integrity]`, custody block, ATT&CK, Inputs view, limitations, status, and test count
- [X] T035 [P] Update `docs/analysis-config.example.toml` with the window and integrity keys
- [X] T036 [P] Update `CHANGELOG.md` and `docs/roadmap.md` for the completed v0.3.0 work
- [X] T037 Bump `Cargo.toml` to `0.3.0` and refresh `Cargo.lock`
- [X] T038 Run `cargo fmt`, pedantic `cargo clippy`, `cargo test --all-targets --locked`, and `cargo build --release --locked`; fix all findings
- [X] T039 Run the `quickstart.md` scenarios against the release binary and record any deviation

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; blocks all stories.
- **US1 (Phase 3)**: after Foundational; verifies existing ingestion.
- **US2 (Phase 4)**: after Foundational and T003/T004/T007; independent of US1.
- **US3 (Phase 5)**: after Foundational and T005/T006/T009; independent of US2.
- **US4 (Phase 6)**: after Foundational and T003; T028 depends on T005 for input errors; T031 depends on T005.
- **Polish (Phase 7)**: after all stories.

## Parallel Opportunities

- T003–T005 touch different files/models and can run together.
- US2 test/fixture tasks (T014, T015) are parallel; T016 and T017 touch different detectors.
- US3 tests (T021, T026) are parallel with export work in different files.
- T034–T036 are parallel documentation edits.

## Implementation Strategy

MVP is US2 + US3: accurate sub-hour detection and a verifiable report. US1 is a
verification pass over shipped code; US4 completes attribution and TUI
provenance. Each phase ends with its test subset green before the next starts.
