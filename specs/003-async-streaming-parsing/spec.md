# Feature Specification: Asynchronous and Streaming Parsing for Large Log Sets

**Feature Branch**: `003-async-streaming-parsing`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Keep the TUI responsive and memory bounded while parsing large and rotated log sets."

## Current Baseline (2026-11-24)

Parsing and analysis are synchronous. Rotated and gzip-compressed files are
already ingested in one combined stream, but the whole log set is read into
memory before the TUI becomes usable. A multi-gigabyte set blocks the UI and can
exhaust memory. Risks 2 and 7 in [`docs/risk-analysis.md`](../../docs/risk-analysis.md)
describe the current exposure.

This feature changes when and how the existing analysis is executed. It does not
change the detection heuristics or the export schemas.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Keep working while a large log set loads (Priority: P1)

An investigator opens a rotation set that takes a long time to parse. The TUI
opens immediately, shows progress, and continues to respond to navigation while
the analysis completes. They can watch partial aggregates appear instead of
staring at a frozen terminal.

**Why this priority**: A frozen UI looks like a crash and prevents the investigator
from doing anything else with the tool. Responsiveness is the minimum viable
outcome.

**Independent Test**: Parse a fixture large enough to take several seconds, and
verify that the UI accepts navigation and redraws while parsing is still in
progress, then settles into the complete result.

**Acceptance Scenarios**:

1. **Given** a large input set, **When** the tool starts, **Then** the TUI appears
   before parsing completes and shows a progress indicator.
2. **Given** parsing in progress, **When** the user presses navigation keys,
   **Then** the UI responds within the stated latency target and does not block.
3. **Given** parsing in progress, **When** partial results are available, **Then**
   the views that can be computed incrementally show them and label them as
   partial.
4. **Given** parsing completes, **When** the final result is ready, **Then** the
   views switch to the complete result without losing keyboard focus.

---

### User Story 2 - Analyze logs that do not fit in memory (Priority: P2)

A responder has a compressed rotation set whose expanded contents exceed the
available memory on a small VPS. They set a memory budget and expect the tool to
stay within it, either by using temporary on-disk storage or by keeping a bounded
raw sample. If raw evidence is incomplete, the tool says so and refuses a full
raw export rather than silently dropping entries.

**Why this priority**: Producing no report at all is worse than producing a
useful aggregate with an explicit raw-evidence limitation. The tool must never
misrepresent incomplete evidence as complete.

**Independent Test**: Run a fixture with many entries under a deliberately small
memory budget. Confirm that peak memory stays within the budget, that aggregates
and findings remain correct, and that any raw-evidence limitation is reported.

**Acceptance Scenarios**:

1. **Given** a memory budget, **When** the analysis runs, **Then** peak resident
   memory stays at or below the configured budget for the fixture.
2. **Given** the budget forces a degraded raw view, **When** the user opens Raw,
   **Then** the view is explicitly labeled as partial and shows how many entries
   are available.
3. **Given** a degraded raw view, **When** the user requests a full entry export,
   **Then** the tool refuses with an actionable message that names the budget and
   the available alternatives.
4. **Given** a budget large enough for the whole input, **When** the analysis
   runs, **Then** the result is identical to the current synchronous output.

---

### User Story 3 - Cancel a long analysis without leaving damage (Priority: P3)

The investigator realizes they selected the wrong rotation set. They cancel the
run; the tool stops promptly, restores the terminal, and leaves no partial export
or corrupt cache behind.

**Why this priority**: Long-running work must be interruptible, especially on a
host under investigation. A partial cache can poison later runs.

**Independent Test**: Start parsing a large fixture, cancel mid-run, and verify
that the process exits promptly, the terminal is restored, no output file is
partially written, and the next run starts from a valid cache state.

**Acceptance Scenarios**:

1. **Given** parsing in progress, **When** the user cancels, **Then** the tool stops
   within the stated cancellation target and restores the terminal.
2. **Given** cancellation during a cache write, **When** the process exits, **Then**
   the previous cache remains valid or no cache is written.
3. **Given** cancellation before an export finishes, **When** the process exits,
   **Then** no partial destination file is presented as complete.
4. **Given** a cancelled run, **When** the user starts again, **Then** the analysis
   recomputes from a valid state and does not read truncated data.

### Edge Cases

- A single very long line, a file with no final newline, or a malformed timestamp.
- A corrupt `.gz` encountered after partial results have already been displayed.
- A file that changes or disappears while it is being read.
- The cache being written while another process reads or writes the same cache.
- Cancellation at the exact moment the cache is renamed into place.
- A terminal resize while parsing is in progress.
- Exports requested before parsing completes.
- A memory budget smaller than the minimum needed for one file's metadata.
- A run with no TUI (CSV/JSON/findings export) where progress must go to stderr.
- A panic or signal during background work; the terminal must still be restored.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Parsing and analysis MUST run independently of the UI event loop so
  that the TUI remains responsive while work is in progress.
- **FR-002**: The tool MUST report progress while parsing, including at least the
  current file, files completed, entries or bytes processed, and elapsed time.
- **FR-003**: Progress updates MUST be delivered at least once per second.
- **FR-004**: The user MUST be able to cancel an in-progress analysis from the TUI
  and from the terminal (for example, `Ctrl+C`), with a bounded stop time.
- **FR-005**: Cancellation MUST NOT leave a partial export presented as complete,
  and MUST NOT corrupt an existing valid cache.
- **FR-006**: The tool MUST support a configurable memory budget for analysis and
  MUST keep peak resident memory within that budget on the reference fixture.
- **FR-007**: The tool MUST NOT silently drop parsed entries when the budget is
  reached. It MUST either keep the data in bounded temporary storage or clearly
  mark the raw evidence as partial and restrict exports accordingly.
- **FR-008**: Aggregates, findings, and coverage MUST remain correct for the full
  input whenever the budget allows complete processing.
- **FR-009**: If raw evidence is partial, every affected view and export MUST carry
  an explicit, machine-readable partial-evidence marker and a human-readable
  explanation.
- **FR-010**: The final result MUST be deterministic and identical to the current
  synchronous result for the same input and configuration when no budget-driven
  degradation occurs.
- **FR-011**: Cache reads and writes MUST remain atomic and safe under interruption.
  A cache format change MUST bump the cache version and invalidate older entries
  cleanly.
- **FR-012**: Non-interactive runs (CSV, JSON, findings) MUST write progress to
  stderr and keep stdout reserved for the requested output.
- **FR-013**: Background work MUST preserve the existing panic behavior: the
  terminal is restored and the original panic hook is reinstalled.
- **FR-014**: The feature MUST remain offline and read-only. It MUST NOT execute
  `ufw`, change firewall state, or open a network connection.
- **FR-015**: Existing CLI flags, exit codes, output schemas, TUI navigation, and
  configuration keys MUST remain valid. New budget and progress controls are
  additive.
- **FR-016**: The analysis MUST expose a machine-readable completion status
  (complete, partial, cancelled, failed) in the report and exports.
- **FR-017**: The reference performance targets MUST be documented and verified:
  UI input latency under 100 ms during parsing, first usable result under 2 s on
  the reference fixture, and cancellation within 1 s.

### Key Entities *(include if feature involves data)*

- **Analysis Job**: A running parse/analysis operation. Attributes: input set,
  phase, progress counters, elapsed time, status, cancellation flag, and memory
  budget.
- **Progress Snapshot**: A consistent set of counters safe to render from the UI:
  current file, files completed, bytes read, entries parsed, elapsed time, and
  estimated remaining work.
- **Completion Status**: One of complete, partial, cancelled, or failed, with the
  reason and the affected evidence.
- **Memory Budget**: The configured limit for analysis memory and the policy used
  when it is reached (temporary storage or bounded raw sample).
- **Partial Evidence Marker**: A flag and explanation attached to views and
  exports when raw evidence is incomplete.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: During parsing of the reference large fixture, UI navigation is
  handled in under 100 ms in 100% of sampled interactions.
- **SC-002**: The first usable result appears in under 2 s on the reference
  fixture, even when the full parse takes longer.
- **SC-003**: Peak resident memory stays at or below the configured budget for a
  fixture with at least five million entries.
- **SC-004**: Cancellation stops the run within 1 s, restores the terminal, and
  leaves no partial export or corrupt cache in 100% of cancellation tests.
- **SC-005**: When no degradation occurs, the final report is byte-for-byte
  equivalent in its logical content to the synchronous baseline for every fixture.
- **SC-006**: Every partial or cancelled result carries an explicit status and
  explanation in both the TUI and the exports.
- **SC-007**: Progress updates arrive at least once per second for runs longer than
  two seconds.
- **SC-008**: Existing tests, flags, and schemas continue to pass, and the required
  quality gates pass.

## Dependencies

- The multi-file and gzip ingestion from v0.3.0 phase 2 is the input path. This
  feature changes execution, not file discovery.
- The custody manifest from 001 should record the completion status and any partial
  evidence marker.
- A background worker plus a message channel is sufficient; a full async runtime is
  not required. The plan chooses the concurrency mechanism.
- Temporary storage, if used, lives in the user's cache or temporary directory and
  is cleaned up on normal exit and after cancellation.

## Out of Scope

- Distributed or multi-host parsing.
- Changing detection thresholds or heuristic behavior.
- GPU acceleration.
- Streaming data from a network socket or a running daemon.
- A new database or service dependency.
- Real-time tailing of a log that is still being written (separate feature).

## Assumptions

- The reference fixture and the exact budget default are defined during planning
  and documented with the performance targets.
- The target host may have limited memory but has a writable cache or temporary
  directory.
- Users accept a bounded raw view if the alternative is an out-of-memory failure,
  provided the limitation is explicit.
- Exports remain file-based and atomic; no partial file is ever presented as a
  complete report.
- The existing cache can be versioned and invalidated; preserving old cache files
  is not a requirement.
