# Feature Specification: Incident Isolation and Filtered Evidence Export

**Feature Branch**: `002-incident-isolation`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Isolate an incident from the TUI and export filtered evidence with reproducible filters."

## Current Baseline (2026-11-24)

The TUI already provides Overview, Daily, Hourly, Raw, and Threats views with
keyboard navigation. CSV/JSON entry exports and JSON/Markdown findings exports
exist, and the analysis already accepts a date range. What is missing is a way to
narrow the working set to an incident (time window, source, network, port, or
protocol) without re-running the tool or exporting the entire log.

This feature builds on the custody manifest defined by
[`specs/001-forensic-triage/spec.md`](../001-forensic-triage/spec.md). It can be
implemented after 001, or in parallel if the filter block is added explicitly.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Isolate a time window from Daily or Hourly (Priority: P1)

An investigator sees a spike in the Daily view. They select that day, press the
isolate action, and the rest of the views show only that day. In Hourly they
narrow it to a single hour. A visible filter indicator shows what is active, and
they can clear it to return to the full analysis.

**Why this priority**: Time is the first dimension of every incident. It is the
smallest useful slice and it does not require any new data source.

**Independent Test**: Use a fixture spanning three days with a spike on one day.
Select the spike day, isolate it, and confirm that Overview, Raw, and Threats only
show entries from that day. Clear the filter and confirm the original counts
return.

**Acceptance Scenarios**:

1. **Given** the Daily view with a selected day, **When** the user isolates it,
   **Then** every view reflects only that day and the header shows the active
   filter.
2. **Given** an isolated day, **When** the user opens Hourly and isolates an hour,
   **Then** the filter narrows to that day and hour without reloading the log.
3. **Given** an active filter, **When** the user clears it, **Then** the full
   analysis returns and the original counts are restored exactly.
4. **Given** an active filter that matches no entries, **When** the user navigates
   the views, **Then** the empty state is explicit and the tool does not crash or
   silently show unfiltered data.

---

### User Story 2 - Isolate a source or network from Threats (Priority: P2)

While reviewing the Threats tab, the investigator selects a source or a network
group and isolates its activity. The table and the raw evidence now contain only
that source or group, and the active filter states exactly which one is selected.

**Why this priority**: Threat findings point at a source; the next step is always
"show me everything that source did".

**Independent Test**: Use the distributed brute-force fixture. Select one source in
Threats, isolate it, and confirm that 100% of exported raw rows match that source
and that a network isolation groups the expected addresses.

**Acceptance Scenarios**:

1. **Given** a selected source in the Threats source view, **When** the user
   isolates it, **Then** only entries from that source remain and the filter label
   names the address.
2. **Given** a selected network group in the Threats network view, **When** the
   user isolates it, **Then** only entries inside that CIDR remain.
3. **Given** an isolated source, **When** the user switches to the network view,
   **Then** the filter remains active and does not silently widen the result.

---

### User Story 3 - Export filtered evidence with a reproducible filter (Priority: P3)

The investigator exports the isolated entries and findings. The export records the
filter criteria, the input files and hashes, the matched and total counts, and the
exact CLI invocation that reproduces the same slice. Another analyst can rerun that
command and get the same evidence without using the TUI.

**Why this priority**: Evidence must be reproducible and must not depend on a
sequence of keystrokes that nobody recorded.

**Independent Test**: Isolate a source and hour in the TUI, export CSV and findings,
then run the displayed CLI command. Compare the exported entry count and the filter
manifest.

**Acceptance Scenarios**:

1. **Given** an active filter, **When** the user exports CSV or JSON entries,
   **Then** only matching entries are written and the existing column/schema
   contract is preserved.
2. **Given** an active filter, **When** the user exports findings, **Then** the
   report includes the filter criteria and the matched/total counts.
3. **Given** an active filter, **When** the user views the reproduction hint,
   **Then** it shows the equivalent non-interactive command with the same
   `--from`, `--to`, source, port, protocol, and direction values.
4. **Given** the same filter applied through the CLI, **When** the analysis runs,
   **Then** the entry count and the matched findings are identical to the TUI
   result.

### Edge Cases

- A filter that matches only allowlisted sources: the entries remain visible, the
  findings and scores stay filtered as today, and the report explains the
  difference.
- A source filter that is an IPv6 address or an IPv6 `/64` group.
- A network filter that spans multiple `/24` or `/64` groups.
- A time filter at second precision that starts or ends inside an hour.
- A filter combined with the existing date range, where the intersection is empty.
- A filter that matches entries only in a rotated or compressed file.
- An export path that already contains different content; the tool must not
  overwrite it silently.
- A filter applied while the analysis is still parsing (once 003 ships).
- A terminal that is too narrow to show the full filter label.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Users MUST be able to isolate the selected day in Daily and the
  selected day/hour in Hourly without re-reading the log.
- **FR-002**: Users MUST be able to isolate the selected source or network group in
  the Threats source and network views.
- **FR-003**: The available filter dimensions MUST include time range, source IP or
  CIDR, network group, destination port, protocol, and direction. Filters combine
  with AND semantics.
- **FR-004**: The active filter MUST be visible in every view, and clearing it MUST
  restore the full analysis with the original counts.
- **FR-005**: Filtering MUST NOT modify the source entries, the cache, or the
  original findings. It selects a view over existing data.
- **FR-006**: Findings shown under a filter MUST be the full-analysis findings that
  intersect the filtered evidence. The tool MUST NOT silently recompute risk
  scores on the reduced slice and present them as equivalent.
- **FR-007**: Existing CSV, JSON, and Markdown exports MUST operate on the filtered
  set without changing their schemas. Empty results MUST still produce a valid
  export with zero rows.
- **FR-008**: Findings exports MUST include a filter block with the criteria, the
  matched entry count, the total entry count before filtering, and the input
  provenance from the custody manifest.
- **FR-009**: The TUI MUST display a non-interactive command that reproduces the
  active filter through the CLI.
- **FR-010**: The CLI MUST expose equivalent filter options for time, source/CIDR,
  network, port, protocol, and direction, so every TUI isolation is reproducible
  without the TUI.
- **FR-011**: Filtering MUST be read-only and offline; it MUST NOT execute `ufw`,
  change firewall state, or open a network connection.
- **FR-012**: Filtering a dataset that already fits in memory MUST complete fast
  enough to feel interactive (target: under 100 ms for 1 million entries on the
  reference fixture).
- **FR-013**: The tool MUST reject invalid filters (malformed CIDR, invalid port,
  unknown protocol, reversed time range) with an actionable message and a non-zero
  exit code.
- **FR-014**: Exports MUST preserve the existing overwrite protection: a different
  file at the destination is not replaced silently.
- **FR-015**: The filter MUST NOT change the default behavior when no filter is
  supplied.

### Key Entities *(include if feature involves data)*

- **Incident Filter**: The active selection. Attributes: start and end timestamps,
  source IP or CIDR, network group, destination port, protocol, direction, and the
  view that created it.
- **Filtered View**: The selected subset of entries and findings, with matched and
  total counts. It references the original analysis and does not own or mutate it.
- **Reproduction Command**: The non-interactive CLI invocation equivalent to the
  active filter.
- **Filter Manifest**: The filter block included in exports, with criteria, counts,
  input provenance, tool version, and execution timestamp.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Selecting a day and isolating it produces entry counts that match the
  fixture for that day, with zero rows from other days.
- **SC-002**: Isolating a source produces an export in which 100% of rows match
  that source, and isolating a network produces only addresses inside the CIDR.
- **SC-003**: Clearing a filter restores the original counts exactly in 100% of
  tested views.
- **SC-004**: The displayed CLI equivalent, when executed, produces the same entry
  count and the same matched findings as the TUI filter in 100% of fixture cases.
- **SC-005**: Every filtered findings export includes the filter criteria, matched
  and total counts, and input provenance.
- **SC-006**: An empty filter result produces a valid zero-row export and an
  explicit empty state, without crashing or showing unfiltered data.
- **SC-007**: Filtering 1 million in-memory entries completes in under 100 ms on the
  reference fixture.
- **SC-008**: Existing unfiltered behavior and all export schemas continue to pass
  their tests, and the required quality gates pass.

## Dependencies

- The custody manifest from 001 is the preferred source of input provenance. If
  002 ships first, the filter manifest includes the same fields and 001 reuses them.
- Filtering operates on the in-memory analysis. It does not re-read rotated files
  and does not require a new cache format.
- Protocol matching uses the normalized protocol names already produced by the
  parser; direction matching uses the existing `IN`/`OUT` semantics.

## Out of Scope

- Automatic incident detection or clustering.
- Case management, notes, tags, or saved filters.
- Cross-host or remote evidence collection.
- Recomputing risk scores or thresholds on the filtered slice.
- Packet capture or payload inspection.
- Generating firewall rules from a filter.

## Assumptions

- A single source or network filter is supported in this iteration. Multiple
  independent sources are out of scope.
- Time filtering uses inclusive start and end boundaries at second precision.
- Findings are not recomputed on the filtered slice. The tool presents the
  intersection of the full analysis and the filter.
- Investigators already use the Daily, Hourly, and Threats views and understand the
  existing date range.
- The TUI can display a compact filter indicator and a reproduction hint without
  disrupting the current layout.
- Exports remain file-based; no server, daemon, or remote API is introduced.
- The feature does not change the analysis engine or the scoring model.
