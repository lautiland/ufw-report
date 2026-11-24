# Feature Specification: Forensic Triage for Rotated and Compressed UFW Logs

**Feature Branch**: `001-forensic-triage`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Add forensic triage for rotated and compressed UFW logs: multi-file and .gz ingestion, second-precision timestamps, sliding-window heuristics, chain-of-custody metadata, and MITRE ATT&CK mapping where defensible. Keep the tool offline and read-only."

## Current Baseline (2026-11-24)

The repository is already partway through v0.3.0. This specification describes the
complete target behavior; the plan MUST verify the baseline instead of
reimplementing it.

Already present on `main`:

- Second-precision timestamps across parsing, cache, aggregation, and export
  (`d8d5e5c`).
- Repeatable `--log-file`, `--include-rotated`, streaming gzip, per-file SHA-256,
  per-file parse counters, file-level deduplication, a decompressed-size limit
  (4 GiB by default, `--max-decompressed-bytes`), and partial-read error reporting
  (`123f54c`).
- Coverage counters for missing hours, out-of-order lines, and future-dated
  entries.

Still missing or needing verification in the plan:

- Sliding-window heuristics: scan, sweep, brute force, and distributed brute force
  still use fixed hourly buckets.
- Chain-of-custody manifest in the findings exports, including execution metadata
  and a configuration hash.
- MITRE ATT&CK identifiers on findings.
- Promotion of coverage anomalies to integrity findings.
- Documentation and version alignment: `README.md`, `docs/actual-state.md`, and
  `Cargo.toml` still describe 0.2.1.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Analyze a complete rotation set in one run (Priority: P1)

An incident responder arrives at a Linux host whose UFW log has rotated several
times. They need one chronological analysis of `ufw.log`, `ufw.log.1`, and
`ufw.log.2.gz`, without manually decompressing or concatenating files. They ask
the tool to discover the rotated siblings, or list the files explicitly, and
receive a single report that accounts for every input.

**Why this priority**: Rotated logs are the normal state of a real host. Without
this, the investigator silently analyzes only the newest slice and may miss the
beginning of an incident. It is the foundation for every later forensic feature.

**Independent Test**: Run the tool against a fixture set containing a base log, a
numbered rotation, and a gzip-compressed rotation. Confirm that all three files
appear in the report with their own parse counters, that entries are merged in
chronological order, and that the combined count matches the fixture.

**Acceptance Scenarios**:

1. **Given** a base log and rotated siblings (including `.gz`), **When** the user
   enables rotated-file discovery, **Then** all readable siblings are ingested and
   listed individually in the report.
2. **Given** the same files, **When** the user lists them explicitly, **Then** the
   result is identical to discovery mode and no file is read twice.
3. **Given** a rotation set where the same file is reachable through a relative
   path, an absolute path, and a symlink, **When** the analysis runs, **Then** the
   file is counted once and all of its entries appear once.
4. **Given** a rotation set containing a corrupt `.gz` file, **When** the analysis
   runs, **Then** the corrupt file is reported as an input error and as a coverage
   gap, the remaining files are still analyzed, and the run exits successfully when
   at least one input was readable.
5. **Given** two identical blocked packets recorded in the same second, **When**
   they are ingested from the same or different files, **Then** both entries are
   preserved and counted separately.

---

### User Story 2 - Detect short bursts that cross an hour boundary (Priority: P2)

A responder needs to know whether an aggressive scan or brute-force burst happened
even when it started at 10:59 and ended at 11:01. The current hourly buckets split
that burst in two and can hide it. The responder expects the tool to evaluate
activity over a configurable moving window and to report the exact interval.

**Why this priority**: Rotation coverage without accurate timing still produces
false negatives for short, high-intensity events, which are common in automated
attacks.

**Independent Test**: Run the tool against a fixture with a burst of attempts
spread across an hour boundary. Confirm that a finding is produced, that its start
and end timestamps match the fixture to the second, and that the same fixture
produces no finding when the window is set wider than the burst.

**Acceptance Scenarios**:

1. **Given** a burst of scan attempts that crosses an hour boundary, **When** the
   analysis runs with the default sliding window, **Then** a scan finding is
   produced with second-precision start and end timestamps.
2. **Given** the same burst, **When** the configured window is large enough to
   dilute the rate below the threshold, **Then** no finding is produced and the
   configuration used is visible in the report.
3. **Given** an entry sequence that is out of chronological order within a file,
   **When** entries are merged, **Then** the analysis orders them chronologically
   before evaluating windows and records the out-of-order count.
4. **Given** a daylight-saving transition in the log's local time, **When** entries
   around the transition are analyzed, **Then** the report does not silently
   reinterpret them and any ambiguity is surfaced as an evidence-quality note.

---

### User Story 3 - Produce a triage report with verifiable custody metadata (Priority: P3)

A responder must hand a report to a reviewer and show exactly which files were
read, what the tool's inputs were, and which evidence supports each finding. They
export the findings as JSON or Markdown and expect a custody block that another
person can verify with standard tools, plus a clear statement of the report's
limits.

**Why this priority**: A finding without provenance is hard to trust or reproduce.
This is what makes the output useful for triage handoff, without overstating it as
legal proof.

**Independent Test**: Export a report for a known fixture and verify that every
input file's SHA-256 matches `sha256sum`, that the execution timestamp, hostname,
tool version, and configuration hash are present, and that both formats include the
same custody block and disclaimer.

**Acceptance Scenarios**:

1. **Given** a completed analysis, **When** the user exports findings as JSON or
   Markdown, **Then** each readable input file appears with its path, size, SHA-256,
   and parse status.
2. **Given** the exported report, **When** a reviewer recomputes the hash of any
   input file with `sha256sum`, **Then** it matches the reported value.
3. **Given** a finding, **When** the reviewer reads it, **Then** it includes the
   exact start and end timestamps and, when applicable, the ports, protocols,
   sources, and destination host involved.
4. **Given** either export format, **When** the reviewer reads the header, **Then**
   it states that findings are heuristic triage indicators, that the hashes
   certify the bytes read during that execution only, and that the report is not a
   substitute for a full forensic investigation.
5. **Given** an input file that could not be read or decompressed, **When** the
   report is exported, **Then** the file is still listed with its failure reason and
   is not presented as successfully analyzed.

---

### User Story 4 - Attribute findings and surface evidence-quality problems (Priority: P4)

A responder wants findings mapped to a recognizable technique where the mapping is
defensible, and wants evidence-quality anomalies to appear as findings rather than
buried counters. They expect no invented ATT&CK identifier when no technique fits.

**Why this priority**: It improves communication and prioritization, but the
feature is still useful without it. It must not reduce trust by forcing incorrect
mappings.

**Independent Test**: Run fixtures for port scan, host sweep, brute force,
persistence, and coverage anomalies. Confirm the expected ATT&CK IDs, confirm that
persistence and integrity findings have no ID, and confirm that anomalies appear in
the findings section as well as the coverage summary.

**Acceptance Scenarios**:

1. **Given** a port-scan finding, **When** the report is generated, **Then** it
   carries `T1046`.
2. **Given** a host-sweep finding, **When** the report is generated, **Then** it
   carries `T1018`.
3. **Given** a brute-force or distributed brute-force finding, **When** the report
   is generated, **Then** it carries `T1110`.
4. **Given** a persistent-source finding or an evidence-integrity finding, **When**
   the report is generated, **Then** the ATT&CK field is empty rather than filled
   with a misleading identifier.
5. **Given** missing hours, out-of-order entries, or future-dated entries that
   exceed the documented severity threshold, **When** the analysis runs, **Then**
   each anomaly appears as an integrity finding with its time range and a severity.
6. **Given** an allowlisted source, **When** it matches a heuristic, **Then** it is
   excluded from findings and scores but remains in raw data and coverage.

### Edge Cases

- A rotation set where the base file does not exist but numbered or compressed
  siblings do.
- A `.gz` file that is truncated, has a bad checksum, or expands beyond the
  configured limit (decompression bomb).
- Files that are empty, contain only unrelated syslog lines, or use an unknown
  timestamp format.
- The same file selected twice through different paths, symlinks, or hard links.
- Overlapping content in two different rotated files: entries must not be
  deduplicated across files.
- A file whose size or modification time changes between metadata collection and
  reading.
- A log with no entries in the requested range, or a range entirely before the
  oldest retained file.
- IPv4 and IPv6 sources in the same rotation set, and mixed syslog/ISO timestamps.
- A hostname that cannot be resolved or a configuration file that cannot be read.
- A cache created before the feature existed, or a cache whose input set has
  changed through rotation.
- An allowlist or `min_score` configuration that hides all profiles while findings
  still exist.
- Extremely large rotation sets that exceed memory or time expectations.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Users MUST be able to select multiple input files explicitly and MUST
  be able to ask the tool to discover rotated siblings of a base log.
- **FR-002**: Rotated-file discovery MUST include the base log, numbered rotations,
  and gzip-compressed rotations that follow the host's normal log-rotation naming.
- **FR-003**: Compressed inputs MUST be decompressed as a stream, with a finite
  configurable limit per file. Exceeding the limit MUST be reported as an input
  error without exhausting memory or aborting the analysis of other files.
- **FR-004**: The tool MUST compute a SHA-256 digest over the raw bytes of every
  input file, in the same pass that reads it, and MUST record the digest in the
  report.
- **FR-005**: Input files MUST be deduplicated by identity (for example, canonical
  path or inode), not by log-entry equality. Repeated identical log lines MUST be
  preserved as distinct evidence.
- **FR-006**: Combined entries MUST be ordered chronologically before analysis, and
  per-file parse counters MUST remain attributable to their source file.
- **FR-007**: Log entries MUST retain second-level timestamps through parsing,
  aggregation, analysis, and export. Existing date/hour fields MUST remain
  available, or their removal MUST be documented as a breaking change.
- **FR-008**: Port scan, host sweep, brute force, and distributed brute force MUST
  be evaluated over configurable moving windows expressed in time units, with
  documented defaults.
- **FR-009**: Every finding MUST include its exact start and end timestamps and,
  when applicable, the ports, protocols, sources, and destination host involved.
- **FR-010**: Findings that map cleanly to a technique MUST carry `T1046` (port
  scan), `T1018` (host sweep), or `T1110` (brute force and distributed brute force).
  Persistence and evidence-integrity findings MUST leave the technique empty.
- **FR-011**: Missing hours, out-of-order entries, and future-dated entries that
  exceed the documented severity threshold MUST be promoted to evidence-integrity
  findings while remaining visible in the coverage summary.
- **FR-012**: JSON and Markdown findings exports MUST include a custody block with
  the readable input files, their SHA-256 digests, their parse status, the
  execution timestamp in UTC, the hostname (best effort), the tool version, and a
  hash of the effective configuration.
- **FR-013**: Both export formats MUST include an explicit disclaimer that findings
  are heuristic triage indicators, that hashes certify only the bytes read during
  that execution, and that the report is not a full forensic investigation.
- **FR-014**: The parse cache MUST be keyed by the ordered set of input files and
  their metadata (at minimum path, size, and modification time), plus the cache and
  parser versions. Adding, removing, or modifying a rotated file MUST invalidate
  the cache.
- **FR-015**: Existing CLI flags, exit-code behavior, CSV/JSON columns, Markdown
  findings structure, TOML keys, allowlist semantics, and `min_score` behavior
  MUST remain valid. New fields are additive; any breaking change MUST be
  documented in `README.md` and `CHANGELOG.md`.
- **FR-016**: The tool MUST remain offline and read-only: no `ufw` execution, no
  firewall changes, no network access, no telemetry, and no writes to log files.
- **FR-017**: Unreadable or corrupt inputs MUST be reported individually. If at
  least one input is readable, the analysis MUST continue and exit successfully
  with the errors recorded; if no input is readable, the tool MUST exit non-zero.
- **FR-018**: The TUI MUST present the combined entry set and make per-file
  coverage and input errors visible; it MUST NOT silently omit a selected input.
- **FR-019**: The tool MUST validate the effective configuration before analysis
  and MUST exit non-zero with a message that names the invalid file, key, and
  accepted value or range when a value is invalid.
- **FR-020**: The tool MUST NOT add external reputation, GeoIP, ASN, or remote
  lookups to enrich findings. All evidence remains local.

### Requirement Traceability

| Requirement | Primary user story | Success criteria |
| --- | --- | --- |
| FR-001 to FR-006, FR-017 | US1 — complete rotation set | SC-001, SC-003, SC-004 |
| FR-007, FR-008 | US2 — sub-hour detection | SC-002 |
| FR-009, FR-012, FR-013, FR-014 | US3 — custody metadata | SC-005, SC-010 |
| FR-010, FR-011 | US4 — attribution and integrity | SC-006 |
| FR-015, FR-016, FR-018, FR-019, FR-020 | Cross-cutting contracts and safety | SC-007, SC-008, SC-009 |

### Key Entities *(include if feature involves data)*

- **Input File Record**: A selected log file and its provenance. Attributes:
  display path, canonical identity, size, modification time, compression state,
  SHA-256 digest, read status, and per-file parse counters.
- **Log Entry**: One parsed UFW record with second-precision timestamp, source and
  destination addresses, source and destination ports, protocol, direction, and
  the input file it came from.
- **Finding**: A heuristic observation. Attributes: kind, severity, risk
  contribution, exact start and end timestamps, sources, destination host, ports,
  protocols, optional ATT&CK technique, and a human-readable explanation.
- **Coverage Summary**: Evidence-quality view. Attributes: hours in range, hours
  with data, missing hours, longest gap, out-of-order count, future-dated count,
  unparsed lines, and per-file status.
- **Custody Manifest**: Run-level provenance. Attributes: execution timestamp,
  hostname, tool version, configuration hash, ordered input file records, and the
  digest of every readable file.
- **Analysis Configuration**: Explicit thresholds, sliding windows, allowlist
  CIDRs, scoring weights, and input limits, with documented defaults.
- **Triage Report**: The complete result: summary, coverage, findings, source and
  network profiles, custody manifest, and disclaimer.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A rotation set of three files (base, `.1`, `.2.gz`) is analyzed in one
  invocation; 100% of readable inputs appear in the report with their own counters
  and hashes.
- **SC-002**: A fixture with a burst crossing an hour boundary produces a finding
  whose start and end timestamps match the fixture to the second; the same fixture
  does not produce that finding when the configured window is widened past the
  burst.
- **SC-003**: A corrupt `.gz` fixture does not abort the run when another input is
  readable; the corrupt file appears with a failure reason and a coverage gap in
  100% of runs.
- **SC-004**: Two identical packets in the same second are both present in the
  exported entries, and passing the same file twice yields the file's entries only
  once.
- **SC-005**: For every readable input file, a reviewer can reproduce the reported
  SHA-256 with standard `sha256sum`; the match rate is 100%.
- **SC-006**: Port scan, host sweep, and brute force findings carry `T1046`,
  `T1018`, and `T1110` respectively; persistence and integrity findings carry no
  ATT&CK identifier in 100% of fixture cases.
- **SC-007**: All existing behavior documented in `docs/actual-state.md` for
  v0.2.1 still passes its tests, or the breaking change is documented in
  `README.md` and `CHANGELOG.md` before release.
- **SC-008**: The required quality gates pass: formatting, pedantic linting, the
  full test suite, and a locked release build.
- **SC-009**: A compressed input that expands beyond the configured limit is
  rejected with an input error and without exhausting memory or terminating the
  process.
- **SC-010**: Both JSON and Markdown reports contain the custody manifest and the
  disclaimer, and a reviewer can identify every input, its hash, and the exact
  evidence behind each finding without reading source code.

## Out of Scope

- Deep egress (`OUT=`) threat analysis or command-and-control beacon detection.
- Passive fingerprinting (TCP flags, window size, TTL).
- Generating `ufw deny` commands or applying any firewall change.
- Packet capture, SIEM replacement, or a legally certified expert report.
- Asynchronous or whole-pipeline streaming aggregation (tracked for a later
  release).
- Distributed collection from multiple hosts.
- Compression formats other than gzip.
- Windows or macOS support.

## Assumptions

- UFW logs follow the host's normal rotation naming (`ufw.log`, `ufw.log.1`,
  `ufw.log.2.gz`, and similar), and gzip is the only compression format in scope.
- The investigator has read access to the logs and runs the tool on Linux; no
  elevated execution is required or requested.
- Timestamps are interpreted as recorded in the log. The tool does not silently
  convert between time zones; any ambiguity around local-time transitions is
  reported as an evidence-quality note.
- "Chain of custody" in this feature means run-level provenance and input
  integrity, not a legal certification.
- The SHA-256 digest covers the raw bytes read during that execution; it does not
  prove that a file was unchanged before or after the run.
- The default decompression limit is a conservative finite value and is
  configurable; the exact default is chosen during planning and documented.
- Existing allowlist and scoring semantics remain unchanged: allowlisted CIDRs are
  excluded from findings and scores but remain in raw data and coverage.
- The effective configuration is explicit through the existing configuration
  path; automatic discovery of configuration files remains unsupported.
- Performance work stays within the current synchronous, in-memory architecture;
  whole-pipeline streaming is not required for this feature.
