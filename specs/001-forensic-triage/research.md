# Research: Forensic Triage for Rotated and Compressed UFW Logs

## Sliding-window detection

**Decision**: Evaluate each heuristic over a per-detector window expressed in
minutes (`scan_window_minutes`, `bruteforce_window_minutes`,
`distributed_window_minutes`; default 60). For every key (source, or target+port
for distributed brute force), sort the relevant entries by timestamp and walk
them with two pointers while keeping a counter map. When the window count (or
distinct port/host/source count) reaches the existing threshold, record a hit
with `start = oldest timestamp in the window` and `end = newest timestamp`, then
clear the window and continue. Hits are grouped per key into one finding with
`occurrences`, `peak`, and exact first/last timestamps.

**Rationale**: The two-pointer scan is O(n log n) per detector and needs only the
entries already in memory. Resetting after each hit yields deterministic,
non-overlapping occurrences and avoids thousands of near-duplicate findings for
one continuous burst. Keeping the legacy `*_per_hour` key names preserves FR-015;
they now mean "per configured window", documented in README and the example TOML.

**Alternatives considered**:

- One-minute buckets plus rolling sums: cheaper per entry but approximates the
  boundary and loses exact start/end timestamps.
- Fully overlapping windows reported individually: more precise but produces a
  finding per entry after the threshold, which is unusable in a report.
- Renaming the keys to `*_per_window`: breaks existing TOML files (FR-015).

## Exact finding timestamps

**Decision**: Add `first_timestamp`/`last_timestamp` (`NaiveDateTime`) to
`ThreatFinding` and keep `first_seen`/`last_seen` (`NaiveDate`) for existing
consumers. Integrity findings use the requested range boundaries.

**Rationale**: FR-007/FR-009 require second precision, while existing Markdown,
TUI, and JSON consumers read the date fields. Additive fields satisfy both.

**Alternatives considered**: Replacing the date fields (breaking), or deriving
timestamps during export (loses information for integrity findings).

## ATT&CK mapping

**Decision**: `ThreatKind::technique()` returns `Some("T1046")` for port scan,
`Some("T1018")` for host sweep, `Some("T1110")` for brute force and distributed
brute force, and `None` otherwise. The finding stores
`technique: Option<String>`, serialized as `null` when absent.

**Rationale**: FR-010 requires identifiers only where defensible; persistence and
integrity findings have no clean technique. A central method prevents divergent
mappings.

**Alternatives considered**: A configuration table (unnecessary degrees of
freedom), or emitting "T1078"-style guesses for persistence (violates honesty).

## Coverage anomalies as findings

**Decision**: Add `[integrity]` thresholds (`missing_hours = 24`,
`out_of_order_lines = 10`, `future_entries = 1`; `0` disables a check). When
exceeded, emit `MissingHours` (Low), `OutOfOrderEntries` (Low), and
`FutureDatedEntries` (Medium) findings in the same section as attack findings.
Each unreadable input also emits an `InputError` (Medium) finding naming the file
and the failure reason.

**Rationale**: FR-011 requires promotion while keeping the coverage summary. Low
severity keeps evidence-quality notes below attack findings in the ranking.
Absolute defaults are documented; the fixture ranges remain manageable.

**Alternatives considered**: Percentage-of-range thresholds (harder to explain),
or always-on findings (too noisy for sparse logs).

## Chain of custody

**Decision**: Build a `CustodyManifest` at analysis time containing
`generated_at` (UTC), best-effort `hostname`, `tool_version`, `config_sha256`,
the serialized effective configuration (`effective_config`), the ordered
`EvidenceFile` records (path, size, SHA-256, parse stats, error, cache flag), and
a fixed `disclaimer`. The configuration hash is SHA-256 over the serialized
effective TOML, so defaults participate and the exact settings are visible to a
reviewer. Hostname is read from `/proc/sys/kernel/hostname`, then `/etc/hostname`,
then `$HOSTNAME`.

**Rationale**: The manifest is reproducible from the effective config and the
bytes read. Hashing the serialized effective config includes every default and
omitted key, unlike hashing the raw file. Reading local files is read-only and
unprivileged.

**Alternatives considered**: Hashing the raw config file (misses defaults and
differs for equivalent configs), or adding a `hostname` crate (avoidable
dependency).

## Cache keying

**Decision**: Keep the existing per-file cache key (canonical path hash + size +
mtime + cache/parser versions) and the SHA-256 verification. An added, removed,
or modified rotated file changes the resolved input set and therefore the report;
unchanged files remain cached.

**Rationale**: FR-014 is satisfied at the file level and avoids invalidating a
large unchanged base log when one rotated sibling changes. This is strictly
better than a single aggregate cache file.

**Alternatives considered**: An aggregate cache keyed by the ordered input list
(simpler invalidation but re-parses every file on any change).

## TUI provenance

**Decision**: Extend the Threats tab to cycle Sources → Networks → Inputs with
`v`, showing one row per input file with size, parsed blocks, cache state, and
error status; the detail pane shows path, SHA-256, and failure reason.

**Rationale**: FR-018 requires per-file coverage and input errors to be visible;
the custody manifest already carries the data, so the TUI reuses it without a
second read of the files.
