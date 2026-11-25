# Data Model: Forensic Triage for Rotated and Compressed UFW Logs

All changes are additive to the existing public JSON schema except where noted.

## ThreatKind (extended enum)

| Variant | Label | ATT&CK | Origin |
| --- | --- | --- | --- |
| `PortScan` | Port scan | `T1046` | sliding-window distinct ports per source |
| `HostSweep` | Host sweep | `T1018` | sliding-window distinct destinations per source |
| `BruteForce` | Brute force | `T1110` | sliding-window admin-port attempts per source |
| `DistributedBruteForce` | Distributed brute force | `T1110` | sliding-window distinct sources per target+port |
| `PersistentSource` | Persistent source | none | active days + blocks |
| `MissingHours` | Missing log hours | none | coverage anomaly |
| `OutOfOrderEntries` | Out-of-order log lines | none | parser counters |
| `FutureDatedEntries` | Future-dated log entries | none | parser counters |
| `InputError` | Input error | none | unreadable/partial input |

`ThreatKind::technique() -> Option<&'static str>` is the single mapping source.
`ThreatKind::ALL` contains all nine variants.

## ThreatFinding (extended)

| Field | Type | Constraint / rule |
| --- | --- | --- |
| `kind` | `ThreatKind` | required |
| `source_ip` | `Option<String>` | primary source; `None` for distributed and integrity findings |
| `target_ip` | `Option<String>` | destination host when one is identifiable |
| `target_port` | `Option<u16>` | destination port when one is identifiable |
| `sources` | `Vec<String>` | distinct sources involved (distributed findings, capped at 32, sorted) |
| `ports` | `Vec<u16>` | distinct destination ports involved (capped at 32, sorted) |
| `protocols` | `Vec<String>` | distinct protocols involved (capped at 8, sorted) |
| `first_seen` | `NaiveDate` | date of `first_timestamp`; kept for compatibility |
| `last_seen` | `NaiveDate` | date of `last_timestamp`; kept for compatibility |
| `first_timestamp` | `NaiveDateTime` | exact start, second precision |
| `last_timestamp` | `NaiveDateTime` | exact end, second precision; `>= first_timestamp` |
| `occurrences` | `u32` | number of non-overlapping hit windows grouped in this finding |
| `peak` | `u64` | maximum count or distinct value observed in one window/day |
| `evidence` | `String` | human-readable explanation naming the window |
| `severity` | `Severity` | attack findings as today; integrity findings Low/Medium |
| `technique` | `Option<String>` | `T1046`/`T1018`/`T1110`; `None` otherwise |

Validation: constructors derive `first_seen`/`last_seen` from the timestamps so
they cannot drift. For integrity findings, timestamps span the requested range
(`from` 00:00:00 to `to` 23:59:59).

## CustodyManifest (new)

| Field | Type | Constraint / rule |
| --- | --- | --- |
| `generated_at` | `DateTime<Utc>` | execution time, RFC 3339 in JSON |
| `hostname` | `Option<String>` | best effort; `None` when unavailable |
| `tool_version` | `String` | compile-time crate version (`CARGO_PKG_VERSION`) |
| `config_sha256` | `String` | lowercase hex SHA-256 of the serialized effective config |
| `effective_config` | `String` | serialized effective TOML (window widths, thresholds, allowlist) |
| `files` | `Vec<EvidenceFile>` | ordered as resolved by the CLI; includes failures |
| `disclaimer` | `String` | fixed heuristic-triage / non-legal-proof text |

`EvidenceFile` is unchanged: `path`, `canonical_path`, `sha256`, `size_bytes`,
`decompressed_bytes`, `modified_at`, `compressed`, `from_cache`, `parse_stats`,
`error`. An unreadable file keeps an empty `sha256` and a populated `error`.

## ThreatReport (extended)

New field: `custody: CustodyManifest`. Existing `from`, `to`, `profiles`,
`findings`, `subnets`, `coverage`, and `summary` keep their meaning.

## AnalysisConfig (extended)

### `[thresholds]`

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `scan_window_minutes` | `u32` | `60` | `1..=10080` |
| `bruteforce_window_minutes` | `u32` | `60` | `1..=10080` |
| `distributed_window_minutes` | `u32` | `60` | `1..=10080` |

Existing `scan_ports_per_hour`, `scan_hosts_per_hour`,
`bruteforce_attempts_per_hour`, `bruteforce_attempts_per_day`, and
`distributed_sources_per_hour` keep their names and defaults; they now apply to
the configured window (default 60 minutes).

### `[integrity]` (new)

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `missing_hours` | `u32` | `24` | `0` disables; finding when `coverage.missing_hours >= value` |
| `out_of_order_lines` | `u64` | `10` | `0` disables; finding when `stats.out_of_order_lines >= value` |
| `future_entries` | `u64` | `1` | `0` disables; finding when `stats.future_entries >= value` |

All keys are optional via `#[serde(default)]`; invalid windows are rejected by
`AnalysisConfig::validate()` with the key name in the message.

## Input File Record (existing)

Unchanged. The custody manifest embeds the same records so JSON consumers see
one canonical shape for per-file provenance.

## Coverage Summary (existing)

Unchanged; integrity findings are derived from it and from `ParseStats` after
coverage is computed.
