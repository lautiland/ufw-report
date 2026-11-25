# Risk Register for `ufw-report`

Risks are reviewed at every release. Each entry states the current mitigation,
or the planned mitigation when the risk is tied to an upcoming release, and what
to do if it materializes.

## Risk 1: Parser breakage due to log format changes

- **Category:** Technical
- **Description:** Parser breakage caused by changes in the UFW log format.
- **Causes:** Major Linux kernel, netfilter, or UFW updates that change the
  syslog syntax.
- **Consequences:** The TUI shows empty or incorrect data, or parsing stops
  early.
- **Probability:** Low
- **Impact:** Critical
- **Trigger:** GitHub issue reports from users on Ubuntu >= 26.04.
- **Mitigation:** The parser never panics on an unrecognized block line. It
  counts it as `unparsed_blocks`, and the coverage summary exposes that counter.
  The test suite keeps samples from multiple distribution versions.
- **Contingency:** Release a hotfix with the new format and add the sample as a
  fixture.
- **Notes:** The risk increases if non-Debian distributions are added.

## Risk 2: TUI freeze on very large logs

- **Category:** Performance
- **Description:** The TUI freezes while processing massive files.
- **Causes:** `ufw.log` grows to several gigabytes during a sustained DoS.
- **Consequences:** The main thread blocks, the interface stops responding, and
  the user must kill the process.
- **Probability:** High
- **Impact:** High
- **Trigger:** TUI response time above 2 seconds when switching tabs.
- **Mitigation:** The parse cache avoids reparsing unchanged logs, and parser
  counters make long runs observable before the UI starts. v0.3.0 adds streaming
  decompression, per-file progress counters, and configurable input limits. The
  remaining gap is asynchronous parsing with a bounded-memory mode, specified in
  [`specs/003-async-streaming-parsing/spec.md`](../specs/003-async-streaming-parsing/spec.md).
- **Contingency:** Document the `--no-cache` and export paths, use CSV/JSON
  export instead of the TUI for oversized logs, or analyze one rotated file at a
  time.
- **Notes:** Exposure increases with multi-file ingestion: reading several
  rotated `.gz` files at once can multiply the number of entries held in memory
  by 5x to 10x. The asynchronous/streaming work is specified in 003.

## Risk 3: False positives in the heuristics engine

- **Category:** Security / Functional
- **Description:** False positives in threat detection.
- **Causes:** Poorly calibrated parameters, or normal internal traffic that
  resembles scanning or brute force.
- **Consequences:** Loss of trust and alert fatigue.
- **Probability:** Medium
- **Impact:** Medium
- **Trigger:** More than 3 community reports of incorrect detections on local
  traffic.
- **Mitigation:** Every threshold is configurable through an explicit TOML file,
  CIDRs can be allowlisted, and `min_score` hides low-confidence profiles
  without discarding their raw data. Scores are labeled as risk indicators, not
  verdicts.
- **Contingency:** Ship a release with recalibrated defaults and document the
  per-environment overrides.
- **Notes:** Findings are derived only from the log, so context that is not in
  the log cannot be considered.

## Risk 4: False negatives from short bursts

- **Category:** Functional
- **Description:** A short burst that is diluted by a wide analysis window can
  fall below a rate threshold.
- **Causes:** Detection windows are configurable and default to 60 minutes; a
  burst spread over a longer period than the window is reported as separate
  occurrences.
- **Consequences:** A slow, low-rate scan may need a wider window or a lower
  threshold to be flagged.
- **Probability:** Low
- **Impact:** Medium
- **Trigger:** A reported incident that the tool did not flag.
- **Status:** Mitigated in v0.3.0.
- **Mitigation:** Sliding windows are evaluated on exact second-precision
  timestamps, so bursts crossing an hour boundary are detected as one event.
  Thresholds and window widths are configurable, and coverage plus risk ranking
  still surface high-volume sources without a finding.
- **Contingency:** Widen `*_window_minutes` or lower the relevant threshold in
  the config file for the affected environment.
- **Notes:** Fixtures cover bursts crossing the hour boundary and verify that a
  narrower window suppresses the finding. See
  [`specs/001-forensic-triage/quickstart.md`](../specs/001-forensic-triage/quickstart.md).

## Risk 5: Runtime failures due to `glibc` incompatibility

- **Category:** Distribution
- **Description:** Dynamically linked binaries fail on older systems.
- **Causes:** GNU builds require the glibc version of the build host.
- **Consequences:** `version 'GLIBC_2.XX' not found` blocks adoption.
- **Probability:** Low
- **Impact:** High
- **Trigger:** Failure reports for binaries downloaded from GitHub Releases.
- **Mitigation:** Every release ships a static
  `x86_64-unknown-linux-musl` binary, and GNU binaries are built on
  `ubuntu-22.04` to lower the glibc floor. The README marks musl as the
  recommended choice for old or air-gapped systems.
- **Contingency:** Point users to the musl tarball or to `cargo build --release`
  from source.
- **Notes:** Critical for air-gapped deployments that cannot install new
  libraries.

## Risk 6: Tampered or corrupt release artifacts

- **Category:** Supply chain
- **Description:** A downloaded binary does not match what CI produced.
- **Causes:** Truncated downloads, mirror interference, or a compromised
  release asset.
- **Consequences:** Users run unexpected code with access to firewall logs.
- **Probability:** Low
- **Impact:** High
- **Trigger:** A checksum mismatch, or a report of unexpected behavior from a
  release binary.
- **Mitigation:** The release workflow publishes a SHA256 file per tarball, the
  README documents `sha256sum -c`, and the tag is checked against `Cargo.toml`
  before publishing.
- **Contingency:** Delete the affected release, rotate credentials, and publish
  a new patch release with regenerated checksums.
- **Notes:** Checksums detect corruption; they do not replace signed releases.
  Signing is specified in
  [`specs/005-signed-releases/spec.md`](../specs/005-signed-releases/spec.md).

## Risk 7: Memory exhaustion on oversized logs

- **Category:** Performance
- **Description:** The process is killed by the OOM killer.
- **Causes:** All parsed entries are kept in memory for the TUI and exports, and
  multi-file ingestion adds the contents of every rotated `.gz` file to the same
  working set.
- **Consequences:** No report is produced and the failure can look like a crash.
- **Probability:** High
- **Impact:** High
- **Trigger:** A log set with millions of blocked entries across rotated files on
  a small VPS.
- **Mitigation:** The cache avoids reparsing, and exports can be produced without
  the TUI. Parse counters report progress. v0.3.0 adds streaming decompression,
  per-file processing, and configurable input limits. 003 adds asynchronous
  parsing and a configurable memory budget.
- **Contingency:** Analyze a narrower date range, one rotated file at a time, or
  a smaller input set.
- **Notes:** The entry count can grow 5x to 10x when several rotated files are
  read together. The bounded-memory and streaming work is specified in
  [`specs/003-async-streaming-parsing/spec.md`](../specs/003-async-streaming-parsing/spec.md).

## Risk 8: Terminal incompatibility in the TUI

- **Category:** Usability
- **Description:** The TUI renders incorrectly or traps the terminal.
- **Causes:** Terminals with limited color support, unusual dimensions, or a
  crash inside the alternate screen.
- **Consequences:** Unreadable output or a terminal left in raw mode.
- **Probability:** Low
- **Impact:** Low
- **Trigger:** Reports of garbled rendering or a broken prompt after exit.
- **Mitigation:** A panic hook restores the terminal and reinstalls the original
  hook. The TUI degrades when space is limited, and every view has a scrolling
  fallback. Non-interactive export paths avoid the TUI entirely.
- **Contingency:** Ask the user to reset the terminal (`reset`) and share
  terminal and size details.
- **Notes:** The Threat tab was smoke-tested with `TestBackend` in both views.

## Risk 9: Corrupted `.gz` files or decompression bombs

- **Category:** Technical / Performance
- **Description:** A rotated log cannot be decompressed, or a compressed file
  expands far beyond its expected size.
- **Causes:** `.gz` files truncated by an abrupt reboot, partially written
  archives, or malicious or oversized archives.
- **Consequences:** The analysis aborts, CPU or memory is exhausted, or part of
  the evidence is silently omitted.
- **Probability:** Medium
- **Impact:** High
- **Trigger:** A decompression error, an unusual expansion ratio, or a memory
  spike while reading a rotated file.
- **Mitigation:** Decompress in streaming mode with a configurable size limit and
  safe line-by-line reads. A corrupt `.gz` is recorded in the coverage counters
  and does not abort the analysis of the remaining files. No partial file is
  presented as complete evidence.
- **Contingency:** Skip the affected file, report it as a coverage gap, inspect
  the archive manually, and rerun the analysis with the remaining inputs.
- **Notes:** Size limits and failure behavior are specified in
  [`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md).

## Risk 10: Multi-file cache invalidation bugs

- **Category:** Technical / Functional
- **Description:** The parse cache returns stale or duplicated data when the
  input set contains more than one file.
- **Causes:** The cache is keyed by a single file (`<hash>.json`); a change in any
  rotated file, or a new rotation, can leave the key unchanged.
- **Consequences:** The report shows outdated or duplicated entries, which is
  especially dangerous in a forensic context.
- **Probability:** Medium
- **Impact:** High
- **Trigger:** A cache hit after a rotation, or duplicate counts in the coverage
  summary.
- **Mitigation:** Derive the cache key from the ordered set of `(path, size,
  mtime)` for every input file, or cache each file independently. Increment
  `cache_version` and add rotation add/remove/change tests.
- **Contingency:** Disable the cache with `--no-cache`, remove the cache
  directory, and rerun the analysis.
- **Notes:** Cache invalidation is part of
  [`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md) and
  must ship with the multi-file ingestion work.

## Risk 11: Misinterpretation of forensic reports as legal proof

- **Category:** Functional / Legal
- **Description:** Users treat the SHA-256 hashes and MITRE ATT&CK mapping as a
  complete judicial or disciplinary expert report.
- **Causes:** The report uses forensic terminology (chain of custody, evidence,
  hashes) that can suggest a stronger legal guarantee than the tool provides.
- **Consequences:** False confidence, reputational damage, or a report challenged
  in a legal or HR process.
- **Probability:** Medium
- **Impact:** High
- **Trigger:** A report is used in a legal or disciplinary process without
  independent validation.
- **Mitigation:** State explicitly in the `--findings` header (JSON and Markdown)
  and in the README that findings are heuristic triage indicators. The hash
  certifies the integrity of the input read during that execution; it does not
  prove that the file was not modified before or after. The tool is not a
  substitute for a full forensic investigation. The disclaimer and custody
  semantics are specified in
  [`specs/001-forensic-triage/spec.md`](../specs/001-forensic-triage/spec.md).
- **Contingency:** Clarify the scope in support responses and recommend
  independent forensic validation before any legal use.
- **Notes:** Review the disclaimer whenever the findings schema changes.
