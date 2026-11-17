# Risk Register for `ufw-report`

Risks are reviewed at every release. Each entry states the current mitigation
and what to do if it materializes.

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
- **Probability:** Medium
- **Impact:** High
- **Trigger:** TUI response time above 2 seconds when switching tabs.
- **Mitigation:** The parse cache avoids reparsing unchanged logs, and parser
  counters make long runs observable before the UI starts.
- **Contingency:** Document the `--no-cache` and export paths, and use CSV/JSON
  export instead of the TUI for oversized logs.
- **Notes:** Asynchronous parsing and streaming aggregation are tracked in the
  roadmap.

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

## Risk 4: False negatives from hourly bucketing

- **Category:** Functional
- **Description:** Short bursts that cross an hour boundary or finish inside one
  hour are aggregated.
- **Causes:** `LogEntry` stores only date and hour, so the analysis cannot see
  sub-hour timing.
- **Consequences:** A fast scan may fall below a per-hour threshold even though
  it was aggressive.
- **Probability:** Medium
- **Impact:** Medium
- **Trigger:** A reported incident that the tool did not flag.
- **Mitigation:** Thresholds are conservative by default, and the coverage and
  ranking sections still surface high-volume sources even without a finding.
- **Contingency:** Lower the relevant threshold in the config file for the
  affected environment.
- **Notes:** Sub-hour resolution requires a schema change and is out of scope for
  the current analysis version.

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
  Signing is a candidate for a later release.

## Risk 7: Memory exhaustion on oversized logs

- **Category:** Performance
- **Description:** The process is killed by the OOM killer.
- **Causes:** All parsed entries are kept in memory for the TUI and exports.
- **Consequences:** No report is produced and the failure can look like a crash.
- **Probability:** Medium
- **Impact:** Medium
- **Trigger:** A log with millions of blocked entries on a small VPS.
- **Mitigation:** The cache avoids reparsing, and exports can be produced without
  the TUI. Parse counters report progress.
- **Contingency:** Analyze a narrower date range or a rotated copy of the log.
- **Notes:** Streaming aggregation is tracked in the roadmap.

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
