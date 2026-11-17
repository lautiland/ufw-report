# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.
Before 1.0.0, minor versions may include breaking changes.

## [0.2.0] - 2026-11-17

### Added

- Offline threat analysis: per-source profiles with volume, first/last seen,
  active days, distinct ports and hosts, administrative hits, and top
  ports/protocols.
- Capped 0-100 risk score with Low, Medium, High, and Critical bands.
- Hourly heuristics for port scans, host sweeps, brute force (hourly and daily),
  distributed brute force, and persistent sources.
- IPv4 `/24` and IPv6 `/64` network grouping with a minimum-source filter.
- Threats tab with Sources/Networks toggle (`v`), row navigation, and a detail
  panel.
- CIDR allowlist that excludes findings and scores while keeping raw data and
  coverage intact.
- Explicit TOML analysis configuration via `--config`, with built-in defaults
  and no autoload.
- Parser quality counters and a coverage summary (hours with data, missing
  hours, longest gap, unparsed blocks, out-of-order lines, future-dated
  entries).
- `--findings <PATH>` export to JSON or Markdown, including `-` for stdout.
- Precompiled release binaries for `x86_64`/`aarch64` GNU Linux and `x86_64`
  musl, packaged as tarballs with SHA256 checksums.
- Release workflow that verifies the tag against `Cargo.toml` and publishes a
  GitHub Release.

### Changed

- The parse cache moved to format version 3 to store whole-file `ParseStats`.
- Findings and entry exports can run in the same invocation as long as they do
  not both write to stdout.
- CI now runs a locked release build in addition to `fmt`, pedantic `clippy`,
  and tests.

### Fixed

- `--findings -` is rejected when an entry export would also write to stdout.

## [0.1.0] - 2026-01-01

- Initial parsed entry report: IPv4/IPv6 parsing, protocol normalization,
  direction detection, configurable date range, and zero-filled days.
- Interactive TUI with Overview, Daily, Hourly, and Raw views.
- CSV and JSON entry export.
- Range-safe JSON parse cache and `--no-cache`.
- GitHub Actions CI with formatting, linting, tests, and a build.

[0.2.0]: https://github.com/lautiland/ufw-report/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/lautiland/ufw-report/releases/tag/v0.1.0
