# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from 1.0.0.
Before 1.0.0, minor versions may include breaking changes.

## Unreleased

### Added

- GitHub Spec Kit adoption with the OpenCode integration, a project
  constitution, and generated workflow commands.
- Specifications for forensic triage, incident isolation, async/streaming
  parsing, distribution (`.deb`, PPA, crates.io), and signed releases.

### Changed

- Consolidated the documentation around `README.md`, `docs/roadmap.md`,
  `docs/risk-analysis.md`, `docs/releasing.md`, and `specs/`.
- Merged the shipped-behavior notes into `README.md` and the product context into
  `docs/roadmap.md`.

### Removed

- Stale duplicate documentation: `docs/actual-state.md`, `docs/lean-canvas.md`,
  `docs/wbs-v0.3.0.md`, and `specs/README.md`.

## 0.2.1 - 2026-11-18

### Fixed

- Release workflow installs `libc6-dev-arm64-cross`, so the
  `aarch64-unknown-linux-gnu` build can link (`Scrt1.o` and `crti.o` are now
  found) and the GitHub Release is published for all three targets.
- The `x86_64-unknown-linux-musl` artifact is fully static again. The build no
  longer overrides the linker with `musl-gcc`, which produced a dynamically
  linked binary that required `/lib/ld-musl-x86_64.so.1` on the target host.

### Changed

- The release workflow can be triggered manually with `workflow_dispatch` to
  build and package every target as a dry run, without publishing a release.
- The packaged version comes from `Cargo.toml` on dry runs and from the tag on
  tagged releases.

## 0.2.0 - 2026-11-17

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

## 0.1.0 - 2026-01-01

- Initial parsed entry report: IPv4/IPv6 parsing, protocol normalization,
  direction detection, configurable date range, and zero-filled days.
- Interactive TUI with Overview, Daily, Hourly, and Raw views.
- CSV and JSON entry export.
- Range-safe JSON parse cache and `--no-cache`.
- GitHub Actions CI with formatting, linting, tests, and a build.
