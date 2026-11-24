# Feature Specification: Distribution through .deb, PPA, and crates.io

**Feature Branch**: `004-distribution-expansion`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Distribute ufw-report through .deb packages, a Launchpad PPA, and crates.io."

## Current Baseline (2026-11-24)

Releases are published as precompiled tarballs on GitHub Releases for
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and
`x86_64-unknown-linux-musl`, with SHA-256 checksums. Users install manually. There
is no `.deb`, no PPA, and no crates.io package. The release workflow already
verifies that the tag matches `Cargo.toml` and supports a manual dry run.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Install from a Debian package (Priority: P1)

A sysadmin on Ubuntu downloads a `.deb` from the release page and installs it with
`apt`. The package installs the binary, README, LICENSE, and CHANGELOG in the
expected locations, reports the same version as the release, and can be removed
cleanly.

**Why this priority**: Ubuntu is the primary target for UFW. A native package is
the lowest-friction installation path and avoids manual tarball handling.

**Independent Test**: Build the `.deb` for `amd64` and `arm64`, install it in clean
Ubuntu 22.04 and 24.04 containers, run `ufw-report --version`, and remove it with
`apt remove`.

**Acceptance Scenarios**:

1. **Given** a release `.deb`, **When** the user installs it with `apt`, **Then**
   the binary is available as `ufw-report` and reports the release version.
2. **Given** the installed package, **When** the user removes it, **Then** the
   binary and package-owned files are removed without touching UFW logs or
   firewall state.
3. **Given** both `amd64` and `arm64` packages, **When** each is installed on its
   matching architecture, **Then** the binary runs without missing libraries.
4. **Given** an older package, **When** the user upgrades to a newer version,
   **Then** `apt` replaces the binary and preserves no stale configuration.

---

### User Story 2 - Install with Cargo (Priority: P2)

A Rust user installs the tool with `cargo install ufw-report --version <version>
--locked` and gets the same behavior as the precompiled binary, provided they have
Rust 1.82 or newer.

**Why this priority**: It serves developers and users on distributions without a
package, and it validates that the crate is self-contained.

**Independent Test**: Publish a release candidate to a dry-run registry, then run
`cargo install --path .` and `cargo install ufw-report --version <version> --locked`
in a clean environment.

**Acceptance Scenarios**:

1. **Given** a published crate version, **When** the user runs `cargo install`, **Then**
   the binary builds and runs on Rust 1.82 or newer.
2. **Given** the crate package, **When** it is inspected, **Then** it contains the
   source, README, LICENSE, and CHANGELOG needed to build and identify the
   project.
3. **Given** a version already published on crates.io, **When** the release
   workflow runs again, **Then** it fails before attempting to republish an
   immutable version.

---

### User Story 3 - Install from a Launchpad PPA (Priority: P3)

An Ubuntu user adds the project PPA and installs the tool with `apt`. Launchpad
builds the package for the supported Ubuntu series, and the user receives updates
through the normal package manager.

**Why this priority**: It provides automatic updates and a familiar trust path for
Ubuntu users, but it depends on the `.deb` packaging work.

**Independent Test**: Push a source package to the staging PPA, wait for the
Launchpad build, add the PPA to a clean Ubuntu container, install, and upgrade.

**Acceptance Scenarios**:

1. **Given** the PPA is configured, **When** the user runs `apt install ufw-report`,
   **Then** the package installs from the PPA.
2. **Given** a newer version in the PPA, **When** the user runs `apt upgrade`,
   **Then** the binary updates and reports the new version.
3. **Given** an unsupported Ubuntu series, **When** the PPA is added, **Then** the
   documentation clearly states which series are supported.

### Edge Cases

- A release tag that does not match `Cargo.toml`.
- A crate version that already exists on crates.io (immutable; cannot be replaced).
- A Launchpad build failure for one architecture or one Ubuntu series.
- A `.deb` built against a newer glibc than the oldest supported Ubuntu.
- An ARM64 build with a missing cross toolchain.
- A package upgrade or downgrade, and removal after a manual tarball install.
- A user who installs from both a `.deb` and `cargo install`; the tool must still
  report the same version and behavior.
- A signing key or token that is missing or expired (see 005).
- A partial release where one channel succeeds and another fails.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The release pipeline MUST produce `.deb` packages for `amd64` and
  `arm64` from the same tagged source as the existing tarballs.
- **FR-002**: Each `.deb` MUST install the `ufw-report` binary and the project
  documentation, declare the correct dependencies, and avoid post-install actions
  that change firewall state or read logs.
- **FR-003**: `.deb` package versions MUST match the Git tag and `Cargo.toml`.
- **FR-004**: The `.deb` MUST run on the supported Ubuntu LTS releases without
  requiring a newer glibc than the project documents.
- **FR-005**: The crate MUST be publishable to crates.io and installable with
  `cargo install ufw-report --version <version> --locked` on Rust 1.82 or newer.
- **FR-006**: The crate package MUST include the source, README, LICENSE, and
  CHANGELOG, and MUST exclude build artifacts, local caches, and generated
  scaffolding.
- **FR-007**: The release pipeline MUST refuse to publish a crate version that
  already exists on crates.io.
- **FR-008**: The project MUST publish a Launchpad PPA for at least one supported
  Ubuntu LTS series, built from the same tagged source.
- **FR-009**: PPA packages MUST install, upgrade, and remove with standard `apt`
  commands and MUST NOT require manual configuration.
- **FR-010**: Every channel MUST expose the same version and the same runtime
  behavior; the binary MUST remain offline and read-only.
- **FR-011**: The release workflow MUST support a dry run that builds every package
  without publishing to crates.io, Launchpad, or GitHub Releases.
- **FR-012**: Channel failures MUST be reported per channel and MUST NOT leave a
  half-published release presented as complete. A failed channel is retried or
  documented as unavailable for that release.
- **FR-013**: Signing and verification from 005 MUST apply to the `.deb` artifacts
  and to the crate checksum/provenance where applicable.
- **FR-014**: `README.md` MUST document installation, upgrade, and removal for
  every channel, including the supported Ubuntu series and the Rust version.
- **FR-015**: The release checklist in `docs/releasing.md` MUST include the package
  and crate publication steps and the post-publication verification.
- **FR-016**: No channel may add a runtime network dependency, telemetry, or a
  privileged post-install step.

### Key Entities *(include if feature involves data)*

- **Release Artifact**: A tarball, `.deb`, checksum, or signature produced from a
  tagged source.
- **Package Metadata**: Name, version, architecture, maintainer, description,
  license, homepage, dependencies, and supported Ubuntu series.
- **Distribution Channel**: GitHub Releases, `.deb` download, Launchpad PPA, or
  crates.io, with its publication status and verification method.
- **Release Manifest**: The version, tag, source commit, artifact list, checksums,
  signatures, and per-channel status for one release.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: On clean Ubuntu 22.04 and 24.04 containers, installing the `amd64`
  `.deb` succeeds and `ufw-report --version` prints the release version.
- **SC-002**: The `arm64` `.deb` installs and runs on an ARM64 Ubuntu environment.
- **SC-003**: `cargo install ufw-report --version <version> --locked` succeeds on
  Rust 1.82 and the installed binary runs.
- **SC-004**: The PPA build succeeds for at least one supported Ubuntu LTS series,
  and `apt install ufw-report` from the PPA installs the expected version.
- **SC-005**: A dry run builds every artifact without publishing to any channel.
- **SC-006**: All channels report the same version, and a reviewer can verify the
  checksum or signature of each artifact.
- **SC-007**: Removing any package leaves no firewall, log, or host configuration
  changes behind.
- **SC-008**: Existing tarball releases and their checksums continue to work, and
  the required quality gates pass.

## Dependencies

- The existing GitHub Actions release workflow and tag/version check are the
  starting point.
- A crates.io account and token are available to the release automation.
- A Launchpad account and signing key are available for the PPA.
- Signing from 005 is available for `.deb` artifacts, or 004 ships without
  signatures and 005 adds them immediately after.
- The `.deb` may use the static musl binary or a GNU binary with documented
  dependencies. The plan chooses the packaging strategy and documents the glibc
  floor.

## Out of Scope

- Snap, Flatpak, Docker, or AppImage as primary channels.
- Windows and macOS packages.
- Automatic updates inside the binary.
- A custom APT repository outside Launchpad.
- Reproducible builds (signed releases from 005 do not imply reproducibility).
- Changing the binary's runtime behavior or adding a daemon.

## Assumptions

- Users install on Linux and have a supported package manager or Rust toolchain.
- Supported Ubuntu series are defined in the plan; at minimum, the current and
  previous LTS releases.
- The project keeps the existing tarballs as the universal fallback.
- Version numbers follow the existing `v<version>` tag and `Cargo.toml` contract.
- The release process remains automated from a tag; no artifact is uploaded
  manually from a workstation.
