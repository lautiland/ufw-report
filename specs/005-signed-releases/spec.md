# Feature Specification: Signed Releases and Offline Provenance Verification

**Feature Branch**: `005-signed-releases`

**Created**: 2026-11-24

**Status**: Draft

**Input**: User description: "Sign release artifacts and document offline verification of provenance."

## Current Baseline (2026-11-24)

Every release publishes tarballs and matching SHA-256 checksums. Checksums detect
corruption but do not prove who produced an artifact. Risk 6 in
[`docs/risk-analysis.md`](../../docs/risk-analysis.md) records the gap. The
release workflow already verifies the tag against `Cargo.toml` and runs from
GitHub Actions.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Verify a release offline before running it (Priority: P1)

A security-conscious user downloads a tarball on an air-gapped host. They also
download the detached signature and the project's public key, verify the signature
without network access, and only then extract and run the binary. A tampered or
truncated artifact fails verification.

**Why this priority**: The tool is used on compromised and air-gapped hosts. Its
own distribution must be verifiable without trusting the download channel or an
online service.

**Independent Test**: Download a release artifact, its signature, and the public
key; verify on a host with no network. Modify one byte of the artifact and confirm
that verification fails.

**Acceptance Scenarios**:

1. **Given** a published artifact and its detached signature, **When** the user
   verifies it with the documented public key, **Then** verification succeeds.
2. **Given** a modified artifact and the original signature, **When** the user
   verifies it, **Then** verification fails with a clear error.
3. **Given** no network access, **When** the user follows the verification steps,
   **Then** they succeed using only local files.

---

### User Story 2 - Sign every artifact automatically in CI (Priority: P2)

A maintainer pushes a release tag. The release workflow builds every artifact,
signs each one with the protected release key, publishes the signatures and the
public key, and fails closed if signing is unavailable. No maintainer signs
artifacts by hand.

**Why this priority**: Manual signing is easy to forget and hard to audit. The
signature must be a property of the release pipeline, not a checklist item.

**Independent Test**: Run a release dry run with the signing secret available and
confirm signatures are produced for every artifact. Run it again with the secret
missing and confirm the release fails before publishing unsigned artifacts.

**Acceptance Scenarios**:

1. **Given** a release tag and a valid signing secret, **When** the workflow runs,
   **Then** every artifact and checksum file has a detached signature.
2. **Given** a missing or invalid signing secret, **When** the workflow runs,
   **Then** it fails closed and publishes nothing unsigned.
3. **Given** a successful release, **When** the user opens the release page,
   **Then** the public key, its fingerprint, and verification instructions are
   present.

---

### User Story 3 - Rotate or revoke a key without breaking old releases (Priority: P3)

The maintainer needs to replace a signing key. Old releases remain verifiable with
the old public key, new releases use the new key, and the documentation explains
which key applies to which version range.

**Why this priority**: Key management is the part of signing that usually fails
years later. A documented rotation policy prevents a future release from becoming
unverifiable.

**Independent Test**: Simulate a rotation with two keys, verify one release with
the old key and a newer release with the new key, and confirm the documentation
maps each key to its version range.

**Acceptance Scenarios**:

1. **Given** an old release, **When** the user verifies it with the old public key,
   **Then** verification still succeeds after a rotation.
2. **Given** a new release, **When** the user verifies it with the new public key,
   **Then** verification succeeds and the old key is not accepted for it.
3. **Given** a revoked key, **When** the user reads the documentation, **Then** the
   revocation date, reason, and replacement are stated.

### Edge Cases

- A missing, expired, or compromised signing key.
- A partial release where some artifacts are signed and others are not.
- A checksum file that is signed but an artifact that is not, or vice versa.
- A signature produced over a decompressed file instead of the published bytes.
- A user who verifies on Windows, macOS, or a minimal Linux host without the
  recommended tool installed.
- A release page edited after publication.
- A mirror that serves a different artifact with a valid-looking name.
- A key rotation in the middle of a release series.
- A signature that verifies but the artifact is older than the expected version.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every published release artifact (tarballs, `.deb` packages, and
  checksum files) MUST have a detached cryptographic signature.
- **FR-002**: Signatures MUST cover the exact published bytes. For compressed
  artifacts, the signature covers the compressed file, not the decompressed
  content.
- **FR-003**: The release workflow MUST sign artifacts automatically from a
  protected secret and MUST NOT require a manual signing step on a workstation.
- **FR-004**: The workflow MUST fail closed: if signing is unavailable or fails,
  no unsigned artifact is published as part of that release.
- **FR-005**: The public verification key MUST be published in the repository and
  on the release page, with a fingerprint and the exact verification command.
- **FR-006**: Verification MUST work offline with local files and a documented
  command-line tool.
- **FR-007**: The project MUST publish a key-rotation and revocation policy,
  including which key applies to which release version range.
- **FR-008**: The workflow MUST sign the checksum file as well as each artifact, or
  otherwise make the full artifact list tamper-evident.
- **FR-009**: The release checklist MUST include signing, signature publication,
  and a post-release verification step.
- **FR-010**: `README.md` MUST document verification for at least the primary Linux
  path, including a tamper-detection example.
- **FR-011**: Existing SHA-256 checksums MUST remain available and documented;
  signatures complement them rather than replace them.
- **FR-012**: The release pipeline MUST use least-privilege permissions and MUST NOT
  print the secret key in logs.
- **FR-013**: If additional provenance attestations (for example, a build
  attestation) are published, their verification steps MUST be optional and MUST
  NOT be required for offline verification.
- **FR-014**: The feature MUST NOT add any runtime network dependency, telemetry,
  or privileged operation to the installed tool.

### Key Entities *(include if feature involves data)*

- **Release Artifact**: A published tarball, `.deb`, checksum file, or other
  distributable file.
- **Detached Signature**: A signature file bound to one artifact's exact bytes.
- **Signing Key**: The private key used by CI and its corresponding public key.
- **Key Record**: The public key, fingerprint, creation date, validity range,
  rotation date, and revocation status.
- **Verification Instruction**: The documented command and expected output for a
  supported platform.
- **Release Manifest**: The version, tag, artifacts, checksums, signatures, key
  fingerprint, and per-artifact verification status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user can verify every release artifact offline using only the
  published artifact, signature, and public key.
- **SC-002**: A one-byte modification to any artifact causes verification to fail
  in 100% of tested cases.
- **SC-003**: 100% of artifacts in a tagged release have a signature, and the
  checksum file is covered by the same tamper-evident scheme.
- **SC-004**: A release dry run with a missing signing secret fails before
  publishing any artifact.
- **SC-005**: The public key fingerprint in the repository, the release page, and
  the documentation match.
- **SC-006**: A simulated key rotation produces verifiable old and new releases,
  and the documentation states the applicable version ranges.
- **SC-007**: The verification instructions work on a host with no network access.
- **SC-008**: Existing tarball, checksum, and release workflows continue to work,
  and the required quality gates pass.

## Dependencies

- The existing release workflow and tag/version check are the starting point.
- A signature tool with offline verification is chosen during planning. This
  specification assumes a detached Ed25519-style signature (for example,
  `minisign`) and documents the chosen tool in the plan.
- The signing secret is stored in the CI secret store and protected by the
  repository's environment rules.
- 004 adds `.deb` artifacts; 005 signs them once they exist. Tarball signing can
  ship before 004.
- The public key is distributed in the repository and attached to releases; a
  compromised repository could alter it, so the documentation also publishes the
  fingerprint through a second channel.

## Out of Scope

- Reproducible builds.
- Hardware security modules or hardware tokens.
- Windows Authenticode or macOS notarization.
- Signing the source repository's commits or tags (a separate supply-chain
  feature).
- A custom transparency log.
- Automatic signature verification inside the tool at runtime.

## Assumptions

- Users can install or already have the documented verification tool.
- Release artifacts remain downloadable as individual files, not only through a
  package manager.
- Signature files and public keys are small enough to attach to every release.
- The release process remains tag-driven and automated.
- The project does not require hardware tokens in this iteration.
