# ufw-report Constitution

## Core Principles

### I. Offline, Read-Only, Least Privilege (NON-NEGOTIABLE)

`ufw-report` is a passive observer of UFW logs. It MUST NOT execute `ufw` or any
other privileged command, modify firewall rules, write to UFW log files, or
change host configuration. It MUST NOT open network connections, send telemetry,
or contact reputation, GeoIP, ASN, or any other remote service. It reads only
files the invoking user can already access and writes only to user-selected
output paths or the documented cache directory.

Any feature that requires network access, elevated execution, or rule changes is
out of scope by design. This is not a temporary limitation: it is the product's
trust model. Investigators run this tool on compromised, air-gapped, or
production hosts, and the tool must never become part of the attack surface.

### II. Evidence Integrity and Honest Reporting (NON-NEGOTIABLE)

Findings are heuristic triage indicators, never verdicts or legal proof. Every
report and every document that describes the output MUST say so explicitly.

The tool MUST preserve and surface source-quality signals: coverage, missing
hours, unparsed lines, out-of-order entries, future-dated entries, and corrupt
inputs. Absence of findings MUST NOT be presented in a way that could be confused
with absence of usable evidence. Corrupt or unreadable inputs MUST be reported,
never silently skipped or presented as complete.

Chain-of-custody metadata (SHA-256, execution timestamps, hostname, tool version,
and configuration hash) MUST state exactly what it certifies: the bytes read
during that execution. It MUST NOT claim that a file was unchanged before or
after the run. Each finding MUST include enough evidence (time range and, when
applicable, ports and protocols) for manual verification.

### III. Specification Before Implementation

Non-trivial behavior changes MUST begin with a specification under
`specs/<NNN-feature>/spec.md`, created through the Spec Kit workflow. `plan.md`,
`tasks.md`, and the implementation MUST trace back to that specification.
`/speckit.analyze` MUST be run before implementation when the full workflow is
used.

Changes to shipped behavior MUST update `README.md` and `CHANGELOG.md`. Bug fixes
MUST record the assessed cause, the scoped fix, and the verification performed; a
specification is required when the fix changes documented behavior. An emergency
fix may bypass the sequence, but the missing artifacts MUST be completed before
the next release.

### IV. Testable Quality Gates

Every behavior change MUST include automated tests, and every bug fix MUST
include a regression test. Parser and heuristic changes MUST include fixtures
based on realistic logs. Tests MUST NOT require root access, network access, or a
live UFW installation.

The required gates are:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
cargo test --all-targets --locked
cargo build --release --locked
```

CI MUST run the same gates, and a red `main` blocks release. New heuristics MUST
be validated for false positives and false negatives against fixtures, and their
thresholds MUST be documented.

### V. Explicit Contracts and Backward Compatibility

CLI flags, exit codes, stdout/stderr behavior, CSV/JSON/Markdown schemas, and
TOML configuration keys are public contracts. Output format MUST be resolved by
the documented precedence, and the tool MUST NOT silently infer or change
formats.

Before `1.0`, breaking changes are allowed only with explicit justification and
MUST be documented in `README.md` and `CHANGELOG.md`. Additive changes are
preferred. A deprecation MUST name the replacement and the version in which
removal is planned.

### VI. Simplicity and Dependency Discipline

Prefer the standard library and existing dependencies. A new dependency MUST
justify its maintenance cost, license, binary-size impact, and offline
compatibility. The analysis pipeline stays synchronous and in-memory unless
measured performance needs justify a change; concurrency is not a default.
Modules communicate through data models, and the CLI, core, output, and TUI keep
their boundaries. No feature is added without a documented user need and a place
in the roadmap.

## Technology and Architecture Constraints

- Rust 1.82 or newer, edition 2021. Linux only: UFW and its log formats are the
  input contract.
- Single binary with a `ratatui` + `crossterm` TUI. No HTTP server, daemon, or
  network listener.
- Supported release targets: `x86_64-unknown-linux-gnu`,
  `aarch64-unknown-linux-gnu`, and `x86_64-unknown-linux-musl`.
- The release version MUST match the `v<version>` tag and `Cargo.toml`, and every
  release artifact MUST ship a SHA-256 checksum.
- The tool MUST remain usable offline and read-only on the target host.

## Development Workflow and Quality Gates

Spec Kit is the process harness. The standard cycle is:

```text
constitution → specify → clarify (when ambiguity exists) → plan
→ checklist (when useful) → tasks → analyze → implement → converge
```

Feature artifacts live under `specs/<NNN-feature>/` and are committed.
`.specify/feature.json` is per-checkout state and MUST NOT be committed.

Documentation roles are deliberately separated to avoid competing sources of
truth:

| Location | Purpose |
| --- | --- |
| `README.md` | User guide, shipped behavior, and technical notes |
| `docs/roadmap.md` | Product direction, product context, scope, and out-of-scope boundaries |
| `docs/risk-analysis.md` | Reviewed risk register |
| `docs/releasing.md` | Release procedure |
| `docs/spec-kit.md` | Contributor workflow and source-of-truth map |
| `specs/` | Change-level specification, plan, tasks, and contracts |
| `CHANGELOG.md` | User-visible changes per release |

Every change ships through a reviewable branch or pull request with green CI. A
completed feature's specification MUST be either maintained or explicitly
archived; it MUST NOT become a stale second source of truth.

## Governance

This constitution supersedes ad-hoc practices. Conflicts with other documents
resolve in its favor.

Amendments require a dedicated pull request that states the rationale, the
affected principles, and a migration note for active specifications. Versioning
is semantic: MAJOR for incompatible governance changes, MINOR for new or
materially expanded principles, and PATCH for clarifications.

Compliance is reviewed during `/speckit.plan`, `/speckit.analyze`, and pull
request review. Non-compliance MUST be justified in writing or corrected. The
constitution is reviewed at least once per release.

**Version**: 1.1.0 | **Ratified**: 2026-11-24 | **Last Amended**: 2026-11-24
