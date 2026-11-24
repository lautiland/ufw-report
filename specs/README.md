# Feature specifications

This directory holds one Spec Kit artifact set per feature, created through the
`/speckit.specify` command. Do not hand-create numbered directories unless you
are repairing a failed command: the specification and its plan, tasks, and
contracts must stay traceable to each other.

## Current specs

| Spec | Scope |
| --- | --- |
| [`001-forensic-triage`](001-forensic-triage/spec.md) | Rotated/compressed ingestion, sub-hour detection, custody manifest, ATT&CK mapping |
| [`002-incident-isolation`](002-incident-isolation/spec.md) | TUI incident isolation and reproducible filtered evidence export |
| [`003-async-streaming-parsing`](003-async-streaming-parsing/spec.md) | Responsive, bounded-memory parsing for large log sets |
| [`004-distribution-expansion`](004-distribution-expansion/spec.md) | `.deb`, Launchpad PPA, and crates.io distribution |
| [`005-signed-releases`](005-signed-releases/spec.md) | Signed artifacts and offline provenance verification |

A typical feature directory contains:

```text
specs/001-feature-name/
├── spec.md          # What and why (mandatory)
├── plan.md          # Technical approach and constitution check
├── research.md      # Phase 0 decisions
├── data-model.md    # Entities and relationships
├── quickstart.md    # Validation scenarios
├── contracts/       # Interface contracts, when applicable
├── checklists/      # Requirements-quality checklists
└── tasks.md         # Dependency-ordered implementation tasks
```

The active feature is recorded in `.specify/feature.json`, which is
per-checkout state and is intentionally ignored by Git. Feature directories are
committed and reviewed like any other change.

See [`docs/spec-kit.md`](../docs/spec-kit.md) for the full workflow, command
list, and documentation map.
