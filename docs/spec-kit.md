# Spec Kit adoption

> **Adopted:** 2026-11-24 | **Specify CLI:** 1.4.4 | **Integration:** `opencode`

This repository uses [GitHub Spec Kit](https://github.github.com/spec-kit/) for
Spec-Driven Development (SDD). The constitution in
[`.specify/memory/constitution.md`](../.specify/memory/constitution.md) is the
highest-level project rule set.

## What was added

| Path | Purpose | Commit? |
| --- | --- | --- |
| `.specify/` | Constitution, templates, scripts, workflow definitions, and integration manifests | Yes, except local state |
| `.specify/feature.json` | Points commands at the active feature directory | No, ignored by `.specify/.gitignore` |
| `.opencode/commands/` | Generated OpenCode slash commands (`/speckit.specify`, `/speckit.plan`, ...) | Yes |
| `.ignore` | Re-includes `.specify/` for OpenCode's ripgrep-based glob and excludes local config | Yes |

The generated artifacts add roughly 350 KB to the repository. No application
source, CI workflow, or release configuration was modified by initialization.

## How we work

The standard cycle is:

```text
constitution → specify → clarify (when needed) → plan
→ checklist (when useful) → tasks → analyze → implement → converge → git.pr
```

For small, well-understood changes, the shorter path is:

```text
specify → plan → tasks → implement → converge → git.pr
```

Commands are invoked in OpenCode chat with dotted notation:

| Command | Use |
| --- | --- |
| `/speckit.constitution` | Create or amend project principles |
| `/speckit.specify` | Write the feature specification |
| `/speckit.clarify` | Resolve ambiguous requirements before planning |
| `/speckit.plan` | Produce the implementation plan and design artifacts |
| `/speckit.checklist` | Generate a requirements-quality checklist |
| `/speckit.tasks` | Break the plan into dependency-ordered tasks |
| `/speckit.analyze` | Check consistency across spec, plan, and tasks |
| `/speckit.implement` | Execute the tasks |
| `/speckit.converge` | Find gaps and append remaining tasks |
| `/speckit.git.feature` | Create the numbered feature branch |
| `/speckit.git.commit` | Commit a phase with a Conventional Commit message (also runs automatically) |
| `/speckit.git.validate` | Validate the branch naming convention |
| `/speckit.git.pr` | Commit any remaining work, push, and open a GitHub PR |

Feature artifacts live under `specs/<NNN-feature>/` (for example,
`specs/001-forensic-triage/`). The active feature is tracked in
`.specify/feature.json`, not by the checked-out Git branch. The Spec Kit `git`
extension is installed and creates `feat/NNN-slug` branches automatically; the
active-feature pointer still comes from `.specify/feature.json`.

The `git` extension commits each phase automatically (`after_specify`,
`after_clarify`, `after_plan`, `after_tasks`, `after_implement`,
`after_checklist`, and `after_analyze`) using the `conventional` commit style.
`/speckit.git.pr` is the final step: it commits anything still dirty, pushes the
branch, and opens the PR. It first tries `gh pr create` and falls back to the
GitHub REST API if GitHub returns a transient GraphQL error.

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

Feature directories are committed and reviewed like any other change.
`.specify/feature.json` is per-checkout state and is intentionally ignored.

## Source-of-truth map

| Question | Authoritative document |
| --- | --- |
| What rules govern the project? | `.specify/memory/constitution.md` |
| What does the tool do today? | `README.md` |
| Where is the product going? | `docs/roadmap.md` |
| What are we building in this change? | `specs/<NNN-feature>/spec.md` and its artifacts |
| What can go wrong? | `docs/risk-analysis.md` |
| How is a release cut? | `docs/releasing.md` |
| How do I contribute? | `docs/spec-kit.md` |
| What changed for users? | `CHANGELOG.md` |

## Removed planning artifacts

The pre-Spec Kit planning files were consolidated instead of kept as parallel
sources of truth:

- `docs/actual-state.md` — merged into `README.md` (shipped behavior and
  technical notes).
- `docs/lean-canvas.md` — strategic context merged into the "Product context"
  section of `docs/roadmap.md`.
- `docs/wbs-v0.3.0.md` — absorbed by
  `specs/001-forensic-triage/spec.md`; the detailed work packages remain in Git
  history at commit `22a2a9a` and are the input for `plan.md` and `tasks.md`.
- `specs/README.md` — artifact layout and spec index moved into this guide.
- `docs/wbs.md` and `docs/implementation-plan.md` — removed in earlier commits
  (`885879c` and `22a2a9a`). They are historical only and are not restored.

The rule going forward: product direction lives in `docs/roadmap.md`,
change-level intent lives in `specs/`, shipped behavior lives in `README.md` and
`CHANGELOG.md`, and the constitution governs conflicts.

## Operational notes

- The Specify CLI was installed with `uv` from the pinned release
  `v1.4.4` (`uv tool install specify-cli --from
  git+https://github.com/github/spec-kit.git@v1.4.4`).
- Check for newer releases with `specify self check`. Upgrade with the same
  pinned-source command, replacing the tag, then run `specify integration
  upgrade opencode` if the integration files changed.
- Initialization was run with `--ignore-agent-tools` because the `opencode`
  executable is not on `PATH` in this environment. Workflow dispatch that shells
  out to `opencode run` will need the CLI installed.
- `.opencode/commands/` is generated. Do not edit those files by hand; keep
  project customizations in Spec Kit presets or project-local overrides.
- The root `.ignore` exists so OpenCode's glob tool can see the hidden
  `.specify/` tree. Keep the `!.specify/` and `!.specify/**` exceptions, and do
  not commit credentials under `.specify/`.
- Spec Kit initialization did not change CI. The required gates remain those in
  the constitution and `docs/releasing.md`.

## Starting the first feature

The current specification set is:

| Spec | Status | Next step |
| --- | --- | --- |
| [`001-forensic-triage`](../specs/001-forensic-triage/spec.md) | Baseline partly implemented | `/speckit.clarify` then `/speckit.plan` |
| [`002-incident-isolation`](../specs/002-incident-isolation/spec.md) | Draft | `/speckit.clarify` then `/speckit.plan` |
| [`003-async-streaming-parsing`](../specs/003-async-streaming-parsing/spec.md) | Draft | `/speckit.clarify` then `/speckit.plan` |
| [`004-distribution-expansion`](../specs/004-distribution-expansion/spec.md) | Draft | `/speckit.clarify` then `/speckit.plan` |
| [`005-signed-releases`](../specs/005-signed-releases/spec.md) | Draft | `/speckit.clarify` then `/speckit.plan` |

The v0.3.0 milestone is specified in `001`. The next steps are
`/speckit.clarify` if requirements remain ambiguous, then `/speckit.plan` and
`/speckit.tasks`.

Future features start with `/speckit.specify ...`. The installed git extension
creates a `feat/NNN-slug` branch from the current state before the specification
is written, matching the repository's branch convention.
