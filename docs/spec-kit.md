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
→ checklist (when useful) → tasks → analyze → implement → converge
```

For small, well-understood changes, the shorter path is:

```text
specify → plan → tasks → implement → converge
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

Feature artifacts live under `specs/<NNN-feature>/` (for example,
`specs/001-forensic-triage/`). The active feature is tracked in
`.specify/feature.json`, not by the checked-out Git branch. The optional Spec Kit
`git` extension is not installed; branches remain a manual choice in this
repository.

## Source-of-truth map

| Question | Authoritative document |
| --- | --- |
| What rules govern the project? | `.specify/memory/constitution.md` |
| What does the tool do today? | `docs/actual-state.md` |
| Where is the product going? | `docs/roadmap.md` |
| What are we building in this change? | `specs/<NNN-feature>/spec.md` and its artifacts |
| What can go wrong? | `docs/risk-analysis.md` |
| How is a release cut? | `docs/releasing.md` |
| What changed for users? | `CHANGELOG.md` |

## Legacy methodology files

The repository previously used a lightweight product-planning methodology. None
of those documents are Spec Kit artifacts, and they are not being deleted
automatically:

- `docs/lean-canvas.md` — product strategy context. Still valid; it is not a
  change-level artifact and does not conflict with Spec Kit.
- `docs/roadmap.md` — product-level direction. Still valid and remains the
  authority for scope and sequencing. It should link to the spec when a roadmap
  item becomes active work.
- `docs/risk-analysis.md` — risk register. Still active and reviewed at every
  release.
- `docs/actual-state.md` — shipped behavior. Still valid; Spec Kit does not
  replace it.
- `docs/wbs-v0.3.0.md` — legacy work breakdown. It is implementation-level
  planning and overlaps with `plan.md` and `tasks.md`. It is retained as
  technical input for the v0.3.0 specification; phases 1.0 and 2.0 are already on
  `main`. Do not update it in parallel with the spec.
- `docs/wbs.md` and `docs/implementation-plan.md` — removed in earlier commits
  (`885879c` and `22a2a9a`). They are historical only and are not restored.

The rule going forward: product direction lives in `docs/roadmap.md`,
change-level intent lives in `specs/`, shipped behavior lives in
`docs/actual-state.md`, and the constitution governs conflicts.

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

The v0.3.0 milestone is specified in `001`. Its legacy WBS is retained as
technical input. The next steps are `/speckit.clarify` if requirements remain
ambiguous, then `/speckit.plan` and `/speckit.tasks`.

Future features start with `/speckit.specify ...`. The installed git extension
creates a `feat/NNN-slug` branch from the current state before the specification
is written, matching the repository's branch convention.
