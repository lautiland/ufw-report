---
description: Commit remaining changes, push the current branch, and open a GitHub pull request
---

<!-- Extension: git -->
<!-- Config: .specify/extensions/git/ -->
# Open a Pull Request

Ship the current branch: commit any remaining work with a Conventional Commit
message, push it, and open a GitHub pull request. The script reuses an existing
open PR and falls back to GitHub's REST API when `gh pr create` fails with a
transient GraphQL error.

## User Input

```text
$ARGUMENTS
```

If the user supplied a title, use it as the PR title. Otherwise generate one
from the specification and the commits on the branch.

## Pre-Execution Checks

- Verify Git is available with `git rev-parse --is-inside-work-tree`.
- Verify the current branch is not `main` (or the configured base branch).
- If Git is unavailable or the directory is not a repository, warn and stop.
- `gh` must be installed and authenticated. The script reports a clear error
  otherwise.

## Outline

1. **Collect context**:
   - `git status --short` and `git diff --stat`
   - `git log --oneline origin/main..HEAD`
   - The active feature spec and plan under `specs/` when present
2. **Commit remaining changes** (when the working tree is dirty):
   - Inspect the diff and generate a single-line Conventional Commit message.
   - Write the message to a temporary file outside the worktree.
   - Run `.specify/extensions/git/scripts/bash/auto-commit.sh after_implement --message-file <path>`.
   - Do not interpolate the message into a shell string.
3. **Generate the PR body**:
   - Write it to a temporary file outside the worktree.
   - Include: Summary, Changes, Test plan, and links to the Spec Kit artifacts
     (`spec.md`, `plan.md`, `tasks.md`) when they exist.
   - Mention the quality gates that were run and their results.
4. **Push and create the PR**:

   ```bash
   .specify/extensions/git/scripts/bash/create-pr.sh \
     --title "<generated title>" \
     --body-file "<body-file>" \
     [--base main] [--draft]
   ```

   The script:
   - reuses an already-open PR for the branch;
   - pushes with `-u origin <branch>` unless `--no-push` is passed;
   - tries `gh pr create`;
   - falls back to `gh api --method POST repos/<owner>/<repo>/pulls`;
   - re-checks for an existing PR before reporting an error.
5. **Report** the PR URL and any fallback note printed by the script.

## Options

The script accepts `--title`, `--body-file` (`-` for stdin), `--base`,
`--repo`, `--draft`, `--no-push`, and `--dry-run`. Use `--dry-run` to inspect the
generated title and body without pushing or creating anything.

## Graceful Degradation

- If there are no changes to commit, skip the commit step.
- If the branch is not a numbered feature branch, the script warns and
  continues; chore/docs branches can also be shipped through a PR.
- If `gh` is missing or unauthenticated, stop with the installation/login hint.
- If both creation paths fail, print both errors and leave the branch pushed so
  the user can retry or open the PR manually.
