#!/usr/bin/env bash
# Git extension: create-pr.sh
# Push the current branch and open a GitHub pull request.
#
# `gh pr create` relies on GitHub's GraphQL API and can fail with transient
# "Something went wrong while executing your query" errors. This script:
#   1. reuses an existing open PR for the branch (idempotent),
#   2. tries `gh pr create` first,
#   3. falls back to the REST API (`gh api .../pulls`) on failure,
#   4. checks again for an already-created PR before reporting an error.
#
# Usage:
#   create-pr.sh --title "feat: ..." --body-file /tmp/pr-body.md [options]
#
# Options:
#   --title <text>       PR title (defaults to the latest commit subject)
#   --body-file <path>   PR body file; use "-" to read stdin
#   --base <branch>      Base branch (default: PR_BASE_BRANCH or main)
#   --repo <owner/repo>  Override the repository derived from origin
#   --draft              Open the PR as a draft
#   --no-push            Do not push the branch before opening the PR
#   --dry-run            Print the plan without pushing or opening the PR
#   -h, --help           Show this help

set -euo pipefail

TITLE=""
BODY_FILE=""
BASE="${PR_BASE_BRANCH:-main}"
REPO_OVERRIDE=""
DRAFT=false
NO_PUSH=false
DRY_RUN=false
CLEANUP_BODY=false
BODY_TMP=""

usage() {
    cat <<'EOF'
Push the current branch and open a GitHub pull request.

`gh pr create` relies on GitHub's GraphQL API and can fail with transient
errors. This script reuses an existing open PR, tries `gh pr create`, falls
back to the REST API, and re-checks before reporting a failure.

Usage:
  create-pr.sh --title "feat: ..." --body-file /tmp/pr-body.md [options]

Options:
  --title <text>       PR title (defaults to the latest commit subject)
  --body-file <path>   PR body file; use "-" to read stdin
  --base <branch>      Base branch (default: PR_BASE_BRANCH or main)
  --repo <owner/repo>  Override the repository derived from origin
  --draft              Open the PR as a draft
  --no-push            Do not push the branch before opening the PR
  --dry-run            Print the plan without pushing or opening the PR
  -h, --help           Show this help
EOF
}

cleanup() {
    if [ "$CLEANUP_BODY" = true ] && [ -n "$BODY_TMP" ]; then
        rm -f "$BODY_TMP"
    fi
    if [ -n "${ERR_FILE:-}" ]; then
        rm -f "$ERR_FILE"
    fi
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
    case "$1" in
        --title)
            [ $# -ge 2 ] || { echo "Error: --title requires a value" >&2; exit 1; }
            TITLE="$2"
            shift 2
            ;;
        --body-file)
            [ $# -ge 2 ] || { echo "Error: --body-file requires a value" >&2; exit 1; }
            BODY_FILE="$2"
            shift 2
            ;;
        --base)
            [ $# -ge 2 ] || { echo "Error: --base requires a value" >&2; exit 1; }
            BASE="$2"
            shift 2
            ;;
        --repo)
            [ $# -ge 2 ] || { echo "Error: --repo requires a value" >&2; exit 1; }
            REPO_OVERRIDE="$2"
            shift 2
            ;;
        --draft)
            DRAFT=true
            shift
            ;;
        --no-push)
            NO_PUSH=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$BASE" ]; then
    echo "Error: base branch cannot be empty" >&2
    exit 1
fi

REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null) || {
    echo "Error: not inside a Git repository" >&2
    exit 1
}
cd "$REPO_ROOT"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" = "HEAD" ]; then
    echo "Error: detached HEAD; check out a branch before opening a PR" >&2
    exit 1
fi
if [ "$BRANCH" = "$BASE" ]; then
    echo "Error: current branch '$BRANCH' is the base branch; check out the feature branch" >&2
    exit 1
fi

# Feature-branch naming is recommended but not mandatory: chore/docs branches
# can also be shipped through a PR. Warn instead of blocking.
SCRIPT_DIR="$(CDPATH="" cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/git-common.sh" ]; then
    # shellcheck source=git-common.sh
    . "$SCRIPT_DIR/git-common.sh"
    if ! check_feature_branch "$BRANCH" true >/dev/null 2>&1; then
        echo "[specify] Warning: '$BRANCH' is not a numbered feature branch; continuing anyway" >&2
    fi
fi

if [ -n "$REPO_OVERRIDE" ]; then
    REPO="$REPO_OVERRIDE"
else
    REMOTE_URL=$(git config --get remote.origin.url 2>/dev/null || true)
    case "$REMOTE_URL" in
        *github.com*) ;;
        *)
            echo "Error: origin does not point to github.com (found: '${REMOTE_URL:-none}')" >&2
            echo "Hint: pass --repo <owner/repo> to override" >&2
            exit 1
            ;;
    esac
    REPO=$(printf '%s\n' "$REMOTE_URL" \
        | sed -E 's#^git@github\.com:##; s#^ssh://git@github\.com/##; s#^https?://([^@/]+@)?github\.com/##; s#\.git$##; s#/$##')
fi

case "$REPO" in
    */*) ;;
    *)
        echo "Error: could not derive owner/repo from origin; pass --repo <owner/repo>" >&2
        exit 1
        ;;
esac

if ! command -v gh >/dev/null 2>&1; then
    echo "Error: GitHub CLI ('gh') is required to open a pull request" >&2
    echo "Hint: install gh and run 'gh auth login'" >&2
    exit 1
fi

current_pr_url() {
    local owner="${REPO%%/*}"
    gh api "repos/$REPO/pulls?head=$owner:$BRANCH&state=open" \
        --template '{{range .}}{{.html_url}}{{end}}' 2>/dev/null || true
}

if [ -z "$TITLE" ]; then
    TITLE=$(git log -1 --pretty=%s 2>/dev/null || true)
fi
if [ -z "$TITLE" ]; then
    TITLE="Update $BRANCH"
fi

if [ -n "$BODY_FILE" ]; then
    if [ "$BODY_FILE" = "-" ]; then
        BODY_TMP=$(mktemp "${TMPDIR:-/tmp}/ufw-report-pr-body.XXXXXX")
        cat > "$BODY_TMP"
        BODY_FILE="$BODY_TMP"
        CLEANUP_BODY=true
    elif [ ! -f "$BODY_FILE" ]; then
        echo "Error: body file '$BODY_FILE' not found" >&2
        exit 1
    fi
else
    BODY_TMP=$(mktemp "${TMPDIR:-/tmp}/ufw-report-pr-body.XXXXXX")
    CLEANUP_BODY=true
    BASE_REF="origin/$BASE"
    if ! git rev-parse --verify --quiet "$BASE_REF" >/dev/null; then
        BASE_REF="$BASE"
    fi
    {
        echo "## Summary"
        echo
        echo "$TITLE"
        echo
        echo "## Changes"
        echo
        git log --oneline --no-decorate "$BASE_REF..HEAD" 2>/dev/null || true
        echo
        echo "## Test plan"
        echo
        echo "- [ ] CI passes"
    } > "$BODY_TMP"
    BODY_FILE="$BODY_TMP"
fi

if [ "$DRY_RUN" = true ]; then
    echo "Branch: $BRANCH"
    echo "Base:   $BASE"
    echo "Repo:   $REPO"
    echo "Title:  $TITLE"
    echo "Draft:  $DRAFT"
    echo "Body:"
    sed 's/^/  /' "$BODY_FILE"
    exit 0
fi

if [ "$NO_PUSH" = false ]; then
    echo "[specify] Pushing '$BRANCH' to origin..." >&2
    git push -u origin "$BRANCH"
fi

EXISTING_URL=$(current_pr_url)
if [ -n "$EXISTING_URL" ]; then
    echo "Pull request already open: $EXISTING_URL"
    exit 0
fi

ERR_FILE=$(mktemp "${TMPDIR:-/tmp}/ufw-report-pr-error.XXXXXX")

CREATE_ARGS=(--repo "$REPO" --base "$BASE" --head "$BRANCH" --title "$TITLE" --body-file "$BODY_FILE")
if [ "$DRAFT" = true ]; then
    CREATE_ARGS+=(--draft)
fi

if OUTPUT=$(gh pr create "${CREATE_ARGS[@]}" 2>"$ERR_FILE"); then
    URL=$(current_pr_url)
    if [ -n "$URL" ]; then
        echo "$URL"
    else
        printf '%s\n' "$OUTPUT" | tail -n 1
    fi
    exit 0
fi

CREATE_ERROR=$(cat "$ERR_FILE" 2>/dev/null || true)

# A transient failure can happen after the PR was created; never duplicate it.
EXISTING_URL=$(current_pr_url)
if [ -n "$EXISTING_URL" ]; then
    echo "Pull request already open: $EXISTING_URL"
    exit 0
fi

echo "[specify] gh pr create failed; retrying through the REST API..." >&2
echo "[specify] Original error: $CREATE_ERROR" >&2

DRAFT_ARGS=(-F draft=false)
if [ "$DRAFT" = true ]; then
    DRAFT_ARGS=(-F draft=true)
fi

if URL=$(gh api --method POST "repos/$REPO/pulls" \
    -f title="$TITLE" \
    -f head="$BRANCH" \
    -f base="$BASE" \
    -f body="$(cat "$BODY_FILE")" \
    "${DRAFT_ARGS[@]}" \
    --template '{{.html_url}}' 2>"$ERR_FILE"); then
    echo "Pull request created via REST fallback: $URL"
    exit 0
fi

REST_ERROR=$(cat "$ERR_FILE" 2>/dev/null || true)
EXISTING_URL=$(current_pr_url)
if [ -n "$EXISTING_URL" ]; then
    echo "Pull request already open: $EXISTING_URL"
    exit 0
fi

echo "Error: could not create the pull request" >&2
echo "  gh pr create: $CREATE_ERROR" >&2
echo "  REST fallback: $REST_ERROR" >&2
exit 1
