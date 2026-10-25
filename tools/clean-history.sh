#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rewrites the Git history so that no personal name or e-mail address remains in it.
#
# All commits get a neutral author/committer – except commits by Claude
# (noreply@anthropic.com), GitHub (noreply@github.com) and bots, which stay unchanged.
# The result is pushed to a NEW, EMPTY repository (recommended), because GitHub keeps the old
# commits of an existing repository reachable through its pull requests.
#
# Usage (Git Bash / Linux, in any folder):
#   NEW_EMAIL=<id>+<user>@users.noreply.github.com sh tools/clean-history.sh <source-url> <target-url>
#   e.g. NEW_EMAIL=222504472+soleil0815@users.noreply.github.com \
#        sh tools/clean-history.sh https://github.com/soleil0815/samaudit.git https://github.com/soleil0815/samaudit-new.git
#
# Optional: NEW_NAME (default "SAMAUDIT"). Nothing is changed in the source repository.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi #
set -euo pipefail

src="${1:?usage: clean-history.sh SOURCE_URL TARGET_URL}"
target="${2:?usage: clean-history.sh SOURCE_URL TARGET_URL}"
NEW_NAME="${NEW_NAME:-SAMAUDIT}"
NEW_EMAIL="${NEW_EMAIL:?set NEW_EMAIL, e.g. 12345+user@users.noreply.github.com}"
export NEW_NAME NEW_EMAIL

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "==> Cloning $src"
git clone -q --mirror "$src" "$work/repo.git"
cd "$work/repo.git"

# pull request refs are GitHub-internal and must not be copied
git for-each-ref --format='%(refname)' refs/pull | while read -r r; do git update-ref -d "$r"; done

echo "==> Rewriting authors and committers"
FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch -f --env-filter '
keep() {
  case "$1" in
    noreply@anthropic.com|noreply@github.com|*\[bot\]@users.noreply.github.com) return 0 ;;
  esac
  return 1
}
if ! keep "$GIT_AUTHOR_EMAIL"; then
  GIT_AUTHOR_NAME="$NEW_NAME"; GIT_AUTHOR_EMAIL="$NEW_EMAIL"
  export GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL
fi
if ! keep "$GIT_COMMITTER_EMAIL"; then
  GIT_COMMITTER_NAME="$NEW_NAME"; GIT_COMMITTER_EMAIL="$NEW_EMAIL"
  export GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL
fi
' --tag-name-filter cat -- --all >/dev/null

# drop the backup refs of filter-branch
git for-each-ref --format='%(refname)' refs/original | while read -r r; do git update-ref -d "$r"; done
git reflog expire --expire=now --all && git gc -q --prune=now

echo "==> Identities in the new history:"
git log --all --format='%an <%ae> | %cn <%ce>' | sort | uniq -c

echo
read -r -p "Push this history to $target ? [y/N] " a
case "$a" in y|Y|j|J) ;; *) echo "Cancelled – nothing pushed."; exit 0 ;; esac
git push "$target" "refs/heads/main:refs/heads/main" "refs/tags/*:refs/tags/*"   # only main and the version tags
echo "Done. Check the new repository, then follow the remaining steps in the checklist."
