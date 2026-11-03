#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Rewrites the Git history so that no personal name or e-mail address remains in it.
#
# All commits get a neutral author/committer (NEW_NAME <NEW_EMAIL>) – except commits by
# Claude (noreply@anthropic.com), GitHub (noreply@github.com) and bots, which stay unchanged.
# Only author/committer fields change; file contents and commit messages stay as they are.
#
# Two ways to use it (Git Bash / Linux, in any folder):
#
#   1) IN PLACE – rewrite the existing repository (keeps name, image, releases, settings):
#        NEW_EMAIL=222504472+soleil0815@users.noreply.github.com \
#          sh tools/clean-history.sh --in-place https://github.com/soleil0815/samaudit.git
#      Overwrites main and the version tags (force push, protected against concurrent changes),
#      offers to delete the other branches, and prints what is left to do: GitHub keeps the old
#      commits reachable through the pull requests until GitHub Support removes them.
#
#   2) INTO A NEW, EMPTY repository:
#        NEW_EMAIL=… sh tools/clean-history.sh <source-url> <target-url>
#      Nothing is changed in the source repository.
#
# NEW_NAME defaults to the user name inside NEW_EMAIL (e.g. "soleil0815").
# Before anything is pushed, the script lists all identities of the new history and refuses
# to push if one of them is neither NEW_NAME <NEW_EMAIL> nor Claude, GitHub or a bot.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi #
set -euo pipefail

usage() { echo "usage: clean-history.sh --in-place REPO_URL   |   clean-history.sh SOURCE_URL TARGET_URL" >&2; exit 2; }
inplace=0
if [ "${1:-}" = "--in-place" ]; then
  inplace=1; src="${2:-}"; target="$src"; [ -n "$src" ] && [ $# -eq 2 ] || usage
else
  [ $# -eq 2 ] || usage
  src="$1"; target="$2"
  [ "$src" != "$target" ] || { echo "source and target are the same – use --in-place" >&2; exit 2; }
fi
NEW_EMAIL="${NEW_EMAIL:?set NEW_EMAIL, e.g. 12345+user@users.noreply.github.com}"
_user="${NEW_EMAIL%%@*}"; _user="${_user#*+}"
NEW_NAME="${NEW_NAME:-$_user}"
case "$NEW_EMAIL" in *@users.noreply.github.com) ;; *)
  echo "NEW_EMAIL should be your GitHub noreply address (…@users.noreply.github.com)" >&2; exit 2 ;;
esac
export NEW_NAME NEW_EMAIL

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
echo "==> Cloning $src"
git clone -q --mirror "$src" "$work/repo.git"
cd "$work/repo.git"

# pull request refs are GitHub-internal: never rewrite or push them
git for-each-ref --format='%(refname)' refs/pull | while read -r r; do git update-ref -d "$r"; done
old_main="$(git rev-parse refs/heads/main)"
other_branches="$(git for-each-ref --format='%(refname:short)' refs/heads | grep -vx main || true)"

echo "==> Rewriting authors and committers to: $NEW_NAME <$NEW_EMAIL>"
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
' --tag-name-filter cat -- refs/heads/main --tags >/dev/null

# drop the backup refs of filter-branch and everything no longer reachable
git for-each-ref --format='%(refname)' refs/original | while read -r r; do git update-ref -d "$r"; done
git reflog expire --expire=now --all && git gc -q --prune=now

echo "==> Identities in the new history (main and tags):"
idents="$(git log refs/heads/main --tags --format='%an <%ae>%n%cn <%ce>' | sort | uniq -c)"
echo "$idents"
bad="$(git log refs/heads/main --tags --format='%an <%ae>%n%cn <%ce>' | sort -u | while read -r line; do
  case "$line" in
    "$NEW_NAME <$NEW_EMAIL>"|"Claude <noreply@anthropic.com>"|"GitHub <noreply@github.com>"|*"[bot] <"*"[bot]@users.noreply.github.com>") ;;
    *) echo "$line" ;;
  esac
done)"
if [ -n "$bad" ]; then
  echo "STOP – these identities would remain, nothing is pushed:" >&2
  echo "$bad" >&2
  exit 1
fi
echo "OK – only $NEW_NAME, Claude, GitHub and bots remain."

echo
if [ "$inplace" = 1 ]; then
  echo "This OVERWRITES main and all version tags in $target."
  echo "Everyone (also your own clones) must fetch the history again afterwards."
fi
read -r -p "Push this history to $target ? [y/N] " a
case "$a" in y|Y|j|J) ;; *) echo "Cancelled – nothing pushed."; exit 0 ;; esac

if [ "$inplace" = 1 ]; then
  # --force-with-lease: refuses if main changed on GitHub since the clone (e.g. a security update)
  git push --force-with-lease="refs/heads/main:$old_main" "$target" "refs/heads/main:refs/heads/main"
  git push --force "$target" "refs/tags/*:refs/tags/*"
  if [ -n "$other_branches" ]; then
    echo
    echo "These branches still carry the old history:"
    echo "$other_branches" | sed 's/^/  /'
    read -r -p "Delete them on GitHub? [y/N] " d
    case "$d" in
      y|Y|j|J) echo "$other_branches" | while read -r b; do git push -q "$target" --delete "$b" && echo "  deleted $b"; done ;;
      *) echo "  kept – delete them later, otherwise the old commits stay reachable." ;;
    esac
  fi
  cat <<'EOT'

Done. Still to do (see the checklist):
  1. Ask GitHub Support to remove the cached views and pull request references of the
     old commits ("Removing sensitive data from a repository"). Text: see the checklist.
  2. Fetch your local clone again:  git fetch --all --tags --force && git reset --hard origin/main
     (or simply clone it again).
EOT
else
  git push "$target" "refs/heads/main:refs/heads/main" "refs/tags/*:refs/tags/*"   # only main and the version tags
  echo "Done. Check the new repository, then follow the remaining steps in the checklist."
fi
