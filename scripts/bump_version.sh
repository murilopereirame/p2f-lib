#!/usr/bin/env bash
# Bump the library version: VERSION, js/package.json and js/package-lock.json
# (they must always match).
#   scripts/bump_version.sh patch     0.4.0 -> 0.4.1
#   scripts/bump_version.sh minor     0.4.1 -> 0.5.0
#   scripts/bump_version.sh major     0.5.0 -> 1.0.0
#   scripts/bump_version.sh 1.2.3     set it
# Prints the new version.
set -euo pipefail
cd "$(dirname "$0")/.."

cur=$(tr -d '[:space:]' < VERSION)
if ! [[ "$cur" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  echo "VERSION is not X.Y.Z: $cur" >&2; exit 1
fi
major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]}

case "${1:-}" in
  patch) patch=$((patch + 1)) ;;
  minor) minor=$((minor + 1)); patch=0 ;;
  major) major=$((major + 1)); minor=0; patch=0 ;;
  *)
    if [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      IFS=. read -r major minor patch <<< "$1"
    else
      echo "usage: $0 patch|minor|major|X.Y.Z" >&2; exit 2
    fi
    ;;
esac

new="$major.$minor.$patch"
if [ "$new" = "$cur" ]; then echo "already $cur" >&2; exit 1; fi
echo "$new" > VERSION
(cd js && npm version "$new" --no-git-tag-version --allow-same-version >/dev/null)
echo "$new"
