#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/next-version.sh <patch|minor|major>
# Output: new version without prefix (e.g. 1.2.4)
#
# Base version is the highest of: latest git tag, package.json, npm registry.
# This repo's package.json (0.2.0) is behind npm (0.7.x); git tags may be absent.

BUMP="${1:-patch}"

case "$BUMP" in
  patch|minor|major) ;;
  *)
    echo "invalid bump: $BUMP" >&2
    exit 1
    ;;
esac

env_file="release-naming.env"
if [[ ! -f "$env_file" ]]; then
  echo "missing naming contract file: $env_file" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$env_file"

if [[ -z "${TAG_PREFIX:-}" ]]; then
  echo "TAG_PREFIX is empty in $env_file" >&2
  exit 1
fi

versions=()

latest_tag=$(git tag -l "${TAG_PREFIX}*" --sort=-version:refname | head -n1 || true)
if [[ -n "$latest_tag" ]]; then
  versions+=("${latest_tag#${TAG_PREFIX}}")
fi

if [[ -f package.json ]]; then
  versions+=("$(node -p "require('./package.json').version")")
fi

if [[ -n "${PKG_NAME:-}" ]]; then
  if published=$(npm view "$PKG_NAME" version 2>/dev/null); then
    versions+=("$published")
  fi
fi

if [[ ${#versions[@]} -eq 0 ]]; then
  base_version="0.0.0"
else
  base_version=$(printf '%s\n' "${versions[@]}" | sed 's/-.*//' | sort -V | tail -n1)
fi

IFS='.' read -r major minor patch_v <<< "$base_version"
major=${major:-0}
minor=${minor:-0}
patch_v=${patch_v:-0}

case "$BUMP" in
  patch)
    patch_v=$((patch_v + 1))
    ;;
  minor)
    minor=$((minor + 1))
    patch_v=0
    ;;
  major)
    major=$((major + 1))
    minor=0
    patch_v=0
    ;;
esac

echo "${major}.${minor}.${patch_v}"
