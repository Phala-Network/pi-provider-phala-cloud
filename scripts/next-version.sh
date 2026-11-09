#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/next-version.sh <patch|minor|major|x.y.z>
# Output: new version without prefix (e.g. 1.2.4)
#
# Base version is the highest of: latest git tag, package.json, npm registry.

ARG="${1:-patch}"
ARG="${ARG#v}"

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

if [[ "$ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  requested="${ARG}"
  if [[ -n "${PKG_NAME:-}" ]] && npm view "$PKG_NAME@$requested" version >/dev/null 2>&1; then
    echo "version $requested is already published on npm" >&2
    exit 1
  fi
  if git rev-parse -q --verify "refs/tags/${TAG_PREFIX}${requested}" >/dev/null 2>&1; then
    echo "tag ${TAG_PREFIX}${requested} already exists" >&2
    exit 1
  fi
  highest=$(printf '%s\n' "$base_version" "$requested" | sort -V | tail -n1)
  if [[ "$requested" == "$base_version" || "$highest" != "$requested" ]]; then
    echo "version $requested is not greater than current $base_version" >&2
    exit 1
  fi
  echo "$requested"
  exit 0
fi

case "$ARG" in
  patch|minor|major) ;;
  *)
    echo "invalid bump or version: $ARG (use patch|minor|major or x.y.z)" >&2
    exit 1
    ;;
esac

IFS='.' read -r major minor patch_v <<< "$base_version"
major=${major:-0}
minor=${minor:-0}
patch_v=${patch_v:-0}

case "$ARG" in
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
