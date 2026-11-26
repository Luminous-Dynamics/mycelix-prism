#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Stage the canonical Mycelix knowledge seed snapshot for Prism's compile-time
# include_str! paths. The upstream repository and commit are pinned in CI.
#
# This script copies only seed-data/ into the expected sibling directory:
#   ../mycelix-knowledge/seed-data/claims/*.json
#
# It never fabricates or substitutes missing claim datasets.

set -euo pipefail

if [[ "${GITHUB_ACTIONS:-}" != "true" || -z "${GITHUB_WORKSPACE:-}" ]]; then
  echo "error: this staging helper is intended for a clean GitHub Actions workspace" >&2
  exit 2
fi

repo_root="$(cd -- "$GITHUB_WORKSPACE" && pwd -P)"
upstream_seed_data="$repo_root/mycelix-upstream/mycelix-workspace/mycelix-knowledge/seed-data"
workspace_parent="$(cd -- "$repo_root/.." && pwd -P)"
sibling_root="$workspace_parent/mycelix-knowledge"
target_seed_data="$sibling_root/seed-data"

required_files=(
  energy-facts.json
  geonames-major.json
  who-health.json
  noaa-climate.json
  fao-agriculture.json
)

if [[ ! -d "$upstream_seed_data/claims" ]]; then
  echo "error: canonical Mycelix seed-data directory is missing: $upstream_seed_data" >&2
  exit 2
fi

for name in "${required_files[@]}"; do
  source_file="$upstream_seed_data/claims/$name"
  if [[ ! -s "$source_file" ]]; then
    echo "error: required canonical claim dataset is missing or empty: $source_file" >&2
    exit 2
  fi
done

if [[ -e "$sibling_root" || -L "$sibling_root" ]]; then
  echo "error: refusing to overwrite pre-existing sibling path: $sibling_root" >&2
  exit 2
fi

mkdir -p "$sibling_root"
cp -a "$upstream_seed_data" "$target_seed_data"

{
  echo "Mycelix knowledge source staged from pinned upstream commit."
  echo "Seed data path: $target_seed_data"
  sha256sum "${required_files[@]/#/$target_seed_data/claims/}"
} | tee "$RUNNER_TEMP/prism-knowledge-seed-digests.txt"

echo "Staged all ${#required_files[@]} canonical JSON datasets."
