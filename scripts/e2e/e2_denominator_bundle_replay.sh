#!/usr/bin/env bash
set -euo pipefail

# Replay wrapper for the E2 denominator reproducibility-bundle gate (bd-fqlfw.2.6).
#
# Picks the latest *complete* preserved artifact bundle (one carrying a
# run_manifest.json), then re-runs the deterministic `ci` validation against the
# committed bundle and asserts the verdict reproduces the preserved one. Honours
# E2_DENOM_BUNDLE_REPLAY_RUN_DIR to pin an exact preserved bundle. Fails closed
# when no complete bundle exists.

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

artifact_root="${E2_DENOM_ARTIFACT_ROOT:-artifacts/e2_denominator_bundle}"

pick_latest_complete() {
  local dir
  while IFS= read -r dir; do
    if [[ -f "$dir/run_manifest.json" ]]; then
      printf '%s\n' "$dir"
      return 0
    fi
  done < <(find "$artifact_root" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r)
  return 1
}

run_dir="${E2_DENOM_BUNDLE_REPLAY_RUN_DIR:-}"
if [[ -z "$run_dir" ]]; then
  if ! run_dir="$(pick_latest_complete)"; then
    echo "❌ no complete e2-denominator-bundle run found under $artifact_root" >&2
    echo "   run ./scripts/run_e2_denominator_bundle_gate.sh ci first" >&2
    exit 1
  fi
fi

manifest="$run_dir/run_manifest.json"
[[ -f "$manifest" ]] || { echo "❌ incomplete bundle (no run_manifest.json): $run_dir" >&2; exit 1; }

prior_outcome="$(jq -r '.outcome' "$manifest")"
prior_status="$(jq -r '.bundle_status' "$manifest")"
echo "Replaying preserved bundle: $run_dir"
echo "  preserved outcome=${prior_outcome} bundle_status=${prior_status}"

# Re-run the deterministic validation against the committed bundle.
replay_root="$(mktemp -d)"
E2_DENOM_ARTIFACT_ROOT="$replay_root" ./scripts/run_e2_denominator_bundle_gate.sh ci
fresh_dir="$(find "$replay_root" -mindepth 1 -maxdepth 1 -type d | sort -r | head -n1)"
fresh_outcome="$(jq -r '.outcome' "$fresh_dir/run_manifest.json")"
fresh_status="$(jq -r '.bundle_status' "$fresh_dir/run_manifest.json")"
echo "  replayed outcome=${fresh_outcome} bundle_status=${fresh_status}"

if [[ "$fresh_outcome" != "$prior_outcome" || "$fresh_status" != "$prior_status" ]]; then
  echo "❌ replay divergence: preserved (${prior_outcome}/${prior_status}) != replayed (${fresh_outcome}/${fresh_status})" >&2
  exit 1
fi

echo "✅ e2-denominator-bundle replay verdict reproduced (${fresh_outcome}/${fresh_status})"
