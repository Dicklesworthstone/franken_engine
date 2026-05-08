#!/usr/bin/env bash
# bv_actionable_filter.sh - Filter bv actionable output to exclude blocked/in-progress beads
#
# This script wraps `bv --recipe actionable --robot-plan` and filters the results
# to exclude beads that are blocked or in-progress, which should not be actionable.
#
# Usage: ./scripts/bv_actionable_filter.sh [--json] [other bv args...]

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Parse arguments to detect --json mode and pass through other args
json_mode=false
bv_args=()
for arg in "$@"; do
  if [[ "$arg" == "--json" ]]; then
    json_mode=true
  fi
  bv_args+=("$arg")
done

# Run bv and capture output
if bv_output=$(bv --recipe actionable --robot-plan "${bv_args[@]}" 2>/dev/null); then
  # If JSON mode, filter the output to exclude blocked/in-progress items
  if [[ "$json_mode" == true ]]; then
    # Get current bead statuses
    br_blocked_json=$(br list --status=blocked --json 2>/dev/null || echo "[]")
    br_in_progress_json=$(br list --status=in_progress --json 2>/dev/null || echo "[]")

    # Filter bv output using jq
    echo "$bv_output" | jq --argjson blocked "$br_blocked_json" --argjson in_progress "$br_in_progress_json" '
      def blocked_ids: [$blocked[].id];
      def in_progress_ids: [$in_progress[].id];
      def excluded_ids: (blocked_ids + in_progress_ids);

      # Filter tracks to exclude blocked/in-progress items
      .plan.tracks |= map(
        .items |= map(
          select(.id as $id | (excluded_ids | index($id)) == null)
        )
      ) |

      # Remove tracks that have no items after filtering
      .plan.tracks |= map(select(.items | length > 0))
    '
  else
    # For non-JSON mode, output as-is (could add text filtering here if needed)
    echo "$bv_output"
  fi
else
  # If bv command failed, exit with same code
  exit $?
fi