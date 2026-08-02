#!/usr/bin/env bash
# bv_actionable_filter.sh - Intersect bv actionable output with authoritative br readiness
#
# This script wraps `bv --recipe actionable --robot-plan` and intersects the
# results with `br ready`, the authoritative claimability surface.
#
# Usage: ./scripts/bv_actionable_filter.sh [--json] [other bv args...]

set -euo pipefail

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
  # In JSON mode, retain only items that the tracker says are ready.
  if [[ "$json_mode" == true ]]; then
    # Get the authoritative ready set. A tracker failure must abort the filter:
    # substituting an empty list or trusting planner status alone would either
    # hide all work or advertise dependency-blocked work as safe.
    br_ready_json=$(br ready --json 2>/dev/null)

    # Filter bv output using jq
    printf '%s\n' "$bv_output" | jq --argjson ready "$br_ready_json" '
      # `br` JSON surfaces may be bare arrays or pagination envelopes. Accept
      # both contracts, but reject every unknown shape so planner safety cannot
      # silently degrade on another CLI drift.
      def issue_array($snapshot; $label):
        if ($snapshot | type) == "array" then
          $snapshot
        elif ($snapshot | type) == "object"
          and (($snapshot.issues // null) | type) == "array"
        then
          $snapshot.issues
        else
          error($label + " must be an issue array or an object with issues[]")
        end;
      def issue_ids($snapshot; $label):
        issue_array($snapshot; $label)
        | map(
            if (.id | type) == "string" then
              .id
            else
              error($label + " contains an issue without a string id")
            end
          );
      def ready_ids: issue_ids($ready; "br ready snapshot");

      # `br ready` is authoritative. Planner items absent from it may be
      # dependency-blocked even when their own serialized status is `open`.
      .plan.tracks |= map(
        .items |= map(
          select(.id as $id | (ready_ids | index($id)) != null)
        )
      ) |

      # Remove tracks that have no items after filtering
      .plan.tracks |= map(select(.items | length > 0))
    '
  else
    # For non-JSON mode, output as-is (could add text filtering here if needed)
    printf '%s\n' "$bv_output"
  fi
else
  # If bv command failed, exit with same code
  exit $?
fi
