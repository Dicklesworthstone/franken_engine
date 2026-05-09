#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_VALIDATION_PLANNER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-validation-planner}"
run_id="${SWARM_VALIDATION_PLANNER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_VALIDATION_PLANNER_RUN_DIR:-${artifact_root}/${run_id}}"
bead_id="${SWARM_VALIDATION_PLANNER_BEAD_ID:-}"
source_revision="${SWARM_VALIDATION_PLANNER_SOURCE_REVISION:-}"
proof_cost_history_json="${SWARM_VALIDATION_PLANNER_PROOF_COST_HISTORY_JSON:-}"
reservation_snapshot_json="${SWARM_VALIDATION_PLANNER_RESERVATION_SNAPSHOT_JSON:-}"
in_progress_json="${SWARM_VALIDATION_PLANNER_IN_PROGRESS_JSON:-}"
native_route_advisory_json="${SWARM_VALIDATION_PLANNER_NATIVE_ROUTE_ADVISORY_JSON:-}"
package_override=""
test_target_override=""
allow_broad="false"
declare -a changed_paths=()
declare -a planned_write_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_validation_planner.sh --bead-id ID [OPTIONS] --changed-path PATH [...]

Options:
  --output-dir DIR          Write plan artifacts to DIR
  --source-revision REV     Source revision to record. Defaults to git rev-parse --short HEAD.
  --proof-cost-history-json PATH
                            Optional franken-engine.proof-cost-history.v1 artifact for cost prediction.
  --reservation-snapshot-json PATH
                            Optional Agent Mail reservation snapshot JSON fixture.
  --in-progress-json PATH   Optional br in-progress bead snapshot JSON fixture.
  --native-route-advisory-json PATH
                            Optional franken-engine.native-dependency-routing-advisory.v1 artifact.
  --package PACKAGE         Optional package override for Rust path fallback.
  --test-target TARGET      Optional exact integration test target.
  --allow-broad             Permit broad all-targets planning. Default is fail-closed/no broad commands.
  --changed-path PATH       Path changed by the bead. May be repeated.
  --planned-write-path PATH Planned write path for collision-risk planning. May be repeated.

By default, artifacts are written outside the repository under TMPDIR.
The planner does not execute validation. It writes:
  plan.json
  commands.txt
  report.md
  collision_receipt.json
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bead-id)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      bead_id="$2"
      shift 2
      ;;
    --output-dir)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      run_dir="$2"
      shift 2
      ;;
    --source-revision)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      source_revision="$2"
      shift 2
      ;;
    --proof-cost-history-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      proof_cost_history_json="$2"
      shift 2
      ;;
    --reservation-snapshot-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      reservation_snapshot_json="$2"
      shift 2
      ;;
    --in-progress-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      in_progress_json="$2"
      shift 2
      ;;
    --native-route-advisory-json)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      native_route_advisory_json="$2"
      shift 2
      ;;
    --package)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      package_override="$2"
      shift 2
      ;;
    --test-target)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      test_target_override="$2"
      shift 2
      ;;
    --allow-broad)
      allow_broad="true"
      shift
      ;;
    --changed-path)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      changed_paths+=("$2")
      shift 2
      ;;
    --planned-write-path)
      [[ "$#" -ge 2 ]] || {
        usage
        exit 64
      }
      planned_write_paths+=("$2")
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ "$#" -gt 0 ]]; do
        changed_paths+=("$1")
        shift
      done
      ;;
    -*)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
    *)
      changed_paths+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$bead_id" ]]; then
  printf 'swarm-validation-planner requires --bead-id\n' >&2
  usage
  exit 64
fi

if [[ "${#changed_paths[@]}" -eq 0 ]]; then
  printf 'swarm-validation-planner requires at least one changed path\n' >&2
  usage
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/plan.json"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
collision_receipt_path="${run_dir}/collision_receipt.json"
commands_jsonl="${run_dir}/commands.jsonl"
budgets_jsonl="${run_dir}/proof_cost_budgets.jsonl"
mappings_jsonl="${run_dir}/path_mappings.jsonl"
warnings_jsonl="${run_dir}/warnings.jsonl"
omitted_jsonl="${run_dir}/omitted_commands.jsonl"
reasons_jsonl="${run_dir}/reason_codes.jsonl"
cost_rows_json="${run_dir}/proof_cost_history_rows.json"
changed_paths_json="${run_dir}/changed_paths.json"
planned_write_paths_json="${run_dir}/planned_write_paths.json"
reservation_rows_json="${run_dir}/reservation_snapshot_rows.json"
in_progress_rows_json="${run_dir}/in_progress_snapshot_rows.json"
dirty_rows_json="${run_dir}/dirty_worktree_rows.json"
dirty_rows_jsonl="${run_dir}/dirty_worktree_rows.jsonl"
native_route_advisory_normalized="${run_dir}/native_route_advisory.normalized.json"
: >"$commands_jsonl"
: >"$budgets_jsonl"
: >"$mappings_jsonl"
: >"$warnings_jsonl"
: >"$omitted_jsonl"
: >"$reasons_jsonl"
: >"$dirty_rows_jsonl"
printf '[]\n' >"$cost_rows_json"
printf '[]\n' >"$changed_paths_json"
printf '[]\n' >"$planned_write_paths_json"
printf '[]\n' >"$reservation_rows_json"
printf '[]\n' >"$in_progress_rows_json"
printf '[]\n' >"$dirty_rows_json"
printf '{}\n' >"$native_route_advisory_normalized"

safe_token() {
  tr -c '[:alnum:]_' '_' <<<"$1" | sed 's/_$//'
}

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    realpath --relative-to="$root_dir" "$path"
  else
    printf '%s\n' "${path#./}"
  fi
}

write_path_array_json() {
  local output_path="$1"
  shift || true

  if [[ "$#" -eq 0 ]]; then
    printf '[]\n' >"$output_path"
    return 0
  fi

  {
    local raw_path
    for raw_path in "$@"; do
      repo_relative_path "$raw_path"
    done
  } | jq -R . | jq -s 'map(select(length > 0)) | sort | unique' >"$output_path"
}

reservation_snapshot_status="missing"
in_progress_snapshot_status="missing"
native_route_advisory_status="not_supplied"

json_string_line() {
  jq -nc --arg value "$1" '$value'
}

add_reason() {
  json_string_line "$1" >>"$reasons_jsonl"
}

emit_warning() {
  local kind="$1"
  local detail="$2"

  jq -nc \
    --arg kind "$kind" \
    --arg detail "$detail" \
    '{kind: $kind, detail: $detail}' >>"$warnings_jsonl"
}

emit_omitted() {
  local kind="$1"
  local path="$2"
  local reason="$3"

  jq -nc \
    --arg kind "$kind" \
    --arg path "$path" \
    --arg reason "$reason" \
    '{kind: $kind, path: $path, reason: $reason}' >>"$omitted_jsonl"
}

emit_mapping() {
  local path="$1"
  local kind="$2"
  local package="$3"
  local target="$4"
  local rationale="$5"

  jq -nc \
    --arg path "$path" \
    --arg kind "$kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rationale "$rationale" \
    '{path: $path, kind: $kind, package: (if $package == "" then null else $package end), target: (if $target == "" then null else $target end), rationale: $rationale}' >>"$mappings_jsonl"
}

emit_dirty_row() {
  local path="$1"
  local status="$2"

  jq -nc \
    --arg path "$path" \
    --arg status "$status" \
    '{path: $path, status: $status}' >>"$dirty_rows_jsonl"
}

normalize_reservation_snapshot() {
  if [[ -z "$reservation_snapshot_json" ]]; then
    reservation_snapshot_status="missing"
    printf '[]\n' >"$reservation_rows_json"
    return 0
  fi

  if [[ ! -f "$reservation_snapshot_json" ]]; then
    reservation_snapshot_status="missing"
    emit_warning "missing_reservation_snapshot" "Reservation snapshot file does not exist: ${reservation_snapshot_json}"
    add_reason "missing_reservation_snapshot"
    printf '[]\n' >"$reservation_rows_json"
    return 0
  fi

  if ! jq empty "$reservation_snapshot_json" >/dev/null 2>&1; then
    reservation_snapshot_status="invalid"
    emit_warning "invalid_reservation_snapshot" "Reservation snapshot is not valid JSON: ${reservation_snapshot_json}"
    add_reason "invalid_reservation_snapshot"
    printf '[]\n' >"$reservation_rows_json"
    return 0
  fi

  reservation_snapshot_status="present"
  jq '
    def rows:
      if type == "array" then .
      elif (.reservations? | type) == "array" then .reservations
      elif (.granted? | type) == "array" then .granted
      else []
      end;
    rows
    | map({
        path_pattern: (.path_pattern // .path // ""),
        agent: (.agent_name // .agent // .holder // .assignee // ""),
        bead_id: (.bead_id // .bead // .issue_id // .id // ""),
        exclusive: (.exclusive // true)
      })
    | map(select(.path_pattern != ""))
  ' "$reservation_snapshot_json" >"$reservation_rows_json"
}

normalize_in_progress_snapshot() {
  if [[ -z "$in_progress_json" ]]; then
    in_progress_snapshot_status="missing"
    printf '[]\n' >"$in_progress_rows_json"
    return 0
  fi

  if [[ ! -f "$in_progress_json" ]]; then
    in_progress_snapshot_status="missing"
    emit_warning "missing_in_progress_snapshot" "In-progress bead snapshot file does not exist: ${in_progress_json}"
    add_reason "missing_in_progress_snapshot"
    printf '[]\n' >"$in_progress_rows_json"
    return 0
  fi

  if ! jq empty "$in_progress_json" >/dev/null 2>&1; then
    in_progress_snapshot_status="invalid"
    emit_warning "invalid_in_progress_snapshot" "In-progress bead snapshot is not valid JSON: ${in_progress_json}"
    add_reason "invalid_in_progress_snapshot"
    printf '[]\n' >"$in_progress_rows_json"
    return 0
  fi

  in_progress_snapshot_status="present"
  jq '
    def rows:
      if type == "array" then .
      elif (.beads? | type) == "array" then .beads
      else []
      end;
    rows
    | map({
        id: (.id // ""),
        assignee: (.assignee // .agent_name // .agent // ""),
        status: (.status // ""),
        paths: ((.planned_write_paths // .changed_paths // .paths // []) | map(tostring))
      })
  ' "$in_progress_json" >"$in_progress_rows_json"
}

normalize_cost_history() {
  if [[ -z "$proof_cost_history_json" ]]; then
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  if [[ ! -f "$proof_cost_history_json" ]]; then
    emit_omitted "missing_cost_history" "$proof_cost_history_json" "Proof-cost history file does not exist"
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  if ! jq -e \
    --arg schema_version "franken-engine.proof-cost-history.v1" \
    '.schema_version == $schema_version and (.rows | type == "array")' \
    "$proof_cost_history_json" >/dev/null; then
    emit_omitted "invalid_cost_history" "$proof_cost_history_json" "Proof-cost history must use franken-engine.proof-cost-history.v1 with rows[]"
    printf '[]\n' >"$cost_rows_json"
    return 0
  fi

  jq \
    --arg evidence_source "$proof_cost_history_json" \
    '[
      . as $doc
      | ($doc.rows // [])[]
      | {
          command_id: (.command_id // ""),
          package: (.package // ""),
          target: (.target // ""),
          source_revision: (.source_revision // $doc.source_revision // ""),
          elapsed_ms: (.elapsed_ms // 0),
          compiled_target_count: (.compiled_target_count // 0),
          linked_target_count: (.linked_target_count // 0),
          rch_worker: (.rch_worker // ""),
          rch_status: (.rch_status // ""),
          fallback_detected: (.fallback_detected // false),
          content_hash: (.content_hash // ""),
          artifact_paths: (.artifact_paths // []),
          evidence_source: $evidence_source
        }
    ]' "$proof_cost_history_json" >"$cost_rows_json"
}

normalize_native_route_advisory() {
  if [[ -z "$native_route_advisory_json" ]]; then
    native_route_advisory_status="not_supplied"
    printf '{}\n' >"$native_route_advisory_normalized"
    return 0
  fi

  if [[ ! -f "$native_route_advisory_json" ]]; then
    native_route_advisory_status="missing"
    emit_warning "missing_native_route_advisory" "Native dependency route advisory file does not exist: ${native_route_advisory_json}"
    add_reason "missing_native_route_advisory"
    printf '{}\n' >"$native_route_advisory_normalized"
    return 0
  fi

  if ! jq empty "$native_route_advisory_json" >/dev/null 2>&1; then
    native_route_advisory_status="invalid"
    emit_warning "invalid_native_route_advisory" "Native dependency route advisory is not valid JSON: ${native_route_advisory_json}"
    add_reason "invalid_native_route_advisory"
    printf '{}\n' >"$native_route_advisory_normalized"
    return 0
  fi

  if ! jq -e \
    '.schema_version == "franken-engine.native-dependency-routing-advisory.v1"
      and (.decision | type == "string")
      and (.truth_state | type == "string")' \
    "$native_route_advisory_json" >/dev/null; then
    native_route_advisory_status="invalid"
    emit_warning "invalid_native_route_advisory" "Native dependency route advisory must use franken-engine.native-dependency-routing-advisory.v1 with decision and truth_state"
    add_reason "invalid_native_route_advisory"
    printf '{}\n' >"$native_route_advisory_normalized"
    return 0
  fi

  native_route_advisory_status="present"
  add_reason "native_route_advisory_supplied"
  jq -cS . "$native_route_advisory_json" >"$native_route_advisory_normalized"
}

build_collision_receipt() {
  jq -n \
    --arg schema_version "franken-engine.swarm-validation-collision-receipt.v1" \
    --arg bead_id "$bead_id" \
    --arg source_revision "$source_revision" \
    --arg reservation_snapshot_status "$reservation_snapshot_status" \
    --arg reservation_snapshot_path "$reservation_snapshot_json" \
    --arg in_progress_snapshot_status "$in_progress_snapshot_status" \
    --arg in_progress_snapshot_path "$in_progress_json" \
    --slurpfile changed "$changed_paths_json" \
    --slurpfile planned "$planned_write_paths_json" \
    --slurpfile reservations "$reservation_rows_json" \
    --slurpfile progress "$in_progress_rows_json" \
    --slurpfile dirty "$dirty_rows_json" '
      def glob_to_regex:
        explode
        | map(
            if . == 42 then
              ".*"
            elif . == 63 then
              "."
            elif ((. >= 48 and . <= 57) or (. >= 65 and . <= 90) or (. >= 97 and . <= 122) or . == 47 or . == 95 or . == 45) then
              [.] | implode
            else
              "\\" + ([.] | implode)
            end
          )
        | join("");
      def overlaps($left; $right):
        ($left == $right)
        or ($left | test("^" + ($right | glob_to_regex) + "$"))
        or ($right | test("^" + ($left | glob_to_regex) + "$"));
      ($changed[0] // []) as $changed_paths
      | ($planned[0] // []) as $planned_paths
      | ($reservations[0] // []) as $reservation_rows
      | ($progress[0] // []) as $progress_rows
      | ($dirty[0] // []) as $dirty_rows
      | [
          $planned_paths[] as $path
          | $reservation_rows[]
          | select(.exclusive != false)
          | select(overlaps($path; .path_pattern))
          | {
              planned_path: $path,
              path_pattern: .path_pattern,
              agent: (.agent // null),
              bead_id: (.bead_id // null),
              source: "reservation"
            }
        ] as $reservation_conflicts_raw
      | ($reservation_conflicts_raw | unique_by(.planned_path, .path_pattern, .agent, .bead_id)) as $reservation_conflicts
      | [
          $planned_paths[] as $path
          | $dirty_rows[]
          | select(overlaps($path; .path))
          | {
              planned_path: $path,
              path: (.path // ""),
              status: (.status // ""),
              source: "dirty"
            }
        ] as $dirty_conflicts_raw
      | ($dirty_conflicts_raw | unique_by(.planned_path, .path)) as $dirty_conflicts
      | [
          $planned_paths[] as $path
          | $progress_rows[]
          | select((.id // "") != $bead_id)
          | . as $entry
          | ($entry.paths // [])[]?
          | select(overlaps($path; .))
          | {
              planned_path: $path,
              path: .,
              bead_id: ($entry.id // null),
              assignee: ($entry.assignee // null),
              source: "in_progress"
            }
        ] as $in_progress_conflicts_raw
      | ($in_progress_conflicts_raw | unique_by(.planned_path, .path, .bead_id, .assignee)) as $in_progress_conflicts
      | ([
          $reservation_conflicts[]?.planned_path,
          $dirty_conflicts[]?.planned_path,
          $in_progress_conflicts[]?.planned_path
        ] | unique | sort) as $conflict_paths
      | ([ $planned_paths[] as $path | select(($conflict_paths | index($path)) | not) | $path ] | unique | sort) as $safe_alternatives
      | ([
          $reservation_conflicts[]?.agent,
          $in_progress_conflicts[]?.assignee
        ] | map(select(. != null and . != "")) | unique | sort) as $conflicting_agents
      | ([
          if ($reservation_conflicts | length) > 0 then
            {
              action: "coordinate_reservation_holder",
              scope: "planned_write_set",
              reason: "planned write paths overlap active exclusive reservations"
            }
          else
            empty
          end,
          if (($reservation_snapshot_status != "present") and ($planned_paths | length) > 0) then
            {
              action: "capture_agent_mail_snapshot",
              scope: "planned_write_set",
              reason: "Agent Mail reservation snapshot is missing or invalid; bead ownership and dirty paths are only degraded evidence"
            }
          else
            empty
          end,
          if ($dirty_conflicts | length) > 0 then
            {
              action: "inspect_dirty_overlap",
              scope: "planned_write_set",
              reason: "planned write paths overlap dirty worktree files"
            }
          else
            empty
          end,
          if ($in_progress_conflicts | length) > 0 then
            {
              action: "coordinate_in_progress_beads",
              scope: "planned_write_set",
              reason: "planned write paths overlap in-progress bead path claims"
            }
          else
            empty
          end,
          if (($safe_alternatives | length) > 0 and (($reservation_conflicts | length) > 0 or ($dirty_conflicts | length) > 0 or ($in_progress_conflicts | length) > 0)) then
            {
              action: "reserve_safe_alternatives_only",
              scope: "planned_write_set",
              reason: "non-conflicting planned write paths are available while other paths are contested"
            }
          else
            empty
          end
        ]) as $reservation_recommendations
      | {
          schema_version: $schema_version,
          bead_id: $bead_id,
          source_revision: $source_revision,
          changed_paths: $changed_paths,
          planned_write_paths: $planned_paths,
          agent_mail_snapshot: {
            status: $reservation_snapshot_status,
            path: (if $reservation_snapshot_path == "" then null else $reservation_snapshot_path end)
          },
          in_progress_snapshot: {
            status: $in_progress_snapshot_status,
            path: (if $in_progress_snapshot_path == "" then null else $in_progress_snapshot_path end)
          },
          collision_risk: (
            if ($reservation_conflicts | length) > 0 then
              "reserved_overlap"
            elif (($dirty_conflicts | length) > 0 or ($in_progress_conflicts | length) > 0) then
              "dirty_or_in_progress_overlap"
            elif ($reservation_snapshot_status != "present") then
              "agent_mail_snapshot_missing"
            else
              "none"
            end
          ),
          conflicting_agents: $conflicting_agents,
          safe_alternatives: $safe_alternatives,
          reservation_recommendations: $reservation_recommendations,
          conflicts: {
            reservations: $reservation_conflicts,
            dirty: $dirty_conflicts,
            in_progress: $in_progress_conflicts
          }
        }
    ' >"$collision_receipt_path"
}

cost_prediction_for_command() {
  local command_id="$1"
  local command_kind="$2"
  local package="$3"
  local target="$4"
  local recommended_target_dir="$5"
  local max_compiled="$6"
  local max_linked="$7"
  local max_elapsed_ms="$8"

  jq -nc \
    --slurpfile rows "$cost_rows_json" \
    --arg schema_version "franken-engine.swarm-validation-predicted-cost.v1" \
    --arg source_revision "$source_revision" \
    --arg command_id "$command_id" \
    --arg command_kind "$command_kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg target_dir "$recommended_target_dir" \
    --arg evidence_source "$proof_cost_history_json" \
    --argjson max_compiled "$max_compiled" \
    --argjson max_linked "$max_linked" \
    --argjson max_elapsed_ms "$max_elapsed_ms" '
      def heavy: ($command_kind | startswith("rch_"));
      def failed_status:
        (.fallback_detected == true)
        or ((.rch_status | ascii_downcase) | test("fail|error|timeout|local"));
      def success_status:
        (.fallback_detected != true)
        and ((.rch_status | ascii_downcase) | test("pass|ok|remote|planned:admit|planned:admit_narrow"));
      def nums($field): map(.[$field] // 0);
      def max_or_zero($field): if length == 0 then 0 else (nums($field) | max) end;
      def median_or_zero($field):
        if length == 0 then 0
        else (nums($field) | sort | .[(length / 2 | floor)])
        end;
      def revisions: map(.source_revision) | unique | sort;
      def hashes: map(.content_hash) | map(select(. != "")) | unique | sort;
      def base_prediction($state; $class; $sample_count; $fresh_rows; $stale_rows; $matched_rows; $risk_flags; $status; $evidence_rows):
        {
          predicted_cost: {
            schema_version: $schema_version,
            state: $state,
            cost_class: $class,
            sample_count: $sample_count,
            elapsed_ms_p50: ($evidence_rows | median_or_zero("elapsed_ms")),
            elapsed_ms_max: ($evidence_rows | max_or_zero("elapsed_ms")),
            compiled_target_count_max: ($evidence_rows | max_or_zero("compiled_target_count")),
            linked_target_count_max: ($evidence_rows | max_or_zero("linked_target_count"))
          },
          recommended_target_dir: (if $target_dir == "" then null else $target_dir end),
          risk_flags: $risk_flags,
          cost_evidence: {
            status: $status,
            source: (if $evidence_source == "" then null else $evidence_source end),
            matched_rows: $matched_rows,
            fresh_rows: $fresh_rows,
            stale_rows: $stale_rows,
            source_revisions: ($evidence_rows | revisions),
            content_hashes: ($evidence_rows | hashes)
          }
        };
      if (heavy | not) then
        base_prediction("static"; "low"; 0; 0; 0; 0; []; "not_required"; [])
      else
        ($rows[0] // []) as $all
        | [$all[] | select(.command_id == $command_id)] as $same_id
        | [$same_id[] | select(.package != $package or .target != $target)] as $mismatched
        | [$all[] | select(.command_id == $command_id and .package == $package and .target == $target)] as $matched
        | [$matched[] | select(.source_revision == $source_revision)] as $fresh
        | [$matched[] | select(.source_revision != $source_revision)] as $stale
        | if ($mismatched | length) > 0 then
            base_prediction("mismatched"; "unknown"; 0; 0; ($stale | length); ($matched | length); ["mismatched_cost_evidence"]; "mismatched"; ($mismatched + $matched))
          elif ($matched | length) == 0 then
            base_prediction("unknown"; "unknown"; 0; 0; 0; 0; ["unknown_cost_evidence"]; "unknown"; [])
          elif ($fresh | length) == 0 then
            base_prediction("stale"; "unknown"; 0; 0; ($stale | length); ($matched | length); ["stale_cost_evidence"]; "stale"; $stale)
          else
            ($fresh | max_or_zero("elapsed_ms")) as $elapsed_max
            | ($fresh | max_or_zero("compiled_target_count")) as $compiled_max
            | ($fresh | max_or_zero("linked_target_count")) as $linked_max
            | ([$fresh[] | select(failed_status)] | length) as $failed_count
            | ([$fresh[] | select(success_status)] | length) as $success_count
            | ([$fresh[] | select(.fallback_detected == true)] | length) as $fallback_count
            | if ($failed_count > 0 and $success_count > 0) then
                base_prediction("contradictory"; "unknown"; ($fresh | length); ($fresh | length); ($stale | length); ($matched | length); ["contradictory_cost_evidence"]; "contradictory"; $fresh)
              else
                ([
                  (if $failed_count > 0 then "failed_cost_history" else empty end),
                  (if $fallback_count > 0 then "fallback_cost_history" else empty end),
                  (if ($elapsed_max > $max_elapsed_ms or $compiled_max > $max_compiled or $linked_max > $max_linked) then "high_cost_history" else empty end)
                ]) as $risks
                | (if ($failed_count > 0 or $fallback_count > 0 or $elapsed_max > $max_elapsed_ms or $compiled_max > $max_compiled or $linked_max > $max_linked) then "high"
                   elif ($elapsed_max > ($max_elapsed_ms / 2 | floor)) then "medium"
                   else "low"
                   end) as $class
                | base_prediction("matched"; $class; ($fresh | length); ($fresh | length); ($stale | length); ($matched | length); $risks; "matched"; $fresh)
              end
          end
      end'
}

native_route_projection_for_command() {
  local display="$1"
  local command_kind="$2"

  jq -nc \
    --arg input_status "$native_route_advisory_status" \
    --arg input_path "$native_route_advisory_json" \
    --arg display "$display" \
    --arg command_kind "$command_kind" \
    --slurpfile advisory "$native_route_advisory_normalized" '
      def heavy: ($command_kind | startswith("rch_"));
      def base_route($status; $decision; $truth_state; $reason_codes; $command_match):
        {
          source: (if $input_path == "" then null else $input_path end),
          status: $status,
          decision: $decision,
          truth_state: $truth_state,
          command_match: $command_match,
          required_dependency_ids: [],
          compatible_worker_ids: [],
          incompatible_worker_ids: [],
          fail_closed_worker_ids: [],
          retry_advice: {},
          reason_codes: $reason_codes,
          mutation_policy: {}
        };
      if (heavy | not) or $input_status == "not_supplied" then
        {include: false, risk_flags: []}
      elif $input_status != "present" then
        {
          include: true,
          risk_flags: ["native_dependency_route_input_" + $input_status],
          routing: base_route("fail_closed"; "fail_closed"; "unknown"; ["native_route_advisory_" + $input_status]; true)
        }
      else
        ($advisory[0] // {}) as $route
        | ($route.command // "") as $route_command
        | (($route_command == "") or ($route_command == $display)) as $command_match
        | ($route.compatible_worker_ids // []) as $compatible
        | (($route.incompatible_workers // []) | map(.worker_id // "unknown-worker")) as $incompatible
        | (($route.fail_closed_workers // []) | map(.worker_id // "unknown-worker")) as $fail_closed_workers
        | ($route.decision // "fail_closed") as $decision
        | ($route.truth_state // "unknown") as $truth_state
        | ($route.reason_codes // []) as $reason_codes
        | (
            if ($command_match | not) then "fail_closed"
            elif $decision == "pass" and $truth_state == "confirmed" and (($incompatible | length) > 0 or ($fail_closed_workers | length) > 0) then "compatible_with_rejections"
            elif $decision == "pass" and $truth_state == "confirmed" then "compatible"
            elif $decision == "blocked" then "blocked"
            else "fail_closed"
            end
          ) as $status
        | {
            include: true,
            risk_flags: (
              if ($command_match | not) then ["native_dependency_route_command_mismatch"]
              elif $status == "blocked" then ["native_dependency_route_blocked"]
              elif $status == "fail_closed" then ["native_dependency_route_fail_closed"]
              elif $status == "compatible_with_rejections" then ["native_dependency_incompatible_workers_rejected"]
              else []
              end
            ),
            routing: {
              source: $input_path,
              status: $status,
              decision: $decision,
              truth_state: $truth_state,
              command_match: $command_match,
              routing_advisory_id: ($route.routing_advisory_id // null),
              validation_id: ($route.validation_id // null),
              required_dependency_ids: ($route.required_dependency_ids // []),
              compatible_worker_ids: $compatible,
              incompatible_worker_ids: $incompatible,
              fail_closed_worker_ids: $fail_closed_workers,
              retry_advice: ($route.retry_advice // {}),
              reason_codes: $reason_codes,
              mutation_policy: ($route.mutation_policy // {})
            }
          }
      end'
}

emit_command() {
  local command_id="$1"
  local display="$2"
  local command_kind="$3"
  local package="$4"
  local target="$5"
  local rationale="$6"
  local recommended_target_dir="${7:-}"
  local max_compiled="${8:-0}"
  local max_linked="${9:-0}"
  local max_elapsed_ms="${10:-0}"
  local prediction native_projection

  prediction="$(cost_prediction_for_command "$command_id" "$command_kind" "$package" "$target" "$recommended_target_dir" "$max_compiled" "$max_linked" "$max_elapsed_ms")"
  native_projection="$(native_route_projection_for_command "$display" "$command_kind")"
  jq -nc \
    --arg command_id "$command_id" \
    --arg display "$display" \
    --arg command_kind "$command_kind" \
    --arg package "$package" \
    --arg target "$target" \
    --arg rationale "$rationale" \
    --argjson prediction "$prediction" \
    --argjson native_projection "$native_projection" \
    '({
      command_id: $command_id,
      display: $display,
      command_kind: $command_kind,
      package: (if $package == "" then null else $package end),
      target: (if $target == "" then null else $target end),
      rationale: $rationale,
      predicted_cost: $prediction.predicted_cost,
      recommended_target_dir: $prediction.recommended_target_dir,
      risk_flags: (($prediction.risk_flags + ($native_projection.risk_flags // [])) | sort | unique),
      cost_evidence: $prediction.cost_evidence
    } + (if $native_projection.include then {native_dependency_routing: $native_projection.routing} else {} end))' >>"$commands_jsonl"
}

emit_budget() {
  local suite="$1"
  local package="$2"
  local max_compiled="$3"
  local max_linked="$4"
  local max_tests="$5"
  local max_libs="$6"

  jq -nc \
    --arg schema_version "franken-engine.focused-proof-cost-budget.v1" \
    --arg suite "$suite" \
    --arg package "$package" \
    --argjson max_compiled "$max_compiled" \
    --argjson max_linked "$max_linked" \
    --argjson max_tests "$max_tests" \
    --argjson max_libs "$max_libs" \
    '{
      schema_version: $schema_version,
      suite: $suite,
      package: $package,
      max_total_compiled_targets: $max_compiled,
      max_total_linked_targets: $max_linked,
      max_unexpected_targets: 0,
      max_targets_by_kind: {
        test: $max_tests,
        lib: $max_libs
      }
    }' >>"$budgets_jsonl"
}

package_for_path() {
  local path="$1"
  if [[ -n "$package_override" ]]; then
    printf '%s\n' "$package_override"
  elif [[ "$path" == crates/franken-engine/* ]]; then
    printf 'frankenengine-engine\n'
  elif [[ "$path" == crates/franken-extension-host/* ]]; then
    printf 'frankenengine-extension-host\n'
  else
    printf '\n'
  fi
}

target_from_test_path() {
  basename "$1" .rs
}

target_dir_for() {
  local suffix="$1"
  printf '/tmp/rch_target_franken_engine_%s_%s\n' "$(safe_token "$bead_id")" "$(safe_token "$suffix")"
}

plan_exact_test() {
  local path="$1"
  local package="$2"
  local target="$3"
  local suffix target_dir command_id command

  suffix="${package}_${target}"
  target_dir="$(target_dir_for "$suffix")"
  command_id="cargo-test-$(safe_token "$target")"
  command="rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo test -p ${package} --test ${target}"
  emit_command "$command_id" "$command" "rch_cargo_test" "$package" "$target" "exact test target inferred from changed integration test path" "$target_dir" 2 1 120000
  emit_budget "$target" "$package" 2 1 1 1
  emit_mapping "$path" "exact_test_target" "$package" "$target" "changed integration test maps to its exact test target"
  add_reason "exact_test_target"
}

plan_package_fallback() {
  local path="$1"
  local package="$2"
  local suffix target_dir command_id command

  suffix="${package}_lib"
  target_dir="$(target_dir_for "$suffix")"
  command_id="cargo-check-$(safe_token "$package")-lib"
  command="rch exec -- env CARGO_TARGET_DIR=${target_dir} cargo check -p ${package} --lib"
  emit_command "$command_id" "$command" "rch_cargo_check_lib" "$package" "lib" "package lib fallback for source changes without an exact test target" "$target_dir" 1 0 90000
  emit_budget "${package}_lib" "$package" 1 0 0 1
  emit_mapping "$path" "package_lib_fallback" "$package" "lib" "source path maps to package-level lib check without broad all-targets fanout"
  add_reason "package_lib_fallback"
}

plan_script() {
  local path="$1"
  local command_id

  command_id="bash-n-$(safe_token "$path")"
  emit_command "$command_id" "bash -n ${path}" "shell_syntax" "" "" "script syntax validation"
  emit_command "shellcheck-$(safe_token "$path")" "shellcheck -x ${path}" "shellcheck" "" "" "script static analysis"
  emit_mapping "$path" "script_only" "" "" "shell script changes need syntax/static checks, not Cargo"
  add_reason "script_only"
}

plan_docs() {
  local path="$1"

  if [[ "$path" == *.json ]]; then
    emit_command "jq-empty-$(safe_token "$path")" "jq empty ${path}" "json_syntax" "" "" "JSON contract syntax validation"
  fi
  emit_command "diff-check-$(safe_token "$path")" "git diff --check -- ${path}" "diff_check" "" "" "docs whitespace validation"
  emit_mapping "$path" "docs_only" "" "" "docs changes do not require Cargo"
  add_reason "docs_only"
}

if [[ "${#planned_write_paths[@]}" -eq 0 ]]; then
  planned_write_paths=("${changed_paths[@]}")
fi

write_path_array_json "$changed_paths_json" "${changed_paths[@]}"
write_path_array_json "$planned_write_paths_json" "${planned_write_paths[@]}"
normalize_reservation_snapshot
normalize_in_progress_snapshot
normalize_cost_history
normalize_native_route_advisory

for raw_path in "${changed_paths[@]}"; do
  path="$(repo_relative_path "$raw_path")"
  package="$(package_for_path "$path")"

  case "$path" in
    crates/franken-engine/tests/*.rs|crates/franken-extension-host/tests/*.rs)
      target="${test_target_override:-$(target_from_test_path "$path")}"
      plan_exact_test "$path" "$package" "$target"
      ;;
    crates/franken-engine/src/*.rs|crates/franken-extension-host/src/*.rs)
      if [[ -n "$test_target_override" ]]; then
        plan_exact_test "$path" "$package" "$test_target_override"
        emit_mapping "$path" "source_with_operator_test_target" "$package" "$test_target_override" "operator supplied exact test target for source change"
        add_reason "operator_test_target"
      elif [[ -n "$package" ]]; then
        plan_package_fallback "$path" "$package"
      else
        emit_omitted "unknown_path_mapping" "$path" "Rust path does not map to a known workspace package"
        add_reason "unknown_path_mapping"
      fi
      ;;
    scripts/*.sh)
      plan_script "$path"
      ;;
    docs/*.json|docs/*.md|README.md|AGENTS.md)
      plan_docs "$path"
      ;;
    .beads/issues.jsonl)
      emit_command "jq-empty-beads" "jq empty .beads/issues.jsonl" "jsonl_syntax" "" "" "beads JSONL validation"
      emit_mapping "$path" "tracker_only" "" "" "tracker updates validate with JSONL parse only"
      add_reason "tracker_only"
      ;;
    *)
      emit_omitted "unknown_path_mapping" "$path" "No focused validation mapping exists for this path"
      add_reason "unknown_path_mapping"
      ;;
  esac
done

if [[ "$allow_broad" == "true" ]]; then
  emit_warning "broad_validation_allowed" "operator passed --allow-broad, but this planner still prefers focused commands"
else
  emit_omitted "broad_all_targets" "*" "Broad all-targets checks are intentionally omitted unless a later artifact justifies them"
fi

dirty_status="${SWARM_VALIDATION_PLANNER_GIT_STATUS_OVERRIDE-__unset__}"
if [[ "$dirty_status" == "__unset__" ]]; then
  dirty_status="$(git -C "$root_dir" status --short --untracked-files=normal 2>/dev/null || true)"
fi

if [[ -n "$dirty_status" ]]; then
  while IFS= read -r status_line; do
    [[ -z "$status_line" ]] && continue
    status_code="${status_line:0:2}"
    dirty_path="${status_line:3}"
    dirty_path="${dirty_path# }"
    dirty_path="${dirty_path#\"}"
    dirty_path="${dirty_path%\"}"
    dirty_path="$(repo_relative_path "$dirty_path")"
    emit_dirty_row "$dirty_path" "$status_code"
    matched="false"
    for raw_path in "${changed_paths[@]}"; do
      rel_changed="$(repo_relative_path "$raw_path")"
      if [[ "$dirty_path" == "$rel_changed" ]]; then
        matched="true"
      fi
    done
    if [[ "$matched" == "true" ]]; then
      emit_warning "dirty_changed_path" "$dirty_path is dirty and part of the requested validation plan"
    else
      emit_warning "unrelated_dirty_worktree" "$dirty_path is dirty but outside the requested validation plan"
    fi
  done <<<"$dirty_status"
fi

jq -s 'sort_by(.path, .status) | unique_by(.path, .status)' "$dirty_rows_jsonl" >"$dirty_rows_json"
build_collision_receipt

collision_risk="$(jq -r '.collision_risk' "$collision_receipt_path")"
reservation_overlap_count="$(jq '.conflicts.reservations | length' "$collision_receipt_path")"
dirty_overlap_count="$(jq '.conflicts.dirty | length' "$collision_receipt_path")"
in_progress_overlap_count="$(jq '.conflicts.in_progress | length' "$collision_receipt_path")"
if [[ "$reservation_overlap_count" -ne 0 ]]; then
  emit_warning "reserved_file_overlap" "planned write paths overlap active exclusive reservations"
  add_reason "reserved_file_overlap"
fi
if [[ "$dirty_overlap_count" -ne 0 ]]; then
  emit_warning "dirty_overlap" "planned write paths overlap dirty worktree files"
  add_reason "dirty_overlap"
fi
if [[ "$in_progress_overlap_count" -ne 0 ]]; then
  emit_warning "in_progress_overlap" "planned write paths overlap in-progress bead path claims"
  add_reason "in_progress_overlap"
fi
if [[ "$collision_risk" == "agent_mail_snapshot_missing" ]]; then
  emit_warning "agent_mail_snapshot_missing" "Agent Mail reservation snapshot is missing or invalid; planner is using degraded ownership evidence"
  add_reason "agent_mail_snapshot_missing"
fi

jq -s 'sort_by(.command_id) | unique_by(.command_id)' "$commands_jsonl" >"${commands_jsonl}.tmp"
mv "${commands_jsonl}.tmp" "$commands_jsonl"
jq -r '.[].display' "$commands_jsonl" >"$commands_path"

command_count="$(jq 'length' "$commands_jsonl")"
unknown_count="$(jq -s '[.[] | select(.kind == "unknown_path_mapping" or .kind == "missing_file")] | length' "$omitted_jsonl")"
cost_failure_count="$(jq -s '[.[] | select(.kind == "missing_cost_history" or .kind == "invalid_cost_history")] | length' "$omitted_jsonl")"
fallback_count="$(jq -s '[.[] | select(.kind == "package_lib_fallback")] | length' "$mappings_jsonl")"
risk_flags_json="$(jq '[.[].risk_flags[]?] | sort | unique' "$commands_jsonl")"
cost_fail_closed_count="$(jq '[.[].risk_flags[]? | select(. == "mismatched_cost_evidence" or . == "contradictory_cost_evidence")] | length' "$commands_jsonl")"
native_route_blocked_count="$(jq '[.[].native_dependency_routing? | select(.status == "blocked")] | length' "$commands_jsonl")"
native_route_fail_closed_count="$(jq '[.[].native_dependency_routing? | select(.status == "fail_closed")] | length' "$commands_jsonl")"
native_route_narrow_count="$(jq '[.[].native_dependency_routing? | select(.status == "compatible_with_rejections")] | length' "$commands_jsonl")"
if [[ "$native_route_blocked_count" -ne 0 ]]; then
  emit_warning "native_route_blocked" "native dependency route advisory reports no compatible worker for at least one heavy proof command"
  add_reason "native_route_blocked"
fi
if [[ "$native_route_fail_closed_count" -ne 0 ]]; then
  emit_warning "native_route_fail_closed" "native dependency route advisory is missing, invalid, stale, contradictory, contaminated, or mismatched for at least one heavy proof command"
  add_reason "native_route_fail_closed"
fi
if [[ "$native_route_narrow_count" -ne 0 ]]; then
  emit_warning "native_route_compatible_with_rejections" "native dependency route advisory selected a compatible worker while rejecting incompatible or fail-closed candidates"
  add_reason "native_route_compatible_with_rejections"
fi
decision="admit"
if [[ "$unknown_count" -ne 0 || "$cost_failure_count" -ne 0 || "$cost_fail_closed_count" -ne 0 || "$native_route_blocked_count" -ne 0 || "$native_route_fail_closed_count" -ne 0 || "$command_count" -eq 0 || "$reservation_overlap_count" -ne 0 ]]; then
  decision="fail_closed"
elif [[ "$fallback_count" -ne 0 || "$dirty_overlap_count" -ne 0 || "$in_progress_overlap_count" -ne 0 || "$collision_risk" == "agent_mail_snapshot_missing" || "$native_route_narrow_count" -ne 0 ]]; then
  decision="admit_narrow"
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-validation-plan.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg run_dir "$run_dir" \
  --arg plan_path "$plan_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg collision_receipt_path "$collision_receipt_path" \
  --argjson allow_broad "$allow_broad" \
  --argjson risk_flags "$risk_flags_json" \
  --slurpfile mappings "$mappings_jsonl" \
  --slurpfile commands "$commands_jsonl" \
  --slurpfile budgets "$budgets_jsonl" \
  --slurpfile warnings "$warnings_jsonl" \
  --slurpfile omitted "$omitted_jsonl" \
  --slurpfile reasons "$reasons_jsonl" \
  --slurpfile changed_paths "$changed_paths_json" \
  --slurpfile planned_write_paths "$planned_write_paths_json" \
  --slurpfile collision "$collision_receipt_path" \
  '{
    schema_version: $schema_version,
    bead_id: $bead_id,
    source_revision: $source_revision,
    decision: $decision,
    allow_broad: $allow_broad,
    reason_codes: ($reasons | sort | unique),
    risk_flags: $risk_flags,
    changed_paths: ($changed_paths[0] // []),
    planned_write_paths: ($planned_write_paths[0] // []),
    collision_risk: ($collision[0].collision_risk // "none"),
    conflicting_agents: ($collision[0].conflicting_agents // []),
    safe_alternatives: ($collision[0].safe_alternatives // []),
    reservation_recommendations: ($collision[0].reservation_recommendations // []),
    collision_receipt: {
      path: $collision_receipt_path,
      schema_version: ($collision[0].schema_version // null),
      agent_mail_snapshot: ($collision[0].agent_mail_snapshot // {}),
      in_progress_snapshot: ($collision[0].in_progress_snapshot // {})
    },
    path_mappings: ($mappings | sort_by(.path, .kind)),
    commands: $commands[0],
    omitted_commands: ($omitted | sort_by(.kind, .path)),
    warnings: $warnings,
    proof_cost_budgets: ($budgets | sort_by(.suite, .package) | unique_by(.suite, .package)),
    expected_artifacts: [
      {path: $plan_path, role: "validation_plan"},
      {path: $commands_path, role: "command_transcript"},
      {path: $report_path, role: "operator_report"},
      {path: $collision_receipt_path, role: "collision_receipt"}
    ],
    artifact_paths: {
      run_dir: $run_dir,
      plan_json: $plan_path,
      commands_txt: $commands_path,
      report_md: $report_path,
      collision_receipt_json: $collision_receipt_path
    }
  }' >"$plan_path"

{
  printf '# Swarm Validation Plan\n\n'
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Decision: \`%s\`\n" "$decision"
  printf -- "- Collision risk: \`%s\`\n" "$(jq -r '.collision_risk' "$plan_path")"
  printf -- "- Planned write paths: \`%s\`\n" "$(jq '.planned_write_paths | length' "$plan_path")"
  printf -- "- Conflicting agents: \`%s\`\n" "$(jq -r 'if (.conflicting_agents | length) == 0 then "none" else (.conflicting_agents | join(", ")) end' "$plan_path")"
  printf -- "- Commands: \`%s\`\n" "$(jq '.commands | length' "$plan_path")"
  printf -- "- Omitted: \`%s\`\n" "$(jq '.omitted_commands | length' "$plan_path")"
  printf -- "- Warnings: \`%s\`\n\n" "$(jq '.warnings | length' "$plan_path")"
  if [[ "$(jq '.safe_alternatives | length' "$plan_path")" -ne 0 ]]; then
    printf '## Safe Alternatives\n\n'
    jq -r '.safe_alternatives[] | "- `" + . + "`"' "$plan_path"
    printf '\n'
  fi
  jq -r '.commands[]? | "- `" + .command_id + "`: " + .display + " (cost: `" + .predicted_cost.cost_class + "`, evidence: `" + .cost_evidence.status + "`)"' "$plan_path"
  if [[ "$(jq '.omitted_commands | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Omitted\n\n'
    jq -r '.omitted_commands[] | "- `" + .kind + "` for `" + .path + "`: " + .reason' "$plan_path"
  fi
  if [[ "$(jq '.reservation_recommendations | length' "$plan_path")" -ne 0 ]]; then
    printf '\n## Reservation Recommendations\n\n'
    jq -r '.reservation_recommendations[] | "- `" + .action + "`: " + .reason' "$plan_path"
  fi
} >"$report_path"

printf 'swarm_validation_plan=%s\n' "$plan_path"
printf 'swarm_validation_commands=%s\n' "$commands_path"
printf 'swarm_validation_report=%s\n' "$report_path"
printf 'swarm_validation_collision_receipt=%s\n' "$collision_receipt_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
