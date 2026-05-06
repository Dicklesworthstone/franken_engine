#!/usr/bin/env bash
set -euo pipefail

artifact_root="${REMOTE_PROOF_ARCHIVE_PRESSURE_SCOREBOARD_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-archive-pressure-scoreboard}"
run_id="${REMOTE_PROOF_ARCHIVE_PRESSURE_SCOREBOARD_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_ARCHIVE_PRESSURE_SCOREBOARD_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

retention_ledger_json=""
compaction_plan_json=""
gc_guard_report_json=""
archive_pack_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/remote_proof_archive_pressure_scoreboard.sh --retention-ledger-json FILE --compaction-plan-json FILE --gc-guard-report-json FILE --archive-pack-json FILE [OPTIONS]

Compose the remote-proof retention, compaction, archive, and GC-guard evidence
into one deterministic archive-pressure advisory surface.

Required:
  --retention-ledger-json FILE
  --compaction-plan-json FILE
  --gc-guard-report-json FILE
  --archive-pack-json FILE

Optional:
  --output-dir DIR

Artifacts:
  remote_proof_archive_pressure_scoreboard.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   low-pressure retain advisory
  42  cold-archive eviction advisory or fail-closed preservation advisory
  75  compaction-first or cool-without-eviction advisory
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --retention-ledger-json)
      retention_ledger_json="${2:-}"
      shift 2
      ;;
    --compaction-plan-json)
      compaction_plan_json="${2:-}"
      shift 2
      ;;
    --gc-guard-report-json)
      gc_guard_report_json="${2:-}"
      shift 2
      ;;
    --archive-pack-json)
      archive_pack_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$retention_ledger_json" || -z "$compaction_plan_json" || -z "$gc_guard_report_json" || -z "$archive_pack_json" ]]; then
  printf 'remote proof archive pressure scoreboard requires all four input JSON files\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for remote proof archive pressure scoreboard\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for remote proof archive pressure scoreboard\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
scoreboard_path="${run_dir}/remote_proof_archive_pressure_scoreboard.json"
scoreboard_tmp="${scoreboard_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
retention_normalized="${run_dir}/retention_ledger.normalized.json"
compaction_normalized="${run_dir}/compaction_plan.normalized.json"
gc_guard_normalized="${run_dir}/gc_guard_report.normalized.json"
archive_normalized="${run_dir}/archive_pack.normalized.json"
scoreboard_core="${run_dir}/archive_pressure_scoreboard.core.json"
input_bundle_json="${run_dir}/archive_pressure_scoreboard.inputs.json"
: >"$events_path"

printf './scripts/remote_proof_archive_pressure_scoreboard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

normalize_required_json() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'remote proof archive pressure scoreboard missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'remote proof archive pressure scoreboard invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
}

normalize_required_json "$retention_ledger_json" "$retention_normalized" "retention ledger"
normalize_required_json "$compaction_plan_json" "$compaction_normalized" "compaction plan"
normalize_required_json "$gc_guard_report_json" "$gc_guard_normalized" "GC guard report"
normalize_required_json "$archive_pack_json" "$archive_normalized" "archive pack"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    retention_decision: (.retention_decision // "unknown"),
    class_counts: {
      hot_replay_critical: (.class_counts.hot_replay_critical // 0),
      warm_operator_inspectable: (.class_counts.warm_operator_inspectable // 0),
      salvage_pinned: (.class_counts.salvage_pinned // 0),
      cold_archival: (.class_counts.cold_archival // 0)
    },
    artifact_paths: (.artifact_paths // {})
  }
' "$retention_normalized" >"${retention_normalized}.tmp"
mv "${retention_normalized}.tmp" "$retention_normalized"
write_event "retention_ledger_loaded" "normalized retention ledger"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    compacted_groups: (
      (.compacted_groups // [])
      | if type == "array" then . else [] end
      | map({
          content_address: (.content_address // ""),
          retained_path: (.retained_path // ""),
          compacted_paths: (
            (.compacted_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          )
        })
      | sort_by(.retained_path, .content_address)
    ),
    blocked_groups: (
      (.blocked_groups // [])
      | if type == "array" then . else [] end
      | map({
          content_address: (.content_address // ""),
          reason: (.reason // "unknown"),
          blocked_paths: (
            (.blocked_paths // [])
            | if type == "array" then map(tostring) else [] end
            | unique
            | sort
          )
        })
      | sort_by(.content_address, .reason)
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$compaction_normalized" >"${compaction_normalized}.tmp"
mv "${compaction_normalized}.tmp" "$compaction_normalized"
write_event "compaction_plan_loaded" "normalized compaction plan"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    guard_decision: (.guard_decision // .decision // "unknown"),
    recommended_action: (.recommended_action // "unknown"),
    reason: (.reason // ""),
    policy_findings: (
      (.policy_findings // [])
      | if type == "array" then map(tostring) else [] end
      | unique
      | sort
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$gc_guard_normalized" >"${gc_guard_normalized}.tmp"
mv "${gc_guard_normalized}.tmp" "$gc_guard_normalized"
write_event "gc_guard_report_loaded" "normalized GC guard report"

jq -cS '
  {
    bundle_id: (.bundle_id // "unknown"),
    archive_state: (.archive_state // "unknown"),
    restore_verdict: (.restore_verdict // "unknown"),
    archive_artifact_count: (
      if (.archive_artifact_count | type) == "number" then .archive_artifact_count
      elif (.archived_artifacts | type) == "array" then (.archived_artifacts | length)
      else 0
      end
    ),
    artifact_paths: (.artifact_paths // {})
  }
' "$archive_normalized" >"${archive_normalized}.tmp"
mv "${archive_normalized}.tmp" "$archive_normalized"
write_event "archive_pack_loaded" "normalized archive pack"

jq -csS '
  {
    retention_ledger: .[0],
    compaction_plan: .[1],
    gc_guard_report: .[2],
    archive_pack: .[3]
  }
' "$retention_normalized" "$compaction_normalized" "$gc_guard_normalized" "$archive_normalized" >"$input_bundle_json"
input_hash="$(sha256sum "$input_bundle_json" | awk '{print $1}')"

jq -n \
  --slurpfile retention "$retention_normalized" \
  --slurpfile compaction "$compaction_normalized" \
  --slurpfile guard "$gc_guard_normalized" \
  --slurpfile archive "$archive_normalized" '
  def has_finding($findings; $needle):
    any($findings[]?; . == $needle);

  ($retention[0]) as $retention
  | ($compaction[0]) as $compaction
  | ($guard[0]) as $guard
  | ($archive[0]) as $archive
  | [
      if (($compaction.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then
        {code: "compaction_bundle_mismatch", message: "compaction plan bundle_id does not match retention ledger"}
      else empty end,
      if (($guard.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then
        {code: "gc_guard_bundle_mismatch", message: "GC guard bundle_id does not match retention ledger"}
      else empty end,
      if (($archive.bundle_id // "unknown") != ($retention.bundle_id // "unknown")) then
        {code: "archive_bundle_mismatch", message: "archive pack bundle_id does not match retention ledger"}
      else empty end
    ] as $bundle_errors
  | ($retention.class_counts // {}) as $counts
  | (($compaction.compacted_groups // []) | length) as $compacted_group_count
  | (($compaction.blocked_groups // []) | length) as $blocked_group_count
  | (
      if (
        ($counts.salvage_pinned // 0) > 0
        or has_finding(($guard.policy_findings // []); "orphan_salvage_pinned")
      ) then
        "critical"
      elif (
        (($counts.cold_archival // 0) >= 4)
        or (
          ($counts.hot_replay_critical // 0) > 0
          and has_finding(($guard.policy_findings // []); "active_warm_target_protected")
          and ((($counts.cold_archival // 0) + ($counts.warm_operator_inspectable // 0)) >= 2)
        )
      ) then
        "critical"
      elif (
        $compacted_group_count > 0
        or ($counts.cold_archival // 0) >= 2
        or ($counts.warm_operator_inspectable // 0) >= 2
      ) then
        "elevated"
      else
        "low"
      end
    ) as $pressure_level
  | (
      if (($bundle_errors | length) > 0) then
        {
          advisory: "fail_closed",
          recommended_action: "manual_review_required",
          reason: ($bundle_errors[0].message),
          exit_code: 42,
          policy_findings: ($bundle_errors | map(.code))
        }
      elif (($guard.guard_decision // "unknown") == "fail_closed") then
        {
          advisory: "fail_closed",
          recommended_action: "manual_review_required",
          reason: ($guard.reason // "GC guard already failed closed"),
          exit_code: 42,
          policy_findings: (($guard.policy_findings // []) + ["upstream_gc_guard_fail_closed"] | unique | sort)
        }
      elif (
        ($counts.salvage_pinned // 0) > 0
        or has_finding(($guard.policy_findings // []); "orphan_salvage_pinned")
      ) then
        {
          advisory: "fail_closed",
          recommended_action: "preserve_pinned_evidence",
          reason: "salvage-pinned evidence prevents honest pressure relief",
          exit_code: 42,
          policy_findings: (($guard.policy_findings // []) + ["salvage_pinned_blocks_eviction"] | unique | sort)
        }
      elif (
        $pressure_level == "critical"
        and ($counts.hot_replay_critical // 0) > 0
        and has_finding(($guard.policy_findings // []); "active_warm_target_protected")
      ) then
        {
          advisory: "fail_closed",
          recommended_action: "preserve_active_evidence",
          reason: "active replay-critical evidence still blocks honest pressure relief",
          exit_code: 42,
          policy_findings: (($guard.policy_findings // []) + ["active_replay_blocks_eviction"] | unique | sort)
        }
      elif ($compacted_group_count > 0 and $pressure_level != "low") then
        {
          advisory: "compaction_first",
          recommended_action: "compact_before_eviction",
          reason: "duplicate archive groups should be compacted before any eviction decision",
          exit_code: 75,
          policy_findings: (($guard.policy_findings // []) + ["compaction_first_remediation"] | unique | sort)
        }
      elif (
        $pressure_level == "critical"
        and ($guard.guard_decision // "unknown") == "allow_gc"
        and ($guard.recommended_action // "unknown") == "delete_cold_archived_bundle"
        and ($archive.restore_verdict // "unknown") == "verified"
      ) then
        {
          advisory: "evict_cold_archive",
          recommended_action: "evict_archived_bundle",
          reason: "critical archive pressure can be relieved by evicting a verified cold archive",
          exit_code: 42,
          policy_findings: (($guard.policy_findings // []) + ["critical_pressure_cold_archive_evictable"] | unique | sort)
        }
      elif (
        $pressure_level == "low"
        and ($guard.guard_decision // "unknown") == "deny_gc"
        and ($guard.recommended_action // "unknown") == "keep_hot"
      ) then
        {
          advisory: "retain",
          recommended_action: "retain_current_residency",
          reason: "bounded archive pressure does not justify eviction or compaction",
          exit_code: 0,
          policy_findings: (($guard.policy_findings // []) + ["low_pressure_retain"] | unique | sort)
        }
      elif (
        ($guard.guard_decision // "unknown") == "cool_only"
        or ($guard.recommended_action // "unknown") == "cool_without_gc"
      ) then
        {
          advisory: "cool_archive",
          recommended_action: "cool_without_gc",
          reason: "archive can be cooled, but the evidence is not honestly deletable",
          exit_code: 75,
          policy_findings: (($guard.policy_findings // []) + ["cool_without_gc"] | unique | sort)
        }
      else
        {
          advisory: "fail_closed",
          recommended_action: "manual_review_required",
          reason: "archive pressure evidence does not support a bounded automatic advisory",
          exit_code: 42,
          policy_findings: (($guard.policy_findings // []) + ["insufficient_advisory_truth"] | unique | sort)
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.remote-proof-archive-pressure-scoreboard.v1",
      bundle_id: $retention.bundle_id,
      pressure_level: $pressure_level,
      advisory: $decision.advisory,
      recommended_action: $decision.recommended_action,
      reason: $decision.reason,
      exit_code: $decision.exit_code,
      class_counts: $counts,
      compaction_summary: {
        compacted_group_count: $compacted_group_count,
        blocked_group_count: $blocked_group_count
      },
      archive_summary: {
        archive_state: ($archive.archive_state // "unknown"),
        restore_verdict: ($archive.restore_verdict // "unknown"),
        archive_artifact_count: ($archive.archive_artifact_count // 0)
      },
      gc_guard_summary: {
        guard_decision: ($guard.guard_decision // "unknown"),
        recommended_action: ($guard.recommended_action // "unknown"),
        reason: ($guard.reason // "")
      },
      policy_findings: $decision.policy_findings
    }
' >"$scoreboard_core"

scoreboard_hash="$(jq -cS . "$scoreboard_core" | sha256sum | awk '{print $1}')"
jq \
  --arg input_hash "$input_hash" \
  --arg scoreboard_hash "$scoreboard_hash" \
  --arg scoreboard_path "$scoreboard_path" \
  --arg summary_path "$summary_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg retention_ledger_path "$retention_ledger_json" \
  --arg compaction_plan_path "$compaction_plan_json" \
  --arg gc_guard_report_path "$gc_guard_report_json" \
  --arg archive_pack_path "$archive_pack_json" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      scoreboard_hash: $scoreboard_hash
    },
    upstream_artifact_paths: {
      retention_ledger_json: $retention_ledger_path,
      compaction_plan_json: $compaction_plan_path,
      gc_guard_report_json: $gc_guard_report_path,
      archive_pack_json: $archive_pack_path
    },
    artifact_paths: {
      remote_proof_archive_pressure_scoreboard_json: $scoreboard_path,
      events_jsonl: $events_path,
      commands_txt: $commands_path,
      report_md: $summary_path
    }
  }
' "$scoreboard_core" >"$scoreboard_tmp"
mv "$scoreboard_tmp" "$scoreboard_path"

write_event "archive_pressure_scoreboard_written" "$(jq -r '.advisory + " / " + .reason' "$scoreboard_path")"

{
  printf '# Remote Proof Archive Pressure Scoreboard\n\n'
  printf '%s\n' "- Advisory: \`$(jq -r '.advisory' "$scoreboard_path")\`"
  printf '%s\n' "- Recommended action: \`$(jq -r '.recommended_action' "$scoreboard_path")\`"
  printf '%s\n' "- Pressure level: \`$(jq -r '.pressure_level' "$scoreboard_path")\`"
  printf '%s\n' "- Reason: $(jq -r '.reason' "$scoreboard_path")"
  printf '%s\n' "- Compacted groups: \`$(jq -r '.compaction_summary.compacted_group_count' "$scoreboard_path")\`"
  printf '%s\n' "- Blocked groups: \`$(jq -r '.compaction_summary.blocked_group_count' "$scoreboard_path")\`"
  printf '%s\n' "- Archive restore verdict: \`$(jq -r '.archive_summary.restore_verdict' "$scoreboard_path")\`"
  printf '%s\n' "- Scoreboard hash: \`$(jq -r '.hash_basis.scoreboard_hash' "$scoreboard_path")\`"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

exit "$(jq -r '.exit_code' "$scoreboard_path")"
