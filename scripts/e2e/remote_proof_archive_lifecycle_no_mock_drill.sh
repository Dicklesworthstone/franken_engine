#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${REMOTE_PROOF_ARCHIVE_LIFECYCLE_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-remote-proof-archive-lifecycle-no-mock-drill}"
run_id="${REMOTE_PROOF_ARCHIVE_LIFECYCLE_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${REMOTE_PROOF_ARCHIVE_LIFECYCLE_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
fixture_dir="${REMOTE_PROOF_ARCHIVE_LIFECYCLE_NO_MOCK_DRILL_FIXTURE_DIR:-}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

retention_ledger="${root_dir}/scripts/remote_proof_retention_class_ledger.sh"
compaction_planner="${root_dir}/scripts/remote_proof_compaction_planner.sh"
archive_exporter="${root_dir}/scripts/remote_proof_archive_exporter.sh"
gc_guard="${root_dir}/scripts/remote_proof_gc_guard.sh"
pressure_scoreboard="${root_dir}/scripts/remote_proof_archive_pressure_scoreboard.sh"

report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the shipped SWARM-CTRL-VI shell surfaces into one deterministic archive
lifecycle drill. The drill uses preserved JSON fixtures and the real shell
surfaces; it does not run heavy Cargo or query live workers.

Modes:
  check       Syntax and composed-surface existence checks.
  run         Run the composed drill against a prepared fixture directory.
  selftest    Generate fixtures, run the drill, and assert the combined report.

Options:
  --fixture-dir DIR
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixture-dir)
      fixture_dir="${2:-}"
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

record_pass() {
  printf 'PASS remote-proof-archive-lifecycle-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL remote-proof-archive-lifecycle-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/remote_proof_archive_lifecycle_no_mock_drill_report.json"
  report_tmp="${report_json}.tmp"
  events_path="${run_dir}/events.jsonl"
  commands_path="${run_dir}/commands.txt"
  report_md="${run_dir}/report.md"
}

require_json() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf 'missing fixture: %s\n' "$path" >&2
    exit 64
  fi
  jq empty "$path" >/dev/null
}

write_json() {
  local path="$1"
  local payload="$2"
  printf '%s\n' "$payload" | jq -cS . >"$path"
}

write_command_log() {
  printf './scripts/e2e/remote_proof_archive_lifecycle_no_mock_drill.sh %q' "$mode" >"$commands_path"
  if [[ -n "$fixture_dir" ]]; then
    printf ' --fixture-dir %q' "$fixture_dir" >>"$commands_path"
  fi
  printf ' --output-dir %q\n' "$run_dir" >>"$commands_path"
}

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

scenario_fixture_dir() {
  printf '%s/%s\n' "$fixture_dir" "$1"
}

run_retention_case() {
  bash "$retention_ledger" \
    --output-dir "$1" \
    --bundle-report-json "$2" \
    --mirror-manifest-json "$3" \
    --batch-manifest-json "$4" \
    --salvage-receipt-json "$5"
}

run_compaction_case() {
  bash "$compaction_planner" \
    --output-dir "$1" \
    --residency-manifest-json "$2" \
    --mirror-manifest-json "$3"
}

run_archive_case() {
  bash "$archive_exporter" \
    --output-dir "$1" \
    --residency-manifest-json "$2" \
    --compaction-plan-json "$3" \
    --archive-source-files-json "$4"
}

run_gc_guard_case() {
  local output_dir="$1"
  local exit_code
  mkdir -p "$output_dir"
  set +e
  bash "$gc_guard" \
    --output-dir "$output_dir" \
    --retention-ledger-json "$2" \
    --warm-target-roi-ledger-json "$3" \
    --salvage-receipt-json "$4" \
    --archive-pack-json "$5" \
    >"${output_dir}/gc_guard.stdout.log" \
    2>"${output_dir}/gc_guard.stderr.log"
  exit_code=$?
  set -e
  printf '%s\n' "$exit_code"
}

run_scoreboard_case() {
  local output_dir="$1"
  local exit_code
  mkdir -p "$output_dir"
  set +e
  bash "$pressure_scoreboard" \
    --output-dir "$output_dir" \
    --retention-ledger-json "$2" \
    --compaction-plan-json "$3" \
    --gc-guard-report-json "$4" \
    --archive-pack-json "$5" \
    >"${output_dir}/archive_pressure_scoreboard.stdout.log" \
    2>"${output_dir}/archive_pressure_scoreboard.stderr.log"
  exit_code=$?
  set -e
  printf '%s\n' "$exit_code"
}

build_scenario_summary() {
  local scenario_id="$1"
  local scenario_dir="$2"
  local retention_dir="${scenario_dir}/retention"
  local compaction_dir="${scenario_dir}/compaction"
  local archive_dir="${scenario_dir}/archive"
  local gc_dir="${scenario_dir}/gc_guard"
  local pressure_dir="${scenario_dir}/pressure"
  local summary_path="${scenario_dir}/scenario_summary.json"
  local retention_exit="$3"
  local compaction_exit="$4"
  local archive_exit="$5"
  local gc_exit="$6"
  local pressure_exit="$7"

  jq -n \
    --arg scenario_id "$scenario_id" \
    --argjson retention_exit "$retention_exit" \
    --argjson compaction_exit "$compaction_exit" \
    --argjson archive_exit "$archive_exit" \
    --argjson gc_exit "$gc_exit" \
    --argjson pressure_exit "$pressure_exit" \
    --slurpfile retention "${retention_dir}/retention_class_ledger.json" \
    --slurpfile residency "${retention_dir}/evidence_residency_manifest.json" \
    --slurpfile compaction "${compaction_dir}/remote_proof_compaction_plan.json" \
    --slurpfile archive_pack "${archive_dir}/archive_pack.json" \
    --slurpfile restore "${archive_dir}/restore_verification_report.json" \
    --slurpfile guard "${gc_dir}/remote_proof_gc_guard_report.json" \
    --slurpfile pressure "${pressure_dir}/remote_proof_archive_pressure_scoreboard.json" '
    ($retention[0]) as $retention
    | ($residency[0]) as $residency
    | ($compaction[0]) as $compaction
    | ($archive_pack[0]) as $archive_pack
    | ($restore[0]) as $restore
    | ($guard[0]) as $guard
    | ($pressure[0]) as $pressure
    | {
        scenario_id: $scenario_id,
        status: (
          if $retention_exit == 0
            and $compaction_exit == 0
            and $archive_exit == 0
            and ($gc_exit == 0 or $gc_exit == 42 or $gc_exit == 75)
            and ($pressure_exit == 0 or $pressure_exit == 42 or $pressure_exit == 75)
            and ($restore.restore_verdict == "verified")
          then
            "pass"
          else
            "fail_closed"
          end
        ),
        bundle_id: ($retention.bundle_id // "unknown"),
        exits: {
          retention_ledger: $retention_exit,
          compaction_planner: $compaction_exit,
          archive_exporter: $archive_exit,
          gc_guard: $gc_exit,
          archive_pressure_scoreboard: $pressure_exit
        },
        retention_summary: {
          retention_decision: ($retention.retention_decision // "unknown"),
          class_counts: ($retention.class_counts // {})
        },
        compaction_summary: {
          compacted_group_count: (($compaction.compacted_groups // []) | length),
          blocked_group_count: (($compaction.blocked_groups // []) | length)
        },
        archive_summary: {
          archive_artifact_count: ($archive_pack.archive_artifact_count // 0),
          restore_verdict: ($restore.restore_verdict // "unknown"),
          restore_reason: ($restore.reason // "")
        },
        gc_guard_summary: {
          guard_decision: ($guard.guard_decision // "unknown"),
          recommended_action: ($guard.recommended_action // "unknown")
        },
        pressure_summary: {
          pressure_level: ($pressure.pressure_level // "unknown"),
          advisory: ($pressure.advisory // "unknown"),
          recommended_action: ($pressure.recommended_action // "unknown")
        },
        artifact_paths: {
          retention_class_ledger_json: ("'"${retention_dir}"'/retention_class_ledger.json"),
          evidence_residency_manifest_json: ("'"${retention_dir}"'/evidence_residency_manifest.json"),
          remote_proof_compaction_plan_json: ("'"${compaction_dir}"'/remote_proof_compaction_plan.json"),
          archive_pack_json: ("'"${archive_dir}"'/archive_pack.json"),
          restore_verification_report_json: ("'"${archive_dir}"'/restore_verification_report.json"),
          remote_proof_gc_guard_report_json: ("'"${gc_dir}"'/remote_proof_gc_guard_report.json"),
          remote_proof_archive_pressure_scoreboard_json: ("'"${pressure_dir}"'/remote_proof_archive_pressure_scoreboard.json")
        }
      }
  ' >"$summary_path"
}

run_scenario() {
  local scenario_id="$1"
  local scenario_inputs scenario_dir retention_dir compaction_dir archive_dir gc_dir pressure_dir
  local retention_exit compaction_exit archive_exit gc_exit pressure_exit

  scenario_inputs="$(scenario_fixture_dir "$scenario_id")"
  scenario_dir="${run_dir}/${scenario_id}"
  retention_dir="${scenario_dir}/retention"
  compaction_dir="${scenario_dir}/compaction"
  archive_dir="${scenario_dir}/archive"
  gc_dir="${scenario_dir}/gc_guard"
  pressure_dir="${scenario_dir}/pressure"

  require_json "${scenario_inputs}/bundle_report.json"
  require_json "${scenario_inputs}/mirror_manifest.json"
  require_json "${scenario_inputs}/batch_manifest.json"
  require_json "${scenario_inputs}/salvage_receipt.json"
  require_json "${scenario_inputs}/warm_target_roi_ledger.json"
  require_json "${scenario_inputs}/archive_source_files.json"

  run_retention_case \
    "$retention_dir" \
    "${scenario_inputs}/bundle_report.json" \
    "${scenario_inputs}/mirror_manifest.json" \
    "${scenario_inputs}/batch_manifest.json" \
    "${scenario_inputs}/salvage_receipt.json"
  retention_exit=0

  run_compaction_case \
    "$compaction_dir" \
    "${retention_dir}/evidence_residency_manifest.json" \
    "${scenario_inputs}/mirror_manifest.json"
  compaction_exit=0

  run_archive_case \
    "$archive_dir" \
    "${retention_dir}/evidence_residency_manifest.json" \
    "${compaction_dir}/remote_proof_compaction_plan.json" \
    "${scenario_inputs}/archive_source_files.json"
  archive_exit=0

  gc_exit="$(run_gc_guard_case \
    "$gc_dir" \
    "${retention_dir}/retention_class_ledger.json" \
    "${scenario_inputs}/warm_target_roi_ledger.json" \
    "${scenario_inputs}/salvage_receipt.json" \
    "${archive_dir}/archive_pack.json")"

  pressure_exit="$(run_scoreboard_case \
    "$pressure_dir" \
    "${retention_dir}/retention_class_ledger.json" \
    "${compaction_dir}/remote_proof_compaction_plan.json" \
    "${gc_dir}/remote_proof_gc_guard_report.json" \
    "${archive_dir}/archive_pack.json")"

  build_scenario_summary \
    "$scenario_id" \
    "$scenario_dir" \
    "$retention_exit" \
    "$compaction_exit" \
    "$archive_exit" \
    "$gc_exit" \
    "$pressure_exit"
  write_event "scenario_completed" "${scenario_id}"
}

write_fixture_resident_bundle() {
  local dir="$1"
  mkdir -p "$dir"

  write_json "${dir}/bundle_report.json" '
    {
      "bundle_id": "bundle-retain",
      "bundle_decision": "pass",
      "expected_worker_id": "vmi1156319",
      "expected_target_dir": "/tmp/rch_target_bundle_retain",
      "source_revision": "smoke-rev",
      "artifact_paths": {
        "bundle_report_json": "/control/bundle-retain/bundle_report.json"
      },
      "phase_results": []
    }
  '
  write_json "${dir}/mirror_manifest.json" '
    {
      "bundle_id": "bundle-retain",
      "bundle_decision": "pass",
      "artifacts": [
        {
          "path": "/archive/replay-retained.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        {
          "path": "/archive/status-report.json",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        }
      ],
      "retrieval_pack_artifacts": [
        {
          "path": "/archive/replay-retained.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
      ],
      "artifact_paths": {
        "artifact_mirror_manifest_json": "/control/bundle-retain/artifact_mirror_manifest.json"
      }
    }
  '
  write_json "${dir}/batch_manifest.json" '
    {
      "packing_decision": "pass",
      "batches": [
        {
          "batch_id": "batch-retain",
          "worker_id": "vmi1156319",
          "target_dir": "/tmp/rch_target_bundle_retain",
          "bundle_ids": ["bundle-retain"]
        }
      ],
      "artifact_paths": {
        "batch_manifest_json": "/control/bundle-retain/batch_manifest.json"
      }
    }
  '
  write_json "${dir}/salvage_receipt.json" '
    {
      "bundle_id": "bundle-retain",
      "workflow_state": "clean_finished",
      "recovery_recommendation": "no_salvage_needed",
      "observed_process_truth": {
        "live_remote_compile": false,
        "orphaned_process_detected": false,
        "worker_reachable": true,
        "recoverable_artifact_set": true
      },
      "bundle_artifact_paths": {
        "bundle_report_json": "/control/bundle-retain/bundle_report.json"
      },
      "upstream_artifact_paths": {
        "bundle_report_json": "/control/bundle-retain/bundle_report.json"
      },
      "artifact_paths": {
        "salvage_receipt_json": "/control/bundle-retain/salvage_receipt.json"
      }
    }
  '
  write_json "${dir}/warm_target_roi_ledger.json" '
    {
      "bundle_id": "bundle-retain",
      "decision": "retain",
      "recommended_action": "retain_warm_target",
      "reason": "resident bundle is still worth keeping hot",
      "target_dir": "/tmp/rch_target_bundle_retain",
      "worker_id": "vmi1156319",
      "policy_findings": ["high_realized_reuse_value"],
      "artifact_paths": {
        "warm_target_roi_ledger_json": "/control/bundle-retain/warm_target_roi_ledger.json"
      }
    }
  '
  write_json "${dir}/archive_source_files.json" '
    {
      "source_files": [
        {
          "path": "/archive/replay-retained.bin",
          "content_address": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "roles": ["replay"],
          "replay_critical": true,
          "size_bytes": 64
        },
        {
          "path": "/archive/status-report.json",
          "content_address": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "size_bytes": 32
        }
      ]
    }
  '
}

write_fixture_compaction() {
  local dir="$1"
  mkdir -p "$dir"

  write_json "${dir}/bundle_report.json" '
    {
      "bundle_id": "bundle-compact",
      "bundle_decision": "pass",
      "expected_worker_id": "vmi1293453",
      "expected_target_dir": "/tmp/rch_target_bundle_compact",
      "source_revision": "smoke-rev",
      "artifact_paths": {
        "bundle_report_json": "/control/bundle-compact/bundle_report.json"
      },
      "phase_results": []
    }
  '
  write_json "${dir}/mirror_manifest.json" '
    {
      "bundle_id": "bundle-compact",
      "bundle_decision": "pass",
      "artifacts": [
        {
          "path": "/archive/replay-retained.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        },
        {
          "path": "/archive/replay-duplicate.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        },
        {
          "path": "/archive/status-report.json",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }
      ],
      "retrieval_pack_artifacts": [
        {
          "path": "/archive/replay-retained.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        },
        {
          "path": "/archive/replay-duplicate.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }
      ],
      "artifact_paths": {
        "artifact_mirror_manifest_json": "/control/bundle-compact/artifact_mirror_manifest.json"
      }
    }
  '
  write_json "${dir}/batch_manifest.json" '
    {
      "packing_decision": "pass",
      "batches": [
        {
          "batch_id": "batch-compact",
          "worker_id": "vmi1293453",
          "target_dir": "/tmp/rch_target_bundle_compact",
          "bundle_ids": ["bundle-compact"]
        }
      ],
      "artifact_paths": {
        "batch_manifest_json": "/control/bundle-compact/batch_manifest.json"
      }
    }
  '
  write_json "${dir}/salvage_receipt.json" '
    {
      "bundle_id": "bundle-compact",
      "workflow_state": "clean_finished",
      "recovery_recommendation": "no_salvage_needed",
      "observed_process_truth": {
        "live_remote_compile": false,
        "orphaned_process_detected": false,
        "worker_reachable": true,
        "recoverable_artifact_set": true
      },
      "bundle_artifact_paths": {
        "bundle_report_json": "/control/bundle-compact/bundle_report.json"
      },
      "upstream_artifact_paths": {
        "bundle_report_json": "/control/bundle-compact/bundle_report.json"
      },
      "artifact_paths": {
        "salvage_receipt_json": "/control/bundle-compact/salvage_receipt.json"
      }
    }
  '
  write_json "${dir}/warm_target_roi_ledger.json" '
    {
      "bundle_id": "bundle-compact",
      "decision": "evict",
      "recommended_action": "evict_warm_target",
      "reason": "resident reuse is not strong enough to stay warm",
      "target_dir": "/tmp/rch_target_bundle_compact",
      "worker_id": "vmi1293453",
      "policy_findings": ["low_realized_reuse_value"],
      "artifact_paths": {
        "warm_target_roi_ledger_json": "/control/bundle-compact/warm_target_roi_ledger.json"
      }
    }
  '
  write_json "${dir}/archive_source_files.json" '
    {
      "source_files": [
        {
          "path": "/archive/replay-retained.bin",
          "content_address": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "roles": ["replay"],
          "replay_critical": true,
          "size_bytes": 64
        },
        {
          "path": "/archive/status-report.json",
          "content_address": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "size_bytes": 32
        }
      ]
    }
  '
}

write_fixture_salvage() {
  local dir="$1"
  mkdir -p "$dir"

  write_json "${dir}/bundle_report.json" '
    {
      "bundle_id": "bundle-salvage",
      "bundle_decision": "fail_closed",
      "expected_worker_id": "vmi1264463",
      "expected_target_dir": "/tmp/rch_target_bundle_salvage",
      "source_revision": "smoke-rev",
      "artifact_paths": {
        "bundle_report_json": "/control/bundle-salvage/bundle_report.json"
      },
      "phase_results": []
    }
  '
  write_json "${dir}/mirror_manifest.json" '
    {
      "bundle_id": "bundle-salvage",
      "bundle_decision": "fail_closed",
      "artifacts": [
        {
          "path": "/archive/salvage-replay.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        },
        {
          "path": "/archive/salvage-status.json",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        }
      ],
      "retrieval_pack_artifacts": [
        {
          "path": "/archive/salvage-replay.bin",
          "roles": ["replay"],
          "replay_critical": true,
          "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }
      ],
      "artifact_paths": {
        "artifact_mirror_manifest_json": "/control/bundle-salvage/artifact_mirror_manifest.json"
      }
    }
  '
  write_json "${dir}/batch_manifest.json" '
    {
      "packing_decision": "pass",
      "batches": [
        {
          "batch_id": "batch-salvage",
          "worker_id": "vmi1264463",
          "target_dir": "/tmp/rch_target_bundle_salvage",
          "bundle_ids": ["bundle-salvage"]
        }
      ],
      "artifact_paths": {
        "batch_manifest_json": "/control/bundle-salvage/batch_manifest.json"
      }
    }
  '
  write_json "${dir}/salvage_receipt.json" '
    {
      "bundle_id": "bundle-salvage",
      "workflow_state": "orphan_reconciliation_required",
      "recovery_recommendation": "clear_orphan_before_retry",
      "observed_process_truth": {
        "live_remote_compile": false,
        "orphaned_process_detected": true,
        "worker_reachable": true,
        "recoverable_artifact_set": true
      },
      "bundle_artifact_paths": {
        "bundle_report_json": "/control/bundle-salvage/bundle_report.json"
      },
      "upstream_artifact_paths": {
        "worker_truth_report_json": "/control/bundle-salvage/worker_truth_report.json"
      },
      "artifact_paths": {
        "salvage_receipt_json": "/control/bundle-salvage/salvage_receipt.json"
      }
    }
  '
  write_json "${dir}/warm_target_roi_ledger.json" '
    {
      "bundle_id": "bundle-salvage",
      "decision": "evict",
      "recommended_action": "evict_warm_target",
      "reason": "bundle is not worth preserving as a warm target",
      "target_dir": "/tmp/rch_target_bundle_salvage",
      "worker_id": "vmi1264463",
      "policy_findings": ["low_realized_reuse_value"],
      "artifact_paths": {
        "warm_target_roi_ledger_json": "/control/bundle-salvage/warm_target_roi_ledger.json"
      }
    }
  '
  write_json "${dir}/archive_source_files.json" '
    {
      "source_files": [
        {
          "path": "/archive/salvage-replay.bin",
          "content_address": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          "roles": ["replay"],
          "replay_critical": true,
          "size_bytes": 64
        },
        {
          "path": "/archive/salvage-status.json",
          "content_address": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "roles": ["inspect", "bundle_report"],
          "replay_critical": false,
          "size_bytes": 32
        }
      ]
    }
  '
}

write_selftest_fixtures() {
  local fixture_root="$1"
  write_fixture_resident_bundle "${fixture_root}/resident_bundle_export_restore"
  write_fixture_compaction "${fixture_root}/duplicate_compaction_before_export"
  write_fixture_salvage "${fixture_root}/salvage_pinned_gc_block"
}

run_drill() {
  local input_bundle="${run_dir}/drill_inputs.json"
  local scenario_reports=()
  local input_hash drill_hash

  refresh_output_paths
  mkdir -p "$run_dir"
  : >"$events_path"
  write_command_log

  run_scenario "resident_bundle_export_restore"
  run_scenario "duplicate_compaction_before_export"
  run_scenario "salvage_pinned_gc_block"

  scenario_reports=(
    "${run_dir}/resident_bundle_export_restore/scenario_summary.json"
    "${run_dir}/duplicate_compaction_before_export/scenario_summary.json"
    "${run_dir}/salvage_pinned_gc_block/scenario_summary.json"
  )

  jq -csS '
    {
      resident_bundle_export_restore: .[0],
      duplicate_compaction_before_export: .[1],
      salvage_pinned_gc_block: .[2]
    }
  ' "${scenario_reports[@]}" >"$input_bundle"
  input_hash="$(sha256sum "$input_bundle" | awk '{print $1}')"

  jq -n \
    --arg input_hash "$input_hash" \
    --slurpfile resident "${run_dir}/resident_bundle_export_restore/scenario_summary.json" \
    --slurpfile compact "${run_dir}/duplicate_compaction_before_export/scenario_summary.json" \
    --slurpfile salvage "${run_dir}/salvage_pinned_gc_block/scenario_summary.json" '
    {
      schema_version: "franken-engine.remote-proof-archive-lifecycle-no-mock-drill.v1",
      drill_decision: (
        if ($resident[0].status == "pass" and $compact[0].status == "pass" and $salvage[0].status == "pass") then
          "pass"
        else
          "fail_closed"
        end
      ),
      scenarios: {
        resident_bundle_export_restore: $resident[0],
        duplicate_compaction_before_export: $compact[0],
        salvage_pinned_gc_block: $salvage[0]
      },
      hash_basis: {
        input_hash: $input_hash
      }
    }
  ' >"${report_json}.core"

  drill_hash="$(jq -cS . "${report_json}.core" | sha256sum | awk '{print $1}')"
  jq \
    --arg drill_hash "$drill_hash" \
    --arg report_path "$report_json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    --arg fixture_dir "$fixture_dir" '
    .hash_basis.drill_hash = $drill_hash
    | .artifact_paths = {
        remote_proof_archive_lifecycle_no_mock_drill_report_json: $report_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    | .fixture_dir = $fixture_dir
  ' "${report_json}.core" >"$report_tmp"
  mv "$report_tmp" "$report_json"
  rm -f "${report_json}.core"
  write_event "drill_report_written" "$(jq -r '.drill_decision' "$report_json")"

  {
    printf '# Remote Proof Archive Lifecycle No-Mock Drill\n\n'
    printf '%s\n' "- Drill decision: \`$(jq -r '.drill_decision' "$report_json")\`"
    printf '%s\n' "- Resident bundle scenario: \`$(jq -r '.scenarios.resident_bundle_export_restore.status' "$report_json")\`"
    printf '%s\n' "- Duplicate compaction scenario: \`$(jq -r '.scenarios.duplicate_compaction_before_export.status' "$report_json")\`"
    printf '%s\n' "- Salvage-pinned scenario: \`$(jq -r '.scenarios.salvage_pinned_gc_block.status' "$report_json")\`"
    printf '%s\n' "- Report hash: \`$(jq -r '.hash_basis.drill_hash' "$report_json")\`"
  } >"${report_md}.tmp"
  mv "${report_md}.tmp" "$report_md"
}

run_check() {
  local path

  refresh_output_paths
  bash -n "$retention_ledger"
  bash -n "$compaction_planner"
  bash -n "$archive_exporter"
  bash -n "$gc_guard"
  bash -n "$pressure_scoreboard"
  bash -n "${BASH_SOURCE[0]}"
  shellcheck -x "$retention_ledger" "$compaction_planner" "$archive_exporter" "$gc_guard" "$pressure_scoreboard" "${BASH_SOURCE[0]}"
  for path in \
    "$retention_ledger" \
    "$compaction_planner" \
    "$archive_exporter" \
    "$gc_guard" \
    "$pressure_scoreboard"; do
    test -x "$path"
  done
  record_pass "bash syntax, shellcheck, and composed surfaces"
}

run_selftest() {
  local tmp_root

  run_check
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/remote-proof-archive-lifecycle-no-mock-drill.XXXXXX")"
  fixture_dir="${tmp_root}/fixtures"
  run_dir="${tmp_root}/run"
  write_selftest_fixtures "$fixture_dir"
  run_drill

  jq -e '
      .drill_decision == "pass"
      and .scenarios.resident_bundle_export_restore.status == "pass"
      and .scenarios.duplicate_compaction_before_export.status == "pass"
      and .scenarios.salvage_pinned_gc_block.status == "pass"
    ' "$report_json" >/dev/null

  jq -e '
      .scenarios.resident_bundle_export_restore.archive_summary.restore_verdict == "verified"
      and .scenarios.resident_bundle_export_restore.gc_guard_summary.guard_decision == "deny_gc"
      and .scenarios.resident_bundle_export_restore.pressure_summary.advisory == "fail_closed"
      and .scenarios.resident_bundle_export_restore.pressure_summary.recommended_action == "preserve_active_evidence"
    ' "$report_json" >/dev/null
  record_pass "retained resident bundle export and restore fixture"

  jq -e '
      .scenarios.duplicate_compaction_before_export.pressure_summary.advisory == "compaction_first"
      and .scenarios.duplicate_compaction_before_export.compaction_summary.compacted_group_count == 1
    ' "$report_json" >/dev/null
  jq -e --slurpfile plan "${run_dir}/duplicate_compaction_before_export/compaction/remote_proof_compaction_plan.json" '
      ($plan[0].compacted_groups | length) == 1
      and any(.archived_artifacts[]?;
        .path == $plan[0].compacted_groups[0].retained_path
        and (.original_paths == $plan[0].compacted_groups[0].compacted_paths)
        and .content_address == $plan[0].compacted_groups[0].content_address
      )
    ' "${run_dir}/duplicate_compaction_before_export/archive/archive_pack.json" >/dev/null
  record_pass "duplicate artifact compaction before archive export fixture"

  jq -e '
      .scenarios.salvage_pinned_gc_block.gc_guard_summary.guard_decision == "deny_gc"
      and .scenarios.salvage_pinned_gc_block.pressure_summary.advisory == "fail_closed"
      and .scenarios.salvage_pinned_gc_block.pressure_summary.recommended_action == "preserve_pinned_evidence"
    ' "$report_json" >/dev/null
  record_pass "salvage-pinned evidence blocks GC fixture"

  test -s "$events_path"
  test -s "$commands_path"
  test -s "$report_md"
  record_pass "explicit artifact-path report bundle"

  printf 'remote_proof_archive_lifecycle_no_mock_drill_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    run_check
    ;;
  run)
    if [[ -z "$fixture_dir" ]]; then
      printf 'run mode requires --fixture-dir\n' >&2
      exit 64
    fi
    run_check
    run_drill
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: ${mode}"
    exit 64
    ;;
esac
