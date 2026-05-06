#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${RESIDENT_REMOTE_PROOF_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-resident-remote-proof-no-mock-drill}"
run_id="${RESIDENT_REMOTE_PROOF_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RESIDENT_REMOTE_PROOF_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
fixture_dir="${RESIDENT_REMOTE_PROOF_NO_MOCK_DRILL_FIXTURE_DIR:-}"
mode="${1:-run}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

executor="${root_dir}/scripts/resident_remote_proof_bundle_executor.sh"
mirror_packer="${root_dir}/scripts/remote_proof_artifact_mirror_packer.sh"
roi_ledger="${root_dir}/scripts/warm_target_roi_eviction_ledger.sh"
salvage_receipt="${root_dir}/scripts/remote_proof_salvage_receipt.sh"
batch_packer="${root_dir}/scripts/locality_aware_remote_proof_batch_packer.sh"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/resident_remote_proof_no_mock_drill.sh [check|run|selftest] [OPTIONS]

Compose the shipped SWARM-CTRL-V shell surfaces into one no-mock operator drill.
The drill uses preserved receipts and deterministic JSON snapshots; it does not
execute heavy Cargo or query live workers.

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

report_json=""
report_tmp=""
events_path=""
commands_path=""
report_md=""

record_pass() {
  printf 'PASS resident-remote-proof-no-mock-drill %s\n' "$1"
}

record_failure() {
  printf 'FAIL resident-remote-proof-no-mock-drill %s\n' "$1" >&2
}

refresh_output_paths() {
  report_json="${run_dir}/resident_remote_proof_no_mock_drill_report.json"
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

write_command_log() {
  printf './scripts/e2e/resident_remote_proof_no_mock_drill.sh %q' "$mode" >"$commands_path"
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

write_manifest() {
  local path="$1"
  local bundle_id="$2"
  local worker_id="$3"
  local target_dir="$4"

  jq -n \
    --arg bundle_id "$bundle_id" \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.resident-remote-proof-phase-manifest.v1",
      bundle_id: $bundle_id,
      expected_worker_id: $worker_id,
      expected_target_dir: $target_dir,
      phases: [
        {
          phase: "check",
          command_id: ($bundle_id + "-check"),
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo check -p frankenengine-engine --test semantic_dark_matter_engine_integration"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        },
        {
          phase: "test",
          command_id: ($bundle_id + "-test"),
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo test -p frankenengine-engine --test semantic_dark_matter_engine_integration -- --nocapture"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        },
        {
          phase: "clippy",
          command_id: ($bundle_id + "-clippy"),
          requested_command: ("rch exec -- env CARGO_TARGET_DIR=" + $target_dir + " cargo clippy -p frankenengine-engine --test semantic_dark_matter_engine_integration -- -D warnings"),
          required_artifacts: ["run_manifest.json", "events.jsonl", "commands.txt"]
        }
      ]
    }
  ' >"$path"
}

write_receipts_success() {
  local path="$1"
  local bundle_id="$2"
  local worker_id="$3"
  local target_dir="$4"

  jq -n \
    --arg bundle_id "$bundle_id" \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.resident-remote-proof-phase-receipts.v1",
      receipts: [
        {
          phase: "check",
          command_id: ($bundle_id + "-check"),
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE check"),
          stderr: ""
        },
        {
          phase: "test",
          command_id: ($bundle_id + "-test"),
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE test"),
          stderr: ""
        },
        {
          phase: "clippy",
          command_id: ($bundle_id + "-clippy"),
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE clippy"),
          stderr: ""
        }
      ]
    }
  ' >"$path"
}

write_receipts_target_drift() {
  local path="$1"
  local bundle_id="$2"
  local worker_id="$3"
  local target_dir="$4"
  local drift_target="$5"

  jq -n \
    --arg bundle_id "$bundle_id" \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" \
    --arg drift_target "$drift_target" '
    {
      schema_version: "franken-engine.resident-remote-proof-phase-receipts.v1",
      receipts: [
        {
          phase: "check",
          command_id: ($bundle_id + "-check"),
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE check"),
          stderr: ""
        },
        {
          phase: "test",
          command_id: ($bundle_id + "-test"),
          worker_id: $worker_id,
          target_dir: $drift_target,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE test"),
          stderr: ""
        },
        {
          phase: "clippy",
          command_id: ($bundle_id + "-clippy"),
          worker_id: $worker_id,
          target_dir: $target_dir,
          exit_code: 0,
          completion_marker: "present",
          stdout: ("[RCH] remote " + $worker_id + "\nREMOTE_PROOF_PHASE_COMPLETE clippy"),
          stderr: ""
        }
      ]
    }
  ' >"$path"
}

write_sticky_plan() {
  local path="$1"
  local worker_id="$2"
  local target_dir="$3"

  jq -n \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.sticky-worker-warm-target-lease-plan.v1",
      plan_decision: "admit_sticky",
      assigned_worker_id: $worker_id,
      assigned_target_dir: $target_dir,
      manifest_phase_count: 3
    }
  ' >"$path"
}

write_hotspot_ledger() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.rch-sync-closure-hotspot-ledger.v1",
      analysis_status: "ok",
      repeated_hotspot_count: 1,
      total_full_sync_commands: 0,
      total_narrow_sync_commands: 3
    }
  ' >"$path"
}

write_pressure_snapshot() {
  local path="$1"

  jq -n '
    {
      disk_pressure: "low",
      memory_pressure: "low"
    }
  ' >"$path"
}

write_incident_history_clean() {
  local path="$1"

  jq -n '{incidents: []}' >"$path"
}

write_artifact_files() {
  local path="$1"
  local bundle_slug="$2"

  jq -n \
    --arg bundle_slug "$bundle_slug" '
    {
      schema_version: "franken-engine.remote-proof-artifact-files.v1",
      artifacts: [
        {
          path: ("artifacts/resident/" + $bundle_slug + "/run_manifest.json"),
          sha256: "1111111111111111111111111111111111111111111111111111111111111111",
          size_bytes: 1200,
          roles: ["replay"],
          replay_critical: true
        },
        {
          path: ("artifacts/resident/" + $bundle_slug + "/events.jsonl"),
          sha256: "2222222222222222222222222222222222222222222222222222222222222222",
          size_bytes: 2400,
          roles: ["replay", "inspect"],
          replay_critical: true
        },
        {
          path: ("artifacts/resident/" + $bundle_slug + "/commands.txt"),
          sha256: "3333333333333333333333333333333333333333333333333333333333333333",
          size_bytes: 600,
          roles: ["replay"],
          replay_critical: true
        },
        {
          path: ("artifacts/resident/" + $bundle_slug + "/bundle_report.json"),
          sha256: "4444444444444444444444444444444444444444444444444444444444444444",
          size_bytes: 1800,
          roles: ["status", "inspect"],
          replay_critical: false
        }
      ]
    }
  ' >"$path"
}

write_retrieval_request() {
  local path="$1"

  jq -n '
    {
      schema_version: "franken-engine.remote-proof-retrieval-request.v1",
      requested_roles: ["replay", "status"]
    }
  ' >"$path"
}

write_retrieved_files() {
  local path="$1"
  local bundle_slug="$2"

  jq -n \
    --arg bundle_slug "$bundle_slug" '
    [
      ("artifacts/resident/" + $bundle_slug + "/bundle_report.json"),
      ("artifacts/resident/" + $bundle_slug + "/commands.txt"),
      ("artifacts/resident/" + $bundle_slug + "/events.jsonl"),
      ("artifacts/resident/" + $bundle_slug + "/run_manifest.json")
    ]
  ' >"$path"
}

build_artifact_files_from_bundle_report() {
  local bundle_report_json="$1"
  local output_path="$2"

  jq -n \
    --slurpfile bundle "$bundle_report_json" '
    ($bundle[0]) as $bundle
    | {
        schema_version: "franken-engine.remote-proof-artifact-files.v1",
        artifacts: [
          {
            path: $bundle.artifact_paths.run_manifest_json,
            sha256: "1111111111111111111111111111111111111111111111111111111111111111",
            size_bytes: 1200,
            roles: ["replay"],
            replay_critical: true
          },
          {
            path: $bundle.artifact_paths.events_jsonl,
            sha256: "2222222222222222222222222222222222222222222222222222222222222222",
            size_bytes: 2400,
            roles: ["replay", "inspect"],
            replay_critical: true
          },
          {
            path: $bundle.artifact_paths.commands_txt,
            sha256: "3333333333333333333333333333333333333333333333333333333333333333",
            size_bytes: 600,
            roles: ["replay"],
            replay_critical: true
          },
          {
            path: $bundle.artifact_paths.bundle_report_json,
            sha256: "4444444444444444444444444444444444444444444444444444444444444444",
            size_bytes: 1800,
            roles: ["status", "inspect"],
            replay_critical: false
          }
        ]
      }
  ' >"$output_path"
}

build_retrieved_files_from_bundle_report() {
  local bundle_report_json="$1"
  local output_path="$2"

  jq -n \
    --slurpfile bundle "$bundle_report_json" '
    ($bundle[0]) as $bundle
    | [
        $bundle.artifact_paths.bundle_report_json,
        $bundle.artifact_paths.commands_txt,
        $bundle.artifact_paths.events_jsonl,
        $bundle.artifact_paths.run_manifest_json
      ]
  ' >"$output_path"
}

write_incident_packet_orphan() {
  local path="$1"
  local worker_id="$2"
  local target_dir="$3"

  jq -n \
    --arg worker_id "$worker_id" \
    --arg target_dir "$target_dir" '
    {
      schema_version: "franken-engine.rch-incident-packet.v1",
      status: "fail",
      failure_kind: "canceled_build_live_orphaned_rustc",
      retry_safety: "unsafe_until_orphaned_processes_are_cleared",
      recommended_next_action: "clear orphan",
      worker_id: $worker_id,
      target_dir: $target_dir,
      exit_code: 130
    }
  ' >"$path"
}

write_worker_truth_orphan() {
  local path="$1"
  local worker_id="$2"

  jq -n \
    --arg worker_id "$worker_id" '
    {
      schema_version: "franken-engine.rch-worker-truth-parity-report.v1",
      decision: "fail_closed",
      drift_count: 1,
      ghost_job_detected: true,
      findings: [
        {
          code: "ghost_job_live_remote_compile",
          worker_id: $worker_id
        }
      ],
      worker_rows: [
        {
          worker_id: $worker_id,
          daemon_present: true,
          daemon_drained: false,
          probe_present: true,
          probe_schedulable: true,
          queue_present: true,
          queue_schedulable: true
        }
      ],
      incident_evidence: {
        failure_kind: "canceled_build_live_orphaned_rustc"
      }
    }
  ' >"$path"
}

write_fairness_policy() {
  local path="$1"

  jq -n '
    {
      max_bundles_per_worker: 2,
      max_total_cost_per_worker: 8,
      starvation_escape_bundle_ids: [],
      explicit_incompatibilities: []
    }
  ' >"$path"
}

prepare_selftest_fixtures() {
  local dir="$1"

  mkdir -p "$dir"
  write_manifest "${dir}/phase_manifest_alpha.json" "bundle-alpha" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_manifest "${dir}/phase_manifest_beta.json" "bundle-beta" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_manifest "${dir}/phase_manifest_gamma.json" "bundle-gamma" "ts2" "/tmp/rch_target_swarm_ctrl_v_gamma"
  write_receipts_success "${dir}/phase_receipts_alpha.json" "bundle-alpha" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_receipts_success "${dir}/phase_receipts_beta.json" "bundle-beta" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_receipts_target_drift "${dir}/phase_receipts_gamma.json" "bundle-gamma" "ts2" "/tmp/rch_target_swarm_ctrl_v_gamma" "/tmp/rch_target_swarm_ctrl_v_gamma_drift"
  write_sticky_plan "${dir}/sticky_plan_alpha.json" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_sticky_plan "${dir}/sticky_plan_beta.json" "ts2" "/tmp/rch_target_swarm_ctrl_v_alpha"
  write_hotspot_ledger "${dir}/hotspot_alpha.json"
  write_hotspot_ledger "${dir}/hotspot_beta.json"
  write_pressure_snapshot "${dir}/pressure_low.json"
  write_incident_history_clean "${dir}/incident_history_clean.json"
  write_artifact_files "${dir}/artifact_files_alpha.json" "bundle-alpha"
  write_artifact_files "${dir}/artifact_files_beta.json" "bundle-beta"
  write_retrieval_request "${dir}/retrieval_request.json"
  write_retrieved_files "${dir}/retrieved_alpha.json" "bundle-alpha"
  write_retrieved_files "${dir}/retrieved_beta.json" "bundle-beta"
  write_incident_packet_orphan "${dir}/incident_packet_orphan.json" "ts2" "/tmp/rch_target_swarm_ctrl_v_gamma"
  write_worker_truth_orphan "${dir}/worker_truth_orphan.json" "ts2"
  write_fairness_policy "${dir}/fairness_policy.json"
}

refresh_output_paths

check_mode() {
  local scope_file

  bash -n "${BASH_SOURCE[0]}"
  test -f "$executor"
  test -f "$mirror_packer"
  test -f "$roi_ledger"
  test -f "$salvage_receipt"
  test -f "$batch_packer"
  test -f "${root_dir}/docs/SWARM_CTRL_V_OPERATOR_RUNBOOK.md"
  test -f "${root_dir}/scripts/e2e/swarm_ctrl_v_runbook_truth_gate.sh"
  record_pass "bash syntax and composed SWARM-CTRL-V surfaces exist"

  scope_file="$(mktemp "${TMPDIR:-/tmp}/resident-remote-proof-no-mock-drill-scope.XXXXXX")"
  printf '%s\n' \
    "scripts/e2e/resident_remote_proof_no_mock_drill.sh" \
    "scripts/resident_remote_proof_bundle_executor.sh" \
    "scripts/remote_proof_artifact_mirror_packer.sh" \
    "scripts/warm_target_roi_eviction_ledger.sh" \
    "scripts/remote_proof_salvage_receipt.sh" \
    "scripts/locality_aware_remote_proof_batch_packer.sh" >"$scope_file"
  "${root_dir}/scripts/rch_policy_compliance_gate.sh" \
    --output-dir "${TMPDIR:-/tmp}/resident-remote-proof-no-mock-drill-rch-policy" \
    --scope-file "$scope_file" >/dev/null
  record_pass "rch policy compliance"
}

run_mode() {
  local alpha_dir beta_dir gamma_dir roi_alpha_dir roi_beta_dir mirror_alpha_dir mirror_beta_dir batch_dir salvage_dir
  local batch_inputs_dir alpha_slug beta_slug salvage_exit salvage_output
  local generated_artifact_files_alpha generated_artifact_files_beta generated_retrieved_alpha generated_retrieved_beta

  if [[ -z "$fixture_dir" ]]; then
    printf 'run mode requires --fixture-dir\n' >&2
    exit 64
  fi

  require_json "${fixture_dir}/phase_manifest_alpha.json"
  require_json "${fixture_dir}/phase_receipts_alpha.json"
  require_json "${fixture_dir}/phase_manifest_beta.json"
  require_json "${fixture_dir}/phase_receipts_beta.json"
  require_json "${fixture_dir}/phase_manifest_gamma.json"
  require_json "${fixture_dir}/phase_receipts_gamma.json"
  require_json "${fixture_dir}/sticky_plan_alpha.json"
  require_json "${fixture_dir}/sticky_plan_beta.json"
  require_json "${fixture_dir}/hotspot_alpha.json"
  require_json "${fixture_dir}/hotspot_beta.json"
  require_json "${fixture_dir}/pressure_low.json"
  require_json "${fixture_dir}/incident_history_clean.json"
  require_json "${fixture_dir}/retrieval_request.json"
  require_json "${fixture_dir}/incident_packet_orphan.json"
  require_json "${fixture_dir}/worker_truth_orphan.json"
  require_json "${fixture_dir}/fairness_policy.json"

  mkdir -p "$run_dir"
  : >"$events_path"
  write_command_log

  alpha_dir="${run_dir}/bundle-alpha"
  beta_dir="${run_dir}/bundle-beta"
  gamma_dir="${run_dir}/bundle-gamma"
  roi_alpha_dir="${run_dir}/roi-alpha"
  roi_beta_dir="${run_dir}/roi-beta"
  mirror_alpha_dir="${run_dir}/mirror-alpha"
  mirror_beta_dir="${run_dir}/mirror-beta"
  batch_dir="${run_dir}/batch-plan"
  salvage_dir="${run_dir}/salvage"
  batch_inputs_dir="${run_dir}/batch-inputs"
  mkdir -p "$batch_inputs_dir"

  "$executor" \
    --agent-id CyanOak \
    --bead-id bd-opgss \
    --phase-manifest-json "${fixture_dir}/phase_manifest_alpha.json" \
    --phase-receipts-json "${fixture_dir}/phase_receipts_alpha.json" \
    --output-dir "$alpha_dir" >/dev/null
  write_event "bundle_alpha_executed" "resident bundle executor succeeded for bundle-alpha"

  "$executor" \
    --agent-id CyanOak \
    --bead-id bd-opgss \
    --phase-manifest-json "${fixture_dir}/phase_manifest_beta.json" \
    --phase-receipts-json "${fixture_dir}/phase_receipts_beta.json" \
    --output-dir "$beta_dir" >/dev/null
  write_event "bundle_beta_executed" "resident bundle executor succeeded for bundle-beta"

  "$executor" \
    --agent-id CyanOak \
    --bead-id bd-opgss \
    --phase-manifest-json "${fixture_dir}/phase_manifest_gamma.json" \
    --phase-receipts-json "${fixture_dir}/phase_receipts_gamma.json" \
    --output-dir "$gamma_dir" >/dev/null || true
  write_event "bundle_gamma_executed" "resident bundle executor emitted fail-closed bundle-gamma evidence"

  generated_artifact_files_alpha="${run_dir}/artifact_files_alpha.generated.json"
  generated_artifact_files_beta="${run_dir}/artifact_files_beta.generated.json"
  generated_retrieved_alpha="${run_dir}/retrieved_alpha.generated.json"
  generated_retrieved_beta="${run_dir}/retrieved_beta.generated.json"
  build_artifact_files_from_bundle_report "${alpha_dir}/bundle_report.json" "$generated_artifact_files_alpha"
  build_artifact_files_from_bundle_report "${beta_dir}/bundle_report.json" "$generated_artifact_files_beta"
  build_retrieved_files_from_bundle_report "${alpha_dir}/bundle_report.json" "$generated_retrieved_alpha"
  build_retrieved_files_from_bundle_report "${beta_dir}/bundle_report.json" "$generated_retrieved_beta"

  "$roi_ledger" \
    --bundle-report-json "${alpha_dir}/bundle_report.json" \
    --sticky-plan-json "${fixture_dir}/sticky_plan_alpha.json" \
    --hotspot-ledger-json "${fixture_dir}/hotspot_alpha.json" \
    --pressure-snapshot-json "${fixture_dir}/pressure_low.json" \
    --incident-history-json "${fixture_dir}/incident_history_clean.json" \
    --output-dir "$roi_alpha_dir" >/dev/null
  write_event "roi_alpha_computed" "warm-target ROI retained bundle-alpha"

  "$roi_ledger" \
    --bundle-report-json "${beta_dir}/bundle_report.json" \
    --sticky-plan-json "${fixture_dir}/sticky_plan_beta.json" \
    --hotspot-ledger-json "${fixture_dir}/hotspot_beta.json" \
    --pressure-snapshot-json "${fixture_dir}/pressure_low.json" \
    --incident-history-json "${fixture_dir}/incident_history_clean.json" \
    --output-dir "$roi_beta_dir" >/dev/null
  write_event "roi_beta_computed" "warm-target ROI retained bundle-beta"

  "$mirror_packer" \
    --bundle-report-json "${alpha_dir}/bundle_report.json" \
    --artifact-files-json "$generated_artifact_files_alpha" \
    --retrieval-request-json "${fixture_dir}/retrieval_request.json" \
    --retrieved-files-json "$generated_retrieved_alpha" \
    --output-dir "$mirror_alpha_dir" >/dev/null
  write_event "mirror_alpha_verified" "bounded retrieval verified for bundle-alpha"

  "$mirror_packer" \
    --bundle-report-json "${beta_dir}/bundle_report.json" \
    --artifact-files-json "$generated_artifact_files_beta" \
    --retrieval-request-json "${fixture_dir}/retrieval_request.json" \
    --retrieved-files-json "$generated_retrieved_beta" \
    --output-dir "$mirror_beta_dir" >/dev/null
  write_event "mirror_beta_verified" "bounded retrieval verified for bundle-beta"

  alpha_slug="$(jq -r '.bundle_id' "${alpha_dir}/bundle_report.json")"
  beta_slug="$(jq -r '.bundle_id' "${beta_dir}/bundle_report.json")"

  jq -n \
    --slurpfile alpha "${alpha_dir}/bundle_report.json" \
    --slurpfile beta "${beta_dir}/bundle_report.json" '
    {
      bundles: [
        ($alpha[0] + {closure_roots: ["crates/franken-engine", "/dp/frankensqlite"], predicted_cost_units: 2}),
        ($beta[0] + {closure_roots: ["crates/franken-engine", "/dp/frankensqlite"], predicted_cost_units: 1})
      ]
    }
  ' >"${batch_inputs_dir}/bundle_reports.json"

  jq -n \
    --arg alpha_slug "$alpha_slug" \
    --arg beta_slug "$beta_slug" \
    --slurpfile alpha "${mirror_alpha_dir}/artifact_mirror_manifest.json" \
    --slurpfile beta "${mirror_beta_dir}/artifact_mirror_manifest.json" '
    {
      bundles: [
        {
          bundle_id: $alpha_slug,
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          retrieval_pack_artifacts: ($alpha[0].selected_artifacts // []),
          mirror_manifest_hash: ($alpha[0].hash_basis.manifest_hash // "")
        },
        {
          bundle_id: $beta_slug,
          closure_roots: ["crates/franken-engine", "/dp/frankensqlite"],
          retrieval_pack_artifacts: ($beta[0].selected_artifacts // []),
          mirror_manifest_hash: ($beta[0].hash_basis.manifest_hash // "")
        }
      ]
    }
  ' >"${batch_inputs_dir}/mirror_manifests.json"

  jq -n \
    --arg alpha_slug "$alpha_slug" \
    --arg beta_slug "$beta_slug" \
    --slurpfile alpha "${roi_alpha_dir}/warm_target_roi_ledger.json" \
    --slurpfile beta "${roi_beta_dir}/warm_target_roi_ledger.json" '
    {
      bundles: [
        ($alpha[0] + {bundle_id: $alpha_slug}),
        ($beta[0] + {bundle_id: $beta_slug})
      ]
    }
  ' >"${batch_inputs_dir}/roi_ledgers.json"

  "$batch_packer" \
    --bundle-reports-json "${batch_inputs_dir}/bundle_reports.json" \
    --mirror-manifests-json "${batch_inputs_dir}/mirror_manifests.json" \
    --roi-ledgers-json "${batch_inputs_dir}/roi_ledgers.json" \
    --fairness-policy-json "${fixture_dir}/fairness_policy.json" \
    --output-dir "$batch_dir" >/dev/null
  write_event "batch_plan_computed" "locality-aware batch plan grouped bundle-alpha and bundle-beta"

  set +e
  salvage_output="$(
    "$salvage_receipt" \
      --bundle-report-json "${gamma_dir}/bundle_report.json" \
      --incident-packet-json "${fixture_dir}/incident_packet_orphan.json" \
      --worker-truth-report-json "${fixture_dir}/worker_truth_orphan.json" \
      --output-dir "$salvage_dir" 2>&1
  )"
  salvage_exit=$?
  set -e
  if [[ "$salvage_exit" -ne 42 ]]; then
    record_failure "salvage receipt expected exit 42, got ${salvage_exit}"
    printf '%s\n' "$salvage_output" >&2
    return 1
  fi
  write_event "salvage_receipt_emitted" "orphan reconciliation workflow captured"

  jq -n \
    --slurpfile alpha_bundle "${alpha_dir}/bundle_report.json" \
    --slurpfile alpha_roi "${roi_alpha_dir}/warm_target_roi_ledger.json" \
    --slurpfile mirror_alpha "${mirror_alpha_dir}/retrieval_verification_report.json" \
    --slurpfile mirror_beta "${mirror_beta_dir}/retrieval_verification_report.json" \
    --slurpfile batch "${batch_dir}/batch_manifest.json" \
    --slurpfile gamma_bundle "${gamma_dir}/bundle_report.json" \
    --slurpfile salvage "${salvage_dir}/salvage_receipt.json" \
    --arg alpha_bundle_report "${alpha_dir}/bundle_report.json" \
    --arg beta_bundle_report "${beta_dir}/bundle_report.json" \
    --arg gamma_bundle_report "${gamma_dir}/bundle_report.json" \
    --arg report_json "$report_json" \
    --arg events_path "$events_path" \
    --arg commands_path "$commands_path" \
    --arg report_md "$report_md" \
    '{
      schema_version: "franken-engine.resident-remote-proof-no-mock-drill.v1",
      drill_decision: (
        if ($alpha_bundle[0].bundle_decision == "pass")
          and ($alpha_roi[0].decision == "retain")
          and ($mirror_alpha[0].verification_decision == "pass")
          and ($mirror_beta[0].verification_decision == "pass")
          and (($batch[0].batches | length) == 1)
          and ($salvage[0].workflow_state == "orphan_reconciliation_required")
        then "pass"
        else "fail_closed"
        end
      ),
      scenarios: {
        resident_bundle_reuse: {
          status: (
            if ($alpha_bundle[0].bundle_decision == "pass") and ($alpha_roi[0].decision == "retain")
            then "pass"
            else "fail_closed"
            end
          ),
          bundle_id: ($alpha_bundle[0].bundle_id // "unknown"),
          worker_id: ($alpha_bundle[0].expected_worker_id // "unknown"),
          target_dir: ($alpha_bundle[0].expected_target_dir // "unknown"),
          roi_decision: ($alpha_roi[0].decision // "unknown")
        },
        bounded_retrieval_and_batching: {
          status: (
            if ($mirror_alpha[0].verification_decision == "pass")
              and ($mirror_beta[0].verification_decision == "pass")
              and (($batch[0].batches | length) == 1)
            then "pass"
            else "fail_closed"
            end
          ),
          batch_manifest_id: ($batch[0].batch_manifest_id // "unknown"),
          batch_count: (($batch[0].batches // []) | length),
          split_reasons: ($batch[0].split_reasons // []),
          alpha_retrieval_verdict: ($mirror_alpha[0].verification_decision // "unknown"),
          beta_retrieval_verdict: ($mirror_beta[0].verification_decision // "unknown")
        },
        salvage_orphan_handling: {
          status: (
            if ($salvage[0].workflow_state == "orphan_reconciliation_required")
            then "pass"
            else "fail_closed"
            end
          ),
          workflow_state: ($salvage[0].workflow_state // "unknown"),
          recovery_recommendation: ($salvage[0].recovery_recommendation // "unknown"),
          source_bundle_decision: ($gamma_bundle[0].bundle_decision // "unknown")
        }
      },
      child_artifacts: {
        bundle_alpha_report_json: $alpha_bundle_report,
        bundle_beta_report_json: $beta_bundle_report,
        bundle_gamma_report_json: $gamma_bundle_report,
        warm_target_roi_ledger_json: ($alpha_roi[0].artifact_paths.warm_target_roi_ledger_json // ""),
        retrieval_verification_report_alpha_json: ($mirror_alpha[0].artifact_paths.retrieval_verification_report_json // ""),
        retrieval_verification_report_beta_json: ($mirror_beta[0].artifact_paths.retrieval_verification_report_json // ""),
        batch_manifest_json: ($batch[0].artifact_paths.batch_manifest_json // ""),
        salvage_receipt_json: ($salvage[0].artifact_paths.salvage_receipt_json // "")
      },
      artifact_paths: {
        resident_remote_proof_no_mock_drill_report_json: $report_json,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    }' >"$report_tmp"
  mv "$report_tmp" "$report_json"

  jq -e '.drill_decision == "pass"' "$report_json" >/dev/null

  {
    printf '# SWARM-CTRL-V No-Mock Resident Proof Drill\n\n'
    printf -- '- Drill decision: %s\n' "$(jq -r '.drill_decision' "$report_json")"
    printf -- '- Resident bundle reuse: %s\n' "$(jq -r '.scenarios.resident_bundle_reuse.status' "$report_json")"
    printf -- '- Retrieval and batching: %s\n' "$(jq -r '.scenarios.bounded_retrieval_and_batching.status' "$report_json")"
    printf -- '- Salvage/orphan handling: %s\n' "$(jq -r '.scenarios.salvage_orphan_handling.status' "$report_json")"
    printf -- '- Batch manifest id: %s\n' "$(jq -r '.scenarios.bounded_retrieval_and_batching.batch_manifest_id' "$report_json")"
    printf -- '- Salvage workflow: %s\n' "$(jq -r '.scenarios.salvage_orphan_handling.workflow_state' "$report_json")"
  } >"$report_md"

  write_event "drill_completed" "resident remote proof no-mock drill passed"
}

run_selftest() {
  local tmp_parent tmp_root fixture_root

  check_mode
  tmp_parent="${RESIDENT_REMOTE_PROOF_NO_MOCK_DRILL_SMOKE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/resident-remote-proof-no-mock-drill.XXXXXX")"
  fixture_root="${tmp_root}/fixtures"
  prepare_selftest_fixtures "$fixture_root"
  fixture_dir="$fixture_root"
  run_dir="${tmp_root}/run"
  refresh_output_paths

  run_mode
  jq -e '
    .drill_decision == "pass"
    and .scenarios.resident_bundle_reuse.status == "pass"
    and .scenarios.bounded_retrieval_and_batching.status == "pass"
    and .scenarios.bounded_retrieval_and_batching.batch_count == 1
    and .scenarios.salvage_orphan_handling.status == "pass"
    and .scenarios.salvage_orphan_handling.workflow_state == "orphan_reconciliation_required"
    and (.artifact_paths.resident_remote_proof_no_mock_drill_report_json | length > 0)
  ' "${run_dir}/resident_remote_proof_no_mock_drill_report.json" >/dev/null
  record_pass "composed resident-proof reuse, bounded retrieval batching, and salvage assertions"

  printf 'resident_remote_proof_no_mock_drill_artifacts=%s\n' "$tmp_root"
}

case "$mode" in
  check)
    check_mode
    ;;
  run)
    run_mode
    ;;
  selftest)
    run_selftest
    ;;
  *)
    record_failure "unknown mode: $mode"
    exit 64
    ;;
esac
