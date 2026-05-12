#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
golden_dir="${root_dir}/scripts/testdata/franken_core_graduation_golden_reports"
golden_json="${golden_dir}/reports.json"
golden_md="${golden_dir}/reports.md.golden"
mode="${1:-check}"
failures=0

record_pass() {
  printf 'PASS franken-core-graduation-golden-reports %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-graduation-golden-reports %s\n' "$1" >&2
  failures=$((failures + 1))
}

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/franken_core_graduation_golden_reports_smoke.sh [check|update]

Set UPDATE_FRANKEN_CORE_GRADUATION_GOLDENS=1 for update mode.
EOF
}

write_truthful_root_manifest() {
  local path="$1"
  cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
]
exclude = ["crates/franken-core"]
resolver = "2"
EOF
}

write_core_manifest() {
  local path="$1"
  cat >"$path" <<'EOF'
[package]
name = "frankenengine-core"
version = "0.1.0"
edition = "2024"
EOF
}

generate_actual() {
  local output_json="$1"
  local output_md="$2"
  local tmpdir validation_dir status_dir drill_dir rehearsal_dir negative_dir fixture_root negative_claim
  tmpdir="$(mktemp -d)"
  validation_dir="${tmpdir}/validation"
  status_dir="${tmpdir}/status"
  drill_dir="${tmpdir}/drill"
  rehearsal_dir="${tmpdir}/rehearsal"
  negative_dir="${tmpdir}/negative-status"
  fixture_root="${tmpdir}/fixture"
  negative_claim="${fixture_root}/docs/status.md"

  "${root_dir}/scripts/franken_core_validation_impact_planner.sh" \
    --bead-id "bd-4w7h9.7-golden" \
    --source-revision "GOLDEN" \
    --output-dir "$validation_dir" \
    --changed-path "docs/FRANKEN_CORE_GRADUATION_CONTRACT_V1.md" >/dev/null

  "${root_dir}/scripts/franken_core_status_truth_gate.sh" \
    --source-revision "GOLDEN" \
    --output-dir "$status_dir" >/dev/null

  "${root_dir}/scripts/franken_core_no_mock_graduation_drill.sh" \
    --source-revision "GOLDEN" \
    --output-dir "$drill_dir" >/dev/null

  "${root_dir}/scripts/franken_core_staged_inclusion_rehearsal.sh" \
    --source-revision "GOLDEN" \
    --output-dir "$rehearsal_dir" >/dev/null

  mkdir -p "${fixture_root}/crates/franken-core" "${fixture_root}/docs"
  write_truthful_root_manifest "${fixture_root}/Cargo.toml"
  write_core_manifest "${fixture_root}/crates/franken-core/Cargo.toml"
  cat >"$negative_claim" <<'EOF'
crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable.

crates/franken-core is workspace-ready and included in the workspace.
EOF

  set +e
  "${root_dir}/scripts/franken_core_status_truth_gate.sh" \
    --root-cargo "${fixture_root}/Cargo.toml" \
    --core-cargo "${fixture_root}/crates/franken-core/Cargo.toml" \
    --claim-file "$negative_claim" \
    --source-revision "GOLDEN-NEGATIVE" \
    --output-dir "$negative_dir" >/dev/null
  local negative_status=$?
  set -e
  if [[ "$negative_status" -ne 42 ]]; then
    record_failure "negative status fixture exit ${negative_status}, expected 42"
  fi

  jq -n \
    --slurpfile contract "${root_dir}/docs/franken_core_graduation_contract_v1.json" \
    --slurpfile parity "${root_dir}/docs/franken_core_api_parity_ledger_v1.json" \
    --slurpfile validation "${validation_dir}/validation_impact_plan.json" \
    --slurpfile status "${status_dir}/truth_report.json" \
    --slurpfile drill "${drill_dir}/graduation_drill_report.json" \
    --slurpfile rehearsal "${rehearsal_dir}/staged_inclusion_rehearsal.json" \
    --slurpfile negative "${negative_dir}/truth_report.json" \
    '{
      schema_version:"franken-engine.franken-core-graduation-golden-reports.v1",
      bead_id:"bd-4w7h9.7",
      parent_bead_id:"bd-4w7h9",
      update_command:"UPDATE_FRANKEN_CORE_GRADUATION_GOLDENS=1 bash scripts/e2e/franken_core_graduation_golden_reports_smoke.sh update",
      dynamic_fields_scrubbed:["source_revision","artifact_paths","run_dir","temporary_paths","timestamps"],
      reports:[
        {
          family:"graduation_contract",
          schema_version:$contract[0].schema_version,
          current_workspace_state:$contract[0].decision.current_workspace_state,
          workspace_inclusion_complete:$contract[0].decision.workspace_inclusion_complete,
          acceptance_suite_required:$contract[0].acceptance_suite_bead_id,
          forbidden_shortcut_count:($contract[0].forbidden_shortcuts | length)
        },
        {
          family:"api_parity_ledger",
          schema_version:$parity[0].schema_version,
          decision_workspace_state:$parity[0].decision.current_workspace_state,
          workspace_inclusion_complete:$parity[0].decision.workspace_inclusion_complete,
          core_module_count:$parity[0].summary.core_module_count,
          matching_engine_export_count:$parity[0].summary.matching_engine_export_count,
          unclassified_row_count:$parity[0].summary.unclassified_row_count,
          row_count:($parity[0].rows | length)
        },
        {
          family:"validation_impact_planner",
          schema_version:$validation[0].schema_version,
          decision:$validation[0].decision,
          change_classes:$validation[0].change_classes,
          workspace_inclusion_claim_supported:$validation[0].workspace_inclusion_policy.workspace_inclusion_claim_supported,
          recommended_command_ids:($validation[0].recommended_commands | map(.command_id) | sort)
        },
        {
          family:"status_truth_gate",
          schema_version:$status[0].schema_version,
          decision:$status[0].decision,
          root_workspace_state:$status[0].root_workspace_state,
          violation_count:$status[0].violation_count,
          evidence_bead_ids:($status[0].evidence_beads | map(.bead_id))
        },
        {
          family:"no_mock_graduation_drill",
          schema_version:$drill[0].schema_version,
          decision:$drill[0].decision,
          root_workspace_state:$drill[0].root_workspace_state,
          workspace_inclusion_ready:$drill[0].workspace_inclusion_ready,
          selected_modules:$drill[0].selected_modules,
          proof_count:($drill[0].proofs_still_needed | length)
        },
        {
          family:"staged_inclusion_rehearsal",
          schema_version:$rehearsal[0].schema_version,
          decision:$rehearsal[0].decision,
          simulation_mode:$rehearsal[0].simulation_mode,
          root_workspace_state:$rehearsal[0].root_workspace_state,
          mutates_root_cargo_toml:$rehearsal[0].mutates_root_cargo_toml,
          risk_ids:($rehearsal[0].risks | map(.risk_id) | sort),
          validation_gate_count:($rehearsal[0].validation_gates | length),
          rollback_step_count:($rehearsal[0].rollback_steps | length)
        },
        {
          family:"negative_status_truth_gate_overclaim",
          schema_version:$negative[0].schema_version,
          decision:$negative[0].decision,
          reason_codes:$negative[0].reason_codes,
          violation_count:$negative[0].violation_count
        }
      ]
    }' >"$output_json"

  jq -r '
    "# Franken-Core Graduation Golden Reports",
    "",
    ("schema_version: `" + .schema_version + "`"),
    ("bead_id: `" + .bead_id + "`"),
    "",
    "## Reports",
    (.reports[] | "- `" + .family + "` decision=`" + ((.decision // .current_workspace_state // .decision_workspace_state) | tostring) + "` schema=`" + .schema_version + "`"),
    "",
    "## Negative Coverage",
    (.reports[] | select(.family == "negative_status_truth_gate_overclaim") | "- `" + .family + "` reason_codes=`" + (.reason_codes | join(",")) + "`")
  ' "$output_json" >"$output_md"
}

assert_golden_shape() {
  jq -e '
    .schema_version == "franken-engine.franken-core-graduation-golden-reports.v1"
    and .bead_id == "bd-4w7h9.7"
    and (.reports | length) == 7
    and ([.reports[].family] | sort) == [
      "api_parity_ledger",
      "graduation_contract",
      "negative_status_truth_gate_overclaim",
      "no_mock_graduation_drill",
      "staged_inclusion_rehearsal",
      "status_truth_gate",
      "validation_impact_planner"
    ]
    and any(.reports[]; .family == "graduation_contract" and .workspace_inclusion_complete == false)
    and any(.reports[]; .family == "api_parity_ledger" and .core_module_count == 41 and .unclassified_row_count == 0)
    and any(.reports[]; .family == "validation_impact_planner" and .decision == "green" and (.workspace_inclusion_claim_supported == false))
    and any(.reports[]; .family == "status_truth_gate" and .decision == "pass" and .violation_count == 0)
    and any(.reports[]; .family == "no_mock_graduation_drill" and .decision == "pass" and (.selected_modules | index("capability") != null))
    and any(.reports[]; .family == "staged_inclusion_rehearsal" and .decision == "pass" and .mutates_root_cargo_toml == false)
    and any(.reports[]; .family == "negative_status_truth_gate_overclaim" and .decision == "fail_closed" and (.reason_codes | index("workspace_inclusion_overclaim") != null))
  ' "$golden_json" >/dev/null || record_failure "golden JSON shape"
}

assert_no_dynamic_values() {
  if grep -Eq '/tmp/|/data/projects|/home/ubuntu' "$golden_json" "$golden_md"; then
    record_failure "golden contains host-specific path"
  fi
  if grep -Eq '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' "$golden_json" "$golden_md"; then
    record_failure "golden contains timestamp"
  fi
}

run_check() {
  local tmpdir actual_json actual_md
  tmpdir="$(mktemp -d)"
  actual_json="${tmpdir}/reports.json"
  actual_md="${tmpdir}/reports.md.golden"
  jq empty "${root_dir}/docs/franken_core_graduation_golden_reports_v1.json" "$golden_json"
  bash -n "${BASH_SOURCE[0]}"
  generate_actual "$actual_json" "$actual_md"
  diff -u "$golden_json" "$actual_json" >/dev/null || record_failure "JSON golden differs; run explicit update command"
  diff -u "$golden_md" "$actual_md" >/dev/null || record_failure "Markdown golden differs; run explicit update command"
  assert_golden_shape
  assert_no_dynamic_values
  grep -Fq "negative_status_truth_gate_overclaim" "$golden_md" || record_failure "Markdown golden missing negative fixture"
  if [[ "$failures" -eq 0 ]]; then
    record_pass "check"
  fi
}

run_update() {
  if [[ "${UPDATE_FRANKEN_CORE_GRADUATION_GOLDENS:-}" != "1" ]]; then
    record_failure "set UPDATE_FRANKEN_CORE_GRADUATION_GOLDENS=1 to update"
    return
  fi
  mkdir -p "$golden_dir"
  generate_actual "$golden_json" "$golden_md"
  record_pass "update"
}

case "$mode" in
  check)
    run_check
    ;;
  update)
    run_update
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage
    record_failure "unknown mode: ${mode}"
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
