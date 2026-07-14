#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_runbook="${root_dir}/docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
default_contract="${root_dir}/docs/swarm_validation_control_plane_contract_v1.json"
default_predictive_contract="${root_dir}/docs/swarm_predictive_dashboard_contract_v1.json"
default_predictive_doc="${root_dir}/docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
runbook_path="${SWARM_VALIDATION_CONTROL_PLANE_RUNBOOK:-${default_runbook}}"
contract_path="${SWARM_VALIDATION_CONTROL_PLANE_CONTRACT:-${default_contract}}"
predictive_contract_path="${SWARM_PREDICTIVE_DASHBOARD_CONTRACT:-${default_predictive_contract}}"
predictive_doc_path="${SWARM_PREDICTIVE_DASHBOARD_DOC:-${default_predictive_doc}}"
validation_failures=0

required_paths=(
  "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
  "docs/SWARM_PREDICTIVE_DASHBOARD_CONTRACT.md"
  "docs/swarm_predictive_dashboard_contract_v1.json"
  "docs/swarm_validation_control_plane_contract_v1.json"
  "scripts/e2e/proof_freshness_decay_gate_smoke.sh"
  "scripts/e2e/proof_reuse_cache_planner_smoke.sh"
  "scripts/e2e/rch_incident_packet_gate_smoke.sh"
  "scripts/e2e/build_storm_qos_batch_planner_smoke.sh"
  "scripts/e2e/staged_ownership_contamination_guard_smoke.sh"
  "scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh"
  "scripts/e2e/swarm_admission_drill.sh"
  "scripts/e2e/swarm_operator_status_report_smoke.sh"
  "scripts/e2e/swarm_predictive_orchestration_e2e.sh"
  "scripts/e2e/swarm_resource_lease_planner_smoke.sh"
  "scripts/e2e/swarm_validation_control_plane_contract_smoke.sh"
  "scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh"
  "scripts/e2e/swarm_validation_control_plane_e2e.sh"
  "scripts/e2e/source_local_rch_validation_admission_smoke.sh"
  "scripts/e2e/source_local_rch_admission_no_mock_proof.sh"
  "scripts/build_storm_qos_batch_planner.sh"
  "scripts/proof_freshness_decay_gate.sh"
  "scripts/proof_reuse_cache_planner.sh"
  "scripts/source_local_rch_validation_admission.sh"
  "scripts/rch_incident_packet_gate.sh"
  "scripts/staged_ownership_contamination_guard.sh"
  "scripts/stale_lock_stalled_bead_recommender.sh"
  "scripts/swarm_validation_planner.sh"
  "scripts/swarm_resource_lease_planner.sh"
  "scripts/swarm_resource_governor.sh"
  "scripts/swarm_operator_status_report.sh"
)

required_runbook_patterns=(
  "br ready --json"
  "br list --status=in_progress --json"
  "bv --recipe actionable --robot-plan"
  "file_reservation_paths"
  "fetch_inbox"
  "./scripts/swarm_validation_planner.sh"
  "./scripts/swarm_resource_lease_planner.sh"
  "./scripts/swarm_resource_governor.sh"
  "./scripts/proof_reuse_cache_planner.sh"
  "./scripts/build_storm_qos_batch_planner.sh"
  "./scripts/stale_lock_stalled_bead_recommender.sh"
  "./scripts/staged_ownership_contamination_guard.sh"
  "./scripts/swarm_operator_status_report.sh"
  "./scripts/e2e/proof_freshness_decay_gate_smoke.sh"
  "./scripts/e2e/proof_reuse_cache_planner_smoke.sh"
  "./scripts/e2e/rch_incident_packet_gate_smoke.sh"
  "./scripts/e2e/build_storm_qos_batch_planner_smoke.sh"
  "./scripts/e2e/staged_ownership_contamination_guard_smoke.sh"
  "./scripts/e2e/stale_lock_stalled_bead_recommender_smoke.sh"
  "./scripts/e2e/swarm_admission_drill.sh"
  "./scripts/e2e/swarm_operator_status_report_smoke.sh"
  "./scripts/e2e/swarm_predictive_orchestration_e2e.sh"
  "./scripts/e2e/swarm_resource_lease_planner_smoke.sh"
  "./scripts/e2e/swarm_validation_control_plane_contract_smoke.sh"
  "./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh"
  "./scripts/e2e/swarm_validation_control_plane_e2e.sh"
  "./scripts/e2e/source_local_rch_validation_admission_smoke.sh"
  "./scripts/e2e/source_local_rch_admission_no_mock_proof.sh"
  "./scripts/source_local_rch_validation_admission.sh"
  "franken-engine.source-local-rch-validation-admission.v1"
  "source_local_rch_validation_admission.json"
  "preflight/preflight_report.json"
  "rch-output.plain.log"
  "run_manifest.json"
  "dependency_root_hash"
  ".cargo/config.toml"
  "-Clinker-features=-lld"
  "replace the checked-in target rustflags"
  "CARGO_ENCODED_RUSTFLAGS"
  "Encoded Rust flags are unsupported"
  "CARGO_INCREMENTAL=0"
  "CARGO_BUILD_JOBS=1"
  "admit_reuse"
  "cold_refresh_required"
  "fail_closed"
  "remote_blocker"
  "local_fallback_contamination"
  "support_crate_contamination"
  "missing_freshness"
  "fail closed: contaminated proof"
  "fail closed for reuse: stale warm-target proof"
  "--validation-plan-json"
  "--collision-receipt-json"
  "--proof-freshness-json"
  "--rch-incident-packet-json"
  "--resource-lease-plan-json"
  "--proof-cache-plan-json"
  "--qos-batch-plan-json"
  "--stale-lock-recommendations-json"
  "--staged-ownership-report-json"
  "proof_cache_plan.json"
  "build_storm_batch_plan.json"
  "stale_lock_recommendations.json"
  "staged_ownership_report.json"
  "safe_to_reopen"
  "contact_first"
  "br doctor"
  "br sync --flush-only"
  "staged ownership"
  "send_message"
  "release_file_reservations"
  "franken-engine.swarm-predictive-dashboard.v1"
  "docs/swarm_predictive_dashboard_contract_v1.json"
  "/dp/frankentui"
  "future"
  "rch exec -- env"
  "CARGO_TARGET_DIR="
  # rch-policy-waive: local_fallback_not_rejected reason=required pattern string for documentation drift checks, not executable rch handling
  "local fallback"
  "Agent Mail"
  "pressure"
  "Unknown path"
  "stale"
)

record_pass() {
  printf 'PASS swarm-validation-control-plane-docs %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-validation-control-plane-docs %s\n' "$1" >&2
  validation_failures=$((validation_failures + 1))
}

check_repo_path_exists() {
  local path="$1"

  if [[ ! -e "${root_dir}/${path}" ]]; then
    record_failure "missing referenced repo path ${path}"
  else
    record_pass "referenced repo path exists ${path}"
  fi
}

validate_required_paths() {
  local path

  for path in "${required_paths[@]}"; do
    check_repo_path_exists "$path"
  done
}

validate_runbook_references() {
  local path
  local pattern

  if [[ ! -f "$runbook_path" ]]; then
    record_failure "runbook is missing: ${runbook_path}"
    return
  fi

  for pattern in "${required_runbook_patterns[@]}"; do
    if ! grep -Fq -- "$pattern" "$runbook_path"; then
      record_failure "runbook missing required pattern: ${pattern}"
    else
      record_pass "runbook contains ${pattern}"
    fi
  done

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    check_repo_path_exists "$path"
  done < <(grep -Eo '(\./)?scripts/[A-Za-z0-9_./-]+' "$runbook_path" | sed 's#^\./##' | sort -u)

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    check_repo_path_exists "$path"
  done < <(grep -Eo 'docs/[A-Za-z0-9_./-]+' "$runbook_path" | sort -u)
}

validate_contract_surface() {
  if [[ ! -f "$contract_path" ]]; then
    record_failure "contract is missing: ${contract_path}"
    return
  fi
  if ! jq empty "$contract_path" >/dev/null; then
    record_failure "contract is not valid JSON: ${contract_path}"
    return
  fi

  if ! jq -e '
    any(.workload_surfaces[];
      .surface_id == "operator_runbook_truth_gate"
      and (.repo_paths | index("docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md") != null)
      and (.repo_paths | index("scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh") != null)
      and (.read_commands | index("./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check") != null)
      and (.read_commands | index("./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh selftest") != null)
    )
  ' "$contract_path" >/dev/null; then
    record_failure "contract missing operator_runbook_truth_gate surface"
  else
    record_pass "contract includes operator_runbook_truth_gate surface"
  fi

  if ! jq -e '
    any(.output_artifact_contracts[];
      .artifact_id == "docs_truth_gate_report"
      and .schema_version == "franken-engine.swarm-validation-docs-truth-gate.v1"
      and (.required_fields | index("checked_paths") != null)
      and (.required_fields | index("heavy_cargo_command_shape") != null)
      and (.required_fields | index("admission_artifact_inputs") != null)
      and (.required_fields | index("br_db_degraded_fallback") != null)
      and (.required_fields | index("staged_ownership_guard") != null)
    )
  ' "$contract_path" >/dev/null; then
    record_failure "contract missing docs truth gate output artifact"
  else
    record_pass "contract includes docs truth gate output artifact"
  fi

  if ! jq -e '
    (.verification_commands | index("bash -n scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh check") != null)
    and (.verification_commands | index("./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh selftest") != null)
  ' "$contract_path" >/dev/null; then
    record_failure "contract verification commands omit docs truth gate"
  else
    record_pass "contract verification commands include docs truth gate"
  fi
}

validate_predictive_contract_surface() {
  if [[ ! -f "$predictive_contract_path" ]]; then
    record_failure "predictive dashboard contract is missing: ${predictive_contract_path}"
    return
  fi
  if ! jq empty "$predictive_contract_path" >/dev/null; then
    record_failure "predictive dashboard contract is not valid JSON: ${predictive_contract_path}"
    return
  fi

  if ! jq -e '
    .schema_version == "franken-engine.swarm-predictive-dashboard-contract.v1"
    and .status == "contract_only"
    and .producer.script == "scripts/swarm_operator_status_report.sh"
    and .producer.dashboard_schema_version == "franken-engine.swarm-predictive-dashboard.v1"
    and .renderer.repo_path == "/dp/frankentui"
    and .renderer.shipped_in_franken_engine == false
    and .renderer.local_renderer == false
  ' "$predictive_contract_path" >/dev/null; then
    record_failure "predictive dashboard contract no longer stays contract-only and frankentui-owned"
  else
    record_pass "predictive dashboard contract is contract-only and frankentui-owned"
  fi

  if ! jq -e '
    (.input_snapshot_contracts | index("franken-engine.swarm-validation-plan.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.swarm-validation-collision-receipt.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.proof-freshness-decay-report.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.rch-incident-packet.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.swarm-resource-lease-plan.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.proof-reuse-cache-plan.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.build-storm-batch-plan.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.stale-lock-recommendations.v1") != null)
    and (.input_snapshot_contracts | index("franken-engine.staged-ownership-report.v1") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.predictive_cost.high_risk_commands") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.collision_risk.conflicting_agents") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.proof_freshness.reusable") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.rch_incidents.incidents") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.resource_leases.lease_decision") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.proof_cache.proof_cache_decision") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.qos_batches.batch_decision") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.stale_lock_recommendations.actionable_commands") != null)
    and (.required_dashboard_fields | index("predictive_dashboard.staged_contamination.decision") != null)
    and (.golden_fixture_cases | index("high_cost") != null)
    and (.golden_fixture_cases | index("collision_risk") != null)
    and (.golden_fixture_cases | index("stale_proof") != null)
    and (.golden_fixture_cases | index("overloaded") != null)
  ' "$predictive_contract_path" >/dev/null; then
    record_failure "predictive dashboard contract omits predictive inputs, fields, or fixture cases"
  else
    record_pass "predictive dashboard contract includes predictive inputs, fields, and fixtures"
  fi
}

validate_predictive_doc_claims() {
  if [[ ! -f "$predictive_doc_path" ]]; then
    record_failure "predictive dashboard doc is missing: ${predictive_doc_path}"
    return
  fi

  if ! grep -Fq "does not ship a local TUI renderer" "$predictive_doc_path"; then
    record_failure "predictive dashboard doc must state no local TUI renderer ships here"
  else
    record_pass "predictive dashboard doc keeps renderer claim non-shipped"
  fi

  if ! grep -Fq "future" "$predictive_doc_path" || ! grep -Fq "/dp/frankentui" "$predictive_doc_path"; then
    record_failure "predictive dashboard doc must keep frankentui rendering future-tense"
  else
    record_pass "predictive dashboard doc keeps frankentui rendering future-tense"
  fi
}

has_env_assignment() {
  local line="$1"
  local variable_name="$2"
  local assignment_pattern="(^|[[:space:]])${variable_name}="

  [[ "$line" =~ $assignment_pattern ]]
}

extract_env_assignment_value() {
  local line="$1"
  local variable_name="$2"
  local rest
  local value=""
  local quote=""
  local escaped=false
  local character
  local index

  has_env_assignment "$line" "$variable_name" || return 1
  rest="${line#*"${variable_name}"=}"

  if [[ "${rest:0:1}" == "'" || "${rest:0:1}" == '"' ]]; then
    quote="${rest:0:1}"
    rest="${rest:1}"
  fi

  for ((index = 0; index < ${#rest}; index++)); do
    character="${rest:index:1}"
    if [[ "$escaped" == true ]]; then
      value+="$character"
      escaped=false
    elif [[ "$character" == "\\" && "$quote" != "'" ]]; then
      escaped=true
    elif [[ -n "$quote" && "$character" == "$quote" ]]; then
      break
    elif [[ -z "$quote" && "$character" =~ [[:space:]] ]]; then
      break
    else
      value+="$character"
    fi
  done

  if [[ "$escaped" == true ]]; then
    value+="\\"
  fi
  printf '%s\n' "$value"
}

rustflags_value_has_effective_linker_policy() {
  local value="$1"
  local -a tokens=()
  local index
  local effective_state="unset"

  read -r -a tokens <<<"$value"
  for ((index = 0; index < ${#tokens[@]}; index += 1)); do
    case "${tokens[index]}" in
      -Clinker-features=-lld)
        effective_state="disabled"
        ;;
      -Clinker-features=*)
        effective_state="other"
        ;;
      -C)
        case "${tokens[index + 1]:-}" in
          linker-features=-lld) effective_state="disabled" ;;
          linker-features=*) effective_state="other" ;;
        esac
        ;;
    esac
  done
  [[ "$effective_state" == "disabled" ]]
}

command_has_dual_encoded_rustflags_clear() {
  local command="$1"
  local client_prefix
  local remote_suffix
  local remote_prefix

  [[ "$command" == *"rch exec --"* ]] || return 1
  client_prefix="${command%%rch exec --*}"
  remote_suffix="${command#*rch exec --}"
  remote_prefix="${remote_suffix%%cargo *}"
  [[ "$client_prefix" == *"env -u CARGO_ENCODED_RUSTFLAGS"* ]] &&
    [[ "$remote_prefix" == *"env -u CARGO_ENCODED_RUSTFLAGS"* ]]
}

emit_logical_source_records() {
  local source="$1"

  if [[ "$source" == *.json ]]; then
    jq -r '.. | strings' "$source"
  else
    awk '
      function append(part) {
        if (buffer == "") buffer = part
        else buffer = buffer " " part
      }
      {
        line = $0
        sub(/\r$/, "", line)
        if (line ~ /\\[[:space:]]*$/) {
          sub(/\\[[:space:]]*$/, "", line)
          append(line)
          next
        }
        if (buffer != "") {
          append(line)
          print buffer
          buffer = ""
        } else {
          print line
        }
      }
      END { if (buffer != "") print buffer }
    ' "$source"
  fi
}

validate_heavy_cargo_command_shape() {
  local line
  local source
  local rustflags_value

  for source in "$runbook_path" "$contract_path" "$predictive_doc_path" "$predictive_contract_path"; do
    [[ -f "$source" ]] || continue
    while IFS= read -r line; do
      if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
        if [[ "$line" != *"rch exec -- env"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
          record_failure "bare or non-target-dir heavy cargo command in ${source}: ${line}"
        elif ! command_has_dual_encoded_rustflags_clear "$line"; then
          record_failure "heavy cargo command lacks client/worker CARGO_ENCODED_RUSTFLAGS clears in ${source}: ${line}"
        elif has_env_assignment "$line" "CARGO_ENCODED_RUSTFLAGS"; then
          record_failure "unsupported CARGO_ENCODED_RUSTFLAGS override in ${source}: ${line}"
        elif has_env_assignment "$line" "RUSTFLAGS"; then
          rustflags_value="$(extract_env_assignment_value "$line" "RUSTFLAGS")"
          if ! rustflags_value_has_effective_linker_policy "$rustflags_value"; then
            record_failure "uncomposed RUSTFLAGS override in ${source}: ${line}"
          else
            record_pass "heavy cargo command is rch-target-dir wrapped and linker-policy-safe in ${source}"
          fi
        else
          record_pass "heavy cargo command is rch-target-dir wrapped and linker-policy-safe in ${source}"
        fi
      fi
    done < <(emit_logical_source_records "$source")
  done
}

validate_all() {
  validation_failures=0
  validate_required_paths
  validate_runbook_references
  validate_contract_surface
  validate_predictive_contract_surface
  validate_predictive_doc_claims
  validate_heavy_cargo_command_shape

  if (( validation_failures > 0 )); then
    return 1
  fi
}

validate_runbook_fixture() {
  local runbook_path="$1"
  validate_all
}

validate_contract_fixture() {
  local contract_path="$1"
  validate_all
}

validate_predictive_contract_fixture() {
  local predictive_contract_path="$1"
  validate_all
}

# linker-policy-negative-fixtures-begin: documentation mutation probes
run_selftest() {
  local tmp_dir
  local bad_runbook
  local bad_linker_only_runbook
  local bad_uncomposed_runbook
  local bad_substring_bypass_runbook
  local bad_encoded_override_runbook
  local bad_later_reenable_runbook
  local bad_multiline_override_runbook
  local good_two_token_runbook
  local bad_contract
  local bad_predictive_contract
  local bad_predictive_sections
  local current_predictive_contract

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-validation-docs-truth.XXXXXX")"
  bad_runbook="${tmp_dir}/bad-runbook.md"
  bad_linker_only_runbook="${tmp_dir}/bad-linker-only-runbook.md"
  bad_uncomposed_runbook="${tmp_dir}/bad-uncomposed-runbook.md"
  bad_substring_bypass_runbook="${tmp_dir}/bad-substring-bypass-runbook.md"
  bad_encoded_override_runbook="${tmp_dir}/bad-encoded-override-runbook.md"
  bad_later_reenable_runbook="${tmp_dir}/bad-later-reenable-runbook.md"
  bad_multiline_override_runbook="${tmp_dir}/bad-multiline-override-runbook.md"
  good_two_token_runbook="${tmp_dir}/good-two-token-runbook.md"
  bad_contract="${tmp_dir}/bad-contract.json"
  bad_predictive_contract="${tmp_dir}/bad-predictive-contract.json"
  bad_predictive_sections="${tmp_dir}/bad-predictive-sections.json"
  current_predictive_contract="$predictive_contract_path"

  cp "$runbook_path" "$bad_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'cargo test -p frankenengine-engine --lib' '```' >>"$bad_runbook"
  if (validate_runbook_fixture "$bad_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected bare cargo example rejection"
  else
    record_pass "selftest rejects bare cargo example"
  fi

  cp "$runbook_path" "$bad_linker_only_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad RUSTFLAGS=-Clinker=cc cargo test -p frankenengine-engine --lib' '```' >>"$bad_linker_only_runbook"
  if (validate_runbook_fixture "$bad_linker_only_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected linker-only RUSTFLAGS rejection"
  else
    record_pass "selftest rejects linker-only RUSTFLAGS override"
  fi

  cp "$runbook_path" "$bad_uncomposed_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad RUSTFLAGS=-Cdebuginfo=0 cargo test -p frankenengine-engine --lib' '```' >>"$bad_uncomposed_runbook"
  if (validate_runbook_fixture "$bad_uncomposed_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected uncomposed custom RUSTFLAGS rejection"
  else
    record_pass "selftest rejects uncomposed custom RUSTFLAGS override"
  fi

  cp "$runbook_path" "$bad_substring_bypass_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad RUSTFLAGS=-Cdebuginfo=0\ -Clinker-features=-lldevil cargo test -p frankenengine-engine --lib' '```' >>"$bad_substring_bypass_runbook"
  if (validate_runbook_fixture "$bad_substring_bypass_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected RUSTFLAGS linker-token substring bypass rejection"
  else
    record_pass "selftest rejects RUSTFLAGS linker-token substring bypass"
  fi

  cp "$runbook_path" "$bad_encoded_override_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad CARGO_ENCODED_RUSTFLAGS=-Clinker-features=-lld cargo test -p frankenengine-engine --lib' '```' >>"$bad_encoded_override_runbook"
  if (validate_runbook_fixture "$bad_encoded_override_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected encoded RUSTFLAGS override rejection"
  else
    record_pass "selftest rejects encoded RUSTFLAGS override"
  fi

  cp "$runbook_path" "$bad_later_reenable_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad RUSTFLAGS=-Clinker-features=-lld\ -Clinker-features=+lld cargo test -p frankenengine-engine --lib' '```' >>"$bad_later_reenable_runbook"
  if (validate_runbook_fixture "$bad_later_reenable_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected later linker-feature re-enable rejection"
  else
    record_pass "selftest rejects later linker-feature re-enable"
  fi

  cp "$runbook_path" "$bad_multiline_override_runbook"
  printf '\n```bash\nenv -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS \\\nCARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bad RUSTFLAGS=-Cdebuginfo=0 \\\ncargo test -p frankenengine-engine --lib\n```\n' >>"$bad_multiline_override_runbook"
  if (validate_runbook_fixture "$bad_multiline_override_runbook") >/dev/null 2>&1; then
    record_failure "selftest expected multiline uncomposed RUSTFLAGS rejection"
  else
    record_pass "selftest rejects multiline uncomposed RUSTFLAGS override"
  fi

  cp "$runbook_path" "$good_two_token_runbook"
  printf "\n%s\n%s\n%s\n" '```bash' 'env -u CARGO_ENCODED_RUSTFLAGS rch exec -- env -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_good RUSTFLAGS=-Cdebuginfo=0\ -C\ linker-features=-lld cargo test -p frankenengine-engine --lib' '```' >>"$good_two_token_runbook"
  if (validate_runbook_fixture "$good_two_token_runbook") >/dev/null 2>&1; then
    record_pass "selftest accepts two-token linker policy"
  else
    record_failure "selftest rejected two-token linker policy"
  fi

  jq '.workload_surfaces |= map(select(.surface_id != "operator_runbook_truth_gate"))' "$contract_path" >"$bad_contract"
  if (validate_contract_fixture "$bad_contract") >/dev/null 2>&1; then
    record_failure "selftest expected missing contract surface rejection"
  else
    record_pass "selftest rejects missing contract surface"
  fi

  jq '.renderer.shipped_in_franken_engine = true | .renderer.local_renderer = true' "$predictive_contract_path" >"$bad_predictive_contract"
  if (validate_predictive_contract_fixture "$bad_predictive_contract") >/dev/null 2>&1; then
    record_failure "selftest expected shipped predictive renderer rejection"
  else
    record_pass "selftest rejects shipped predictive renderer claim"
  fi

  jq '(.input_snapshot_contracts |= map(select(. != "franken-engine.swarm-resource-lease-plan.v1"))) | (.required_dashboard_fields |= map(select(. != "predictive_dashboard.resource_leases.lease_decision")))' \
    "$current_predictive_contract" >"$bad_predictive_sections"
  if (validate_predictive_contract_fixture "$bad_predictive_sections") >/dev/null 2>&1; then
    record_failure "selftest expected missing admission dashboard section rejection"
  else
    record_pass "selftest rejects missing admission dashboard section"
  fi
}
# linker-policy-negative-fixtures-end

case "${1:-check}" in
  check)
    validate_all
    ;;
  selftest)
    validate_all
    run_selftest
    ;;
  *)
    echo "usage: $0 [check|selftest]" >&2
    exit 64
    ;;
esac

if (( validation_failures > 0 )); then
  exit 1
fi
