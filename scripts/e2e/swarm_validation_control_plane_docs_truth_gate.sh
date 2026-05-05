#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
default_runbook="${root_dir}/docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
default_contract="${root_dir}/docs/swarm_validation_control_plane_contract_v1.json"
runbook_path="${SWARM_VALIDATION_CONTROL_PLANE_RUNBOOK:-${default_runbook}}"
contract_path="${SWARM_VALIDATION_CONTROL_PLANE_CONTRACT:-${default_contract}}"
validation_failures=0

required_paths=(
  "docs/SWARM_VALIDATION_CONTROL_PLANE_OPERATOR_RUNBOOK.md"
  "docs/swarm_validation_control_plane_contract_v1.json"
  "scripts/e2e/swarm_validation_control_plane_contract_smoke.sh"
  "scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh"
  "scripts/e2e/swarm_validation_control_plane_e2e.sh"
  "scripts/swarm_validation_planner.sh"
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
  "./scripts/swarm_resource_governor.sh"
  "./scripts/swarm_operator_status_report.sh"
  "./scripts/e2e/swarm_validation_control_plane_contract_smoke.sh"
  "./scripts/e2e/swarm_validation_control_plane_docs_truth_gate.sh"
  "./scripts/e2e/swarm_validation_control_plane_e2e.sh"
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
    if ! grep -Fq "$pattern" "$runbook_path"; then
      record_failure "runbook missing required pattern: ${pattern}"
    else
      record_pass "runbook contains ${pattern}"
    fi
  done

  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    check_repo_path_exists "$path"
  done < <(grep -Eo '\./scripts/[A-Za-z0-9_./-]+' "$runbook_path" | sed 's#^\./##' | sort -u)

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

validate_heavy_cargo_command_shape() {
  local line
  local source

  for source in "$runbook_path" "$contract_path"; do
    [[ -f "$source" ]] || continue
    while IFS= read -r line; do
      if [[ "$line" =~ (^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$) ]]; then
        if [[ "$line" != *"rch exec -- env"* || "$line" != *"CARGO_TARGET_DIR="* ]]; then
          record_failure "bare or non-target-dir heavy cargo command in ${source}: ${line}"
        else
          record_pass "heavy cargo command is rch-target-dir wrapped in ${source}"
        fi
      fi
    done < <(
      if [[ "$source" == *.json ]]; then
        jq -r '.. | strings' "$source"
      else
        cat "$source"
      fi
    )
  done
}

validate_all() {
  validation_failures=0
  validate_required_paths
  validate_runbook_references
  validate_contract_surface
  validate_heavy_cargo_command_shape

  if (( validation_failures > 0 )); then
    return 1
  fi
}

run_selftest() {
  local tmp_dir
  local bad_runbook
  local bad_contract

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/swarm-validation-docs-truth.XXXXXX")"
  bad_runbook="${tmp_dir}/bad-runbook.md"
  bad_contract="${tmp_dir}/bad-contract.json"

  cp "$runbook_path" "$bad_runbook"
  printf '\n```bash\ncargo test -p frankenengine-engine --lib\n```\n' >>"$bad_runbook"
  if (runbook_path="$bad_runbook"; validate_all) >/dev/null 2>&1; then
    record_failure "selftest expected bare cargo example rejection"
  else
    record_pass "selftest rejects bare cargo example"
  fi

  jq '.workload_surfaces |= map(select(.surface_id != "operator_runbook_truth_gate"))' "$contract_path" >"$bad_contract"
  if (contract_path="$bad_contract"; validate_all) >/dev/null 2>&1; then
    record_failure "selftest expected missing contract surface rejection"
  else
    record_pass "selftest rejects missing contract surface"
  fi
}

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
