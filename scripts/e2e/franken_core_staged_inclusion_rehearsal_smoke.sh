#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
rehearsal="${root_dir}/scripts/franken_core_staged_inclusion_rehearsal.sh"
contract_json="${root_dir}/docs/franken_core_staged_inclusion_rehearsal_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-staged-inclusion-rehearsal %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-staged-inclusion-rehearsal %s\n' "$1" >&2
  exit 1
}

write_root_manifest() {
  local path="$1"
  local state="$2"
  case "$state" in
    excluded)
      cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
]
exclude = ["crates/franken-core"]
resolver = "2"
EOF
      ;;
    included)
      cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
  "crates/franken-core",
]
resolver = "2"
EOF
      ;;
    ambiguous)
      cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
  "crates/franken-core",
]
exclude = ["crates/franken-core"]
resolver = "2"
EOF
      ;;
  esac
}

write_member_manifest() {
  local path="$1"
  local name="$2"
  mkdir -p "$(dirname "$path")"
  cat >"$path" <<EOF
[package]
name = "${name}"
version = "0.1.0"
edition = "2024"
EOF
}

write_fixture_manifests() {
  local tmpdir="$1"
  local state="$2"
  write_root_manifest "${tmpdir}/Cargo.toml" "$state"
  write_member_manifest "${tmpdir}/crates/franken-engine/Cargo.toml" "frankenengine-engine"
  write_member_manifest "${tmpdir}/crates/franken-core/Cargo.toml" "frankenengine-core"
  cat >>"${tmpdir}/crates/franken-core/Cargo.toml" <<'EOF'

[features]
default = []
asupersync-integration = []
EOF
}

assert_report_shape() {
  local report_path="$1"
  jq -e '
    .schema_version == "franken-engine.franken-core-staged-inclusion-rehearsal-report.v1"
    and (.decision == "pass" or .decision == "fail_closed")
    and .mutates_root_cargo_toml == false
    and .creates_generated_manifest_file == false
    and (.simulated_workspace_patch.add_members | index("crates/franken-core") != null)
    and (.simulated_workspace_patch.remove_exclude | index("crates/franken-core") != null)
    and any(.risks[]; .risk_id == "workspace_membership_blast_radius")
    and any(.risks[]; .risk_id == "feature_propagation")
    and any(.risks[]; .risk_id == "package_name_conflict")
    and any(.risks[]; .risk_id == "rollback_required")
    and any(.validation_gates[]; startswith("rch exec -- env CARGO_TARGET_DIR="))
    and (.rollback_steps | index("restore crates/franken-core in root workspace exclude") != null)
    and (.final_acceptance_inputs | index("docs/franken_core_staged_inclusion_rehearsal_v1.json") != null)
    and .non_mutation_attestation.mutates_root_cargo_toml == false
    and .non_mutation_attestation.runs_cargo == false
    and .non_mutation_attestation.runs_rch == false
  ' "$report_path" >/dev/null || record_failure "report shape ${report_path}"
}

run_live_case() {
  local tmpdir output_dir report_path
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  "$rehearsal" --source-revision "smoke-live" --output-dir "$output_dir" >/dev/null
  report_path="${output_dir}/staged_inclusion_rehearsal.json"
  [[ -f "$report_path" ]] || record_failure "missing live report"
  [[ -f "${output_dir}/simulated_workspace_patch.json" ]] || record_failure "missing live patch"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing live events"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing live commands"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing live markdown"
  assert_report_shape "$report_path"
  jq -e '.decision == "pass" and .simulation_mode == "current" and .root_workspace_state == "excluded_standalone"' "$report_path" >/dev/null \
    || record_failure "live state mismatch"
  jq -e '.mutates_root_cargo_toml == false and .simulated_to.expected_root_workspace_state == "included"' "${output_dir}/simulated_workspace_patch.json" >/dev/null \
    || record_failure "live patch mismatch"
  record_pass "live-current-excluded"
}

run_fixture_case() {
  local case_name="$1"
  local state="$2"
  local simulation_mode="$3"
  local expected_decision="$4"
  local required_reason="$5"
  local tmpdir output_dir status expected_exit report_path

  tmpdir="$(mktemp -d)"
  write_fixture_manifests "$tmpdir" "$state"
  output_dir="${tmpdir}/out"
  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$rehearsal" \
    --root-cargo "${tmpdir}/Cargo.toml" \
    --core-cargo "${tmpdir}/crates/franken-core/Cargo.toml" \
    --simulation-mode "$simulation_mode" \
    --source-revision "smoke-${case_name}" \
    --output-dir "$output_dir" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "${case_name} exit ${status}, expected ${expected_exit}"
  fi

  report_path="${output_dir}/staged_inclusion_rehearsal.json"
  [[ -f "$report_path" ]] || record_failure "missing report ${case_name}"
  [[ -f "${output_dir}/simulated_workspace_patch.json" ]] || record_failure "missing patch ${case_name}"
  assert_report_shape "$report_path"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_path" >/dev/null \
    || record_failure "decision mismatch ${case_name}"
  if [[ -n "$required_reason" ]]; then
    jq -e --arg reason "$required_reason" '.reason_codes | index($reason)' "$report_path" >/dev/null \
      || record_failure "missing reason ${required_reason} ${case_name}"
  fi
  record_pass "$case_name"
}

run_check() {
  jq empty "$contract_json"
  bash -n "$rehearsal" "${BASH_SOURCE[0]}"
  run_live_case
  run_fixture_case "current-excluded-fixture" "excluded" "current" "pass" ""
  run_fixture_case "included-artifact-fixture" "included" "included_artifact" "pass" ""
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_STAGED_INCLUSION_REHEARSAL_V1.md \
    docs/franken_core_staged_inclusion_rehearsal_v1.json \
    scripts/franken_core_staged_inclusion_rehearsal.sh \
    scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh
  record_pass "check"
}

run_negative() {
  run_fixture_case "ambiguous-topology" "ambiguous" "current" "fail_closed" "ambiguous_workspace_topology"
  run_fixture_case "included-in-current-mode" "included" "current" "fail_closed" "ambiguous_workspace_topology"
  run_fixture_case "excluded-in-included-artifact-mode" "excluded" "included_artifact" "fail_closed" "artifact_mode_state_mismatch"
  record_pass "negative"
}

case "$mode" in
  check)
    run_check
    ;;
  negative)
    run_negative
    ;;
  -h|--help|help)
    printf 'Usage: ./scripts/e2e/franken_core_staged_inclusion_rehearsal_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
