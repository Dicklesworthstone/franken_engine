#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/franken_core_status_truth_gate.sh"
contract_json="${root_dir}/docs/franken_core_status_truth_gate_v1.json"
mode="${1:-check}"

record_pass() {
  printf 'PASS franken-core-status-truth-gate %s\n' "$1"
}

record_failure() {
  printf 'FAIL franken-core-status-truth-gate %s\n' "$1" >&2
  exit 1
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

write_included_root_manifest() {
  local path="$1"
  cat >"$path" <<'EOF'
[workspace]
members = [
  "crates/franken-engine",
  "crates/franken-core",
]
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

assert_report_shape() {
  local report_path="$1"
  jq -e '
    .schema_version == "franken-engine.franken-core-status-truth-report.v1"
    and (.decision == "pass" or .decision == "fail_closed")
    and (.root_workspace_state | type == "string")
    and (.manifest_state.core_manifest_state | type == "string")
    and (.canonical_truth.workspace_graduation_complete == false)
    and (.canonical_truth.workspace_acceptance_required == "bd-4w7h9.8")
    and any(.evidence_beads[]; .bead_id == "bd-ucemx")
    and any(.evidence_beads[]; .bead_id == "bd-zsais")
    and any(.evidence_beads[]; .bead_id == "bd-dymfz")
    and any(.evidence_beads[]; .bead_id == "bd-nwhcp")
    and (.non_mutation_attestation.rewrites_docs == false)
    and (.non_mutation_attestation.edits_manifests == false)
    and (.non_mutation_attestation.runs_cargo == false)
    and (.non_mutation_attestation.runs_rch == false)
  ' "$report_path" >/dev/null || record_failure "report shape ${report_path}"
}

run_live_case() {
  local tmpdir output_dir report_path
  tmpdir="$(mktemp -d)"
  output_dir="${tmpdir}/out"
  "$gate" --source-revision "smoke-live" --output-dir "$output_dir" >/dev/null
  report_path="${output_dir}/truth_report.json"

  [[ -f "$report_path" ]] || record_failure "missing live report"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing live events"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing live commands"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing live markdown"
  assert_report_shape "$report_path"
  jq -e '
    .decision == "pass"
    and .root_workspace_state == "excluded_standalone"
    and .violation_count == 0
  ' "$report_path" >/dev/null || record_failure "live truthful state mismatch"
  record_pass "live-current-truthful-state"
}

run_fixture_case() {
  local case_name="$1"
  local expected_decision="$2"
  local required_reason="$3"
  local root_mode="$4"
  local claim_text="$5"
  local tmpdir root_manifest core_manifest claim_file output_dir status expected_exit report_path

  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/crates/franken-core" "${tmpdir}/docs"
  root_manifest="${tmpdir}/Cargo.toml"
  core_manifest="${tmpdir}/crates/franken-core/Cargo.toml"
  claim_file="${tmpdir}/docs/status.md"
  output_dir="${tmpdir}/out"

  if [[ "$root_mode" == "included" ]]; then
    write_included_root_manifest "$root_manifest"
  else
    write_truthful_root_manifest "$root_manifest"
  fi
  write_core_manifest "$core_manifest"
  printf '%s\n' "$claim_text" >"$claim_file"

  if [[ "$expected_decision" == "fail_closed" ]]; then
    expected_exit=42
  else
    expected_exit=0
  fi

  set +e
  "$gate" \
    --root-cargo "$root_manifest" \
    --core-cargo "$core_manifest" \
    --claim-file "$claim_file" \
    --source-revision "smoke-${case_name}" \
    --output-dir "$output_dir" >/dev/null 2>"${tmpdir}/stderr.log"
  status=$?
  set -e

  if [[ "$status" -ne "$expected_exit" ]]; then
    cat "${tmpdir}/stderr.log" >&2
    record_failure "${case_name} exit ${status}, expected ${expected_exit}"
  fi

  report_path="${output_dir}/truth_report.json"
  [[ -f "$report_path" ]] || record_failure "missing report ${case_name}"
  [[ -f "${output_dir}/events.jsonl" ]] || record_failure "missing events ${case_name}"
  [[ -f "${output_dir}/commands.txt" ]] || record_failure "missing commands ${case_name}"
  [[ -f "${output_dir}/report.md" ]] || record_failure "missing markdown ${case_name}"
  assert_report_shape "$report_path"
  jq -e --arg decision "$expected_decision" '.decision == $decision' "$report_path" >/dev/null \
    || record_failure "decision mismatch ${case_name}"
  if [[ -n "$required_reason" ]]; then
    jq -e --arg code "$required_reason" '.reason_codes | index($code)' "$report_path" >/dev/null \
      || record_failure "missing reason ${required_reason} ${case_name}"
    jq -e --arg code "$required_reason" 'any(.violations[]; .code == $code and (.remediation | length > 0) and (.path | length > 0))' "$report_path" >/dev/null \
      || record_failure "missing remediation ${case_name}"
  fi
  grep -Fq "bd-zsais" "${output_dir}/commands.txt" || record_failure "commands missing superseding bead ${case_name}"
  record_pass "$case_name"
}

run_check() {
  jq empty "$contract_json"
  bash -n "$gate" "${BASH_SOURCE[0]}"
  run_live_case
  run_fixture_case \
    "truthful-fixture" \
    "pass" \
    "" \
    "excluded" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable. The old reference-only state is superseded by bd-zsais, bd-dymfz, and bd-nwhcp. Workspace graduation remains blocked until bd-4w7h9.8 passes."
  git -C "$root_dir" diff --check -- \
    docs/FRANKEN_CORE_STATUS_TRUTH_GATE_V1.md \
    docs/franken_core_status_truth_gate_v1.json \
    scripts/franken_core_status_truth_gate.sh \
    scripts/e2e/franken_core_status_truth_gate_smoke.sh
  record_pass "check"
}

run_negative() {
  run_fixture_case \
    "stale-reference-only-claim" \
    "fail_closed" \
    "stale_reference_only_claim" \
    "excluded" \
    "crates/franken-core is reference-only because required modules are missing."
  run_fixture_case \
    "workspace-inclusion-overclaim" \
    "fail_closed" \
    "workspace_inclusion_overclaim" \
    "excluded" \
    "crates/franken-core is workspace-ready and included in the workspace."
  run_fixture_case \
    "manifest-doc-contradiction" \
    "fail_closed" \
    "root_manifest_state_contradicts_excluded_contract" \
    "included" \
    "crates/franken-core remains excluded from the root workspace, while its standalone manifest is compileable. Workspace graduation remains blocked until bd-4w7h9.8 passes."
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
    printf 'Usage: ./scripts/e2e/franken_core_status_truth_gate_smoke.sh [check|negative]\n'
    ;;
  *)
    printf 'unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac
