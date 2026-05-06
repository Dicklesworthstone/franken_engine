#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
generator="${root_dir}/scripts/rch_validation_run_artifacts.sh"
contract_path="${root_dir}/docs/rch_validation_run_artifacts_contract_v1.json"
preflight_path="${root_dir}/docs/rch_validation_preflight_contract_v1.json"
classifier_path="${root_dir}/docs/rch_validation_remote_proof_classifier_v1.json"

record_pass() {
  printf 'PASS rch-validation-run-artifacts %s\n' "$1"
}

record_failure() {
  printf 'FAIL rch-validation-run-artifacts %s\n' "$1" >&2
}

require_jq() {
  if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required for rch validation run artifact smoke" >&2
    exit 2
  fi
}

assert_contract() {
  jq -e '
    .schema_version == "franken-engine.rch-validation-run-artifacts-contract.v1"
    and .bead_id == "bd-wwfiw"
    and .parent_bead_id == "bd-zk8ji"
    and .command_policy.heavy_cargo_commands_require_rch_exec == true
    and .command_policy.overwrite_existing_artifacts == false
    and (.output_artifacts | sort) == ([
      "commands.txt",
      "events.jsonl",
      "run_manifest.json",
      "summary.md",
      "trace_ids.json"
    ] | sort)
    and (.required_verdict_categories | length) == 6
    and (.smoke_modes | sort) == (["check", "replay", "selftest"] | sort)
    and (.required_event_fields | sort) == ([
      "command_kind",
      "reason_code",
      "remediation",
      "trace_id",
      "validation_id",
      "verdict",
      "worker_id"
    ] | sort)
    and (.fixture_case_ids | length) == 6
  ' "$contract_path" >/dev/null
}

assert_manifest() {
  local case_dir="$1"
  local case_id="$2"
  local expected_category="$3"
  local expected_source_evidence="$4"

  test -s "${case_dir}/run_manifest.json"
  test -s "${case_dir}/events.jsonl"
  test -s "${case_dir}/commands.txt"
  test -s "${case_dir}/trace_ids.json"
  test -s "${case_dir}/summary.md"

  jq -e \
    --arg case_id "$case_id" \
    --arg expected_category "$expected_category" \
    --argjson expected_source_evidence "$expected_source_evidence" '
      .schema_version == "franken-engine.rch-validation-run-manifest.v1"
      and .bead_id == "bd-wwfiw"
      and .parent_bead_id == "bd-zk8ji"
      and .thread_id == "rch-validation-control-plane"
      and .case_id == $case_id
      and .validation_id == ("validation-rch-" + $case_id)
      and .operator_category == $expected_category
      and .source_evidence == $expected_source_evidence
      and (.input_contracts | length) == 2
      and (.command_kind | test("^(cargo_check|cargo_test|cargo_clippy)$"))
      and (.remote_command | length) > 0
      and (.safe_validation_command | startswith("rch exec -- "))
      and (.cargo_target_dir_policy | has("isolated") and has("path") and has("source"))
      and (.required_components | type) == "array"
      and (.remote_proof | has("selected_worker") and has("remote_command_started") and has("remote_command_finished") and has("remote_exit_code") and has("observed_log_markers"))
      and (.trace_ids.trace_id | startswith("trace-rch-validation-"))
      and .artifact_paths.run_manifest_json == "run_manifest.json"
      and .artifact_paths.events_jsonl == "events.jsonl"
      and .artifact_paths.commands_txt == "commands.txt"
      and .artifact_paths.trace_ids_json == "trace_ids.json"
      and .artifact_paths.summary_md == "summary.md"
    ' "${case_dir}/run_manifest.json" >/dev/null

  jq -e \
    --arg case_id "$case_id" \
    --arg expected_category "$expected_category" '
      .schema_version == "franken-engine.rch-validation-run.event.v1"
      and .event == "validation_run_classified"
      and .case_id == $case_id
      and .validation_id == ("validation-rch-" + $case_id)
      and (.worker_id | length) > 0
      and (.command_kind | test("^(cargo_check|cargo_test|cargo_clippy)$"))
      and (.verdict | length) > 0
      and (.reason_code | length) > 0
      and (.remediation | length) > 0
      and .operator_category == $expected_category
    ' "${case_dir}/events.jsonl" >/dev/null

  jq -e \
    --arg case_id "$case_id" '
      .schema_version == "franken-engine.rch-validation-run-trace-ids.v1"
      and .case_id == $case_id
      and .validation_id == ("validation-rch-" + $case_id)
      and (.trace_ids.policy_id == "policy-rch-validation-run-artifacts-v1")
    ' "${case_dir}/trace_ids.json" >/dev/null

  if awk '/cargo / && $0 !~ /^rch exec -- / { found=1 } END { exit found ? 0 : 1 }' "${case_dir}/commands.txt"; then
    record_failure "${case_id} commands.txt contains bare cargo"
    cat "${case_dir}/commands.txt" >&2
    exit 1
  fi

  for category in \
    "source evidence" \
    "source failure" \
    "remote toolchain failure" \
    "remote timeout" \
    "local fallback refusal" \
    "missing proof"; do
    if ! grep -Fq "$category" "${case_dir}/summary.md"; then
      record_failure "${case_id} summary missing category: ${category}"
      exit 1
    fi
  done
}

run_case() {
  local tmp_root="$1"
  local case_id="$2"
  local expected_category="$3"
  local expected_source_evidence="$4"
  local case_dir="${tmp_root}/${case_id}"

  bash "$generator" \
    --output-dir "$case_dir" \
    --case-id "$case_id" \
    --generated-at "2026-05-06T00:00:00Z" >/dev/null

  assert_manifest "$case_dir" "$case_id" "$expected_category" "$expected_source_evidence"
  run_replay "$case_dir" >/dev/null
  record_pass "${case_id}"
}

assert_byte_stable() {
  local tmp_root="$1"
  local case_a="${tmp_root}/stable-a"
  local case_b="${tmp_root}/stable-b"

  bash "$generator" \
    --output-dir "$case_a" \
    --case-id "remote-source-diagnostic" \
    --generated-at "2026-05-06T00:00:00Z" >/dev/null

  bash "$generator" \
    --output-dir "$case_b" \
    --case-id "remote-source-diagnostic" \
    --generated-at "2026-05-06T00:00:00Z" >/dev/null

  for artifact in run_manifest.json events.jsonl commands.txt trace_ids.json summary.md; do
    cmp "${case_a}/${artifact}" "${case_b}/${artifact}" >/dev/null
  done

  record_pass "byte-stable repeated fixture"
}

assert_refuses_overwrite() {
  local tmp_root="$1"
  local case_dir="${tmp_root}/overwrite-refusal"
  local actual_exit

  bash "$generator" \
    --output-dir "$case_dir" \
    --case-id "remote-cargo-check-pass" \
    --generated-at "2026-05-06T00:00:00Z" >/dev/null

  set +e
  bash "$generator" \
    --output-dir "$case_dir" \
    --case-id "remote-cargo-check-pass" \
    --generated-at "2026-05-06T00:00:00Z" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -eq 0 ]]; then
    record_failure "generator overwrote existing artifact directory"
    exit 1
  fi

  record_pass "overwrite refusal"
}

run_replay() {
  local bundle_dir="${1:-}"

  require_jq
  if [[ -z "$bundle_dir" ]]; then
    record_failure "replay requires a bundle directory"
    return 64
  fi

  for artifact in run_manifest.json events.jsonl commands.txt trace_ids.json summary.md; do
    if [[ ! -s "${bundle_dir}/${artifact}" ]]; then
      record_failure "replay missing required artifact: ${bundle_dir}/${artifact}"
      return 1
    fi
  done

  jq -e '
    .schema_version == "franken-engine.rch-validation-run-manifest.v1"
    and (.validation_id | startswith("validation-rch-"))
    and (.thread_id | length) > 0
    and (.command_kind | test("^(cargo_check|cargo_test|cargo_clippy)$"))
    and (.remote_proof.observed_log_markers | length) > 0
    and (.verdict | length) > 0
    and (.reason_code | length) > 0
    and (.remediation | length) > 0
    and (.suggested_next_command | startswith("rch exec -- "))
  ' "${bundle_dir}/run_manifest.json" >/dev/null

  jq -e \
    --slurpfile manifest "${bundle_dir}/run_manifest.json" '
      .schema_version == "franken-engine.rch-validation-run.event.v1"
      and .trace_id == $manifest[0].trace_ids.trace_id
      and .validation_id == $manifest[0].validation_id
      and .worker_id == ($manifest[0].selected_worker // "none")
      and .command_kind == $manifest[0].command_kind
      and .verdict == $manifest[0].verdict
      and .reason_code == $manifest[0].reason_code
      and .remediation == $manifest[0].remediation
    ' "${bundle_dir}/events.jsonl" >/dev/null

  jq -e \
    --slurpfile manifest "${bundle_dir}/run_manifest.json" '
      .schema_version == "franken-engine.rch-validation-run-trace-ids.v1"
      and .validation_id == $manifest[0].validation_id
      and .trace_ids.trace_id == $manifest[0].trace_ids.trace_id
    ' "${bundle_dir}/trace_ids.json" >/dev/null

  if awk '/cargo / && $0 !~ /^rch exec -- / { found=1 } END { exit found ? 0 : 1 }' "${bundle_dir}/commands.txt"; then
    record_failure "replay commands.txt contains bare cargo"
    cat "${bundle_dir}/commands.txt" >&2
    return 1
  fi

  for category in \
    "source evidence" \
    "source failure" \
    "remote toolchain failure" \
    "remote timeout" \
    "local fallback refusal" \
    "missing proof"; do
    if ! grep -Fq "$category" "${bundle_dir}/summary.md"; then
      record_failure "replay summary missing category: ${category}"
      return 1
    fi
  done

  record_pass "replay ${bundle_dir}"
}

assert_replay_fails_missing_artifact() {
  local tmp_root="$1"
  local source_dir="${tmp_root}/remote-cargo-check-pass"
  local incomplete_dir="${tmp_root}/missing-artifact-replay"
  local actual_exit

  mkdir -p "$incomplete_dir"
  cp "${source_dir}/run_manifest.json" "${incomplete_dir}/run_manifest.json"

  set +e
  run_replay "$incomplete_dir" >/dev/null 2>&1
  actual_exit=$?
  set -e

  if [[ "$actual_exit" -eq 0 ]]; then
    record_failure "replay accepted a bundle with missing artifacts"
    exit 1
  fi

  record_pass "replay missing artifact fail-closed"
}

run_check() {
  require_jq
  bash -n "$generator"
  bash -n "${BASH_SOURCE[0]}"
  jq empty "$contract_path" "$preflight_path" "$classifier_path" >/dev/null
  assert_contract
  record_pass "syntax and contract"
}

run_selftest() {
  local tmp_parent tmp_root

  run_check
  tmp_parent="${RCH_VALIDATION_RUN_ARTIFACTS_SMOKE_ROOT:-${TMPDIR:-/tmp}}"
  mkdir -p "$tmp_parent"
  tmp_root="$(mktemp -d "${tmp_parent%/}/rch-validation-run-artifacts.XXXXXX")"

  run_case "$tmp_root" "remote-cargo-check-pass" "source evidence" true
  run_case "$tmp_root" "remote-source-diagnostic" "source failure" true
  run_case "$tmp_root" "missing-cargo-clippy-before-lint" "remote toolchain failure" false
  run_case "$tmp_root" "ssh-timeout-no-final-verdict" "remote timeout" false
  run_case "$tmp_root" "local-fallback-refused" "local fallback refusal" false
  run_case "$tmp_root" "missing-worker-or-command-evidence" "missing proof" false
  assert_byte_stable "$tmp_root"
  assert_refuses_overwrite "$tmp_root"
  assert_replay_fails_missing_artifact "$tmp_root"

  printf 'rch_validation_run_artifacts_smoke_artifacts=%s\n' "$tmp_root"
}

mode="${1:-check}"
case "$mode" in
  check)
    run_check
    ;;
  selftest)
    run_selftest
    ;;
  replay)
    shift
    run_replay "${1:-}"
    ;;
  *)
    record_failure "unknown mode: ${mode:-}"
    exit 64
    ;;
esac
