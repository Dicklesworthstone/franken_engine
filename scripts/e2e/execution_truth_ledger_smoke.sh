#!/usr/bin/env bash
# Public adversarial E2E for BRIDGE-00.1.
#
# Exercises the real Rust validator and renderer against the live repository,
# then injects omissions, tamper, a seeded false claim, stale input, malformed
# partial output, ownership conflict, schema drift, tracking drift, and missing
# proof input.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

mode="${1:-run}"
if [[ "$mode" != "run" ]]; then
  echo "usage: $0 [run] [artifact_root]" >&2
  exit 2
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
artifact_root="${2:-artifacts/execution_truth_ledger_e2e/${timestamp}-$$}"
target_dir="${EXECUTION_TRUTH_LEDGER_E2E_CARGO_TARGET_DIR:-/tmp/rch_target_franken_engine_truth_e2e_${timestamp}_$$}"
toolchain="${RUSTUP_TOOLCHAIN:-nightly}"
timeout_seconds="${RCH_EXEC_TIMEOUT_SECONDS:-1200}"
rch_bin="${EXECUTION_TRUTH_LEDGER_RCH_BIN:-rch}"
canonical_ledger="docs/execution_truth_ledger_v1.json"
tool_manifest="tools/execution-truth-ledger/Cargo.toml"
commands_path="${artifact_root}/commands.txt"
events_path="${artifact_root}/events.jsonl"
scenario_root="${artifact_root}/scenarios"
manifest_path="${artifact_root}/run_manifest.json"
run_id="run-execution-truth-ledger-e2e-${timestamp}-$$"
trace_id="trace-execution-truth-ledger-e2e-${timestamp}-$$"
seed=9090
attempt=1
source_cutoff="$(jq -r '.source_cutoff_utc' "$canonical_ledger")"
validation_as_of="$(jq -nr --arg cutoff "$source_cutoff" \
  '$cutoff | fromdateiso8601 + 3600 | todateiso8601')"
platform="$(uname -srm 2>/dev/null || printf 'unknown')"
sequence=0
scenario_count=0
failure_count=0

mkdir -p "$(dirname "$artifact_root")"
if [[ -e "$artifact_root" ]]; then
  echo "refusing to overwrite existing truth-ledger E2E directory: ${artifact_root}" >&2
  exit 2
fi
mkdir "$artifact_root"
mkdir "$scenario_root"
: >"$commands_path"
: >"$events_path"

run_rch() {
  timeout "$timeout_seconds" \
    "$rch_bin" exec -- env -u CARGO_ENCODED_RUSTFLAGS \
      "RUSTUP_TOOLCHAIN=${toolchain}" \
      "CARGO_TARGET_DIR=${target_dir}" \
      "CARGO_INCREMENTAL=0" \
      "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" \
      "$@"
}

record_rch_command() {
  printf 'timeout %q %q exec -- env -u CARGO_ENCODED_RUSTFLAGS ' \
    "$timeout_seconds" "$rch_bin" >>"$commands_path"
  printf '%q ' \
    "RUSTUP_TOOLCHAIN=${toolchain}" \
    "CARGO_TARGET_DIR=${target_dir}" \
    "CARGO_INCREMENTAL=0" \
    "RUSTFLAGS=-C linker=cc -Clinker-features=-lld" >>"$commands_path"
  printf '%q ' "$@" >>"$commands_path"
  printf '\n' >>"$commands_path"
}

append_event() {
  local scenario="$1"
  local decision="$2"
  local reason="$3"
  local expected_code="${4:-}"
  local observed_exit="${5:-0}"
  sequence=$((sequence + 1))
  jq -nc \
    --arg schema_version "franken-engine.execution-truth-ledger.e2e-event.v1" \
    --arg run_id "$run_id" \
    --arg trace_id "$trace_id" \
    --arg test_id "$scenario" \
    --arg scenario_id "$scenario" \
    --argjson seed "$seed" \
    --argjson attempt "$attempt" \
    --arg source_cutoff "$source_cutoff" \
    --arg platform "$platform" \
    --arg phase "e2e.challenge" \
    --argjson sequence "$sequence" \
    --arg decision "$decision" \
    --arg reason "$reason" \
    --arg expected_code "$expected_code" \
    --argjson observed_exit "$observed_exit" \
    '{
      schema_version:$schema_version,
      run_id:$run_id,
      trace_id:$trace_id,
      test_id:$test_id,
      scenario_id:$scenario_id,
      seed:$seed,
      attempt:$attempt,
      source_cutoff:$source_cutoff,
      platform:$platform,
      phase:$phase,
      sequence:$sequence,
      decision:$decision,
      reason:$reason,
      expected_error_code:(if $expected_code == "" then null else $expected_code end),
      observed_exit:$observed_exit,
      duration_us:0,
      artifact_hashes:{}
    }' >>"$events_path"
}

validate_failure() {
  local scenario="$1"
  local ledger="$2"
  local expected_code="$3"
  local scenario_dir="${scenario_root}/${scenario}"
  local report="${scenario_dir}/report.json"
  local validator_events="${scenario_dir}/validator_events.jsonl"
  local log="${scenario_dir}/stderr.log"
  mkdir -p "$scenario_dir"
  scenario_count=$((scenario_count + 1))
  record_rch_command cargo run --locked --manifest-path "$tool_manifest" -q \
    --bin franken_execution_truth_ledger -- \
    validate \
    --repo-root "$root_dir" \
    --ledger "$ledger" \
    --events "$validator_events" \
    --run-id "$run_id" \
    --trace-id "$trace_id" \
    --scenario-id "$scenario" \
    --seed "$seed" \
    --attempt "$attempt" \
    --as-of "$validation_as_of"
  set +e
  run_rch cargo run --locked --manifest-path "$tool_manifest" -q \
    --bin franken_execution_truth_ledger -- \
    validate \
    --repo-root "$root_dir" \
    --ledger "$ledger" \
    --events "$validator_events" \
    --run-id "$run_id" \
    --trace-id "$trace_id" \
    --scenario-id "$scenario" \
    --seed "$seed" \
    --attempt "$attempt" \
    --as-of "$validation_as_of" \
    >"$report" 2>"$log"
  local observed_exit="$?"
  set -e
  if [[ "$observed_exit" -ne 0 ]] \
    && jq -e --arg code "$expected_code" \
      '.findings | any(.error_code == $code)' "$report" >/dev/null 2>&1; then
    append_event "$scenario" "pass" "validator rejected injected fault with ${expected_code}" "$expected_code" "$observed_exit"
    return 0
  fi
  failure_count=$((failure_count + 1))
  append_event "$scenario" "fail" "expected ${expected_code}, exit=${observed_exit}" "$expected_code" "$observed_exit"
  return 1
}

canonical_gate_dir="${artifact_root}/canonical_gate"
printf 'EXECUTION_TRUTH_LEDGER_CARGO_TARGET_DIR=%s ./scripts/run_execution_truth_ledger_gate.sh check %s\n' \
  "$target_dir" "$canonical_gate_dir" >>"$commands_path"
set +e
EXECUTION_TRUTH_LEDGER_CARGO_TARGET_DIR="$target_dir" \
  ./scripts/run_execution_truth_ledger_gate.sh check "$canonical_gate_dir" \
  >"${artifact_root}/canonical_gate.stdout.log" 2>"${artifact_root}/canonical_gate.stderr.log"
canonical_exit="$?"
set -e
scenario_count=$((scenario_count + 1))
if [[ "$canonical_exit" -eq 0 ]]; then
  append_event "canonical" "pass" "canonical live validation passed" "" "$canonical_exit"
else
  failure_count=$((failure_count + 1))
  append_event "canonical" "fail" "canonical live validation exited ${canonical_exit}" "FE-TRUTH-E2E-1001" "$canonical_exit"
fi

missing_dependency_gate="${artifact_root}/missing_dependency_gate"
printf 'EXECUTION_TRUTH_LEDGER_RCH_BIN=%q ./scripts/run_execution_truth_ledger_gate.sh check %q\n' \
  "franken-truth-ledger-missing-rch" "$missing_dependency_gate" >>"$commands_path"
set +e
EXECUTION_TRUTH_LEDGER_RCH_BIN="franken-truth-ledger-missing-rch" \
  ./scripts/run_execution_truth_ledger_gate.sh check "$missing_dependency_gate" \
  >"${artifact_root}/missing_dependency.stdout.log" \
  2>"${artifact_root}/missing_dependency.stderr.log"
missing_dependency_exit="$?"
set -e
scenario_count=$((scenario_count + 1))
if [[ "$missing_dependency_exit" -ne 0 ]] \
  && jq -s -e 'any(.[]; .error_code == "FE-TRUTH-GATE-1001")' \
    "$missing_dependency_gate/events.jsonl" >/dev/null 2>&1 \
  && [[ "$(jq -r '.verdict' "$missing_dependency_gate/run_manifest.json")" == "fail" ]]; then
  append_event "missing_dependency" "pass" \
    "public gate retained a structured failing bundle when rch was unavailable" \
    "FE-TRUTH-GATE-1001" "$missing_dependency_exit"
else
  failure_count=$((failure_count + 1))
  append_event "missing_dependency" "fail" \
    "missing-rch challenge was not recorded fail-closed" \
    "FE-TRUTH-GATE-1001" "$missing_dependency_exit"
fi

canonical_sha_before="$(sha256sum "$canonical_ledger" | awk '{print $1}')"

missing_subject="${scenario_root}/missing_subject.json"
jq '.subjects |= map(select(.subject_id != "bead:bd-1lsy.7.3"))' \
  "$canonical_ledger" >"$missing_subject"
validate_failure "missing_subject" "$missing_subject" "FE-TRUTH-1004" || true

tampered_hash="${scenario_root}/tampered_hash.json"
jq '(.subjects[].proofs[] | select(.proof_id == "fe-claim-010.denominator")).file_sha256 = ("0" * 64)' \
  "$canonical_ledger" >"$tampered_hash"
validate_failure "tampered_hash" "$tampered_hash" "FE-TRUTH-1014" || true

seeded_false_claim="${scenario_root}/seeded_false_claim.json"
jq '(.subjects[] | select(.subject_id == "claim:FE-CLAIM-010")).claim_posture = "observed"' \
  "$canonical_ledger" >"$seeded_false_claim"
validate_failure "seeded_false_claim" "$seeded_false_claim" "FE-TRUTH-1009" || true

missing_proof="${scenario_root}/missing_proof.json"
jq '(.subjects[].proofs[] | select(.proof_id == "fe-claim-010.denominator")).path = "artifacts/definitely-missing-denominator.json"' \
  "$canonical_ledger" >"$missing_proof"
validate_failure "missing_proof" "$missing_proof" "FE-TRUTH-1011" || true

stale_cutoff="${scenario_root}/stale_cutoff.json"
jq '.source_cutoff_utc = "2020-01-01T00:00:00Z"' \
  "$canonical_ledger" >"$stale_cutoff"
validate_failure "stale_cutoff" "$stale_cutoff" "FE-TRUTH-1018" || true

schema_drift="${scenario_root}/schema_drift.json"
jq '.schema_version = "franken-engine.execution-truth-ledger.v999"' \
  "$canonical_ledger" >"$schema_drift"
validate_failure "schema_drift" "$schema_drift" "FE-TRUTH-1003" || true

ownership_conflict="${scenario_root}/ownership_conflict.json"
jq '(.subjects[] | select(.subject_id == "claim:FE-CLAIM-010")).revalidation.owner_id = ""' \
  "$canonical_ledger" >"$ownership_conflict"
validate_failure "ownership_conflict" "$ownership_conflict" "FE-TRUTH-1006" || true

reordered="${scenario_root}/reordered.json"
jq '.subjects |= reverse' "$canonical_ledger" >"$reordered"
validate_failure "reordered" "$reordered" "FE-TRUTH-1005" || true

duplicate_subject="${scenario_root}/duplicate_subject.json"
jq '.subjects += [.subjects[0]] | .subjects |= sort_by(.subject_id)' \
  "$canonical_ledger" >"$duplicate_subject"
validate_failure "duplicate_subject" "$duplicate_subject" "FE-TRUTH-1005" || true

tracking_drift="${scenario_root}/tracking_drift.json"
jq '(.subjects[].proofs[] | select(.proof_id == "bd-o4cbn.pass1-baseline")).expected_git_tracked = true' \
  "$canonical_ledger" >"$tracking_drift"
validate_failure "tracking_drift" "$tracking_drift" "FE-TRUTH-1017" || true

partial_json="${scenario_root}/partial_output.json"
printf '{"schema_version":"franken-engine.execution-truth-ledger.v1","subjects":[' >"$partial_json"
validate_failure "partial_output" "$partial_json" "FE-TRUTH-1002" || true

unknown_field="${scenario_root}/unknown_field.json"
jq '.silently_ignored_claim = "must fail"' \
  "$canonical_ledger" >"$unknown_field"
validate_failure "unknown_field" "$unknown_field" "FE-TRUTH-1002" || true

symlink_path="${scenario_root}/proof_escape_link"
ln -s /etc/hosts "$symlink_path"
if [[ "$symlink_path" == /* ]]; then
  symlink_relative="${symlink_path#${root_dir}/}"
else
  symlink_relative="${symlink_path#./}"
fi
if [[ "$symlink_relative" == /* || "$symlink_relative" == ../* ]]; then
  failure_count=$((failure_count + 1))
  scenario_count=$((scenario_count + 1))
  append_event "symlink_escape" "fail" \
    "artifact root must be inside repository for symlink escape challenge" \
    "FE-TRUTH-E2E-1004"
else
  symlink_escape="${scenario_root}/symlink_escape.json"
  jq --arg path "$symlink_relative" \
    '(.subjects[].proofs[] | select(.proof_id == "fe-claim-010.denominator")).path = $path' \
    "$canonical_ledger" >"$symlink_escape"
  validate_failure "symlink_escape" "$symlink_escape" "FE-TRUTH-1010" || true
fi

render_one="${artifact_root}/render_one.md"
render_two="${artifact_root}/render_two.md"
record_rch_command cargo run --locked --manifest-path "$tool_manifest" -q \
  --bin franken_execution_truth_ledger -- render \
  --repo-root "$root_dir" --ledger "$canonical_ledger"
record_rch_command cargo run --locked --manifest-path "$tool_manifest" -q \
  --bin franken_execution_truth_ledger -- render \
  --repo-root "$root_dir" --ledger "$canonical_ledger"
set +e
run_rch cargo run --locked --manifest-path "$tool_manifest" -q \
  --bin franken_execution_truth_ledger -- render \
  --repo-root "$root_dir" --ledger "$canonical_ledger" >"$render_one" 2>"${artifact_root}/render_one.stderr.log"
render_one_exit="$?"
run_rch cargo run --locked --manifest-path "$tool_manifest" -q \
  --bin franken_execution_truth_ledger -- render \
  --repo-root "$root_dir" --ledger "$canonical_ledger" >"$render_two" 2>"${artifact_root}/render_two.stderr.log"
render_two_exit="$?"
set -e
scenario_count=$((scenario_count + 1))
if [[ "$render_one_exit" -eq 0 && "$render_two_exit" -eq 0 ]] \
  && cmp -s "$render_one" "$render_two" \
  && cmp -s "$render_one" docs/EXECUTION_TRUTH_LEDGER_V1.md; then
  append_event "clean_regeneration" "pass" "two renders and committed Markdown are byte-identical"
else
  failure_count=$((failure_count + 1))
  append_event "clean_regeneration" "fail" "renderer output drifted" "FE-TRUTH-E2E-1002"
fi

canonical_sha_after="$(sha256sum "$canonical_ledger" | awk '{print $1}')"
scenario_count=$((scenario_count + 1))
if [[ "$canonical_sha_before" == "$canonical_sha_after" ]]; then
  append_event "rollback_preservation" "pass" "adversarial runs left canonical ledger byte-identical"
else
  failure_count=$((failure_count + 1))
  append_event "rollback_preservation" "fail" "canonical ledger changed during challenges" "FE-TRUTH-E2E-1003"
fi

verdict="pass"
if [[ "$failure_count" -ne 0 ]]; then
  verdict="fail"
fi

commands_sha="$(sha256sum "$commands_path" | awk '{print $1}')"
events_sha="$(sha256sum "$events_path" | awk '{print $1}')"
jq -n \
  --arg schema_version "franken-engine.execution-truth-ledger.e2e-manifest.v1" \
  --arg run_id "$run_id" \
  --arg trace_id "$trace_id" \
  --arg verdict "$verdict" \
  --arg source_cutoff "$source_cutoff" \
  --arg validation_as_of "$validation_as_of" \
  --arg target_dir "$target_dir" \
  --arg canonical_sha_before "$canonical_sha_before" \
  --arg canonical_sha_after "$canonical_sha_after" \
  --arg commands_sha "$commands_sha" \
  --arg events_sha "$events_sha" \
  --argjson seed "$seed" \
  --argjson attempt "$attempt" \
  --argjson scenario_count "$scenario_count" \
  --argjson failure_count "$failure_count" \
  '{
    schema_version:$schema_version,
    run_id:$run_id,
    trace_id:$trace_id,
    seed:$seed,
    attempt:$attempt,
    source_cutoff:$source_cutoff,
    validation_as_of:$validation_as_of,
    verdict:$verdict,
    scenario_count:$scenario_count,
    failure_count:$failure_count,
    cargo_target_dir:$target_dir,
    canonical_ledger_sha256:{before:$canonical_sha_before,after:$canonical_sha_after},
    artifact_hashes:{"commands.txt":$commands_sha,"events.jsonl":$events_sha},
    scenarios:[
      "canonical",
      "missing_dependency",
      "missing_subject",
      "tampered_hash",
      "seeded_false_claim",
      "missing_proof",
      "stale_cutoff",
      "schema_drift",
      "ownership_conflict",
      "reordered",
      "duplicate_subject",
      "tracking_drift",
      "partial_output",
      "unknown_field",
      "symlink_escape",
      "clean_regeneration",
      "rollback_preservation"
    ],
    recovery:{
      partial_output:"retained under scenarios/partial_output.json",
      rollback:"canonical tracked files are never written by the validator",
      rerun:"./scripts/e2e/execution_truth_ledger_smoke.sh run"
    },
    owning_bead:"bd-performance-conformance-bridge-tu32j.1.1"
  }' >"$manifest_path"

echo "execution_truth_ledger_e2e_root=${artifact_root}"
echo "execution_truth_ledger_e2e_manifest=${manifest_path}"
echo "execution_truth_ledger_e2e_verdict=${verdict}"

if [[ "$verdict" == "pass" ]]; then
  exit 0
fi
exit 1
