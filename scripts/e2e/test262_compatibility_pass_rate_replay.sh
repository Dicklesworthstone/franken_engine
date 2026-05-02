#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARTIFACT="$ROOT_DIR/docs/test262_compatibility_pass_rate_v1.json"
DOC="$ROOT_DIR/docs/TEST262_COMPATIBILITY_POSTURE.md"

if ! command -v jq >/dev/null 2>&1; then
  echo "final_verdict=fail missing jq" >&2
  exit 2
fi

if [[ ! -f "$ARTIFACT" ]]; then
  echo "final_verdict=fail missing_artifact path=$ARTIFACT" >&2
  exit 1
fi

schema="$(jq -r '.schema_version' "$ARTIFACT")"
proof_state="$(jq -r '.proof_state' "$ARTIFACT")"
claim_scope="$(jq -r '.claim_scope' "$ARTIFACT")"
selected_profile="$(jq -r '.selected_profile' "$ARTIFACT")"
vector_source="$(jq -r '.vector_source' "$ARTIFACT")"
runner_command="$(jq -r '.runner_command' "$ARTIFACT")"
denominator="$(jq -r '.denominator' "$ARTIFACT")"
passed="$(jq -r '.passed' "$ARTIFACT")"
failed="$(jq -r '.failed' "$ARTIFACT")"
skipped="$(jq -r '.skipped' "$ARTIFACT")"
waived="$(jq -r '.waived' "$ARTIFACT")"
timed_out="$(jq -r '.timed_out' "$ARTIFACT")"
crashed="$(jq -r '.crashed' "$ARTIFACT")"
blocked_failures="$(jq -r '.blocked_failures' "$ARTIFACT")"
pass_rate_millionths="$(jq -r '.pass_rate_millionths' "$ARTIFACT")"
full_suite_claim_allowed="$(jq -r '.full_suite_claim_allowed' "$ARTIFACT")"

if [[ "$schema" != "franken-engine.test262-compatibility-pass-rate.v1" ]]; then
  echo "final_verdict=fail bad_schema value=$schema" >&2
  exit 1
fi

if (( denominator <= 0 )); then
  echo "final_verdict=fail zero_denominator" >&2
  exit 1
fi

counter_sum=$((passed + failed + skipped + waived + timed_out + crashed))
if (( counter_sum != denominator )); then
  echo "final_verdict=fail count_mismatch denominator=$denominator sum=$counter_sum" >&2
  exit 1
fi

expected_rate=$((passed * 1000000 / denominator))
if (( expected_rate != pass_rate_millionths )); then
  echo "final_verdict=fail bad_pass_rate expected=$expected_rate actual=$pass_rate_millionths" >&2
  exit 1
fi

if [[ "$claim_scope" == "full_official_test262" && "$full_suite_claim_allowed" != "true" ]]; then
  echo "final_verdict=fail illegal_full_suite_claim" >&2
  exit 1
fi

if [[ "$proof_state" != "full_official_suite" && "$full_suite_claim_allowed" == "true" ]]; then
  echo "final_verdict=fail illegal_full_suite_flag proof_state=$proof_state" >&2
  exit 1
fi

if [[ "$proof_state" == "checked_in_vectors_provisional" && "$full_suite_claim_allowed" != "false" ]]; then
  echo "final_verdict=fail checked_in_vectors_must_be_provisional" >&2
  exit 1
fi

echo "runner_command=$runner_command"
echo "selected_profile=$selected_profile"
echo "vector_source=$vector_source"
echo "proof_state=$proof_state"
echo "counts denominator=$denominator passed=$passed failed=$failed skipped=$skipped waived=$waived timed_out=$timed_out crashed=$crashed blocked_failures=$blocked_failures pass_rate_millionths=$pass_rate_millionths"
echo "high_water_comparison=not_applied_checked_in_vectors_do_not_update_full_suite_high_water_mark"
echo "artifact_path=$ARTIFACT"
echo "doc_path=$DOC"
echo "final_verdict=pass provisional_checked_in_vector_pass_rate_published"
