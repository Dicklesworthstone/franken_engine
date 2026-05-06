#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${1:-${root_dir}/docs/rch_validation_remote_proof_classifier_v1.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for rch validation remote-proof classifier smoke" >&2
  exit 2
fi

if [[ ! -f "$contract_path" ]]; then
  echo "classifier contract not found: $contract_path" >&2
  exit 1
fi

jq -e '
  .schema_version == "franken-engine.rch-validation-remote-proof-classifier.v1"
  and .bead_id == "bd-bpoi9"
  and (.cases | length) >= 6
' "$contract_path" >/dev/null

missing_required_fields="$(
  jq -r '
    [
      .cases[]
      | select(
          (
            has("case_id")
            and has("validation_command")
            and has("selected_worker")
            and has("remote_command_started")
            and has("remote_command_finished")
            and has("remote_exit_code")
            and has("observed_log_markers")
            and (.observed_log_markers | type == "array")
            and (.observed_log_markers | length > 0)
            and has("verdict")
            and has("reason_code")
            and has("source_evidence")
            and has("remediation")
          ) | not
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$missing_required_fields" ]]; then
  echo "classifier cases missing required fields:" >&2
  echo "$missing_required_fields" >&2
  exit 1
fi

invalid_enums="$(
  jq -r '
    .valid_verdicts as $verdicts
    | .valid_reason_codes as $reason_codes
    |
    [
      .cases[]
      | select(
          ((.verdict as $verdict | $verdicts | index($verdict)) | not)
          or ((.reason_code as $reason | $reason_codes | index($reason)) | not)
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$invalid_enums" ]]; then
  echo "classifier cases contain invalid enum values:" >&2
  echo "$invalid_enums" >&2
  exit 1
fi

source_evidence_mismatches="$(
  jq -r '
    [
      .cases[]
      | select(
          ((.verdict == "source_pass" or .verdict == "source_failure") and .source_evidence != true)
          or ((.verdict != "source_pass" and .verdict != "source_failure") and .source_evidence != false)
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$source_evidence_mismatches" ]]; then
  echo "source_evidence does not match verdict class:" >&2
  echo "$source_evidence_mismatches" >&2
  exit 1
fi

finished_state_mismatches="$(
  jq -r '
    [
      .cases[]
      | select(
          (.verdict == "source_pass" and (.remote_command_finished != true or .remote_exit_code != 0))
          or (.verdict == "source_failure" and (.remote_command_finished != true or .remote_exit_code == 0))
          or (.verdict == "transport_timeout" and .remote_command_finished != false)
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$finished_state_mismatches" ]]; then
  echo "remote finish/exit state does not match verdict:" >&2
  echo "$finished_state_mismatches" >&2
  exit 1
fi

bare_heavy_without_missing_proof="$(
  jq -r '
    [
      .cases[]
      | select(
          (.validation_command | test("^cargo (check|test|clippy|fmt)( |$)"))
          and .verdict != "missing_remote_proof"
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$bare_heavy_without_missing_proof" ]]; then
  echo "bare heavy cargo commands must classify as missing_remote_proof:" >&2
  echo "$bare_heavy_without_missing_proof" >&2
  exit 1
fi

missing_expected_cases="$(
  jq -r '
    [.cases[].case_id] as $case_ids
    |
    [
      "remote-cargo-check-pass",
      "remote-source-diagnostic",
      "missing-cargo-clippy-before-lint",
      "ssh-timeout-no-final-verdict",
      "local-fallback-refused",
      "missing-worker-or-command-evidence"
    ] as $expected
    | [
        $expected[]
        | select(. as $id | $case_ids | index($id) | not)
      ]
      | join("\n")
  ' "$contract_path"
)"

if [[ -n "$missing_expected_cases" ]]; then
  echo "classifier contract missing expected cases:" >&2
  echo "$missing_expected_cases" >&2
  exit 1
fi

echo "rch validation remote-proof classifier smoke PASS: $contract_path"
