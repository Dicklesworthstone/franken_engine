#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
contract_path="${1:-${root_dir}/docs/rch_validation_preflight_contract_v1.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for rch validation preflight contract smoke" >&2
  exit 2
fi

if [[ ! -f "$contract_path" ]]; then
  echo "contract file not found: $contract_path" >&2
  exit 1
fi

jq -e '
  .schema_version == "franken-engine.rch-validation-preflight.v1"
  and .bead_id == "bd-xxi8i"
  and .heavy_command_policy.cargo_requires_rch_exec == true
  and (.cases | length) >= 4
' "$contract_path" >/dev/null

missing_required_fields="$(
  jq -r '
    [
      .cases[]
      | select(
          (
            has("case_id")
            and has("command_kind")
            and has("validation_command")
            and has("worker")
            and (.worker | has("worker_id") and has("host") and has("toolchain") and has("components"))
            and has("required_components")
            and has("target_dir_policy")
            and (.target_dir_policy | has("isolated") and has("path"))
            and has("local_fallback_policy")
            and has("capability_snapshot")
            and (.capability_snapshot | has("captured_at_utc") and has("max_age_seconds") and has("fresh"))
            and has("verdict")
            and has("reason_code")
            and has("operator_guidance")
          ) | not
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$missing_required_fields" ]]; then
  echo "cases missing required fields:" >&2
  echo "$missing_required_fields" >&2
  exit 1
fi

invalid_enums="$(
  jq -r '
    .valid_command_kinds as $command_kinds
    | .valid_verdicts as $verdicts
    | .valid_reason_codes as $reason_codes
    |
    [
      .cases[]
      | select(
          ((.command_kind as $kind | $command_kinds | index($kind)) | not)
          or ((.verdict as $verdict | $verdicts | index($verdict)) | not)
          or ((.reason_code as $reason | $reason_codes | index($reason)) | not)
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$invalid_enums" ]]; then
  echo "cases contain invalid enum values:" >&2
  echo "$invalid_enums" >&2
  exit 1
fi

bare_heavy_commands="$(
  jq -r '
    [
      .cases[]
      | select(
          (.command_kind | startswith("cargo_"))
          and (.validation_command | startswith("rch exec -- ") | not)
          and .reason_code != "bare_cargo_not_allowed"
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$bare_heavy_commands" ]]; then
  echo "heavy cargo cases must use rch exec --:" >&2
  echo "$bare_heavy_commands" >&2
  exit 1
fi

expected_cases="$(
  jq -r '
    [.cases[].case_id] as $case_ids
    |
    [
      "missing-cargo-clippy",
      "remote-cargo-check-pass",
      "stale-worker-capability-snapshot",
      "bare-cargo-command"
    ] as $expected
    | [
        $expected[]
        | select(. as $id | $case_ids | index($id) | not)
      ]
      | join("\n")
  ' "$contract_path"
)"

if [[ -n "$expected_cases" ]]; then
  echo "contract missing expected case ids:" >&2
  echo "$expected_cases" >&2
  exit 1
fi

component_consistency_failures="$(
  jq -r '
    [
      .cases[]
      | select(
          .reason_code == "component_available"
          and ((.required_components - .worker.components) | length != 0)
        )
      | .case_id
    ]
    | join("\n")
  ' "$contract_path"
)"

if [[ -n "$component_consistency_failures" ]]; then
  echo "component_available cases lack required worker components:" >&2
  echo "$component_consistency_failures" >&2
  exit 1
fi

echo "rch validation preflight contract smoke PASS: $contract_path"
