#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root_dir}"
# shellcheck source=scripts/lib/proof_artifact_contract.sh
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

usage() {
  cat >&2 <<'EOF'
Usage: FOCUSED_PROOF_* ./scripts/focused_proof_runner.sh

Required environment:
  FOCUSED_PROOF_BEAD_ID            Bead that owns this proof.
  FOCUSED_PROOF_SUITE              Stable suite id.
  FOCUSED_PROOF_COMMAND            Command to execute.
  FOCUSED_PROOF_CARGO_PACKAGE      Cargo package under proof.
  FOCUSED_PROOF_EXPECTED_TARGETS   Comma-separated target names allowed by this focused proof.
  FOCUSED_PROOF_OBSERVED_TARGETS   Newline-separated rows:
                                   package|kind|target|profile|compiled|linked|dragged_by_csv

Optional environment:
  FOCUSED_PROOF_ARTIFACT_ROOT      Default: artifacts/focused_proof_runner
  FOCUSED_PROOF_RUN_ID             Default: UTC timestamp.
  FOCUSED_PROOF_RUN_DIR            Overrides artifact root/run id.
  FOCUSED_PROOF_WORKER             Worker label for remote/offloaded runs.
  FOCUSED_PROOF_SYNC_ROOTS         Comma-separated synced roots.
  FOCUSED_PROOF_DURATION_MS_OVERRIDE  Deterministic duration override for smoke tests.
EOF
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf 'focused-proof-runner missing required environment: %s\n' "${name}" >&2
    usage
    exit 64
  fi
}

sha256_text() {
  local text="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "${text}" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "${text}" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "${text}" | openssl dgst -sha256 | awk '{print $NF}'
  fi
}

csv_json_array() {
  local csv="${1:-}"
  jq -Rn --arg csv "${csv}" '
    $csv
    | split(",")
    | map(gsub("^\\s+|\\s+$"; ""))
    | map(select(length > 0))
    | sort
    | unique
  '
}

write_observed_targets() {
  local output_path="$1"
  local observed_rows="$2"

  printf '%s\n' "${observed_rows}" \
    | jq -R -s '
      split("\n")
      | map(select(length > 0))
      | map(split("|"))
      | map(
          if length < 6 then
            error("observed target rows require at least 6 pipe-delimited fields")
          else
            {
              package: .[0],
              kind: .[1],
              target: .[2],
              profile: .[3],
              compiled: (.[4] == "true"),
              linked: (.[5] == "true"),
              dragged_by: (
                if (length > 6 and .[6] != "") then
                  (.[6] | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)) | sort | unique)
                else
                  []
                end
              )
            }
          end
        )
      | map(
          if (.package == "" or .kind == "" or .target == "" or .profile == "") then
            error("observed target rows must not contain blank package/kind/target/profile fields")
          elif (.kind | IN("lib", "bin", "test", "bench", "example", "build_script", "dependency") | not) then
            error("unsupported proof target kind: " + .kind)
          elif ((.compiled or .linked) | not) then
            error("observed target rows must be compiled or linked")
          else
            .
          end
        )
      | sort_by(.package, .kind, .target, .profile)
      | unique_by([.package, .kind, .target, .profile])
    ' >"${output_path}"
}

target_counts_json() {
  local targets_path="$1"
  jq '
    map(.kind)
    | group_by(.)
    | map({key: .[0], value: length})
    | from_entries
  ' "${targets_path}"
}

unexpected_targets_json() {
  local targets_path="$1"
  local expected_json="$2"
  jq -n --slurpfile targets "${targets_path}" --argjson expected "${expected_json}" '
    [
      $targets[0][]
      | select((.target as $target | $expected | index($target) | not))
      | "\(.package):\(.kind):\(.target)"
    ]
    | sort
    | unique
  '
}

operator_log_json() {
  local suite="$1"
  local bead_id="$2"
  local cargo_package="$3"
  local compiled_count="$4"
  local linked_count="$5"
  local command_hash="$6"
  local unexpected_json="$7"

  jq -n \
    --arg suite "${suite}" \
    --arg bead_id "${bead_id}" \
    --arg cargo_package "${cargo_package}" \
    --arg compiled_count "${compiled_count}" \
    --arg linked_count "${linked_count}" \
    --arg command_hash "${command_hash}" \
    --argjson unexpected "${unexpected_json}" '
    [
      "proof_cost suite=\($suite) bead=\($bead_id) package=\($cargo_package) compiled=\($compiled_count) linked=\($linked_count) unexpected=\($unexpected | length)",
      "proof_cost command_hash=\($command_hash)"
    ] + ($unexpected | map("proof_cost unexpected_target=\(.)"))
  '
}

require_env FOCUSED_PROOF_BEAD_ID
require_env FOCUSED_PROOF_SUITE
require_env FOCUSED_PROOF_COMMAND
require_env FOCUSED_PROOF_CARGO_PACKAGE
require_env FOCUSED_PROOF_EXPECTED_TARGETS
require_env FOCUSED_PROOF_OBSERVED_TARGETS

artifact_root="${FOCUSED_PROOF_ARTIFACT_ROOT:-artifacts/focused_proof_runner}"
run_id="${FOCUSED_PROOF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${FOCUSED_PROOF_RUN_DIR:-${artifact_root}/${run_id}}"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
source_report_path="${run_dir}/source_report.json"
output_path="${run_dir}/command_output.log"
targets_path="${run_dir}/observed_targets.json"
proof_cost_path="${run_dir}/proof_cost_manifest.json"

mkdir -p "${run_dir}"

expected_json="$(csv_json_array "${FOCUSED_PROOF_EXPECTED_TARGETS}")"
if [[ "$(jq 'length' <<<"${expected_json}")" -eq 0 ]]; then
  printf 'focused-proof-runner expected target list must not be empty\n' >&2
  exit 64
fi

write_observed_targets "${targets_path}" "${FOCUSED_PROOF_OBSERVED_TARGETS}"
if [[ "$(jq 'length' "${targets_path}")" -eq 0 ]]; then
  printf 'focused-proof-runner observed target list must not be empty\n' >&2
  exit 64
fi

redacted_command="$(proof_contract_redact_text "${FOCUSED_PROOF_COMMAND}")"
printf '%s\n' "${redacted_command}" >"${commands_path}"

command_hash="$(sha256_text "${FOCUSED_PROOF_COMMAND}")"
target_counts="$(target_counts_json "${targets_path}")"
unexpected_targets="$(unexpected_targets_json "${targets_path}" "${expected_json}")"
unexpected_count="$(jq 'length' <<<"${unexpected_targets}")"
compiled_count="$(jq '[.[] | select(.compiled)] | length' "${targets_path}")"
linked_count="$(jq '[.[] | select(.linked)] | length' "${targets_path}")"
operator_log="$(operator_log_json \
  "${FOCUSED_PROOF_SUITE}" \
  "${FOCUSED_PROOF_BEAD_ID}" \
  "${FOCUSED_PROOF_CARGO_PACKAGE}" \
  "${compiled_count}" \
  "${linked_count}" \
  "${command_hash}" \
  "${unexpected_targets}")"
manifest_id_input="$(
  jq -c -n \
    --arg bead_id "${FOCUSED_PROOF_BEAD_ID}" \
    --arg suite "${FOCUSED_PROOF_SUITE}" \
    --arg command_hash "${command_hash}" \
    --slurpfile targets "${targets_path}" \
    '{bead_id: $bead_id, focused_suite: $suite, command_hash: $command_hash, observed_targets: $targets[0]}'
)"
manifest_id="proof-cost-$(sha256_text "${manifest_id_input}" | cut -c1-16)"

jq -n \
  --arg schema_version "franken-engine.proof-cost-manifest.v1" \
  --arg manifest_id "${manifest_id}" \
  --arg bead_id "${FOCUSED_PROOF_BEAD_ID}" \
  --arg focused_suite "${FOCUSED_PROOF_SUITE}" \
  --arg command "${redacted_command}" \
  --arg command_hash "${command_hash}" \
  --arg cargo_package "${FOCUSED_PROOF_CARGO_PACKAGE}" \
  --argjson expected_focus_targets "${expected_json}" \
  --slurpfile observed_targets "${targets_path}" \
  --argjson target_counts "${target_counts}" \
  --argjson total_compiled_targets "${compiled_count}" \
  --argjson total_linked_targets "${linked_count}" \
  --argjson unexpected_targets "${unexpected_targets}" \
  --argjson operator_log "${operator_log}" \
  '{
    schema_version: $schema_version,
    manifest_id: $manifest_id,
    bead_id: $bead_id,
    focused_suite: $focused_suite,
    command: $command,
    command_hash: $command_hash,
    cargo_package: $cargo_package,
    expected_focus_targets: $expected_focus_targets,
    observed_targets: $observed_targets[0],
    target_counts: $target_counts,
    total_compiled_targets: $total_compiled_targets,
    total_linked_targets: $total_linked_targets,
    unexpected_targets: $unexpected_targets,
    operator_log: $operator_log
  }' >"${proof_cost_path}"

start_ms="$(date +%s%3N)"
command_exit=0
if bash -lc "${FOCUSED_PROOF_COMMAND}" >"${output_path}" 2>&1; then
  command_exit=0
else
  command_exit=$?
fi
end_ms="$(date +%s%3N)"
duration_ms=$((end_ms - start_ms))
if [[ -n "${FOCUSED_PROOF_DURATION_MS_OVERRIDE:-}" ]]; then
  duration_ms="${FOCUSED_PROOF_DURATION_MS_OVERRIDE}"
fi

status="pass"
failure_reason=""
runner_exit="${command_exit}"
bundle_failure_count="${unexpected_count}"
if [[ "${command_exit}" -ne 0 ]]; then
  status="fail"
  failure_reason="command_exit_${command_exit}"
  bundle_failure_count=$((bundle_failure_count + 1))
elif [[ "${unexpected_count}" -ne 0 ]]; then
  status="fail"
  failure_reason="unexpected_target_fanout"
  runner_exit=42
fi

severity="info"
if [[ "${status}" != "pass" ]]; then
  severity="error"
fi

proof_cost_rel="$(proof_contract_repo_relative_path "${proof_cost_path}")"
output_rel="$(proof_contract_repo_relative_path "${output_path}")"
sync_roots_json="$(csv_json_array "${FOCUSED_PROOF_SYNC_ROOTS:-}")"

jq -nc \
  --arg schema_version "${PROOF_ARTIFACT_EVENT_SCHEMA_VERSION}" \
  --arg event_name "focused_proof_runner.command_executed" \
  --arg severity "${severity}" \
  --arg step_id "${FOCUSED_PROOF_SUITE}" \
  --arg command_id "focused-proof-runner" \
  --arg decision "${status}" \
  --arg failure_reason "${failure_reason}" \
  --arg proof_cost_manifest "${proof_cost_rel}" \
  --arg output_path "${output_rel}" \
  --arg worker "${FOCUSED_PROOF_WORKER:-local}" \
  --argjson exit_code "${command_exit}" \
  --argjson duration_ms "${duration_ms}" \
  --argjson target_counts "${target_counts}" \
  --argjson unexpected_targets "${unexpected_targets}" \
  '{
    schema_version: $schema_version,
    event_name: $event_name,
    severity: $severity,
    step_id: $step_id,
    command_id: $command_id,
    decision: $decision,
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    exit_code: $exit_code,
    duration_ms: $duration_ms,
    worker: $worker,
    target_counts: $target_counts,
    unexpected_targets: $unexpected_targets,
    proof_cost_manifest: $proof_cost_manifest,
    output_path: $output_path
  }' >"${events_path}"

jq -n \
  --arg schema_version "franken-engine.focused-proof-runner-report.v1" \
  --arg status "${status}" \
  --arg bead_id "${FOCUSED_PROOF_BEAD_ID}" \
  --arg suite "${FOCUSED_PROOF_SUITE}" \
  --arg command "${redacted_command}" \
  --arg command_hash "${command_hash}" \
  --arg cargo_package "${FOCUSED_PROOF_CARGO_PACKAGE}" \
  --arg run_dir "$(proof_contract_repo_relative_path "${run_dir}")" \
  --arg proof_cost_manifest "${proof_cost_rel}" \
  --arg output_path "${output_rel}" \
  --arg worker "${FOCUSED_PROOF_WORKER:-local}" \
  --arg failure_reason "${failure_reason}" \
  --argjson exit_code "${command_exit}" \
  --argjson duration_ms "${duration_ms}" \
  --argjson sync_roots "${sync_roots_json}" \
  --argjson expected_targets "${expected_json}" \
  --argjson target_counts "${target_counts}" \
  --argjson unexpected_targets "${unexpected_targets}" \
  '{
    schema_version: $schema_version,
    status: $status,
    bead_id: $bead_id,
    focused_suite: $suite,
    command: $command,
    command_hash: $command_hash,
    cargo_package: $cargo_package,
    worker: $worker,
    duration_ms: $duration_ms,
    sync_roots: $sync_roots,
    command_exit_code: $exit_code,
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    expected_targets: $expected_targets,
    target_counts: $target_counts,
    target_cardinality: ($target_counts | to_entries | map(.value) | add),
    unexpected_targets: $unexpected_targets,
    artifact_paths: {
      run_dir: $run_dir,
      proof_cost_manifest_json: $proof_cost_manifest,
      command_output_log: $output_path
    }
  }' >"${source_report_path}"

proof_contract_write_standard_bundle \
  "${run_dir}" \
  "${FOCUSED_PROOF_SUITE}" \
  "${status}" \
  "./scripts/focused_proof_runner.sh" \
  "${source_report_path}" \
  "${events_path}" \
  "${commands_path}" \
  "${FOCUSED_PROOF_BEAD_ID}" \
  "" \
  "${bundle_failure_count}"

proof_cost_sha256="$(proof_contract_sha256_file "${proof_cost_path}")"
jq \
  --arg proof_cost_path "${proof_cost_rel}" \
  --arg proof_cost_sha256 "${proof_cost_sha256}" \
  '.artifact_paths.proof_cost_manifest_json = $proof_cost_path
   | .generated_artifacts += [
       {path: $proof_cost_path, sha256: $proof_cost_sha256, role: "proof_cost_manifest"}
     ]' \
  "${run_dir}/manifest.json" >"${run_dir}/manifest.json.tmp"
mv "${run_dir}/manifest.json.tmp" "${run_dir}/manifest.json"

{
  printf '\n## Focused Proof Cost\n\n'
  printf -- "- Proof cost manifest: \`%s\`\n" "${proof_cost_rel}"
  printf -- "- Worker: \`%s\`\n" "${FOCUSED_PROOF_WORKER:-local}"
  printf -- "- Target cardinality: \`%s\`\n" "$(jq '.target_cardinality' "${source_report_path}")"
  printf -- "- Unexpected targets: \`%s\`\n" "${unexpected_count}"
} >>"${run_dir}/report.md"

printf 'focused_proof_manifest=%s\n' "${run_dir}/manifest.json"
printf 'proof_cost_manifest=%s\n' "${proof_cost_path}"

exit "${runner_exit}"
