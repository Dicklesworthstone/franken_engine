#!/usr/bin/env bash
set -euo pipefail

artifact_root="${ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-artifact-retrieval-budget-manifest-gate}"
run_id="${ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${ARTIFACT_RETRIEVAL_BUDGET_MANIFEST_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
suite_manifest_json=""
retrieval_manifest_json=""
retrieved_files_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/artifact_retrieval_budget_manifest_gate.sh --suite-manifest-json FILE --retrieval-manifest-json FILE --retrieved-files-json FILE [OPTIONS]

Validate that a remote proof suite declares and retrieves only the minimal
artifact set needed for replay. This gate is deterministic and fixture-driven:
it does not query live rch state or execute proof commands.

Required:
  --suite-manifest-json FILE
  --retrieval-manifest-json FILE
  --retrieved-files-json FILE

Optional:
  --output-dir DIR

Artifacts:
  artifact_retrieval_budget_verdict.json
  artifact_retrieval_budget_summary.md
  commands.txt
  events.jsonl

Exit codes:
  0  manifest and retrieval stay within budget
  42 over-broad retrieval or missing replay-critical artifact
  64 invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --suite-manifest-json)
      suite_manifest_json="${2:-}"
      shift 2
      ;;
    --retrieval-manifest-json)
      retrieval_manifest_json="${2:-}"
      shift 2
      ;;
    --retrieved-files-json)
      retrieved_files_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$suite_manifest_json" || -z "$retrieval_manifest_json" || -z "$retrieved_files_json" ]]; then
  printf 'artifact retrieval budget gate requires --suite-manifest-json, --retrieval-manifest-json, and --retrieved-files-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for artifact retrieval budget validation\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for artifact retrieval budget validation\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
verdict_path="${run_dir}/artifact_retrieval_budget_verdict.json"
verdict_tmp="${verdict_path}.tmp"
summary_path="${run_dir}/artifact_retrieval_budget_summary.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
suite_manifest_normalized="${run_dir}/suite_manifest.normalized.json"
retrieval_manifest_normalized="${run_dir}/retrieval_manifest.normalized.json"
retrieved_files_normalized="${run_dir}/retrieved_files.normalized.json"
verdict_core="${run_dir}/verdict_core.json"
: >"$events_path"

printf './scripts/artifact_retrieval_budget_manifest_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg event "$1" \
    --arg detail "$2" \
    '{event: $event, detail: $detail}' >>"$events_path"
}

json_input() {
  local path="$1"
  local label="$2"

  if [[ ! -f "$path" ]]; then
    printf 'artifact retrieval budget gate missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'artifact retrieval budget gate invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

json_input "$suite_manifest_json" "suite manifest"
json_input "$retrieval_manifest_json" "retrieval manifest"
json_input "$retrieved_files_json" "retrieved files"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    suite_id: (.suite_id // .component // .suite // "unknown"),
    artifacts: (
      (.artifacts // .artifact_paths // {})
      | to_entries
      | map(select((.value | type) == "string"))
      | map(.value | tostring)
      | unique
      | sort
    )
  }
' "$suite_manifest_json" >"$suite_manifest_normalized"
write_event "suite_manifest_loaded" "normalized suite manifest"

jq -cS '
  {
    schema_version: (.schema_version // "unknown"),
    suite_id: (.suite_id // .component // .suite // "unknown"),
    declared_artifacts: (
      (.declared_artifacts // .retrieval_paths // .artifacts // [])
      | if type == "array" then map(tostring) | unique | sort else [] end
    ),
    replay_critical_artifacts: (
      (.replay_critical_artifacts // .required_artifacts // [])
      | if type == "array" then map(tostring) | unique | sort else [] end
    )
  }
' "$retrieval_manifest_json" >"$retrieval_manifest_normalized"
write_event "retrieval_manifest_loaded" "normalized retrieval manifest"

jq -cS '
  {
    retrieved_artifacts: (
      if type == "array" then
        map(tostring) | unique | sort
      else
        (.retrieved_artifacts // .paths // [])
        | if type == "array" then map(tostring) | unique | sort else [] end
      end
    )
  }
' "$retrieved_files_json" >"$retrieved_files_normalized"
write_event "retrieved_files_loaded" "normalized retrieved file set"

jq -n \
  --slurpfile suite "$suite_manifest_normalized" \
  --slurpfile retrieval "$retrieval_manifest_normalized" \
  --slurpfile retrieved "$retrieved_files_normalized" '
  def broad_path($path):
    ($path | test("(^|/)(target|\\.rch-target|rch_target|tmp/rch_target)($|/|\\*)"))
    or ($path | test("/\\*\\*$"))
    or ($path | test("(^|/)[*]$"));
  ($suite[0]) as $suite
  | ($retrieval[0]) as $retrieval
  | ($retrieved[0]) as $retrieved
  | ($retrieval.declared_artifacts // []) as $declared
  | ($retrieval.replay_critical_artifacts // []) as $critical
  | ($retrieved.retrieved_artifacts // []) as $actual
  | (($declared - ($suite.artifacts // [])) | unique | sort) as $undeclared_by_suite
  | (($actual - $declared) | unique | sort) as $over_budget_retrievals
  | (($critical - $actual) | unique | sort) as $missing_critical
  | (($declared | map(select(broad_path(.)))) | unique | sort) as $broad_declared
  | (($actual | map(select(broad_path(.)))) | unique | sort) as $broad_actual
  | (
      if (($broad_declared | length) > 0) or (($broad_actual | length) > 0) then
        {
          budget_verdict: "fail_closed",
          exit_code: 42,
          reason: "target-dir or wildcard retrieval exceeds the declared artifact budget"
        }
      elif (($missing_critical | length) > 0) then
        {
          budget_verdict: "fail_closed",
          exit_code: 42,
          reason: "replay-critical artifact is missing from the retrieved file set"
        }
      elif (($over_budget_retrievals | length) > 0) then
        {
          budget_verdict: "fail_closed",
          exit_code: 42,
          reason: "retrieved file set exceeds the declared artifact budget"
        }
      elif (($undeclared_by_suite | length) > 0) then
        {
          budget_verdict: "fail_closed",
          exit_code: 42,
          reason: "retrieval manifest declares artifacts absent from the suite manifest"
        }
      else
        {
          budget_verdict: "pass",
          exit_code: 0,
          reason: "declared retrieval budget matches the replay-critical artifact set"
        }
      end
    ) as $decision
  | {
      schema_version: "franken-engine.artifact-retrieval-budget-manifest-gate.v1",
      suite_id: ($suite.suite_id // "unknown"),
      suite_manifest_artifacts: ($suite.artifacts // []),
      declared_artifacts: $declared,
      replay_critical_artifacts: $critical,
      retrieved_artifacts: $actual,
      undeclared_by_suite: $undeclared_by_suite,
      over_budget_retrievals: $over_budget_retrievals,
      missing_replay_critical_artifacts: $missing_critical,
      broad_declared_artifacts: $broad_declared,
      broad_retrieved_artifacts: $broad_actual,
      budget_verdict: $decision.budget_verdict,
      reason: $decision.reason,
      exit_code: $decision.exit_code
    }
' >"$verdict_core"

input_hash="$(
  jq -n \
    --slurpfile suite "$suite_manifest_normalized" \
    --slurpfile retrieval "$retrieval_manifest_normalized" \
    --slurpfile retrieved "$retrieved_files_normalized" '
      {
        suite_manifest: ($suite[0]),
        retrieval_manifest: ($retrieval[0]),
        retrieved_files: ($retrieved[0])
      }
    ' | jq -cS . | sha256sum | awk '{print $1}'
)"
verdict_hash="$(jq -cS . "$verdict_core" | sha256sum | awk '{print $1}')"

jq \
  --arg input_hash "$input_hash" \
  --arg verdict_hash "$verdict_hash" \
  --arg verdict_path "$verdict_path" \
  --arg summary_path "$summary_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" '
  . + {
    hash_basis: {
      input_hash: $input_hash,
      verdict_hash: $verdict_hash
    },
    artifact_paths: {
      artifact_retrieval_budget_verdict_json: $verdict_path,
      artifact_retrieval_budget_summary_md: $summary_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path
    }
  }
' "$verdict_core" >"$verdict_tmp"
mv "$verdict_tmp" "$verdict_path"

{
  printf '# Artifact Retrieval Budget Manifest Gate\n\n'
  printf -- '- Verdict: %s\n' "$(jq -r '.budget_verdict' "$verdict_path")"
  printf -- '- Reason: %s\n' "$(jq -r '.reason' "$verdict_path")"
  printf -- '- Suite ID: %s\n' "$(jq -r '.suite_id' "$verdict_path")"
  printf -- '- Declared artifacts: %s\n' "$(jq -r '.declared_artifacts | length' "$verdict_path")"
  printf -- '- Replay-critical artifacts: %s\n' "$(jq -r '.replay_critical_artifacts | length' "$verdict_path")"
  printf -- '- Retrieved artifacts: %s\n' "$(jq -r '.retrieved_artifacts | length' "$verdict_path")"
  printf -- "- Input hash: \`%s\`\n" "$(jq -r '.hash_basis.input_hash' "$verdict_path")"
  printf -- "- Verdict hash: \`%s\`\n" "$(jq -r '.hash_basis.verdict_hash' "$verdict_path")"
  printf '\n## Budget Diagnostics\n\n'
  jq -r '
    (
      [
        "| Field | Count |",
        "| --- | ---: |",
        "| undeclared_by_suite | \(.undeclared_by_suite | length) |",
        "| over_budget_retrievals | \(.over_budget_retrievals | length) |",
        "| missing_replay_critical_artifacts | \(.missing_replay_critical_artifacts | length) |",
        "| broad_declared_artifacts | \(.broad_declared_artifacts | length) |",
        "| broad_retrieved_artifacts | \(.broad_retrieved_artifacts | length) |"
      ]
    ) | join("\n")
  ' "$verdict_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

write_event "budget_verdict_written" "wrote artifact retrieval budget verdict artifacts"

exit "$(jq -r '.exit_code' "$verdict_path")"
