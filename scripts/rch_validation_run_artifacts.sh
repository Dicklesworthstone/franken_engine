#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight_json="${root_dir}/docs/rch_validation_preflight_contract_v1.json"
classifier_json="${root_dir}/docs/rch_validation_remote_proof_classifier_v1.json"
output_dir=""
case_id="remote-cargo-check-pass"
bead_id="bd-wwfiw"
parent_bead_id="bd-zk8ji"
thread_id="rch-validation-control-plane"
generated_at="${RCH_VALIDATION_RUN_GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

usage() {
  cat <<'USAGE'
usage: scripts/rch_validation_run_artifacts.sh --output-dir DIR [options]

Options:
  --case-id ID              classifier fixture case id
  --preflight-json PATH     input preflight contract JSON
  --classifier-json PATH    input remote-proof classifier JSON
  --bead-id ID              owning bead id
  --parent-bead-id ID       parent bead id
  --thread-id ID            Agent Mail or coordination thread id
  --generated-at UTC        deterministic timestamp for generated artifacts
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --preflight-json)
      preflight_json="${2:-}"
      shift 2
      ;;
    --classifier-json)
      classifier_json="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --parent-bead-id)
      parent_bead_id="${2:-}"
      shift 2
      ;;
    --thread-id)
      thread_id="${2:-}"
      shift 2
      ;;
    --generated-at)
      generated_at="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

if [[ -z "$output_dir" ]]; then
  echo "--output-dir is required" >&2
  usage >&2
  exit 64
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for rch validation run artifacts" >&2
  exit 2
fi

if [[ ! -f "$preflight_json" ]]; then
  echo "preflight contract not found: $preflight_json" >&2
  exit 66
fi

if [[ ! -f "$classifier_json" ]]; then
  echo "remote-proof classifier not found: $classifier_json" >&2
  exit 66
fi

if ! jq -e --arg case_id "$case_id" '.cases[] | select(.case_id == $case_id)' "$classifier_json" >/dev/null; then
  echo "classifier case not found: $case_id" >&2
  exit 65
fi

mkdir -p "$output_dir"

manifest_path="${output_dir}/run_manifest.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
trace_ids_path="${output_dir}/trace_ids.json"
summary_path="${output_dir}/summary.md"

for artifact_path in "$manifest_path" "$events_path" "$commands_path" "$trace_ids_path" "$summary_path"; do
  if [[ -e "$artifact_path" ]]; then
    echo "refusing to overwrite existing artifact: $artifact_path" >&2
    exit 73
  fi
done

jq -n \
  --slurpfile preflight "$preflight_json" \
  --slurpfile classifier "$classifier_json" \
  --arg preflight_path "$preflight_json" \
  --arg classifier_path "$classifier_json" \
  --arg case_id "$case_id" \
  --arg bead_id "$bead_id" \
  --arg parent_bead_id "$parent_bead_id" \
  --arg thread_id "$thread_id" \
  --arg generated_at "$generated_at" '
  def target_path_from_command($cmd):
    ([ $cmd | capture("CARGO_TARGET_DIR=(?<path>[^ ]+)")? | .path ][0] // null);

  def is_heavy_cargo($cmd):
    $cmd | test("(^| )cargo (check|test|clippy|fmt|build|bench|doc)( |$)");

  def safe_validation_command($cmd):
    if ($cmd | startswith("rch exec -- ")) then
      $cmd
    elif is_heavy_cargo($cmd) then
      "rch exec -- env CARGO_TARGET_DIR=/data/tmp/franken_engine-validation CARGO_INCREMENTAL=0 " + $cmd
    else
      $cmd
    end;

  def inferred_components($cmd):
    if ($cmd | test("cargo clippy")) then
      ["cargo", "rustc", "cargo-clippy"]
    elif ($cmd | test("cargo (check|test|fmt|build|bench|doc)")) then
      ["cargo", "rustc"]
    else
      []
    end;

  def command_kind($cmd):
    if ($cmd | test("cargo clippy")) then
      "cargo_clippy"
    elif ($cmd | test("cargo check")) then
      "cargo_check"
    elif ($cmd | test("cargo test")) then
      "cargo_test"
    elif ($cmd | test("cargo fmt")) then
      "cargo_fmt"
    elif ($cmd | test("cargo doc")) then
      "rustdoc"
    else
      "unknown"
    end;

  def operator_category($verdict):
    {
      "source_pass": "source evidence",
      "source_failure": "source failure",
      "toolchain_blocker": "remote toolchain failure",
      "transport_timeout": "remote timeout",
      "local_fallback_refused": "local fallback refusal",
      "missing_remote_proof": "missing proof"
    }[$verdict] // "unknown";

  ($classifier[0].cases[] | select(.case_id == $case_id)) as $case
  | ([ $preflight[0].cases[]
       | select(.case_id == $case_id or .validation_command == $case.validation_command)
     ][0] // null) as $pre
  | (safe_validation_command($case.validation_command)) as $safe_command
  | (command_kind($case.validation_command)) as $command_kind
  | {
      schema_version: "franken-engine.rch-validation-run-manifest.v1",
      bead_id: $bead_id,
      parent_bead_id: $parent_bead_id,
      thread_id: $thread_id,
      case_id: $case.case_id,
      validation_id: ("validation-rch-" + $case.case_id),
      generated_at_utc: $generated_at,
      input_contracts: [
        {
          path: $preflight_path,
          schema_version: $preflight[0].schema_version,
          bead_id: $preflight[0].bead_id
        },
        {
          path: $classifier_path,
          schema_version: $classifier[0].schema_version,
          bead_id: $classifier[0].bead_id
        }
      ],
      preflight_case_id: ($pre.case_id // null),
      selected_worker: $case.selected_worker,
      command_kind: $command_kind,
      remote_command: $case.validation_command,
      safe_validation_command: $safe_command,
      cargo_target_dir_policy: {
        isolated: ($pre.target_dir_policy.isolated // ($case.validation_command | test("CARGO_TARGET_DIR="))),
        path: ($pre.target_dir_policy.path // target_path_from_command($case.validation_command)),
        source: (if $pre.target_dir_policy then "preflight" elif target_path_from_command($case.validation_command) then "classifier_command" else "missing" end)
      },
      required_components: ($pre.required_components // inferred_components($case.validation_command)),
      worker_components: ($pre.worker.components // []),
      worker_capability_snapshot: ($pre.capability_snapshot // null),
      remote_proof: {
        selected_worker: $case.selected_worker,
        remote_command_started: $case.remote_command_started,
        remote_command_finished: $case.remote_command_finished,
        remote_exit_code: $case.remote_exit_code,
        observed_log_markers: $case.observed_log_markers
      },
      verdict: $case.verdict,
      reason_code: $case.reason_code,
      source_evidence: $case.source_evidence,
      operator_category: operator_category($case.verdict),
      remediation: $case.remediation,
      suggested_next_command: $safe_command,
      trace_ids: {
        trace_id: ("trace-rch-validation-" + $case.case_id),
        decision_id: ("decision-rch-validation-" + $case.case_id),
        policy_id: "policy-rch-validation-run-artifacts-v1"
      },
      artifact_paths: {
        run_manifest_json: "run_manifest.json",
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        trace_ids_json: "trace_ids.json",
        summary_md: "summary.md"
      }
    }
' >"$manifest_path"

jq -c '
  {
    schema_version: "franken-engine.rch-validation-run.event.v1",
    trace_id: .trace_ids.trace_id,
    validation_id: .validation_id,
    decision_id: .trace_ids.decision_id,
    policy_id: .trace_ids.policy_id,
    event: "validation_run_classified",
    bead_id: .bead_id,
    parent_bead_id: .parent_bead_id,
    thread_id: .thread_id,
    case_id: .case_id,
    selected_worker: .selected_worker,
    worker_id: (.selected_worker // "none"),
    command_kind: .command_kind,
    verdict: .verdict,
    reason_code: .reason_code,
    source_evidence: .source_evidence,
    operator_category: .operator_category,
    remediation: .remediation,
    suggested_next_command: .suggested_next_command
  }
' "$manifest_path" >"$events_path"

jq '
  {
    schema_version: "franken-engine.rch-validation-run-trace-ids.v1",
    bead_id: .bead_id,
    parent_bead_id: .parent_bead_id,
    thread_id: .thread_id,
    case_id: .case_id,
    validation_id: .validation_id,
    trace_ids: .trace_ids
  }
' "$manifest_path" >"$trace_ids_path"

jq -r '.safe_validation_command' "$manifest_path" >"$commands_path"

jq -r '
  "# RCH Validation Run Summary",
  "",
  ("- Bead: `" + .bead_id + "`"),
  ("- Parent bead: `" + .parent_bead_id + "`"),
  ("- Thread: `" + .thread_id + "`"),
  ("- Case: `" + .case_id + "`"),
  ("- Validation: `" + .validation_id + "`"),
  ("- Selected worker: `" + (.selected_worker // "none") + "`"),
  ("- Command kind: `" + .command_kind + "`"),
  ("- Verdict: `" + .verdict + "`"),
  ("- Reason: `" + .reason_code + "`"),
  ("- Category: `" + .operator_category + "`"),
  ("- Source evidence: `" + (.source_evidence | tostring) + "`"),
  "",
  "## Verdict Taxonomy",
  "",
  "| State | Source evidence | Closeout treatment |",
  "| --- | --- | --- |",
  "| source evidence | yes | cite as validation proof |",
  "| source failure | yes | fix or cite touched-target failure |",
  "| remote toolchain failure | no | cite as worker/toolchain blocker |",
  "| remote timeout | no | split target, salvage artifacts, or rerun narrower |",
  "| local fallback refusal | no | cite remote infrastructure blocker |",
  "| missing proof | no | rerun with preserved `rch exec --` evidence |",
  "",
  "## Evidence",
  "",
  ("Remote command: `" + .remote_command + "`"),
  ("Safe command: `" + .safe_validation_command + "`"),
  ("CARGO_TARGET_DIR: `" + (.cargo_target_dir_policy.path // "missing") + "`"),
  ("Required components: `" + (.required_components | join(", ")) + "`"),
  "",
  "## Operator Action",
  "",
  .remediation,
  "",
  ("Suggested next command: `" + .suggested_next_command + "`")
' "$manifest_path" >"$summary_path"

printf 'rch_validation_run_manifest=%s\n' "$manifest_path"
printf 'rch_validation_events=%s\n' "$events_path"
printf 'rch_validation_commands=%s\n' "$commands_path"
printf 'rch_validation_trace_ids=%s\n' "$trace_ids_path"
printf 'rch_validation_summary=%s\n' "$summary_path"
