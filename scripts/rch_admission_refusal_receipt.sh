#!/usr/bin/env bash
set -euo pipefail

diagnose_json=""
output_dir=""
case_id="manual"
bead_id="unknown"
parent_bead_id="unknown"
thread_id="rch-admission-refusal"
generated_at="${RCH_ADMISSION_REFUSAL_GENERATED_AT:-1970-01-01T00:00:00Z}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_admission_refusal_receipt.sh --diagnose-json FILE --output-dir DIR [OPTIONS]

Normalizes `rch diagnose --dry-run --json` outputs where the command would be
intercepted but no worker is admissible. The normalizer reads fixtures or saved
dry-run JSON only. It never runs cargo, rch, br, git, or worker mutations.

Required:
  --diagnose-json FILE      Saved `rch diagnose --dry-run --json` output.
  --output-dir DIR          Fresh artifact directory.

Optional:
  --case-id ID
  --bead-id ID
  --parent-bead-id ID
  --thread-id ID
  --generated-at UTC        Defaults to 1970-01-01T00:00:00Z for deterministic tests.

Artifacts:
  rch_admission_refusal_receipt.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   admission refusal receipt emitted
  42  dry-run JSON did not describe a no-admissible-worker refusal
  64  usage or input error
  73  output artifact already exists
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --diagnose-json)
      diagnose_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$diagnose_json" || -z "$output_dir" ]]; then
  printf 'rch admission refusal receipt requires --diagnose-json and --output-dir\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for rch admission refusal receipt\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for rch admission refusal receipt\n' >&2
  exit 2
fi
if [[ ! -f "$diagnose_json" ]]; then
  printf 'diagnose JSON not found: %s\n' "$diagnose_json" >&2
  exit 64
fi
if ! jq empty "$diagnose_json" >/dev/null 2>&1; then
  printf 'diagnose JSON is invalid: %s\n' "$diagnose_json" >&2
  exit 64
fi

mkdir -p "$output_dir"
receipt_path="${output_dir}/rch_admission_refusal_receipt.json"
events_path="${output_dir}/events.jsonl"
commands_path="${output_dir}/commands.txt"
report_path="${output_dir}/report.md"

for artifact_path in "$receipt_path" "$events_path" "$commands_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

input_hash="$(jq -cS . "$diagnose_json" | sha256sum | awk '{print $1}')"
receipt_id="rch-admission-refusal-${input_hash:0:16}"

printf './scripts/rch_admission_refusal_receipt.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -n \
  --slurpfile input "$diagnose_json" \
  --arg schema_version "franken-engine.rch-admission-refusal-receipt.v1" \
  --arg receipt_id "$receipt_id" \
  --arg input_hash "$input_hash" \
  --arg case_id "$case_id" \
  --arg bead_id "$bead_id" \
  --arg parent_bead_id "$parent_bead_id" \
  --arg thread_id "$thread_id" \
  --arg generated_at "$generated_at" '
  def reason_count_text($d):
    if (($d.worker_selection.reason.no_admissible_workers // "") != "") then
      $d.worker_selection.reason.no_admissible_workers
    else
      (try (($d.dry_run.reason // "") | capture("no admissible workers: (?<counts>.*)$").counts) catch "")
    end;

  def parse_counts($text):
    reduce (($text // "") | split(",")[]?) as $part ({};
      (try ($part | capture("^\\s*(?<key>[^=, ]+)=(?<value>[0-9]+)\\s*$")) catch null) as $match
      | if $match == null then . else .[$match.key] = ($match.value | tonumber) end
    );

  def target_dir($cmd):
    try ($cmd | capture("CARGO_TARGET_DIR=(?<path>[^ ]+)").path) catch null;

  def worker_rows($d):
    [($d.worker_selection.diagnostics.workers // [])[]?
     | {
         worker_id: (.worker_id // "unknown"),
         status: (.status // null),
         circuit_state: (.circuit_state // null),
         pressure_state: (.pressure_state // null),
         pressure_reason_code: (.pressure_reason_code // null),
         success_rate: (.success_rate // null),
         runtime_available: (.runtime_available // null),
         available_slots: (.available_slots // null),
         total_slots: (.total_slots // null),
         active_project_excluded: ((.active_project_excluded // false) == true),
         final_decision: (.final_decision // null),
         final_reason: (.final_reason // null),
         reason_codes: ((.reason_codes // []) | sort)
       }]
    | sort_by(.worker_id);

  def reason_code_counts($workers):
    reduce ($workers[]?.reason_codes[]?) as $code ({}; .[$code] = ((.[$code] // 0) + 1));

  def active_project_workers($workers):
    [$workers[]? | select(.active_project_excluded == true) | .worker_id] | sort;

  def count_present($counts; $key): (($counts[$key] // 0) > 0);
  def operator_category($counts; $would_intercept; $would_offload; $reason_code):
    if ($would_intercept | not) then "not_interceptable"
    elif $would_offload then "admissible"
    elif $reason_code != "no_admissible_workers" then "other_dry_run_refusal"
    else
      ([count_present($counts; "active_project_exclusion"),
        count_present($counts; "critical_pressure"),
        count_present($counts; "health_below_fallback"),
        count_present($counts; "hard_preflight")]
       | map(select(. == true))
       | length) as $category_count
      | if $category_count > 1 then "mixed_no_admissible_workers"
        elif count_present($counts; "active_project_exclusion") then "wait_for_active_project"
        elif (count_present($counts; "critical_pressure") or count_present($counts; "health_below_fallback")) then "worker_health_or_capacity"
        elif count_present($counts; "hard_preflight") then "worker_preflight_or_toolchain"
        else "mixed_no_admissible_workers"
        end
    end;

  def next_action($category):
    {
      "admissible": "worker is admissible; use the normal rch exec validation path instead of an admission-refusal receipt",
      "not_interceptable": "fix command shape or classification before attempting heavy validation",
      "wait_for_active_project": "wait for the active project build to clear, then rerun rch diagnose before rch exec",
      "worker_health_or_capacity": "wait for worker health/capacity to recover or route to a healthy worker, then rerun rch diagnose before rch exec",
      "worker_preflight_or_toolchain": "repair worker preflight/toolchain blockers if owned, then rerun rch diagnose before rch exec",
      "mixed_no_admissible_workers": "wait for active project exclusion and worker pressure to clear, repair hard-preflight/toolchain blockers if owned, then rerun rch diagnose before rch exec",
      "other_dry_run_refusal": "preserve the dry-run JSON and classify the refusal before launching rch exec"
    }[$category];

  ($input[0]) as $root
  | ($root.data // {}) as $d
  | (($d.command // "") | tostring) as $command
  | (($d.normalized_command // "") | tostring) as $normalized_command
  | (($d.decision.would_intercept // false) == true) as $would_intercept
  | (($d.dry_run.would_offload // false) == true) as $would_offload
  | (reason_count_text($d)) as $reason_text
  | ({
      critical_pressure: 0,
      health_below_fallback: 0,
      hard_preflight: 0,
      active_project_exclusion: 0
    } + parse_counts($reason_text)) as $reason_counts
  | (worker_rows($d)) as $workers
  | (if $would_intercept and ($would_offload | not) and (($reason_text != "") or (($d.dry_run.reason // "") | contains("no admissible workers"))) then
       "admission_refused"
     elif $would_offload then
       "admissible"
     else
       "not_admission_refusal"
     end) as $final_verdict
  | (if $final_verdict == "admission_refused" then "no_admissible_workers"
     elif $final_verdict == "admissible" then "worker_admissible"
     else "diagnose_not_interceptable"
     end) as $reason_code
  | (operator_category($reason_counts; $would_intercept; $would_offload; $reason_code)) as $category
  | {
      schema_version: $schema_version,
      receipt_id: $receipt_id,
      input_sha256: $input_hash,
      case_id: $case_id,
      bead_id: $bead_id,
      parent_bead_id: $parent_bead_id,
      thread_id: $thread_id,
      generated_at_utc: $generated_at,
      final_verdict: $final_verdict,
      reason_code: $reason_code,
      source_evidence: false,
      cargo_executed: false,
      command_kind: ($d.classification.kind // "unknown"),
      classification: {
        is_compilation: (($d.classification.is_compilation // false) == true),
        confidence: ($d.classification.confidence // null),
        reason: ($d.classification.reason // null),
        threshold: ($d.threshold.value // null)
      },
      commands: {
        diagnose_command: ("rch diagnose --dry-run --json -- " + $command),
        normalized_cargo_command: $normalized_command,
        safe_validation_command: ("rch exec -- " + $command),
        target_dir: target_dir($command)
      },
      decisions: {
        would_intercept: $would_intercept,
        would_offload: $would_offload,
        daemon_status: ($d.daemon.status // null),
        selected_worker: ($d.worker_selection.worker // null)
      },
      refusal: {
        reason_text: $reason_text,
        reason_counts: $reason_counts,
        active_project_exclusion: {
          count: ($d.worker_selection.diagnostics.active_project_exclusion_count // ($reason_counts.active_project_exclusion // 0)),
          workers: active_project_workers($workers)
        },
        worker_denials: $workers,
        denied_reason_counts: reason_code_counts($workers),
        skipped_pipeline_steps: [
          ($d.dry_run.pipeline_steps // [])[]?
          | select((.skipped // false) == true)
          | {
              step: (.step // null),
              name: (.name // null),
              skip_reason: (.skip_reason // null)
            }
        ]
      },
      operator_category: $category,
      next_action: next_action($category),
      artifact_paths: {
        receipt_json: "rch_admission_refusal_receipt.json",
        events_jsonl: "events.jsonl",
        commands_txt: "commands.txt",
        report_md: "report.md"
      }
    }
' >"$receipt_path"

jq -c '
  {
    schema_version: "franken-engine.rch-admission-refusal-receipt.event.v1",
    event: "rch_admission_refusal.normalized",
    receipt_id: .receipt_id,
    case_id: .case_id,
    bead_id: .bead_id,
    final_verdict: .final_verdict,
    reason_code: .reason_code,
    operator_category: .operator_category,
    would_intercept: .decisions.would_intercept,
    would_offload: .decisions.would_offload,
    cargo_executed: .cargo_executed
  }
' "$receipt_path" >"$events_path"

jq -r '
  "# RCH Admission Refusal Receipt",
  "",
  ("- Receipt: `" + .receipt_id + "`"),
  ("- Bead: `" + .bead_id + "`"),
  ("- Case: `" + .case_id + "`"),
  ("- Verdict: `" + .final_verdict + "`"),
  ("- Reason: `" + .reason_code + "`"),
  ("- Operator category: `" + .operator_category + "`"),
  ("- Would intercept: `" + (.decisions.would_intercept | tostring) + "`"),
  ("- Would offload: `" + (.decisions.would_offload | tostring) + "`"),
  ("- Cargo executed: `" + (.cargo_executed | tostring) + "`"),
  "",
  "## Reason Counts",
  "",
  (.refusal.reason_counts | to_entries | sort_by(.key)[]? | ("- `" + .key + "=" + (.value | tostring) + "`")),
  "",
  "## Next Action",
  "",
  .next_action,
  "",
  "## Commands",
  "",
  ("Diagnose command: `" + .commands.diagnose_command + "`"),
  ("Safe validation command: `" + .commands.safe_validation_command + "`")
' "$receipt_path" >"$report_path"

final_verdict="$(jq -r '.final_verdict' "$receipt_path")"
printf 'rch_admission_refusal_receipt=%s\n' "$receipt_path"
printf 'rch_admission_refusal_events=%s\n' "$events_path"
printf 'rch_admission_refusal_commands=%s\n' "$commands_path"
printf 'rch_admission_refusal_report=%s\n' "$report_path"

if [[ "$final_verdict" == "admission_refused" ]]; then
  exit 0
fi
exit 42
