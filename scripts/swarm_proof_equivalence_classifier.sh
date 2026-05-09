#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-equivalence-classifier}"
run_id="${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
candidate_json=""
requested_json=""
case_id=""
source_revision="${SWARM_PROOF_EQUIVALENCE_CLASSIFIER_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_equivalence_classifier.sh [OPTIONS]

Compare a candidate proof receipt/request against a requested proof surface and
emit reuse, rerun, refusal, or human-review verdicts. The classifier never runs
Cargo or RCH.

Options:
  --fixture-json FILE     Single fixture case with candidate/requested objects.
  --candidate-json FILE   Existing proof request or receipt to test for reuse.
  --requested-json FILE   Requested proof surface.
  --case-id ID            Deterministic case id.
  --source-revision REV   Source revision recorded in artifacts.
  --output-dir DIR        Artifact directory.

Artifacts:
  equivalence_report.json
  reuse_refusal_receipt.json
  run_manifest.json
  events.jsonl
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixture-json)
      fixture_json="${2:-}"
      shift 2
      ;;
    --candidate-json)
      candidate_json="${2:-}"
      shift 2
      ;;
    --requested-json)
      requested_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof equivalence classification\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof equivalence classification\n' >&2
  exit 2
fi

if [[ -n "$fixture_json" ]]; then
  if [[ ! -f "$fixture_json" ]]; then
    printf 'fixture JSON not found: %s\n' "$fixture_json" >&2
    exit 64
  fi
  if ! jq empty "$fixture_json" >/dev/null 2>&1; then
    printf 'invalid fixture JSON: %s\n' "$fixture_json" >&2
    exit 64
  fi
  if [[ -z "$case_id" ]]; then
    case_id="$(jq -r '.case_id // ""' "$fixture_json")"
  fi
fi
if [[ -z "$case_id" ]]; then
  case_id="manual"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
candidate_path="${run_dir}/candidate_request.json"
requested_path="${run_dir}/requested_request.json"
report_path_json="${run_dir}/equivalence_report.json"
report_tmp="${report_path_json}.tmp"
receipt_path="${run_dir}/reuse_refusal_receipt.json"
receipt_tmp="${receipt_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
core_path="${run_dir}/classifier_core.json"

for artifact_path in \
  "$candidate_path" \
  "$requested_path" \
  "$report_path_json" \
  "$report_tmp" \
  "$receipt_path" \
  "$receipt_tmp" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$commands_path" \
  "$report_md" \
  "$core_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_equivalence_classifier.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-equivalence-classifier.event.v1" \
    --arg component "swarm_proof_equivalence_classifier" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      case_id: $case_id
    }' >>"$events_path"
}

if [[ -n "$fixture_json" ]]; then
  jq -cS '.candidate' "$fixture_json" >"$candidate_path"
  jq -cS '.requested' "$fixture_json" >"$requested_path"
else
  if [[ -z "$candidate_json" || -z "$requested_json" ]]; then
    printf 'candidate and requested JSON are required without --fixture-json\n' >&2
    exit 64
  fi
  for input_path in "$candidate_json" "$requested_json"; do
    if [[ ! -f "$input_path" ]]; then
      printf 'input JSON not found: %s\n' "$input_path" >&2
      exit 64
    fi
    if ! jq empty "$input_path" >/dev/null 2>&1; then
      printf 'invalid input JSON: %s\n' "$input_path" >&2
      exit 64
    fi
  done
  jq -cS . "$candidate_json" >"$candidate_path"
  jq -cS . "$requested_json" >"$requested_path"
fi

write_event "classification.started" "ok" "$case_id"

jq -n \
  --slurpfile candidate "$candidate_path" \
  --slurpfile requested "$requested_path" \
  --arg schema_version "franken-engine.swarm-proof-equivalence-report.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg candidate_path "$candidate_path" \
  --arg requested_path "$requested_path" \
  --arg report_path "$report_path_json" \
  --arg receipt_path "$receipt_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def sorted($v): arr($v) | map(tostring) | sort;
  def command_text($r): (arr($r.normalized_command_argv) | join(" "));
  def shell_wrapper($r): command_text($r) | test("^(bash|sh|zsh) -(lc|c) "; "i");
  def bare_cargo($r): command_text($r) | test("^cargo (check|test|clippy|build|run|bench)"; "i");
  def contaminated($r):
    shell_wrapper($r)
    or bare_cargo($r)
    or (($r.rch_posture // "") == "local_fallback")
    or (($r.local_fallback_observed // false) == true);
  def target_rank($r):
    ($r.target_kind // "unknown") as $kind
    | if $kind == "exact_integration_test" or $kind == "lib_test_filter" then 1
      elif $kind == "package_lib_test" or $kind == "package_check" or $kind == "package_clippy" then 2
      elif $kind == "workspace_all_targets" then 3
      else 0
      end;
  def same($field; $a; $b): (($a[$field] // null) == ($b[$field] // null));
  def same_sorted($field; $a; $b): sorted($a[$field]) == sorted($b[$field]);
  def same_array($field; $a; $b): arr($a[$field]) == arr($b[$field]);
  def identical($a; $b):
    same_array("normalized_command_argv"; $a; $b)
    and same("command_kind"; $a; $b)
    and same("package"; $a; $b)
    and same("target_kind"; $a; $b)
    and same("target_name"; $a; $b)
    and same("test_filter"; $a; $b)
    and same_sorted("feature_flags"; $a; $b)
    and same_sorted("accepted_env_allowlist"; $a; $b)
    and same("source_revision"; $a; $b)
    and same("git_commit"; $a; $b)
    and same_sorted("dependency_closure_roots"; $a; $b)
    and same_sorted("dirty_paths"; $a; $b)
    and same("target_dir_policy"; $a; $b)
    and same("rch_posture"; $a; $b);
  def relation($a; $b):
    (target_rank($a)) as $ar
    | (target_rank($b)) as $br
    | if $ar == 0 or $br == 0 then "unknown"
      elif $ar < $br then "candidate_narrower"
      elif $ar > $br then "candidate_wider"
      else "same_scope"
      end;
  def remediation($verdict; $reason):
    if $verdict == "reuse_allowed" then "Reuse is allowed for this exact proof request while freshness policy remains valid."
    elif $reason == "candidate_narrower_than_requested" then "Rerun the requested wider proof; a narrower candidate cannot satisfy a wider acceptance criterion."
    elif $reason == "candidate_wider_than_requested" then "Ask for human review or rerun the exact requested proof before treating a wider candidate as equivalent."
    elif $reason == "env_allowlist_mismatch" then "Rerun with the requested environment allowlist; env leakage or missing env changes the proof surface."
    elif $reason == "changed_dependency_root" then "Refresh the proof after dependency closure changes; stale dependency roots invalidate reuse."
    elif $reason == "dirty_lane_mismatch" then "Refresh dirty-path evidence and rerun the proof for the current claimed lane."
    elif $reason == "contaminated_command_shape" then "Reject this receipt and rerun through direct rch exec -- env with no shell wrapper, bare cargo, or local fallback."
    else "Request human review before reusing this proof evidence."
    end;

  ($candidate[0] // {}) as $c
  | ($requested[0] // {}) as $r
  | relation($c; $r) as $scope_relation
  | (
      if contaminated($c) or contaminated($r) then {verdict: "reuse_refused", reason_codes: ["contaminated_command_shape"]}
      elif (same("source_revision"; $c; $r) | not) or (same("git_commit"; $c; $r) | not) then {verdict: "rerun_required", reason_codes: ["changed_source_revision"]}
      elif (same_sorted("dependency_closure_roots"; $c; $r) | not) then {verdict: "rerun_required", reason_codes: ["changed_dependency_root"]}
      elif (same_sorted("accepted_env_allowlist"; $c; $r) | not) then {verdict: "reuse_refused", reason_codes: ["env_allowlist_mismatch"]}
      elif (same_sorted("dirty_paths"; $c; $r) | not) then {verdict: "reuse_refused", reason_codes: ["dirty_lane_mismatch"]}
      elif $scope_relation == "candidate_narrower" then {verdict: "reuse_refused", reason_codes: ["candidate_narrower_than_requested"]}
      elif $scope_relation == "candidate_wider" then {verdict: "human_review", reason_codes: ["candidate_wider_than_requested"]}
      elif (($c.test_filter // null) != ($r.test_filter // null)) then {verdict: "reuse_refused", reason_codes: ["test_filter_mismatch"]}
      elif identical($c; $r) then {verdict: "reuse_allowed", reason_codes: ["identical_request"]}
      else {verdict: "human_review", reason_codes: ["partial_overlap_uncertain"]}
      end
    ) as $decision
  | ($decision.reason_codes[0]) as $primary_reason
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      verdict: $decision.verdict,
      reason_codes: $decision.reason_codes,
      remediation: remediation($decision.verdict; $primary_reason),
      candidate: $c,
      requested: $r,
      partial_overlap: {
        relation: $scope_relation,
        candidate_target_rank: target_rank($c),
        requested_target_rank: target_rank($r),
        candidate_command: command_text($c),
        requested_command: command_text($r)
      },
      artifact_paths: {
        equivalence_report_json: $report_path,
        reuse_refusal_receipt_json: $receipt_path,
        run_manifest_json: $manifest_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md,
        candidate_request_json: $candidate_path,
        requested_request_json: $requested_path
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false
      }
    }
  ' >"$core_path"

classifier_hash="$(jq -cS '{case_id, verdict, reason_codes, candidate, requested, partial_overlap}' "$core_path" | sha256sum | awk '{print $1}')"
jq --arg classifier_hash "$classifier_hash" '. + {classifier_hash: $classifier_hash}' "$core_path" >"$report_tmp"
mv "$report_tmp" "$report_path_json"

verdict="$(jq -r '.verdict' "$report_path_json")"
reason_summary="$(jq -r '.reason_codes | join(",")' "$report_path_json")"
remediation="$(jq -r '.remediation' "$report_path_json")"

if [[ "$verdict" == "reuse_allowed" ]]; then
  jq -n \
    --arg schema_version "franken-engine.swarm-proof-reuse-receipt.v1" \
    --arg case_id "$case_id" \
    --arg classifier_hash "$classifier_hash" \
    --arg verdict "$verdict" \
    '{schema_version: $schema_version, case_id: $case_id, classifier_hash: $classifier_hash, verdict: $verdict, reuse_eligible: true}' >"$receipt_tmp"
else
  jq -n \
    --arg schema_version "franken-engine.swarm-proof-reuse-refusal-receipt.v1" \
    --arg case_id "$case_id" \
    --arg classifier_hash "$classifier_hash" \
    --arg verdict "$verdict" \
    --arg reason_summary "$reason_summary" \
    --arg remediation "$remediation" \
    '{
      schema_version: $schema_version,
      case_id: $case_id,
      classifier_hash: $classifier_hash,
      verdict: $verdict,
      reuse_eligible: false,
      reason_summary: $reason_summary,
      remediation: $remediation
    }' >"$receipt_tmp"
fi
mv "$receipt_tmp" "$receipt_path"

jq -n \
  --arg schema_version "franken-engine.swarm-proof-equivalence-classifier-run-manifest.v1" \
  --arg component "swarm_proof_equivalence_classifier" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg verdict "$verdict" \
  --arg reason_summary "$reason_summary" \
  --arg classifier_hash "$classifier_hash" \
  --arg report_path "$report_path_json" \
  --arg receipt_path "$receipt_path" \
  '{
    schema_version: $schema_version,
    component: $component,
    case_id: $case_id,
    source_revision: $source_revision,
    verdict: $verdict,
    reason_summary: $reason_summary,
    classifier_hash: $classifier_hash,
    equivalence_report_json: $report_path,
    reuse_receipt_json: $receipt_path,
    executed_heavy_work: false
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

write_event "classification.completed" "$verdict" "$reason_summary"

{
  printf '# Swarm Proof Equivalence Classifier\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- verdict: \`%s\`\n" "$verdict"
  printf -- "- reason_codes: \`%s\`\n" "$reason_summary"
  printf -- "- classifier_hash: \`%s\`\n" "$classifier_hash"
  printf -- "- remediation: %s\n" "$remediation"
} >"$report_md"

exit 0
