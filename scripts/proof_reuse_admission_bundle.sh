#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${PROOF_REUSE_ADMISSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-reuse-admission}"
run_id="${PROOF_REUSE_ADMISSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_REUSE_ADMISSION_RUN_DIR:-${artifact_root}/${run_id}}"
proof_index_json=""
expected_source_revision="${PROOF_REUSE_ADMISSION_EXPECTED_SOURCE_REVISION:-}"
source_revision="${PROOF_REUSE_ADMISSION_SOURCE_REVISION:-}"
declare -a freshness_reports=()
declare -a changed_paths=()
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_reuse_admission_bundle.sh --proof-index-json FILE [OPTIONS]

Builds a read-only proof reuse admission bundle from preserved proof evidence.
It invokes proof_reuse_cache_planner.sh, then fail-closes reuse unless source
revision/hash, command, target-dir policy, artifact role, freshness, and changed
path compatibility are all proven.

Options:
  --proof-index-json FILE       Proof evidence query report JSON.
  --freshness-report FILE       Proof freshness decay report JSON. Repeatable.
  --expected-source-revision REV
  --source-revision REV         Revision recorded in the admission bundle.
  --changed-path PATH           Changed path since proof generation. Repeatable.
  --output-dir DIR              Artifact output directory.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --proof-index-json)
      proof_index_json="${2:-}"
      shift 2
      ;;
    --freshness-report)
      freshness_reports+=("${2:-}")
      shift 2
      ;;
    --expected-source-revision)
      expected_source_revision="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --changed-path)
      changed_paths+=("${2:-}")
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof reuse admission planning\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof reuse admission planning\n' >&2
  exit 2
fi
if [[ -z "$proof_index_json" || ! -f "$proof_index_json" ]]; then
  printf 'proof reuse admission requires --proof-index-json\n' >&2
  usage
  exit 64
fi
if ! jq empty "$proof_index_json" >/dev/null 2>&1; then
  printf 'invalid proof index JSON: %s\n' "$proof_index_json" >&2
  exit 64
fi
for report in "${freshness_reports[@]}"; do
  if [[ ! -f "$report" ]]; then
    printf 'freshness report not found: %s\n' "$report" >&2
    exit 64
  fi
  if ! jq empty "$report" >/dev/null 2>&1; then
    printf 'invalid freshness report JSON: %s\n' "$report" >&2
    exit 64
  fi
done
if [[ -z "$expected_source_revision" ]]; then
  expected_source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
planner_dir="${run_dir}/proof_reuse_cache"
bundle_core="${run_dir}/proof_reuse_admission_bundle.core.json"
bundle_path="${run_dir}/proof_reuse_admission_bundle.json"
bundle_tmp="${bundle_path}.tmp"
admission_rows_path="${run_dir}/admission_rows.jsonl"
freshness_reports_jsonl="${run_dir}/freshness_reports.jsonl"
freshness_reports_path="${run_dir}/freshness_reports.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in "$planner_dir" "$bundle_core" "$bundle_path" "$bundle_tmp" "$admission_rows_path" "$freshness_reports_jsonl" "$freshness_reports_path" "$events_path" "$commands_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$admission_rows_path"
: >"$freshness_reports_jsonl"

repo_relative_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    case "$path" in
      "$root_dir"/*) printf '%s\n' "${path#"$root_dir"/}" ;;
      "$root_dir") printf '.\n' ;;
      *) printf '%s\n' "$path" ;;
    esac
  else
    printf '%s\n' "${path#./}"
  fi
}

json_array_from_lines() {
  jq -R 'select(length > 0)' | jq -s .
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.proof-reuse-admission.event.v1" \
    --arg event "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

printf './scripts/proof_reuse_admission_bundle.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

planner_cmd=(
  "${root_dir}/scripts/proof_reuse_cache_planner.sh"
  --proof-index-json "$proof_index_json"
  --expected-source-revision "$expected_source_revision"
  --output-dir "$planner_dir"
)
for path in "${changed_paths[@]:-}"; do
  [[ -n "$path" ]] && planner_cmd+=(--changed-path "$path")
done
for report in "${freshness_reports[@]}"; do
  [[ -n "$report" ]] && planner_cmd+=(--freshness-report "$report")
done

printf './scripts/proof_reuse_cache_planner.sh' >>"$commands_path"
for arg in "${planner_cmd[@]:1}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event "admission_started" "running proof reuse cache planner"
set +e
"${planner_cmd[@]}" >"${run_dir}/proof_reuse_cache.stdout" 2>"${run_dir}/proof_reuse_cache.stderr"
planner_exit_code=$?
set -e
if [[ "$planner_exit_code" -ne 0 && "$planner_exit_code" -ne 42 ]]; then
  printf 'proof reuse cache planner failed with exit %s\n' "$planner_exit_code" >&2
  exit "$planner_exit_code"
fi
if [[ ! -f "${planner_dir}/proof_cache_plan.json" ]]; then
  printf 'proof reuse cache planner did not emit proof_cache_plan.json\n' >&2
  exit 64
fi

for report in "${freshness_reports[@]}"; do
  [[ -n "$report" ]] || continue
  jq -nc \
    --arg report_path "$(repo_relative_path "$report")" \
    --argjson report "$(jq -c . "$report")" \
    '{report_path:$report_path, report:$report}' >>"$freshness_reports_jsonl"
done
jq -s '.' "$freshness_reports_jsonl" >"$freshness_reports_path"

changed_paths_json="$(
  printf '%s\n' "${changed_paths[@]:-}" | while IFS= read -r raw_path; do
    [[ -n "$raw_path" ]] || continue
    repo_relative_path "$raw_path"
  done | json_array_from_lines
)"

jq -n \
  --slurpfile plan "${planner_dir}/proof_cache_plan.json" \
  --slurpfile index "$proof_index_json" \
  --slurpfile freshness "$freshness_reports_path" \
  --arg schema_version "franken-engine.proof-reuse-admission-bundle.v1" \
  --arg source_revision "$source_revision" \
  --arg expected_source_revision "$expected_source_revision" \
  --arg proof_index_json "$(repo_relative_path "$proof_index_json")" \
  --arg proof_cache_plan_json "proof_reuse_cache/proof_cache_plan.json" \
  --arg events_jsonl "events.jsonl" \
  --arg commands_txt "commands.txt" \
  --arg report_md "report.md" \
  --argjson planner_exit_code "$planner_exit_code" \
  --argjson changed_paths "$changed_paths_json" \
  '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def norm_path($p): (($p // "") | tostring | sub("^\\./"; ""));
  def metadata_for($row):
    ($row.metadata_json // "") as $raw
    | if $raw == "" or $raw == null then {}
      else (($raw | fromjson?) // {})
      end;
  def metadata_valid($row):
    ($row.metadata_json // "") as $raw
    | ($raw == "" or $raw == null or (($raw | fromjson?) != null));
  def row_match($item; $row):
    (($item.artifact_id // "") != "" and ($item.artifact_id // "") == ($row.artifact_id // ""))
    or (($item.artifact_path // "") != "" and norm_path($item.artifact_path) == norm_path($row.artifact_path));
  def first_match($items; $row):
    (arr($items) | map(select(row_match(.; $row))) | .[0] // null);
  def freshness_match($row):
    ($freshness[0] // []) as $reports
    | (
        $reports
        | map(select(
            (((.report.proof_artifact_id // "") != "") and (.report.proof_artifact_id == ($row.artifact_id // "")))
            or (((.report.artifact_path // "") != "") and norm_path(.report.artifact_path) == norm_path($row.artifact_path))
          ))
        | .[0] // null
      );
  def command_for($m):
    ($m.refresh_command // $m.command // ($m.refresh_commands[0]? // $m.commands[0]? // ""));
  def heavy_cargo($cmd):
    (($cmd // "") | test("(^|[[:space:]])cargo[[:space:]]+(build|check|test|clippy|bench|run)([[:space:]]|$)"));
  def rch_wrapped($cmd):
    (($cmd // "") | contains("rch exec -- env")) and (($cmd // "") | contains("CARGO_TARGET_DIR="));
  def role_ok($role):
    ["proof_manifest","proof_artifact","gate_report","test_report","freshness_report"] | index($role // "") != null;
  def path_overlap($a; $b):
    ($a != "" and $b != "" and ($a == $b or ($a | startswith($b + "/")) or ($b | startswith($a + "/"))));
  def covered_paths($m; $fr):
    ((arr($m.covered_paths) + arr($m.changed_paths) + arr($fr.report.covered_paths)) | map(norm_path(.)) | unique | sort);
  def changed_overlap($paths):
    any($paths[]? as $covered | any($changed_paths[]?; path_overlap($covered; .)));
  def source_hash_ok($m; $fr):
    ($m.source_hash // "") as $metadata_hash
    | ($fr.report.source_hash // $fr.report.artifact_source_hash // "") as $freshness_hash
    | ($fr.report.expected_source_hash // $freshness_hash) as $expected_hash
    | ($metadata_hash != "" and $freshness_hash != "" and $metadata_hash == $freshness_hash and $freshness_hash == $expected_hash);
  def source_revision_ok($row; $fr):
    (($row.source_revision // "") == $expected_source_revision)
    and (($fr.report.source_revision // "") == $expected_source_revision)
    and (((($fr.report.expected_source_revision // "") == "") or (($fr.report.expected_source_revision // "") == $expected_source_revision)));
  def base_class($hit; $refresh; $invalid):
    if $invalid != null then
      if (($invalid.reason // "") | contains("matching freshness report is missing")) then "unknown" else "invalid" end
    elif $refresh != null then "refresh_required"
    elif $hit != null then "reusable"
    else "unknown"
    end;
  def final_class($base; $invalid_reasons; $refresh_reasons):
    if ($invalid_reasons | length) > 0 then "invalid"
    elif $base == "unknown" then "unknown"
    elif ($refresh_reasons | length) > 0 then "refresh_required"
    else $base
    end;
  def admission_row($row):
    metadata_for($row) as $m
    | freshness_match($row) as $fr
    | first_match($plan[0].cache_hit_artifacts; $row) as $hit
    | first_match($plan[0].required_refreshes; $row) as $refresh
    | first_match($plan[0].invalid_artifacts; $row) as $invalid
    | command_for($m) as $command
    | covered_paths($m; ($fr // {})) as $coverage
    | base_class($hit; $refresh; $invalid) as $base
    | ([
        if metadata_valid($row) | not then "metadata_json_invalid" else empty end,
        if (($row.artifact_id // "") == "" or norm_path($row.artifact_path) == "" or ($row.source_revision // "") == "") then "artifact_identity_incomplete" else empty end,
        if role_ok($row.artifact_role // "") | not then "unsupported_artifact_role" else empty end,
        if (heavy_cargo($command) and (rch_wrapped($command) | not)) then "direct_cargo_command_rejected" else empty end,
        if (heavy_cargo($command) and (($m.cargo_target_dir // "") == "" or (($command | contains($m.cargo_target_dir)) | not))) then "target_dir_policy_unproven" else empty end
      ]) as $invalid_reasons
    | ([
        if (($row.bead_id // "") == "") then "anonymous_artifact_requires_refresh" else empty end,
        if (($m.local_fallback_observed // false) == true) then "local_fallback_requires_refresh" else empty end,
        if ($base == "reusable" and (source_revision_ok($row; ($fr // {})) | not)) then "source_revision_unproven" else empty end,
        if ($base == "reusable" and (source_hash_ok($m; ($fr // {})) | not)) then "source_hash_unproven" else empty end,
        if ($base == "reusable" and (($m.command_fingerprint // "") == "")) then "command_fingerprint_unproven" else empty end,
        if ($base == "reusable" and (($fr.report.freshness_state // "") != "fresh" or (($fr.report.reusable // false) != true))) then "freshness_not_reusable" else empty end,
        if ($base == "reusable" and changed_overlap($coverage)) then "changed_path_overlap_requires_refresh" else empty end
      ]) as $refresh_reasons
    | final_class($base; $invalid_reasons; $refresh_reasons) as $classification
    | {
        artifact_id:($row.artifact_id // ""),
        bead_id:($row.bead_id // ""),
        artifact_path:norm_path($row.artifact_path),
        artifact_role:($row.artifact_role // ""),
        receipt_kind:($row.receipt_kind // ""),
        classification:$classification,
        admission_allowed:($classification == "reusable"),
        deterministic_reasons:(
          ([if $hit != null then ($hit.reason // "fresh proof artifact may be reused") else empty end,
            if $refresh != null then ($refresh.reason // "proof artifact requires refresh") else empty end,
            if $invalid != null then ($invalid.reason // "proof artifact is invalid") else empty end]
           + $invalid_reasons + $refresh_reasons)
          | map(select(. != null and . != "")) | unique | sort
        ),
        compatibility:{
          source_revision_ok:source_revision_ok($row; ($fr // {})),
          source_hash_ok:source_hash_ok($m; ($fr // {})),
          command_policy_ok:(if heavy_cargo($command) then rch_wrapped($command) else ($command != "") end),
          target_dir_policy_ok:(if heavy_cargo($command) then (($m.cargo_target_dir // "") != "" and ($command | contains($m.cargo_target_dir))) else true end),
          artifact_role_ok:role_ok($row.artifact_role // ""),
          freshness_ok:(($fr.report.freshness_state // "") == "fresh" and (($fr.report.reusable // false) == true)),
          changed_path_overlap:changed_overlap($coverage),
          metadata_valid:metadata_valid($row),
          anonymous_artifact:(($row.bead_id // "") == ""),
          local_fallback_observed:(($m.local_fallback_observed // false) == true)
        },
        command_fingerprint:($m.command_fingerprint // null),
        cargo_target_dir:($m.cargo_target_dir // null),
        refresh_command:(if $command == "" then null else $command end),
        source_hash:($m.source_hash // null),
        covered_paths:$coverage,
        evidence_paths:{
          proof_index_json:$proof_index_json,
          proof_cache_plan_json:$proof_cache_plan_json,
          freshness_report_json:(($fr.report_path // null))
        }
      };
  ($index[0].rows // []) as $rows
  | ($rows | map(admission_row(.))) as $admissions
  | (if any($admissions[]?; .classification == "invalid" or .classification == "unknown") then "fail_closed"
     elif any($admissions[]?; .classification == "refresh_required") and any($admissions[]?; .classification == "reusable") then "partial_refresh_required"
     elif any($admissions[]?; .classification == "refresh_required") then "refresh_required"
     elif ($admissions | length) > 0 and all($admissions[]; .classification == "reusable") then "admit_reuse"
     else "fail_closed"
     end) as $decision
  | {
      schema_version:$schema_version,
      source_revision:$source_revision,
      expected_source_revision:$expected_source_revision,
      proof_index_json:$proof_index_json,
      changed_paths:$changed_paths,
      planner_exit_code:$planner_exit_code,
      admission_decision:$decision,
      admission_rows:$admissions,
      classification_counts:($admissions | group_by(.classification) | map({classification:.[0].classification,count:length})),
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        runs_cargo:false,
        runs_rch:false,
        mutates_br:false,
        sends_agent_mail:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false,
        creates_deletes_target_dirs:false
      },
      artifact_paths:{
        proof_reuse_admission_bundle_json:"proof_reuse_admission_bundle.json",
        admission_rows_jsonl:"admission_rows.jsonl",
        proof_cache_plan_json:$proof_cache_plan_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      }
    }
  ' >"$bundle_core"

bundle_hash="$(jq -cS '{source_revision,expected_source_revision,changed_paths,admission_rows,admission_decision}' "$bundle_core" | sha256sum | awk '{print substr($1, 1, 16)}')"
jq --arg bundle_id "proof-reuse-admission-${bundle_hash}" '. + {bundle_id:$bundle_id}' "$bundle_core" >"$bundle_tmp"
mv "$bundle_tmp" "$bundle_path"
jq -c '.admission_rows[]?' "$bundle_path" >"$admission_rows_path"

decision="$(jq -r '.admission_decision' "$bundle_path")"
write_event "admission_classified" "$decision"

{
  printf '# Proof Reuse Admission Bundle\n\n'
  printf -- "- bundle_id: \`%s\`\n" "$(jq -r '.bundle_id' "$bundle_path")"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- rows: \`%s\`\n" "$(jq -r '.admission_rows | length' "$bundle_path")"
  printf '\n## Classifications\n\n'
  jq -r '.classification_counts[]? | "- `" + .classification + "`: `" + (.count | tostring) + "`"' "$bundle_path"
} >"$report_path"

printf 'proof_reuse_admission_bundle=%s\n' "$bundle_path"
printf 'proof_reuse_admission_decision=%s\n' "$decision"
if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
