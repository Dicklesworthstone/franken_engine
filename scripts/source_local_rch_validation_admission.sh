#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SOURCE_LOCAL_RCH_ADMISSION_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-source-local-rch-admission}"
run_id="${SOURCE_LOCAL_RCH_ADMISSION_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SOURCE_LOCAL_RCH_ADMISSION_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

request_json=""
preflight_json=""
proof_admission_json=""
sticky_plan_json=""
local_fallback_markers_json=""
case_id=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/source_local_rch_validation_admission.sh --request-json FILE --preflight-json FILE [OPTIONS]

Composes source-local lib-unit request identity with existing proof command
preflight, proof-reuse admission, and sticky-worker warm-target evidence. The
composer is advisory-only: it does not run Cargo, run rch, reserve files,
mutate workers, or alter live queue policy.

Required:
  --request-json FILE        Source-local validation request JSON.
  --preflight-json FILE      Output from swarm_proof_command_preflight.sh.

Optional:
  --proof-admission-json FILE
  --sticky-plan-json FILE
  --local-fallback-markers-json FILE
  --case-id ID
  --output-dir DIR

Artifacts:
  source_local_rch_validation_admission.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   warm/sticky reuse admitted
  42  fail-closed due unsafe command or contamination
  75  reuse refused; cold-refresh command emitted
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --request-json)
      request_json="${2:-}"
      shift 2
      ;;
    --preflight-json)
      preflight_json="${2:-}"
      shift 2
      ;;
    --proof-admission-json)
      proof_admission_json="${2:-}"
      shift 2
      ;;
    --sticky-plan-json)
      sticky_plan_json="${2:-}"
      shift 2
      ;;
    --local-fallback-markers-json)
      local_fallback_markers_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
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

if [[ -z "$request_json" || -z "$preflight_json" ]]; then
  printf 'source-local rch admission requires --request-json and --preflight-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for source-local rch validation admission\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for source-local rch validation admission\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
admission_path="${run_dir}/source_local_rch_validation_admission.json"
admission_tmp="${admission_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
request_normalized="${run_dir}/request.normalized.json"
preflight_normalized="${run_dir}/preflight.normalized.json"
proof_normalized="${run_dir}/proof_admission.normalized.json"
sticky_normalized="${run_dir}/sticky_plan.normalized.json"
markers_normalized="${run_dir}/local_fallback_markers.normalized.json"

for artifact_path in \
  "$admission_path" \
  "$admission_tmp" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$request_normalized" \
  "$preflight_normalized" \
  "$proof_normalized" \
  "$sticky_normalized" \
  "$markers_normalized"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"

printf './scripts/source_local_rch_validation_admission.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$input_path" ]]; then
    printf 'source-local admission missing %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'source-local admission invalid %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
}

normalize_optional_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  local default_json="$4"

  if [[ -z "$input_path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    return
  fi
  normalize_required_json "$input_path" "$output_path" "$label"
}

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.source-local-rch-validation-admission.event.v1" \
    --arg component "source_local_rch_validation_admission" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail}' \
    >>"$events_path"
}

normalize_required_json "$request_json" "$request_normalized" "request"
normalize_required_json "$preflight_json" "$preflight_normalized" "preflight"
normalize_optional_json "$proof_admission_json" "$proof_normalized" "proof admission" '{"schema_version":"franken-engine.proof-reuse-admission-bundle.v1","admission_decision":"missing","admission_rows":[]}'
normalize_optional_json "$sticky_plan_json" "$sticky_normalized" "sticky worker plan" '{"schema_version":"franken-engine.sticky-worker-warm-target-lease-plan.v1","plan_decision":"missing","assigned_worker_id":null,"assigned_target_dir":null,"phase_plans":[],"local_fallback_marker_count":0}'
normalize_optional_json "$local_fallback_markers_json" "$markers_normalized" "local fallback markers" '{"markers":[]}'

if [[ -z "$case_id" ]]; then
  case_id="$(jq -r '.case_id // "manual"' "$request_normalized")"
fi

write_event "admission.started" "ok" "$case_id"

jq -n \
  --slurpfile request "$request_normalized" \
  --slurpfile preflight "$preflight_normalized" \
  --slurpfile proof "$proof_normalized" \
  --slurpfile sticky "$sticky_normalized" \
  --slurpfile markers "$markers_normalized" \
  --arg schema_version "franken-engine.source-local-rch-validation-admission.v1" \
  --arg case_id "$case_id" \
  --arg request_json "$request_json" \
  --arg preflight_json "$preflight_json" \
  --arg proof_admission_json "$proof_admission_json" \
  --arg sticky_plan_json "$sticky_plan_json" \
  --arg local_fallback_markers_json "$local_fallback_markers_json" \
  --arg admission_path "$admission_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def s($v): (($v // "") | tostring);
  def b($v): (($v // false) == true);
  def ident($row; $name):
    ($row.request_identity[$name] // $row.identity[$name] // $row.compatibility[$name] // $row[$name] // "");
  def norm_path($p): (($p // "") | tostring | sub("^\\./"; ""));
  def path_overlap($a; $b):
    (norm_path($a) as $left | norm_path($b) as $right
     | $left != "" and $right != ""
       and ($left == $right or ($left | startswith($right + "/")) or ($right | startswith($left + "/"))));
  def changed_overlap($covered; $changed):
    ([arr($covered)[]? as $covered_path | arr($changed)[]? | select(path_overlap($covered_path; .))] | length) > 0;
  def mismatch($label; $expected; $actual):
    if s($expected) == "" then ($label + "_missing")
    elif s($actual) == "" then ($label + "_unproven")
    elif s($expected) != s($actual) then ($label + "_mismatch")
    else empty
    end;

  ($request[0]) as $req
  | ($preflight[0]) as $pre
  | ($proof[0]) as $proof_doc
  | ($sticky[0]) as $sticky_doc
  | (($proof_doc.admission_rows // [])[0] // {}) as $row
  | arr($markers[0].markers) as $marker_rows
  | arr($req.changed_paths) as $changed_paths
  | (arr($req.covered_paths) + arr($row.covered_paths) + arr($row.compatibility.covered_paths)) as $covered_paths
  | ([
      if (($req.schema_version // "") != "franken-engine.source-local-rch-validation-request.v1") then "bad_request_schema" else empty end,
      if (($pre.schema_version // "") != "franken-engine.swarm-proof-command-preflight.v1") then "bad_preflight_schema" else empty end,
      if s($req.source_revision) == "" then "source_revision_missing" else empty end,
      if s($req.source_hash) == "" then "source_hash_missing" else empty end,
      if s($req.cargo_lock_hash) == "" then "cargo_lock_hash_missing" else empty end,
      if s($req.command_fingerprint) == "" then "command_fingerprint_missing" else empty end,
      if s($req.cargo_target_dir) == "" then "missing_target_dir_identity" else empty end,
      if (($pre.decision // "") != "proof_safe") then ("preflight_" + s($pre.reason_code // "not_proof_safe")) else empty end,
      if (($pre.command.has_target_dir // false) != true) then "missing_target_dir_policy" else empty end,
      if b($req.local_fallback_observed)
         or b($row.local_fallback_observed)
         or b($row.compatibility.local_fallback_observed)
         or (($sticky_doc.local_fallback_marker_count // 0) > 0)
         or any($marker_rows[]?; b(.detected)) then "local_fallback_contamination" else empty end,
      if b($req.support_crate_contamination_observed)
         or b($row.support_crate_contamination_observed)
         or b($row.compatibility.support_crate_contamination_observed) then "support_crate_contamination" else empty end
    ] | unique | sort) as $hard_reasons
  | ([
      if (($proof_doc.admission_decision // "") == "fail_closed") then "proof_reuse_fail_closed"
      elif (($proof_doc.admission_decision // "") != "admit_reuse") then "proof_reuse_not_admitted"
      else empty end,
      if any(arr($row.deterministic_reasons)[]?; (tostring | test("freshness.*missing|matching freshness report is missing"))) then "missing_freshness" else empty end,
      mismatch("source_revision"; $req.source_revision; ident($row; "source_revision")),
      mismatch("source_hash"; $req.source_hash; ident($row; "source_hash")),
      mismatch("cargo_lock_hash"; $req.cargo_lock_hash; ident($row; "cargo_lock_hash")),
      if s($req.dependency_root_hash) != "" then mismatch("dependency_root_hash"; $req.dependency_root_hash; ident($row; "dependency_root_hash")) else empty end,
      mismatch("rustflags"; $req.rustflags; ident($row; "rustflags")),
      mismatch("toolchain"; $req.toolchain; ident($row; "toolchain")),
      mismatch("package"; $req.package; ident($row; "package")),
      mismatch("target_kind"; $req.target_kind; ident($row; "target_kind")),
      mismatch("test_filter"; $req.test_filter; ident($row; "test_filter")),
      mismatch("command_fingerprint"; $req.command_fingerprint; ident($row; "command_fingerprint")),
      if changed_overlap($covered_paths; $changed_paths) then "changed_path_overlap" else empty end,
      if (($sticky_doc.plan_decision // "") != "admit_sticky") then "warm_target_not_admitted" else empty end,
      if s($sticky_doc.assigned_worker_id) == "" then "unknown_worker_evidence" else empty end,
      if s($sticky_doc.assigned_target_dir) == "" then "missing_sticky_target_dir" else empty end,
      if s($sticky_doc.assigned_target_dir) != "" and s($sticky_doc.assigned_target_dir) != s($req.cargo_target_dir) then "sticky_target_dir_mismatch" else empty end
    ] | unique | sort) as $cold_reasons
  | (if ($hard_reasons | length) > 0 then "fail_closed"
     elif ($cold_reasons | length) > 0 then "cold_refresh_required"
     else "admit_reuse"
     end) as $decision
  | (if $decision == "fail_closed" then 42 elif $decision == "cold_refresh_required" then 75 else 0 end) as $exit_code
  | (if $decision == "admit_reuse" then
       ($sticky_doc.phase_plans[0].requested_command // $req.reusable_rch_command // $pre.pasteable_command // null)
     elif $decision == "cold_refresh_required" then
       ($req.cold_refresh_command // $pre.pasteable_command // null)
     else
       null
     end) as $selected_command
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      admission_decision: $decision,
      admission_allowed: ($decision == "admit_reuse"),
      exit_code: $exit_code,
      reason_codes: (($hard_reasons + (if $decision == "fail_closed" then [] else $cold_reasons end)) | unique | sort),
      hard_fail_reasons: $hard_reasons,
      cold_refresh_reasons: $cold_reasons,
      selected_command: $selected_command,
      suggested_cold_refresh_command: ($req.cold_refresh_command // $pre.pasteable_command // null),
      request_identity: {
        source_revision: ($req.source_revision // null),
        source_hash: ($req.source_hash // null),
        cargo_lock_hash: ($req.cargo_lock_hash // null),
        dependency_root_hash: ($req.dependency_root_hash // null),
        package: ($req.package // null),
        target_kind: ($req.target_kind // null),
        test_filter: ($req.test_filter // null),
        rustflags: ($req.rustflags // null),
        toolchain: ($req.toolchain // null),
        cargo_target_dir: ($req.cargo_target_dir // null),
        command_fingerprint: ($req.command_fingerprint // null),
        changed_paths: $changed_paths,
        covered_paths: ($covered_paths | map(norm_path(.)) | unique | sort)
      },
      preflight_summary: {
        decision: ($pre.decision // "unknown"),
        reason_code: ($pre.reason_code // "unknown"),
        command_kind: ($pre.command.command_kind // "unknown"),
        transport: ($pre.command.transport // "unknown"),
        has_target_dir: (($pre.command.has_target_dir // false) == true),
        target_dir: ($pre.command.target_dir // null),
        unsupported_env: ($pre.command.unsupported_env // [])
      },
      proof_reuse_summary: {
        decision: ($proof_doc.admission_decision // "missing"),
        row_count: (($proof_doc.admission_rows // []) | length),
        first_row_artifact_id: ($row.artifact_id // null),
        first_row_classification: ($row.classification // null)
      },
      sticky_worker_summary: {
        decision: ($sticky_doc.plan_decision // "missing"),
        assigned_worker_id: ($sticky_doc.assigned_worker_id // null),
        assigned_target_dir: ($sticky_doc.assigned_target_dir // null),
        local_fallback_marker_count: ($sticky_doc.local_fallback_marker_count // 0)
      },
      mutation_policy: {
        advisory_only: true,
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false,
        creates_deletes_target_dirs: false
      },
      input_paths: {
        request_json: $request_json,
        preflight_json: $preflight_json,
        proof_admission_json: (if $proof_admission_json == "" then null else $proof_admission_json end),
        sticky_plan_json: (if $sticky_plan_json == "" then null else $sticky_plan_json end),
        local_fallback_markers_json: (if $local_fallback_markers_json == "" then null else $local_fallback_markers_json end)
      },
      artifact_paths: {
        admission_json: $admission_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      }
    }
  ' >"$admission_tmp"
mv "$admission_tmp" "$admission_path"

selected_command="$(jq -r '.selected_command // .suggested_cold_refresh_command // empty' "$admission_path")"
if [[ -n "$selected_command" ]]; then
  printf '%s\n' "$selected_command" >>"$commands_path"
fi

write_event "admission.completed" "$(jq -r '.admission_decision' "$admission_path")" "$(jq -r '.reason_codes | join(",")' "$admission_path")"

jq -r '
  "# Source-Local RCH Validation Admission",
  "",
  ("- Case: `" + .case_id + "`"),
  ("- Decision: `" + .admission_decision + "`"),
  ("- Allowed: `" + (.admission_allowed | tostring) + "`"),
  ("- Exit code: `" + (.exit_code | tostring) + "`"),
  ("- Reasons: `" + (.reason_codes | join(",")) + "`"),
  ("- Selected command: `" + (.selected_command // "none") + "`"),
  ("- Cold refresh command: `" + (.suggested_cold_refresh_command // "none") + "`"),
  "",
  "## Evidence",
  "",
  ("- Preflight: `" + .preflight_summary.decision + "` / `" + .preflight_summary.reason_code + "`"),
  ("- Proof reuse: `" + .proof_reuse_summary.decision + "`"),
  ("- Sticky worker: `" + .sticky_worker_summary.decision + "`")
' "$admission_path" >"$report_path"

printf 'source_local_rch_admission=%s\n' "$admission_path"
printf 'source_local_rch_decision=%s\n' "$(jq -r '.admission_decision' "$admission_path")"
exit "$(jq -r '.exit_code' "$admission_path")"
