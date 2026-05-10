#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_CACHE_MISS_FORENSIC_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-cache-miss-forensics}"
run_id="${RCH_CACHE_MISS_FORENSIC_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_CACHE_MISS_FORENSIC_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${RCH_CACHE_MISS_FORENSIC_SOURCE_REVISION:-}"
case_id="manual"
summary_log=""
metadata_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_cache_miss_forensic_ledger.sh --summary-log FILE --metadata-json FILE [OPTIONS]

Analyzes a preserved RCH summary/transcript plus command metadata to explain
cache HIT/MISS outcomes and proof freshness drift. It never runs Cargo, invokes
rch, queries workers, mutates br, sends Agent Mail, or changes target dirs.

Required:
  --summary-log FILE      Preserved RCH summary or transcript excerpt.
  --metadata-json FILE    Command metadata and optional expected freshness JSON.

Options:
  --case-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  rch_cache_miss_forensic_ledger.json
  proof_freshness_diff.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   pass or degraded forensic ledger emitted
  42  fail-closed ledger emitted
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --summary-log)
      summary_log="${2:-}"
      shift 2
      ;;
    --metadata-json)
      metadata_json="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for RCH cache miss forensic ledger\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for RCH cache miss forensic ledger\n' >&2
  exit 2
fi
if [[ -z "$summary_log" || -z "$metadata_json" ]]; then
  printf 'cache miss forensic ledger requires --summary-log and --metadata-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$summary_log" ]]; then
  printf 'summary log not found: %s\n' "$summary_log" >&2
  exit 64
fi
if [[ ! -f "$metadata_json" ]]; then
  printf 'metadata JSON not found: %s\n' "$metadata_json" >&2
  exit 64
fi
if ! jq empty "$metadata_json" >/dev/null 2>&1; then
  printf 'invalid metadata JSON: %s\n' "$metadata_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/rch_cache_miss_forensic_ledger.json"
ledger_tmp="${ledger_path}.tmp"
freshness_diff_path="${run_dir}/proof_freshness_diff.json"
metadata_normalized="${run_dir}/command_metadata.normalized.json"
summary_excerpt="${run_dir}/summary_excerpt.txt"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in "$ledger_path" "$ledger_tmp" "$freshness_diff_path" "$metadata_normalized" "$summary_excerpt" "$events_path" "$commands_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/rch_cache_miss_forensic_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -cS . "$metadata_json" >"$metadata_normalized"
sed -n '1,240p' "$summary_log" >"$summary_excerpt"
summary_hash="$(sha256sum "$summary_excerpt" | awk '{print $1}')"

has_marker() {
  grep -Eiq "$1" "$summary_log"
}

bool_from_marker() {
  if has_marker "$1"; then
    printf 'true'
  else
    printf 'false'
  fi
}

remote_proof_observed="$(bool_from_marker '(\[RCH\].*remote|remote proof|Remote execution succeeded|executed remotely)')"
# rch-policy-waive: local_fallback_not_rejected reason=pattern detects fallback markers and the ledger fails closed below
local_fallback_observed="$(bool_from_marker '(local fallback|fallback to local|falling back to local|Executing command locally|running locally|\[RCH\] local|RCH-E326)')"
cache_hit_observed="$(bool_from_marker '(Cache HIT|cache hit|CACHE_HIT)')"
cache_miss_observed="$(bool_from_marker '(Cache MISS|cache miss|CACHE_MISS)')"
artifact_retrieval_failed="$(bool_from_marker '(artifact retrieval failed|failed to retrieve artifacts|rsync artifact retrieval failed|rsync error)')"
completion_marker_observed="$(bool_from_marker '(exit_code=0|exit code: 0|completed_at|Remote execution succeeded|finished remote proof)')"

jq -n \
  --slurpfile metadata "$metadata_normalized" \
  --arg schema_version "franken-engine.rch-cache-miss-forensic-ledger.v1" \
  --arg diff_schema_version "franken-engine.proof-freshness-diff.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg summary_log "$summary_log" \
  --arg summary_excerpt "$summary_excerpt" \
  --arg summary_hash "$summary_hash" \
  --arg ledger_path "$ledger_path" \
  --arg freshness_diff_path "$freshness_diff_path" \
  --arg metadata_normalized "$metadata_normalized" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson remote_proof_observed "$remote_proof_observed" \
  --argjson local_fallback_observed "$local_fallback_observed" \
  --argjson cache_hit_observed "$cache_hit_observed" \
  --argjson cache_miss_observed "$cache_miss_observed" \
  --argjson artifact_retrieval_failed "$artifact_retrieval_failed" \
  --argjson completion_marker_observed "$completion_marker_observed" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def reason($code; $detail; $remediation):
    {code:$code, detail:$detail, remediation:$remediation};
  def field_diff($name; $current; $expected):
    if ($expected == null) or ($current == $expected) then empty
    else {
      field:$name,
      current:$current,
      expected:$expected,
      stale:true
    } end;
  def class_from_diffs($diffs):
    if any($diffs[]?; .field == "command_fingerprint") then "command_fingerprint_miss"
    elif any($diffs[]?; .field == "toolchain") then "toolchain_miss"
    elif any($diffs[]?; .field == "cargo_target_dir") then "target_dir_policy_miss"
    elif any($diffs[]?; .field == "sync_root_hash") then "sync_root_miss"
    elif any($diffs[]?; .field == "dependency_roots") then "dependency_root_miss"
    elif ($diffs | length) == 0 then "unexplained_cache_miss"
    else "mixed_freshness_miss" end;

  ($metadata[0]) as $m
  | ($m.expected // {}) as $expected
  | ([
      field_diff("command_fingerprint"; ($m.command_fingerprint // null); ($expected.command_fingerprint // null)),
      field_diff("toolchain"; ($m.toolchain // null); ($expected.toolchain // null)),
      field_diff("cargo_target_dir"; ($m.cargo_target_dir // null); ($expected.cargo_target_dir // null)),
      field_diff("rustflags"; ($m.rustflags // null); ($expected.rustflags // null)),
      field_diff("sync_root_hash"; ($m.sync_root_hash // null); ($expected.sync_root_hash // null)),
      field_diff("dependency_roots"; (arr($m.dependency_roots) | sort); (if ($expected.dependency_roots // null) == null then null else (arr($expected.dependency_roots) | sort) end))
    ]) as $diffs
  | ([
      if $remote_proof_observed | not then
        reason("FE-IW3-RCH-MISSING-REMOTE-PROOF"; "summary log lacks an explicit RCH remote proof marker"; "Rerun through rch and preserve the remote proof line before using this evidence.")
      else empty end,
      if $local_fallback_observed then
        reason("FE-IW3-RCH-LOCAL-FALLBACK"; "summary log contains local fallback markers"; "Reject this transcript as remote proof and rerun after RCH routing is healthy.")
      else empty end,
      if (($m.worker_id // "") == "") then
        reason("FE-IW3-RCH-MISSING-WORKER"; "command metadata lacks worker_id"; "Capture worker id from RCH status or transcript before classifying cache behavior.")
      else empty end,
      if (($m.job_id // "") == "") then
        reason("FE-IW3-RCH-MISSING-JOB"; "command metadata lacks job_id"; "Capture job id from RCH status or transcript before classifying cache behavior.")
      else empty end,
      if ($completion_marker_observed | not) then
        reason("FE-IW3-RCH-TRUNCATED-LOG"; "summary log lacks a remote completion marker"; "Preserve a complete transcript before classifying cache behavior.")
      else empty end
    ]) as $fail_closed_reasons
  | ([
      if $artifact_retrieval_failed then
        reason("FE-IW3-RCH-ARTIFACT-RETRIEVAL"; "artifact retrieval failure was observed"; "Treat the run as degraded evidence until artifacts are retrieved or explicitly waived.")
      else empty end,
      if $cache_miss_observed and (($diffs | length) > 0) then
        reason("FE-IW3-RCH-PROOF-FRESHNESS-DRIFT"; "cache miss aligns with proof freshness drift"; "Use the freshness diff before assuming equivalent commands should hit cache.")
      elif $cache_miss_observed then
        reason("FE-IW3-RCH-UNEXPLAINED-CACHE-MISS"; "cache miss has no metadata drift explanation"; "Inspect worker cache residency, sync manifest, and artifact mirror state.")
      else empty end
    ]) as $degraded_reasons
  | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
     elif ($degraded_reasons | length) > 0 then "degraded"
     else "pass" end) as $decision
  | (if $cache_hit_observed then "cache_hit"
     elif $cache_miss_observed then class_from_diffs($diffs)
     else "unknown_cache_state" end) as $miss_classification
  | {
      schema_version:$schema_version,
      case_id:$case_id,
      source_revision:$source_revision,
      decision:$decision,
      miss_classification:$miss_classification,
      cache_hit_observed:$cache_hit_observed,
      cache_miss_observed:$cache_miss_observed,
      remote_proof_observed:$remote_proof_observed,
      local_fallback_observed:$local_fallback_observed,
      artifact_retrieval_failed:$artifact_retrieval_failed,
      completion_marker_observed:$completion_marker_observed,
      worker_id:($m.worker_id // null),
      job_id:($m.job_id // null),
      command_fingerprint:($m.command_fingerprint // null),
      toolchain:($m.toolchain // null),
      cargo_target_dir:($m.cargo_target_dir // null),
      rustflags:($m.rustflags // null),
      sync_root_hash:($m.sync_root_hash // null),
      dependency_roots:arr($m.dependency_roots),
      artifact_retrieval_bytes:($m.artifact_retrieval_bytes // null),
      fail_closed_reasons:$fail_closed_reasons,
      degraded_reasons:$degraded_reasons,
      proof_freshness_diff:{
        schema_version:$diff_schema_version,
        source_revision:$source_revision,
        diff_count:($diffs | length),
        diffs:$diffs,
        current:{
          command_fingerprint:($m.command_fingerprint // null),
          toolchain:($m.toolchain // null),
          cargo_target_dir:($m.cargo_target_dir // null),
          rustflags:($m.rustflags // null),
          sync_root_hash:($m.sync_root_hash // null),
          dependency_roots:arr($m.dependency_roots)
        },
        expected:$expected
      },
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
        ledger_json:$ledger_path,
        proof_freshness_diff_json:$freshness_diff_path,
        metadata_normalized_json:$metadata_normalized,
        summary_excerpt_txt:$summary_excerpt,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      },
      evidence_hashes:{
        summary_excerpt_sha256:$summary_hash
      },
      source_paths:{
        summary_log:$summary_log,
        metadata_json:$metadata_normalized
      }
    }
  ' >"$ledger_tmp"

mv "$ledger_tmp" "$ledger_path"
jq '.proof_freshness_diff' "$ledger_path" >"$freshness_diff_path"
jq -c '
  {
    schema_version:"franken-engine.rch-cache-miss-forensic-event.v1",
    event:"ledger_emitted",
    decision:.decision,
    miss_classification:.miss_classification,
    worker_id:.worker_id,
    job_id:.job_id,
    source_revision:.source_revision
  },
  (.degraded_reasons[]? | {
    schema_version:"franken-engine.rch-cache-miss-forensic-event.v1",
    event:"degraded_reason",
    code:.code,
    detail:.detail
  }),
  (.fail_closed_reasons[]? | {
    schema_version:"franken-engine.rch-cache-miss-forensic-event.v1",
    event:"fail_closed_reason",
    code:.code,
    detail:.detail
  })
' "$ledger_path" >"$events_path"
jq -r '
  "# RCH Cache Miss Forensic Ledger\n\n"
  + "- decision: `" + .decision + "`\n"
  + "- miss classification: `" + .miss_classification + "`\n"
  + "- worker: `" + ((.worker_id // "") | tostring) + "`\n"
  + "- job: `" + ((.job_id // "") | tostring) + "`\n"
  + "- freshness diffs: `" + (.proof_freshness_diff.diff_count | tostring) + "`\n\n"
  + "## Reasons\n\n"
  + (if ((.degraded_reasons + .fail_closed_reasons) | length) == 0 then "No degraded or fail-closed reasons.\n"
     else ((.degraded_reasons + .fail_closed_reasons) | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
' "$ledger_path" >"$report_path"

decision="$(jq -r '.decision' "$ledger_path")"
printf 'rch_cache_miss_forensic_ledger=%s\n' "$ledger_path"
printf 'rch_cache_miss_forensic_decision=%s\n' "$decision"
if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
