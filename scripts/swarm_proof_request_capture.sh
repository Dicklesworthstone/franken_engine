#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_REQUEST_CAPTURE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-request-capture}"
run_id="${SWARM_PROOF_REQUEST_CAPTURE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_REQUEST_CAPTURE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
br_json=""
agent_mail_json=""
git_status_json=""
rch_summary_json=""
case_id=""
bead_id="bd-proof-request-capture"
source_revision="${SWARM_PROOF_REQUEST_CAPTURE_SOURCE_REVISION:-}"
declare -a claimed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_request_capture.sh [OPTIONS]

Capture proof request intent from br, Agent Mail, git, and RCH summary snapshots
without executing heavy Cargo or RCH work.

Options:
  --fixture-json FILE       Single fixture case containing sources.* snapshots.
  --br-json FILE            br/bv state snapshot JSON.
  --agent-mail-json FILE    Agent Mail message/reservation snapshot JSON.
  --git-status-json FILE    Git status snapshot JSON.
  --rch-summary-json FILE   RCH command summary snapshot JSON.
  --claimed-path PATH       Claimed lane path. May be repeated.
  --bead-id ID              Bead id recorded in output rows.
  --case-id ID              Deterministic case id.
  --source-revision REV     Source revision recorded in artifacts.
  --output-dir DIR          Artifact directory.

Artifacts:
  proof_request_capture.json
  proof_requests.jsonl
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
    --br-json)
      br_json="${2:-}"
      shift 2
      ;;
    --agent-mail-json)
      agent_mail_json="${2:-}"
      shift 2
      ;;
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --rch-summary-json)
      rch_summary_json="${2:-}"
      shift 2
      ;;
    --claimed-path)
      claimed_paths+=("${2:-}")
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
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
  printf 'jq is required for swarm proof request capture\n' >&2
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
  if [[ "$bead_id" == "bd-proof-request-capture" ]]; then
    bead_id="$(jq -r '.bead_id // .sources.br.bead_id // "bd-proof-request-capture"' "$fixture_json")"
  fi
fi

if [[ -z "$case_id" ]]; then
  case_id="manual"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
capture_path="${run_dir}/proof_request_capture.json"
capture_tmp="${capture_path}.tmp"
requests_path="${run_dir}/proof_requests.jsonl"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
br_source_path="${run_dir}/source_br_snapshot.json"
mail_source_path="${run_dir}/source_agent_mail_snapshot.json"
git_source_path="${run_dir}/source_git_status.json"
rch_source_path="${run_dir}/source_rch_summary.json"

for artifact_path in \
  "$capture_path" \
  "$capture_tmp" \
  "$requests_path" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$br_source_path" \
  "$mail_source_path" \
  "$git_source_path" \
  "$rch_source_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_request_capture.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-request-capture.event.v1" \
    --arg component "swarm_proof_request_capture" \
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

array_to_json() {
  if [[ "$#" -eq 0 ]]; then
    printf '[]\n'
    return 0
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

normalize_source_file() {
  local input_path="$1"
  local output_path="$2"
  local fallback_json="$3"

  if [[ -n "$input_path" ]]; then
    if [[ ! -f "$input_path" ]]; then
      printf 'source JSON not found: %s\n' "$input_path" >&2
      exit 64
    fi
    if ! jq empty "$input_path" >/dev/null 2>&1; then
      printf 'invalid source JSON: %s\n' "$input_path" >&2
      exit 64
    fi
    jq -cS . "$input_path" >"$output_path"
  else
    printf '%s\n' "$fallback_json" | jq -cS . >"$output_path"
  fi
}

if [[ -n "$fixture_json" ]]; then
  jq -cS '.sources.br // {}' "$fixture_json" >"$br_source_path"
  jq -cS '.sources.agent_mail // {"status":"missing","messages":[],"reservations":[]}' "$fixture_json" >"$mail_source_path"
  jq -cS '.sources.git // {"dirty_paths":[],"claimed_paths":[]}' "$fixture_json" >"$git_source_path"
  jq -cS '.sources.rch // {"rows":[]}' "$fixture_json" >"$rch_source_path"
else
  if [[ -z "$br_json" ]]; then
    if command -v br >/dev/null 2>&1; then
      if br list --status=in_progress --json >"$br_source_path" 2>/dev/null; then
        jq -cS '. + {fresh: true, source: "live-br-in-progress"}' "$br_source_path" >"${br_source_path}.tmp"
        mv "${br_source_path}.tmp" "$br_source_path"
      else
        printf '{"fresh":false,"issues":[],"source":"live-br-unavailable"}\n' | jq -cS . >"$br_source_path"
      fi
    else
      printf '{"fresh":false,"issues":[],"source":"br-not-found"}\n' | jq -cS . >"$br_source_path"
    fi
  else
    normalize_source_file "$br_json" "$br_source_path" '{}'
  fi

  normalize_source_file "$agent_mail_json" "$mail_source_path" '{"status":"missing","messages":[],"reservations":[]}'
  normalize_source_file "$rch_summary_json" "$rch_source_path" '{"rows":[]}'
  if [[ -n "$git_status_json" ]]; then
    normalize_source_file "$git_status_json" "$git_source_path" '{"dirty_paths":[],"claimed_paths":[]}'
  else
    {
      git -C "$root_dir" status --porcelain 2>/dev/null | sed -E 's/^...//' || true
    } | jq -R . | jq -s '{dirty_paths: map(select(length > 0)), claimed_paths: []}' >"$git_source_path"
  fi
fi

claimed_paths_json="$(array_to_json "${claimed_paths[@]}")"

write_event "capture.started" "ok" "$case_id"

jq -n \
  --slurpfile br "$br_source_path" \
  --slurpfile mail "$mail_source_path" \
  --slurpfile git "$git_source_path" \
  --slurpfile rch "$rch_source_path" \
  --argjson cli_claimed_paths "$claimed_paths_json" \
  --arg schema_version "franken-engine.swarm-proof-request-capture.v1" \
  --arg case_id "$case_id" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg br_source_path "$br_source_path" \
  --arg mail_source_path "$mail_source_path" \
  --arg git_source_path "$git_source_path" \
  --arg rch_source_path "$rch_source_path" \
  --arg capture_path "$capture_path" \
  --arg requests_path "$requests_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def rows($doc):
    if ($doc | type) == "array" then $doc
    elif ($doc.issues? | type) == "array" then $doc.issues
    elif ($doc.rows? | type) == "array" then $doc.rows
    elif ($doc.messages? | type) == "array" then $doc.messages
    else []
    end;
  def reservations($doc):
    if ($doc.reservations? | type) == "array" then $doc.reservations
    elif ($doc.granted? | type) == "array" then $doc.granted
    else []
    end;
  def strings($value):
    if ($value | type) == "string" then [$value]
    elif ($value | type) == "array" then ($value | map(strings(.)) | add // [])
    elif ($value | type) == "object" then ([$value.title?, $value.description?, $value.notes?, $value.body_md?, $value.subject?, $value.command?, $value.validation_command?, $value.requested_command?, $value.transcript?, $value.stderr?, $value.output?] | map(select(type == "string")))
    else []
    end;
  def norm($s): ($s | gsub("[[:space:]]+"; " ") | gsub("^ "; "") | gsub(" $"; ""));
  def commands_from_text($s): [($s // "" | scan("rch exec --[^\\n`\"]*cargo[^\\n`\"]*"))] | map(norm(.));
  def explicit_commands($rows): [$rows[]? | (.command // .validation_command // .requested_command // empty)] | map(norm(.));
  def proof_commands($br; $mail; $rch):
    (
      explicit_commands(rows($rch))
      + ([rows($br)[], rows($mail)[]] | map(strings(.)) | add // [] | map(commands_from_text(.)) | add // [])
    )
    | map(select(length > 0))
    | unique;
  def dirty_paths($git):
    if ($git.dirty_paths? | type) == "array" then
      $git.dirty_paths | map(if type == "object" then (.path // "") else tostring end) | map(select(length > 0))
    elif ($git.paths? | type) == "array" then
      $git.paths | map(if type == "object" then (.path // "") else tostring end) | map(select(length > 0))
    else []
    end;
  def claimed_paths($br; $git; $cli):
    (($cli // []) + ($git.claimed_paths // []) + ($br.claimed_paths // []))
    | map(if type == "object" then (.path // "") else tostring end)
    | map(select(length > 0))
    | unique;
  def overlaps($path; $claim):
    ($path | startswith($claim)) or ($claim | startswith($path));
  def dirty_outside($dirty; $claimed):
    [$dirty[] as $path | select((any($claimed[]; overlaps($path; .))) | not)];
  def local_fallback($rch):
    any(rows($rch)[];
      (.local_fallback_observed == true)
      or ((.transcript // .stderr // .output // "") | test("falling back to local|fallback to local|local fallback|running locally|\\[RCH\\] local"; "i"))
    );
  def first_agent($mail; $rch):
    (rows($rch)[0].agent // rows($rch)[0].agent_name // rows($mail)[0].from // rows($mail)[0].sender_name // "unknown");
  def first_timestamp($mail; $rch):
    (rows($rch)[0].timestamp // rows($rch)[0].created_ts // rows($mail)[0].created_ts // "unknown");
  def evidence($br; $mail; $git; $rch):
    [
      {kind: "br", evidence_path: $br_source_path, id: ((rows($br)[0].id // $bead_id) | tostring)},
      {kind: "agent_mail", evidence_path: $mail_source_path, id: ((rows($mail)[0].id // rows($mail)[0].message_id // "agent-mail-snapshot") | tostring)},
      {kind: "git", evidence_path: $git_source_path, id: "git-status"},
      {kind: "rch_summary", evidence_path: $rch_source_path, id: ((rows($rch)[0].summary_id // rows($rch)[0].id // "rch-summary") | tostring)}
    ];

  ($br[0] // {}) as $br_doc
  | ($mail[0] // {}) as $mail_doc
  | ($git[0] // {}) as $git_doc
  | ($rch[0] // {}) as $rch_doc
  | (proof_commands($br_doc; $mail_doc; $rch_doc)) as $commands
  | (dirty_paths($git_doc)) as $dirty
  | (claimed_paths($br_doc; $git_doc; $cli_claimed_paths)) as $claimed
  | (dirty_outside($dirty; $claimed)) as $dirty_bad
  | (
      if ($br_doc | has("fresh")) then ($br_doc.fresh == true)
      elif ($br_doc | has("snapshot_fresh")) then ($br_doc.snapshot_fresh == true)
      else true
      end
    ) as $br_fresh
  | ((($mail_doc.status // "present") != "missing") and ((rows($mail_doc) | length) > 0 or (reservations($mail_doc) | length) > 0)) as $mail_present
  | (local_fallback($rch_doc)) as $fallback
  | (
      if ($mail_present | not) then ["missing_agent_mail_context"]
      elif ($br_fresh | not) then ["stale_br_snapshot"]
      elif ($dirty_bad | length) > 0 then ["dirty_outside_claimed_lane"]
      elif $fallback then ["local_fallback_contamination"]
      elif ($commands | length) != 1 then ["ambiguous_command_text"]
      else []
      end
    ) as $failures
  | ($failures | length == 0) as $passed
  | (if $passed then
      [{
        trace_id: ("trace-" + $case_id),
        proof_request_id: ("spbreq-capture-" + $case_id),
        bead_id: $bead_id,
        agent: first_agent($mail_doc; $rch_doc),
        command: $commands[0],
        request_kind: (rows($rch_doc)[0].request_kind // "captured_proof_request"),
        captured_at: first_timestamp($mail_doc; $rch_doc),
        source_revision: $source_revision,
        source_evidence: evidence($br_doc; $mail_doc; $git_doc; $rch_doc)
      }]
    else [] end) as $proof_requests
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      bead_id: $bead_id,
      source_revision: $source_revision,
      decision: (if $passed then "pass" else "fail_closed" end),
      fail_closed_reasons: $failures,
      proof_request_count: ($proof_requests | length),
      proof_requests: $proof_requests,
      diagnostics: {
        br_fresh: $br_fresh,
        agent_mail_present: $mail_present,
        command_candidates: $commands,
        dirty_paths: $dirty,
        claimed_paths: $claimed,
        dirty_outside_claimed_lane: $dirty_bad,
        local_fallback_observed: $fallback
      },
      artifact_paths: {
        proof_request_capture_json: $capture_path,
        proof_requests_jsonl: $requests_path,
        run_manifest_json: $manifest_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path,
        br_snapshot_json: $br_source_path,
        agent_mail_snapshot_json: $mail_source_path,
        git_status_json: $git_source_path,
        rch_summary_json: $rch_source_path
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
  ' >"$capture_tmp"
mv "$capture_tmp" "$capture_path"

jq -c '.proof_requests[]?' "$capture_path" >"$requests_path"

decision="$(jq -r '.decision' "$capture_path")"
reason_summary="$(jq -r '.fail_closed_reasons | join(",")' "$capture_path")"
request_count="$(jq -r '.proof_request_count' "$capture_path")"

jq -n \
  --arg schema_version "franken-engine.swarm-proof-request-capture-run-manifest.v1" \
  --arg component "swarm_proof_request_capture" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg reason_summary "$reason_summary" \
  --arg capture_path "$capture_path" \
  --arg requests_path "$requests_path" \
  '{
    schema_version: $schema_version,
    component: $component,
    case_id: $case_id,
    source_revision: $source_revision,
    decision: $decision,
    fail_closed_reason_summary: $reason_summary,
    proof_request_capture_json: $capture_path,
    proof_requests_jsonl: $requests_path,
    executed_heavy_work: false
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

write_event "capture.completed" "$decision" "$reason_summary"

{
  printf '# Swarm Proof Request Capture\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- proof_request_count: \`%s\`\n" "$request_count"
  if [[ -n "$reason_summary" ]]; then
    printf -- "- fail_closed_reasons: \`%s\`\n" "$reason_summary"
  fi
} >"$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
