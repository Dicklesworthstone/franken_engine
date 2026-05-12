#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${AGENT_RUN_EVIDENCE_INDEX_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-run-evidence-index}"
run_id="${AGENT_RUN_EVIDENCE_INDEX_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${AGENT_RUN_EVIDENCE_INDEX_RUN_DIR:-${artifact_root}/${run_id}}"
run_snapshot_json=""
source_revision_override=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/agent_run_evidence_index.sh --run-snapshot-json FILE [OPTIONS]

Builds a fixture-fed agent-run evidence index that links bead, Agent Mail,
commit, validation command, RCH manifest, artifact bundle, and causal graph
evidence. The script reuses the existing swarm causal trace normalizer and
graph producers. It does not query live services and does not run Cargo or rch.

Options:
  --run-snapshot-json FILE    Preserved agent-run snapshot JSON.
  --source-revision REV       Override source revision recorded in the index.
  --output-dir DIR            Artifact output directory.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --run-snapshot-json)
      run_snapshot_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision_override="${2:-}"
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
  printf 'jq is required for agent-run evidence indexing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for agent-run evidence indexing\n' >&2
  exit 2
fi
if [[ -z "$run_snapshot_json" || ! -f "$run_snapshot_json" ]]; then
  printf 'agent-run evidence index requires --run-snapshot-json\n' >&2
  usage
  exit 64
fi
if ! jq -e '
  type == "object"
  and .schema_version == "franken-engine.agent-run-evidence-index.snapshot.v1"
  and ((.bead_id // "") | length > 0)
  and ((.agent_name // "") | length > 0)
  and (.sources | type == "object")
' "$run_snapshot_json" >/dev/null; then
  printf 'run snapshot must match franken-engine.agent-run-evidence-index.snapshot.v1\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
sources_dir="${run_dir}/sources"
normalizer_dir="${run_dir}/causal_trace_normalizer"
graph_dir="${run_dir}/causal_trace_graph"
index_core="${run_dir}/agent_run_evidence_index.core.json"
index_path="${run_dir}/agent_run_evidence_index.json"
index_tmp="${index_path}.tmp"
edges_jsonl="${run_dir}/index_edges.jsonl"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in "$sources_dir" "$normalizer_dir" "$graph_dir" "$index_core" "$index_path" "$index_tmp" "$edges_jsonl" "$events_path" "$commands_path" "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done
mkdir -p "$sources_dir"
: >"$events_path"
: >"$edges_jsonl"

bead_id="$(jq -r '.bead_id' "$run_snapshot_json")"
agent_name="$(jq -r '.agent_name' "$run_snapshot_json")"
source_revision="$source_revision_override"
if [[ -z "$source_revision" ]]; then
  source_revision="$(jq -r '.source_revision // ""' "$run_snapshot_json")"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.agent-run-evidence-index.event.v1" \
    --arg event "$1" \
    --arg detail "$2" \
    --arg bead_id "$bead_id" \
    --arg agent_name "$agent_name" \
    '{schema_version:$schema_version,event:$event,detail:$detail,bead_id:$bead_id,agent_name:$agent_name}' >>"$events_path"
}

write_optional_source() {
  local key="$1"
  local output="${sources_dir}/${key}.json"
  if jq -e --arg key "$key" '.sources[$key] != null' "$run_snapshot_json" >/dev/null; then
    jq --arg key "$key" '.sources[$key]' "$run_snapshot_json" >"$output"
    printf '%s\n' "$output"
  else
    printf '\n'
  fi
}

printf './scripts/agent_run_evidence_index.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

br_issue_json="$(write_optional_source br_issue_json)"
br_ready_json="$(write_optional_source br_ready_json)"
br_sync_status_json="$(write_optional_source br_sync_status_json)"
bv_actionable_plan_json="$(write_optional_source bv_actionable_plan_json)"
agent_mail_profiles_json="$(write_optional_source agent_mail_profiles_json)"
agent_mail_messages_json="$(write_optional_source agent_mail_messages_json)"
file_reservations_json="$(write_optional_source file_reservations_json)"
declared_write_set_json="$(write_optional_source declared_write_set_json)"
git_status_json="$(write_optional_source git_status_json)"
git_closeout_commits_json="$(write_optional_source git_closeout_commits_json)"
rch_validation_artifacts_json="$(write_optional_source rch_validation_artifacts_json)"
validation_commands_json="$(write_optional_source validation_commands_json)"
operator_status_json="$(write_optional_source operator_status_json)"

if [[ -z "$br_issue_json" ]]; then
  printf 'run snapshot must include sources.br_issue_json\n' >&2
  exit 64
fi

normalizer_cmd=(
  "${root_dir}/scripts/swarm_agent_causal_trace_normalizer.sh"
  --bead-id "$bead_id"
  --agent-name "$agent_name"
  --source-revision "$source_revision"
  --br-issue-json "$br_issue_json"
  --output-dir "$normalizer_dir"
)
[[ -n "$br_ready_json" ]] && normalizer_cmd+=(--br-ready-json "$br_ready_json")
[[ -n "$br_sync_status_json" ]] && normalizer_cmd+=(--br-sync-status-json "$br_sync_status_json")
[[ -n "$bv_actionable_plan_json" ]] && normalizer_cmd+=(--bv-actionable-plan-json "$bv_actionable_plan_json")
[[ -n "$agent_mail_profiles_json" ]] && normalizer_cmd+=(--agent-mail-profiles-json "$agent_mail_profiles_json")
[[ -n "$agent_mail_messages_json" ]] && normalizer_cmd+=(--agent-mail-messages-json "$agent_mail_messages_json")
[[ -n "$file_reservations_json" ]] && normalizer_cmd+=(--file-reservations-json "$file_reservations_json")
[[ -n "$declared_write_set_json" ]] && normalizer_cmd+=(--declared-write-set-json "$declared_write_set_json")
[[ -n "$git_status_json" ]] && normalizer_cmd+=(--git-status-json "$git_status_json")
[[ -n "$git_closeout_commits_json" ]] && normalizer_cmd+=(--git-closeout-commits-json "$git_closeout_commits_json")
[[ -n "$rch_validation_artifacts_json" ]] && normalizer_cmd+=(--rch-validation-artifacts-json "$rch_validation_artifacts_json")
[[ -n "$validation_commands_json" ]] && normalizer_cmd+=(--validation-commands-json "$validation_commands_json")
[[ -n "$operator_status_json" ]] && normalizer_cmd+=(--operator-status-json "$operator_status_json")

printf './scripts/swarm_agent_causal_trace_normalizer.sh' >>"$commands_path"
for arg in "${normalizer_cmd[@]:1}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event "index_started" "running causal trace normalizer"
set +e
"${normalizer_cmd[@]}" >"${run_dir}/normalizer.stdout" 2>"${run_dir}/normalizer.stderr"
normalizer_exit_code=$?
set -e
if [[ "$normalizer_exit_code" -ne 0 && "$normalizer_exit_code" -ne 42 ]]; then
  printf 'causal trace normalizer failed with exit %s\n' "$normalizer_exit_code" >&2
  exit "$normalizer_exit_code"
fi
if [[ ! -f "${normalizer_dir}/swarm_agent_causal_trace_events.json" ]]; then
  printf 'causal trace normalizer did not emit swarm_agent_causal_trace_events.json\n' >&2
  exit 64
fi

graph_cmd=(
  "${root_dir}/scripts/swarm_agent_causal_trace_graph.sh"
  --normalized-events-json "${normalizer_dir}/swarm_agent_causal_trace_events.json"
  --output-dir "$graph_dir"
)
printf './scripts/swarm_agent_causal_trace_graph.sh' >>"$commands_path"
for arg in "${graph_cmd[@]:1}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event "normalizer_completed" "running causal trace graph"
set +e
"${graph_cmd[@]}" >"${run_dir}/graph.stdout" 2>"${run_dir}/graph.stderr"
graph_exit_code=$?
set -e
if [[ "$graph_exit_code" -ne 0 && "$graph_exit_code" -ne 42 ]]; then
  printf 'causal trace graph failed with exit %s\n' "$graph_exit_code" >&2
  exit "$graph_exit_code"
fi
if [[ ! -f "${graph_dir}/swarm_agent_causal_trace_graph.json" ]]; then
  printf 'causal trace graph did not emit swarm_agent_causal_trace_graph.json\n' >&2
  exit 64
fi

jq -n \
  --slurpfile snapshot "$run_snapshot_json" \
  --slurpfile normalizer "${normalizer_dir}/swarm_agent_causal_trace_normalizer_summary.json" \
  --slurpfile graph "${graph_dir}/swarm_agent_causal_trace_graph.json" \
  --arg schema_version "franken-engine.agent-run-evidence-index.v1" \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg run_snapshot_json "$run_snapshot_json" \
  --arg normalizer_events_json "causal_trace_normalizer/swarm_agent_causal_trace_events.json" \
  --arg causal_graph_json "causal_trace_graph/swarm_agent_causal_trace_graph.json" \
  --arg index_edges_jsonl "index_edges.jsonl" \
  --arg events_jsonl "events.jsonl" \
  --arg commands_txt "commands.txt" \
  --arg report_md "report.md" \
  --argjson normalizer_exit_code "$normalizer_exit_code" \
  --argjson graph_exit_code "$graph_exit_code" \
  '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def present($name): $snapshot[0].sources[$name] != null;
  def rows($name; $field):
    if present($name) | not then []
    elif (($snapshot[0].sources[$name] | type) == "array") then $snapshot[0].sources[$name]
    elif (($snapshot[0].sources[$name] | type) == "object" and ($snapshot[0].sources[$name] | has($field))) then $snapshot[0].sources[$name][$field]
    else [] end;
  def issue_rows:
    if present("br_issue_json") | not then []
    elif (($snapshot[0].sources.br_issue_json | type) == "array") then $snapshot[0].sources.br_issue_json
    elif (($snapshot[0].sources.br_issue_json | type) == "object" and ($snapshot[0].sources.br_issue_json | has("issues"))) then $snapshot[0].sources.br_issue_json.issues
    else [$snapshot[0].sources.br_issue_json] end;
  def artifact_manifest_present:
    any(rows("rch_validation_artifacts_json"; "artifacts")[]?;
      (((.artifact_path // .path // "") | test("(^|/)run_manifest\\.json$|(^|/)manifest\\.json$"))
       and (((.content_hash // .sha256 // "") | length) > 0))
    );
  def edge($type; $status; $source; $detail; $hash_or_revision):
    {
      edge_id:("agent-run-edge-" + $type),
      edge_type:$type,
      status:$status,
      source:$source,
      evidence_path:($source + ".json"),
      hash_or_revision:$hash_or_revision,
      detail:$detail
    };
  ($snapshot[0].complete_run_expected // false) as $complete
  | (issue_rows | map(select((.id // "") == $bead_id)) | length) as $bead_count
  | (rows("agent_mail_profiles_json"; "agents") | length) as $profile_count
  | (rows("agent_mail_messages_json"; "messages") | length) as $message_count
  | (rows("git_closeout_commits_json"; "commits") | length) as $commit_count
  | (rows("validation_commands_json"; "commands") | length) as $command_count
  | (rows("rch_validation_artifacts_json"; "artifacts") | length) as $rch_artifact_count
  | artifact_manifest_present as $manifest_present
  | [
      edge("bead"; (if $bead_count > 0 then "observed" else "missing" end); "br_issue_json"; "bead identity evidence"; $source_revision),
      edge("agent_mail_thread"; (if ($profile_count > 0 and $message_count > 0) then "observed" else "degraded" end); "agent_mail_messages_json"; "Agent Mail profile/message thread evidence"; $source_revision),
      edge("closeout_commit"; (if $commit_count > 0 then "observed" else "missing" end); "git_closeout_commits_json"; "closeout commit evidence"; $source_revision),
      edge("validation_command_transcript"; (if $command_count > 0 then "observed" else "missing" end); "validation_commands_json"; "validation command transcript evidence"; $source_revision),
      edge("rch_artifact_manifest"; (if $manifest_present then "observed" elif $rch_artifact_count > 0 then "degraded" else "missing" end); "rch_validation_artifacts_json"; "RCH run manifest or artifact bundle evidence"; $source_revision),
      edge("causal_trace_graph"; ($graph[0].anomaly_summary.decision // "missing"); "causal_trace_graph"; "reused swarm causal trace graph"; ($graph[0].trace_id // $source_revision))
    ] as $edges
  | ([
      if $complete and $bead_count == 0 then {code:"complete_run_missing_bead", message:"complete run snapshot has no matching bead state"} else empty end,
      if $complete and $commit_count == 0 then {code:"complete_run_missing_commit", message:"complete run snapshot has no closeout commit evidence"} else empty end,
      if $complete and $command_count == 0 then {code:"complete_run_missing_command_transcript", message:"complete run snapshot has no validation command transcript"} else empty end,
      if $complete and ($manifest_present | not) then {code:"complete_run_missing_artifact_manifest", message:"complete run snapshot has no RCH run manifest or artifact bundle hash"} else empty end,
      if ($graph[0].anomaly_summary.decision // "pass") == "fail_closed" then {code:"causal_trace_graph_fail_closed", message:"reused causal trace graph reported fail_closed"} else empty end
    ]) as $fail_closed
  | ([
      if ($profile_count == 0 or $message_count == 0) then {code:"agent_mail_snapshot_missing", message:"Agent Mail snapshot is missing or empty"} else empty end,
      if ($graph[0].anomaly_summary.decision // "pass") == "degraded" then {code:"causal_trace_graph_degraded", message:"reused causal trace graph reported degraded"} else empty end
    ]) as $degraded
  | (if ($fail_closed | length) > 0 then "fail_closed"
     elif ($degraded | length) > 0 then "degraded"
     else "pass" end) as $decision
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      agent_name:$agent_name,
      source_revision:$source_revision,
      complete_run_expected:$complete,
      decision:$decision,
      normalizer_exit_code:$normalizer_exit_code,
      graph_exit_code:$graph_exit_code,
      fail_closed_reasons:$fail_closed,
      degraded_reasons:$degraded,
      index_edges:$edges,
      summary:{
        edge_count:($edges | length),
        observed_edge_count:([$edges[] | select(.status == "observed")] | length),
        missing_edge_count:([$edges[] | select(.status == "missing")] | length),
        degraded_edge_count:([$edges[] | select(.status == "degraded")] | length)
      },
      reused_artifacts:{
        normalizer_summary:($normalizer[0].artifact_paths // {}),
        causal_graph:($graph[0].artifact_paths // {})
      },
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        run_snapshot_json:$run_snapshot_json,
        normalizer_events_json:$normalizer_events_json,
        causal_graph_json:$causal_graph_json,
        agent_run_evidence_index_json:"agent_run_evidence_index.json",
        index_edges_jsonl:$index_edges_jsonl,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      }
    }
  ' >"$index_core"

index_hash="$(jq -cS '{bead_id,agent_name,source_revision,decision,index_edges,fail_closed_reasons,degraded_reasons}' "$index_core" | sha256sum | awk '{print substr($1, 1, 16)}')"
jq --arg index_id "agent-run-evidence-${index_hash}" '. + {index_id:$index_id}' "$index_core" >"$index_tmp"
mv "$index_tmp" "$index_path"
jq -c '.index_edges[]' "$index_path" >"$edges_jsonl"

decision="$(jq -r '.decision' "$index_path")"
write_event "index_emitted" "$decision"
{
  printf '# Agent Run Evidence Index\n\n'
  printf -- "- index_id: \`%s\`\n" "$(jq -r '.index_id' "$index_path")"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- bead: \`%s\`\n" "$bead_id"
  printf -- "- agent: \`%s\`\n" "$agent_name"
  printf -- "- edges: \`%s\`\n" "$(jq -r '.summary.edge_count' "$index_path")"
  printf -- "- fail-closed reasons: \`%s\`\n" "$(jq -r '.fail_closed_reasons | length' "$index_path")"
  printf -- "- degraded reasons: \`%s\`\n" "$(jq -r '.degraded_reasons | length' "$index_path")"
} >"$report_path"

printf 'agent_run_evidence_index=%s\n' "$index_path"
printf 'agent_run_evidence_decision=%s\n' "$decision"
if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
