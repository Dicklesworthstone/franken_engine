#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-agent-mail-identity-reconciler}"
run_id="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_MAIL_IDENTITY_RECONCILER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

agent_name=""
bead_id=""
source_revision=""
profiles_json=""
contacts_json=""
messages_json=""
reservations_json=""
br_issue_json=""
sla_panel_json=""
causal_trace_anomalies_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_agent_mail_identity_reconciler.sh --agent-name NAME --agent-mail-messages-json FILE [OPTIONS]

Builds a fixture-fed, proof-only reconciliation receipt for Agent Mail identity
or recipient drift behind failed acknowledgement attempts. It never queries live
Agent Mail, mutates br, acknowledges messages, approves contacts, releases
reservations, runs cargo/rch, or mutates workers.

Required:
  --agent-name NAME
  --agent-mail-messages-json FILE

Optional:
  --bead-id ID
  --source-revision REV
  --agent-mail-profiles-json FILE
  --agent-mail-contacts-json FILE
  --file-reservations-json FILE
  --br-issue-json FILE
  --agent-mail-sla-panel-json FILE
  --causal-trace-anomalies-json FILE
  --output-dir DIR

Exit codes:
  0   pass or degraded receipt
  42  fail-closed evidence problem
  64  invalid option or malformed required input
  75  blocked identity-drift repair receipt
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --agent-name)
      agent_name="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --agent-mail-profiles-json)
      profiles_json="${2:-}"
      shift 2
      ;;
    --agent-mail-contacts-json)
      contacts_json="${2:-}"
      shift 2
      ;;
    --agent-mail-messages-json)
      messages_json="${2:-}"
      shift 2
      ;;
    --file-reservations-json)
      reservations_json="${2:-}"
      shift 2
      ;;
    --br-issue-json)
      br_issue_json="${2:-}"
      shift 2
      ;;
    --agent-mail-sla-panel-json)
      sla_panel_json="${2:-}"
      shift 2
      ;;
    --causal-trace-anomalies-json)
      causal_trace_anomalies_json="${2:-}"
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

if [[ -z "$agent_name" || -z "$messages_json" ]]; then
  printf 'agent-mail identity reconciler requires --agent-name and --agent-mail-messages-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for Agent Mail identity reconciliation\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for Agent Mail identity reconciliation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
input_path="${run_dir}/swarm_agent_mail_identity_reconciliation_input.json"
sources_path="${run_dir}/swarm_agent_mail_identity_reconciliation_sources.json"
receipt_path="${run_dir}/swarm_agent_mail_identity_reconciliation_receipt.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
source_entries_jsonl="${run_dir}/source_entries.jsonl"
degraded_jsonl="${run_dir}/degraded_reasons.jsonl"
fail_closed_jsonl="${run_dir}/fail_closed_reasons.jsonl"

profiles_normalized="${run_dir}/agent_mail_profiles.normalized.json"
contacts_normalized="${run_dir}/agent_mail_contacts.normalized.json"
messages_normalized="${run_dir}/agent_mail_messages.normalized.json"
reservations_normalized="${run_dir}/file_reservations.normalized.json"
br_issue_normalized="${run_dir}/br_issue.normalized.json"
sla_panel_normalized="${run_dir}/agent_mail_sla_panel.normalized.json"
causal_trace_normalized="${run_dir}/causal_trace_anomalies.normalized.json"

printf './scripts/swarm_agent_mail_identity_reconciler.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$source_entries_jsonl"
: >"$degraded_jsonl"
: >"$fail_closed_jsonl"

emit_event() {
  local event="$1"
  local detail="$2"
  jq -cn --arg event "$event" --arg detail "$detail" \
    '{schema_version:"franken-engine.swarm-agent-mail-identity-reconciliation-event.v1", event:$event, detail:$detail}' >>"$events_path"
}

record_problem() {
  local severity="$1"
  local code="$2"
  local message="$3"
  local source_id="$4"
  case "$severity" in
    degraded)
      jq -cn --arg code "$code" --arg message "$message" --arg source_id "$source_id" \
        '{code:$code, message:$message, source_id:$source_id}' >>"$degraded_jsonl"
      ;;
    fail_closed)
      jq -cn --arg code "$code" --arg message "$message" --arg source_id "$source_id" \
        '{code:$code, message:$message, source_id:$source_id}' >>"$fail_closed_jsonl"
      ;;
    pass|"")
      return
      ;;
    *)
      printf 'unknown problem severity: %s\n' "$severity" >&2
      exit 64
      ;;
  esac
  emit_event "$severity" "${source_id}:${code}"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

write_default_json() {
  local default_json="$1"
  local output="$2"
  printf '%s\n' "$default_json" | jq -cS . >"$output"
}

append_source_entry() {
  local source_id="$1"
  local source_path="$2"
  local normalized_path="$3"
  local required="$4"
  local status="$5"
  local missing_decision="$6"

  jq -cn \
    --arg source_id "$source_id" \
    --arg source_path "$source_path" \
    --arg normalized_path "$normalized_path" \
    --arg content_hash "sha256:$(hash_file "$normalized_path")" \
    --arg status "$status" \
    --arg missing_decision "$missing_decision" \
    --argjson required "$required" \
    '{
      source_id:$source_id,
      source_path:(if $source_path == "" then null else $source_path end),
      normalized_path:$normalized_path,
      content_hash:$content_hash,
      required:$required,
      status:$status,
      missing_decision:$missing_decision
    }' >>"$source_entries_jsonl"
}

normalize_source_json() {
  local source_id="$1"
  local input="$2"
  local output="$3"
  local required="$4"
  local missing_decision="$5"
  local default_json="$6"
  local missing_code="$7"
  local label="$8"
  local status="provided"

  if [[ -z "$input" ]]; then
    write_default_json "$default_json" "$output"
    status="missing"
    record_problem "$missing_decision" "$missing_code" "${label} was not supplied" "$source_id"
  elif [[ ! -f "$input" ]]; then
    write_default_json "$default_json" "$output"
    status="missing"
    record_problem "$missing_decision" "$missing_code" "${label} path does not exist: ${input}" "$source_id"
  elif ! jq -cS . "$input" >"$output"; then
    write_default_json "$default_json" "$output"
    status="malformed"
    record_problem "$missing_decision" "$missing_code" "${label} was malformed JSON" "$source_id"
  else
    emit_event "source_loaded" "$source_id"
  fi

  append_source_entry "$source_id" "$input" "$output" "$required" "$status" "$missing_decision"
}

normalize_source_json "agent_mail_profiles_json" "$profiles_json" "$profiles_normalized" "false" "degraded" '{"agents":[]}' "optional_snapshot_missing" "Agent Mail profiles snapshot"
normalize_source_json "agent_mail_contacts_json" "$contacts_json" "$contacts_normalized" "false" "degraded" '{"contacts":[]}' "optional_snapshot_missing" "Agent Mail contacts snapshot"
normalize_source_json "agent_mail_messages_json" "$messages_json" "$messages_normalized" "true" "fail_closed" '{"messages":[],"ack_attempts":[]}' "missing_required_agent_mail_messages" "Agent Mail messages snapshot"
normalize_source_json "file_reservations_json" "$reservations_json" "$reservations_normalized" "false" "degraded" '{"reservations":[]}' "optional_snapshot_missing" "Agent Mail file reservations snapshot"
normalize_source_json "br_issue_json" "$br_issue_json" "$br_issue_normalized" "false" "degraded" '{}' "optional_snapshot_missing" "br issue snapshot"
normalize_source_json "agent_mail_sla_panel_json" "$sla_panel_json" "$sla_panel_normalized" "false" "degraded" '{"diagnostics":[]}' "optional_snapshot_missing" "Agent Mail SLA panel snapshot"
normalize_source_json "causal_trace_anomalies_json" "$causal_trace_anomalies_json" "$causal_trace_normalized" "false" "degraded" '{"anomalies":[]}' "optional_snapshot_missing" "causal trace anomalies snapshot"

jq -s . "$degraded_jsonl" >"${run_dir}/source_degraded_reasons.json"
jq -s . "$fail_closed_jsonl" >"${run_dir}/source_fail_closed_reasons.json"

jq -n \
  --slurpfile profiles "$profiles_normalized" \
  --slurpfile contacts "$contacts_normalized" \
  --slurpfile messages "$messages_normalized" \
  --slurpfile reservations "$reservations_normalized" \
  --slurpfile br_issue "$br_issue_normalized" \
  --slurpfile sla "$sla_panel_normalized" \
  --slurpfile causal "$causal_trace_normalized" \
  --slurpfile source_degraded "${run_dir}/source_degraded_reasons.json" \
  --slurpfile source_fail_closed "${run_dir}/source_fail_closed_reasons.json" \
  --arg schema_version "franken-engine.swarm-agent-mail-identity-reconciliation-receipt.v1" \
  --arg agent_name "$agent_name" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg sources_path "$sources_path" \
  --arg receipt_path "$receipt_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def rows($x; $field):
    if ($x | type) == "array" then $x
    elif ($x | type) == "object" and ($x | has($field)) and (($x[$field] // null) | type) == "array" then $x[$field]
    elif ($x | type) == "object" and ($x | has("result")) and (($x.result // null) | type) == "array" then $x.result
    else [] end;
  def agent_rows: rows($profiles[0]; "agents");
  def contact_rows: rows($contacts[0]; "contacts") + rows($contacts[0]; "links");
  def message_rows: rows($messages[0]; "messages") + rows($messages[0]; "inbox");
  def ack_attempt_rows:
    rows($messages[0]; "ack_attempts")
    + rows($messages[0]; "acknowledgement_attempts")
    + rows($messages[0]; "message_ack_attempts");
  def reservation_rows: rows($reservations[0]; "reservations") + rows($reservations[0]; "granted");
  def sla_diagnostics: rows($sla[0]; "diagnostics");
  def causal_anomalies: rows($causal[0]; "anomalies");
  def br_issue_obj:
    if ($br_issue[0] | type) == "array" then ($br_issue[0][0] // {})
    elif ($br_issue[0] | type) == "object" and ($br_issue[0] | has("id")) then $br_issue[0]
    elif ($br_issue[0] | type) == "object" and ($br_issue[0] | has("issues")) then ($br_issue[0].issues[0] // {})
    else {} end;
  def raw_error($a): (($a.error // $a.error_message // $a.detail // "") | tostring);
  def failed($a): (($a.success // $a.acknowledged // false) == false);
  def parse_error($err):
    if ($err | test("^MessageRecipient not found: [0-9]+:[0-9]+$")) then
      ($err | capture("^MessageRecipient not found: (?<message_recipient_row_id>[0-9]+):(?<message_id>[0-9]+)$"))
      | . + {pattern_id:"message_recipient_not_found"}
    elif ($err | test("^AgentLink not found: [^:]+:.+$")) then
      ($err | capture("^AgentLink not found: (?<from_agent>[^:]+):(?<to_agent>.+)$"))
      | . + {pattern_id:"agent_link_not_found"}
    elif ($err | test("contact policy"; "i")) then
      {pattern_id:"contact_policy_blocked"}
    else
      {pattern_id:"unknown"}
    end;
  def agent_names: [agent_rows[] | (.name // .agent_name // "") | select(length > 0)];
  def contact_names: [contact_rows[] | (.to_agent // .target // .agent_name // .name // "") | select(length > 0)];
  def issue_assignee: (br_issue_obj.assignee // "");
  def attempted_agent($a): ($a.agent_name // $a.recipient // $a.to_agent // "");
  def inferred_thread($a): ($a.thread_id // $a.bead_id // $bead_id);
  def anomaly($class; $severity; $a; $parsed; $detail; $recipe):
    {
      anomaly_class:$class,
      severity:$severity,
      raw_error:raw_error($a),
      parsed_error:$parsed,
      affected_entities:{
        message_id:($a.message_id // $a.id // $parsed.message_id // null),
        message_recipient_row_id:($parsed.message_recipient_row_id // null),
        from_agent:($a.from_agent // $parsed.from_agent // null),
        to_agent:($a.to_agent // $a.recipient // $parsed.to_agent // null),
        thread_id:inferred_thread($a),
        bead_id:($a.bead_id // $bead_id),
        contact_link_id:($a.contact_link_id // null),
        reservation_id:null,
        reservation_path:null
      },
      detail:$detail,
      manual_repair_recipe:$recipe
    };
  def source_problem_anomalies($rows; $severity):
    [$rows[]? | {
      anomaly_class:(.code // "source_problem"),
      severity:$severity,
      raw_error:"",
      parsed_error:{pattern_id:"source_problem"},
      affected_entities:{message_id:null,message_recipient_row_id:null,from_agent:null,to_agent:null,thread_id:$bead_id,bead_id:$bead_id,contact_link_id:null,reservation_id:null,reservation_path:null},
      detail:(.message // ""),
      manual_repair_recipe:"Capture the missing fixture snapshot before trusting the reconciliation receipt."
    }];
  def failed_attempts: [ack_attempt_rows[] | select(failed(.) == true)];
  def failed_with_raw: [failed_attempts[] | select((raw_error(.) | length) > 0)];
  def failed_without_raw: [failed_attempts[] | select((raw_error(.) | length) == 0)];
  def ack_failure_claimed:
    any(sla_diagnostics[]?; (.code // "") == "ack_attempt_failed")
    or any(causal_anomalies[]?; (.anomaly_class // "") == "ack_attempt_failed");
  (
    source_problem_anomalies($source_degraded[0]; "degraded")
    + source_problem_anomalies($source_fail_closed[0]; "fail_closed")
    + (if ((ack_attempt_rows | length) == 0 and ack_failure_claimed) then [{
        anomaly_class:"missing_ack_attempt_snapshot",
        severity:"fail_closed",
        raw_error:"",
        parsed_error:{pattern_id:"missing_ack_attempt_snapshot"},
        affected_entities:{message_id:null,message_recipient_row_id:null,from_agent:null,to_agent:null,thread_id:$bead_id,bead_id:$bead_id,contact_link_id:null,reservation_id:null,reservation_path:null},
        detail:"SLA or causal-trace evidence reports ack_attempt_failed, but the Agent Mail message snapshot did not include ack attempt rows.",
        manual_repair_recipe:"Recapture the Agent Mail thread snapshot with ack_attempts or acknowledgement_attempts before accepting repair evidence."
      }] else [] end)
    + [failed_without_raw[] as $a | anomaly(
        "missing_raw_error";
        "fail_closed";
        $a;
        {pattern_id:"missing_raw_error"};
        "Failed acknowledgement attempt lacks raw error text.";
        "Recapture the failed acknowledgement attempt and preserve the exact error string before diagnosing identity drift."
      )]
    + [failed_with_raw[] as $a
        | (parse_error(raw_error($a))) as $parsed
        | if $parsed.pattern_id == "message_recipient_not_found" then
            anomaly(
              "stale_message_recipient_row";
              "blocked";
              $a;
              $parsed;
              "Agent Mail reports a missing MessageRecipient row for the failed acknowledgement attempt.";
              ("Manual recipe only: verify message " + (($parsed.message_id // $a.message_id // $a.id // "") | tostring) + " and recipient row " + (($parsed.message_recipient_row_id // "") | tostring) + ", then rerun acknowledge_message only after confirming the live recipient mapping.")
            )
          elif $parsed.pattern_id == "agent_link_not_found" then
            anomaly(
              "stale_contact_link";
              "blocked";
              $a;
              $parsed;
              "Agent Mail reports a missing AgentLink/contact relationship for the failed acknowledgement attempt.";
              "Manual recipe only: run list_contacts for the affected agents, then request_contact/respond_contact only if the live contact policy still permits it."
            )
          elif $parsed.pattern_id == "contact_policy_blocked" then
            anomaly(
              "blocked_contact_policy";
              "blocked";
              $a;
              $parsed;
              "Contact policy blocks or may block the acknowledgement path.";
              "Manual recipe only: inspect the recipient contact policy and request explicit contact approval before retrying the acknowledgement."
            )
          else
            anomaly(
              "unparsable_ack_error";
              "fail_closed";
              $a;
              $parsed;
              "Failed acknowledgement error did not match a supported identity-drift pattern.";
              "Extend the parser or preserve the blocker manually before accepting the reconciliation receipt."
            )
          end]
    + [failed_with_raw[] as $a
        | attempted_agent($a) as $candidate
        | select($candidate != "" and ((agent_names | index($candidate)) == null))
        | anomaly(
            "missing_agent_profile";
            "degraded";
            $a;
            parse_error(raw_error($a));
            ("No Agent Mail profile snapshot row was supplied for " + $candidate + ".");
            "Recapture Agent Mail list_agents output before relying on profile freshness."
          )]
    + [failed_with_raw[] as $a
        | attempted_agent($a) as $candidate
        | select($candidate != "" and (contact_names | length) > 0 and ((contact_names | index($candidate)) == null))
        | anomaly(
            "unknown_agent_profile";
            "degraded";
            $a;
            parse_error(raw_error($a));
            ("Contact snapshot does not include the attempted recipient " + $candidate + ".");
            "Recapture list_contacts for the affected agents before retrying acknowledgement."
          )]
    + [reservation_rows[] as $r
        | ($r.agent_name // $r.agent // $r.holder // "") as $holder
        | select($holder != "" and issue_assignee != "" and $holder != issue_assignee and (($r.released_ts // null) == null))
        | {
            anomaly_class:"contradictory_active_reservation",
            severity:"blocked",
            raw_error:"",
            parsed_error:{pattern_id:"reservation_owner_conflict"},
            affected_entities:{message_id:null,message_recipient_row_id:null,from_agent:null,to_agent:$holder,thread_id:$bead_id,bead_id:($r.bead_id // $bead_id),contact_link_id:null,reservation_id:($r.id // $r.file_reservation_id // null),reservation_path:($r.path_pattern // $r.path // null)},
            detail:("Active reservation holder " + $holder + " differs from br assignee " + issue_assignee + "."),
            manual_repair_recipe:"Manual recipe only: coordinate with the reservation holder and use release_file_reservations or force_release_file_reservation only after explicit stale-owner review."
          }]
  ) as $anomalies
  | {
      schema_version:$schema_version,
      decision:(if any($anomalies[]; .severity == "fail_closed") then "fail_closed" elif any($anomalies[]; .severity == "blocked") then "blocked" elif any($anomalies[]; .severity == "degraded") then "degraded" else "pass" end),
      evaluated_at:(now | todateiso8601),
      source_revision:$source_revision,
      agent_name:$agent_name,
      bead_id:$bead_id,
      thread_id:(([failed_with_raw[]?.thread_id, failed_with_raw[]?.bead_id, $bead_id] | map(select(. != null and . != "")))[0] // ""),
      raw_error:(([failed_with_raw[] | raw_error(.)] | .[0]) // ""),
      parsed_error:((([failed_with_raw[] | parse_error(raw_error(.))] | .[0]) // {pattern_id:"none"})),
      affected_entities:(([$anomalies[]?.affected_entities] | .[0]) // {message_id:null,message_recipient_row_id:null,from_agent:null,to_agent:null,thread_id:$bead_id,bead_id:$bead_id,contact_link_id:null,reservation_id:null,reservation_path:null}),
      anomaly_classes:($anomalies | map(.anomaly_class) | unique | sort),
      evidence:{
        agent_profile_count:(agent_rows | length),
        contact_count:(contact_rows | length),
        message_count:(message_rows | length),
        ack_attempt_count:(ack_attempt_rows | length),
        failed_ack_attempt_count:(failed_attempts | length),
        reservation_count:(reservation_rows | length),
        source_degraded_reasons:$source_degraded[0],
        source_fail_closed_reasons:$source_fail_closed[0],
        anomalies:$anomalies
      },
      manual_repair_recipes:($anomalies | map({anomaly_class, severity, affected_entities, recipe:.manual_repair_recipe}) | unique_by(.anomaly_class, (.affected_entities | tostring))),
      artifact_paths:{
        input_json:$input_path,
        sources_json:$sources_path,
        receipt_json:$receipt_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path
      },
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_agent_mail:false,
        acknowledges_messages:false,
        sends_agent_mail:false,
        approves_contacts:false,
        mutates_br:false,
        reassigns_beads:false,
        closes_beads:false,
        releases_reservations:false,
        force_releases_reservations:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }
' >"$receipt_path"

jq -n \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg agent_mail_profiles_json "$profiles_json" \
  --arg agent_mail_contacts_json "$contacts_json" \
  --arg agent_mail_messages_json "$messages_json" \
  --arg file_reservations_json "$reservations_json" \
  --arg br_issue_json "$br_issue_json" \
  --arg agent_mail_sla_panel_json "$sla_panel_json" \
  --arg causal_trace_anomalies_json "$causal_trace_anomalies_json" \
  '{
    schema_version:"franken-engine.swarm-agent-mail-identity-reconciliation-input.v1",
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    source_paths:{
      agent_mail_profiles_json:$agent_mail_profiles_json,
      agent_mail_contacts_json:$agent_mail_contacts_json,
      agent_mail_messages_json:$agent_mail_messages_json,
      file_reservations_json:$file_reservations_json,
      br_issue_json:$br_issue_json,
      agent_mail_sla_panel_json:$agent_mail_sla_panel_json,
      causal_trace_anomalies_json:$causal_trace_anomalies_json
    }
  }' >"$input_path"

jq -s \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  '{
    schema_version:"franken-engine.swarm-agent-mail-identity-reconciliation-sources.v1",
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    sources:.
  }' "$source_entries_jsonl" >"$sources_path"

decision="$(jq -r '.decision' "$receipt_path")"
anomaly_count="$(jq '.evidence.anomalies | length' "$receipt_path")"
emit_event "reconciliation_complete" "$decision"

{
  printf '# Agent Mail Identity Reconciliation\n\n'
  printf -- '- Decision: `%s`\n' "$decision"
  printf -- '- Bead: `%s`\n' "${bead_id:-unknown}"
  printf -- '- Agent: `%s`\n' "$agent_name"
  printf -- '- Anomalies: `%s`\n' "$anomaly_count"
} >"$report_path"

printf 'swarm_agent_mail_identity_reconciliation_receipt=%s\n' "$receipt_path"
case "$decision" in
  fail_closed) exit 42 ;;
  blocked) exit 75 ;;
  *) exit 0 ;;
esac
