#!/usr/bin/env bash
set -euo pipefail

artifact_root="${RCH_WORKER_TRUTH_PARITY_LEDGER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-worker-truth-parity-ledger}"
run_id="${RCH_WORKER_TRUTH_PARITY_LEDGER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_WORKER_TRUTH_PARITY_LEDGER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

daemon_workers_json=""
probe_workers_json=""
queue_diagnostics_json=""
incident_packet_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_worker_truth_parity_ledger.sh --daemon-workers-json FILE --probe-workers-json FILE [OPTIONS]

Reconcile rch daemon worker state, probe/capability snapshots, queue diagnostics,
and incident evidence into one fail-closed worker-truth report.

Required:
  --daemon-workers-json FILE
  --probe-workers-json FILE

Optional:
  --queue-diagnostics-json FILE
  --incident-packet-json FILE
  --output-dir DIR

Artifacts:
  worker_truth_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   snapshot parity holds and no ghost-job drift is present
  42  fail-closed due to parity drift, drained-worker disappearance, or ghost-job evidence
  64  invalid or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --daemon-workers-json)
      daemon_workers_json="${2:-}"
      shift 2
      ;;
    --probe-workers-json)
      probe_workers_json="${2:-}"
      shift 2
      ;;
    --queue-diagnostics-json)
      queue_diagnostics_json="${2:-}"
      shift 2
      ;;
    --incident-packet-json)
      incident_packet_json="${2:-}"
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

if [[ -z "$daemon_workers_json" || -z "$probe_workers_json" ]]; then
  printf 'rch worker truth parity ledger requires --daemon-workers-json and --probe-workers-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for rch worker truth parity ledger\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
report_path="${run_dir}/worker_truth_report.json"
report_tmp="${report_path}.tmp"
summary_path="${run_dir}/report.md"
summary_tmp="${summary_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
daemon_normalized="${run_dir}/daemon_workers.normalized.json"
probe_normalized="${run_dir}/probe_workers.normalized.json"
queue_normalized="${run_dir}/queue_diagnostics.normalized.json"
incident_normalized="${run_dir}/incident_packet.normalized.json"
: >"$events_path"

printf './scripts/rch_worker_truth_parity_ledger.sh' >"$commands_path"
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
  local default_json="$2"
  local output_path="$3"
  local label="$4"

  if [[ -z "$path" ]]; then
    printf '%s\n' "$default_json" >"$output_path"
    printf 'missing'
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf 'rch worker truth parity ledger missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'rch worker truth parity ledger invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  printf 'provided'
}

if [[ ! -f "$daemon_workers_json" ]]; then
  printf 'rch worker truth parity ledger missing daemon worker JSON: %s\n' "$daemon_workers_json" >&2
  exit 64
fi
if ! jq empty "$daemon_workers_json" >/dev/null 2>&1; then
  printf 'rch worker truth parity ledger invalid daemon worker JSON: %s\n' "$daemon_workers_json" >&2
  exit 64
fi
if [[ ! -f "$probe_workers_json" ]]; then
  printf 'rch worker truth parity ledger missing probe worker JSON: %s\n' "$probe_workers_json" >&2
  exit 64
fi
if ! jq empty "$probe_workers_json" >/dev/null 2>&1; then
  printf 'rch worker truth parity ledger invalid probe worker JSON: %s\n' "$probe_workers_json" >&2
  exit 64
fi

jq -cS '
  def rows:
    if type == "array" then .
    elif (.workers? | type) == "array" then .workers
    else [] end;
  def healthy_status($status):
    ($status | ascii_downcase) as $value
    | ($value == "idle" or $value == "available" or $value == "ok");
  {
    workers: (
      rows
      | map({
          worker_id: (.worker_id // .worker // .name // .id // ""),
          status: (.status // "unknown"),
          drained: (
            if (.drained | type) == "boolean" then .drained
            else ((.status // "") | ascii_downcase | test("drain"))
            end
          ),
          healthy: healthy_status(.status // "unknown"),
          cpu_slots_available: (.cpu_slots_available // .available_cpu_slots // 0)
        })
      | map(select(.worker_id != ""))
      | sort_by(.worker_id)
    )
  }
' "$daemon_workers_json" >"$daemon_normalized"
write_event "daemon_snapshot_loaded" "normalized daemon worker snapshot"

jq -cS '
  def rows:
    if type == "array" then .
    elif (.workers? | type) == "array" then .workers
    else [] end;
  def healthy_status($status):
    ($status | ascii_downcase) as $value
    | ($value == "idle" or $value == "available" or $value == "ok");
  {
    workers: (
      rows
      | map({
          worker_id: (.worker_id // .worker // .name // .id // ""),
          status: (.status // "unknown"),
          projects_root_ok: (
            if (.projects_root_ok | type) == "boolean" then .projects_root_ok
            else true
            end
          ),
          toolchain_ready: (
            if (.nightly_available | type) == "boolean" then .nightly_available
            elif (.toolchain_ready | type) == "boolean" then .toolchain_ready
            elif (.toolchain_ok | type) == "boolean" then .toolchain_ok
            else true
            end
          ),
          schedulable: (
            if (.schedulable | type) == "boolean" then .schedulable
            elif (.selectable | type) == "boolean" then .selectable
            else (
              healthy_status(.status // "unknown")
              and (
                if (.projects_root_ok | type) == "boolean" then .projects_root_ok
                else true
                end
              )
              and (
                if (.nightly_available | type) == "boolean" then .nightly_available
                elif (.toolchain_ready | type) == "boolean" then .toolchain_ready
                elif (.toolchain_ok | type) == "boolean" then .toolchain_ok
                else true
                end
              )
            )
            end
          )
        })
      | map(select(.worker_id != ""))
      | sort_by(.worker_id)
    )
  }
' "$probe_workers_json" >"$probe_normalized"
write_event "probe_snapshot_loaded" "normalized probe worker snapshot"

queue_status="$(json_input "$queue_diagnostics_json" '{"workers":[],"drained_workers":[],"decision":"unknown","reason":""}' "$queue_normalized" 'queue diagnostics')"
incident_status="$(json_input "$incident_packet_json" '{"status":"missing","failure_kind":"missing","remote_worker_id":"","live_remote_compile":false}' "$incident_normalized" 'incident packet')"

if [[ "$queue_status" == "provided" ]]; then
  jq -cS '
    def rows:
      if type == "array" then .
      elif (.workers? | type) == "array" then .workers
      elif (.worker_selection?.workers? | type) == "array" then .worker_selection.workers
      else [] end;
    {
      decision: (.queue_decision // .decision // "unknown"),
      reason: (.reason // .worker_selection.reason // ""),
      drained_workers: (
        (.drained_workers // .expected_drained_workers // [])
        | if type == "array" then . else [] end
        | map(tostring)
        | map(select(length > 0))
        | unique
        | sort
      ),
      workers: (
        rows
        | map({
            worker_id: (.worker_id // .worker // .name // .id // ""),
            schedulable: (
              if (.schedulable | type) == "boolean" then .schedulable
              elif (.selectable | type) == "boolean" then .selectable
              elif (.available | type) == "boolean" then .available
              else false
              end
            ),
            selection_reason: (.selection_reason // .reason // "")
          })
        | map(select(.worker_id != ""))
        | sort_by(.worker_id)
      )
    }
  ' "$queue_normalized" >"${queue_normalized}.tmp"
  mv "${queue_normalized}.tmp" "$queue_normalized"
  write_event "queue_snapshot_loaded" "normalized queue diagnostics snapshot"
fi

if [[ "$incident_status" == "provided" ]]; then
  jq -cS '
    {
      status: (.status // "unknown"),
      failure_kind: (.failure_kind // "unknown"),
      remote_worker_id: (.remote_worker_id // .worker_id // .worker // ""),
      live_remote_compile: (
        if (.live_remote_compile | type) == "boolean" then .live_remote_compile
        else (
          (.failure_kind // "")
          | ascii_downcase
          | . == "timed_out_transport_live_remote_compile"
            or . == "canceled_build_live_orphaned_rustc"
        )
        end
      )
    }
  ' "$incident_normalized" >"${incident_normalized}.tmp"
  mv "${incident_normalized}.tmp" "$incident_normalized"
  write_event "incident_snapshot_loaded" "normalized incident packet snapshot"
fi

jq -n \
  --arg queue_status "$queue_status" \
  --arg incident_status "$incident_status" \
  --slurpfile daemon "$daemon_normalized" \
  --slurpfile probe "$probe_normalized" \
  --slurpfile queue "$queue_normalized" \
  --slurpfile incident "$incident_normalized" \
  --arg report_path "$report_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg summary_path "$summary_path" '
  def daemon_row($id):
    ([($daemon[0].workers // [])[] | select(.worker_id == $id)][0] // null);
  def probe_row($id):
    ([($probe[0].workers // [])[] | select(.worker_id == $id)][0] // null);
  def queue_row($id):
    ([($queue[0].workers // [])[] | select(.worker_id == $id)][0] // null);
  def union_worker_ids:
    (
      (($daemon[0].workers // []) | map(.worker_id))
      + (($probe[0].workers // []) | map(.worker_id))
      + (($queue[0].workers // []) | map(.worker_id))
      + (($queue[0].drained_workers // []) | map(tostring))
    )
    | map(select(type == "string" and length > 0))
    | unique
    | sort;
  def row_findings($id; $daemon_row; $probe_row; $queue_row):
    [
      if ($probe_row != null and ($probe_row.schedulable // false) == true and ($daemon_row == null or ($daemon_row.healthy // false) != true)) then
        {
          code: "healthy_probe_absent_or_unschedulable_in_daemon",
          severity: "error",
          worker_id: $id,
          detail: "probe snapshot marks the worker schedulable, but daemon state is missing or not healthy"
        }
      else empty end,
      if ($daemon_row != null and ($daemon_row.healthy // false) == true and ($probe_row == null or ($probe_row.schedulable // false) != true)) then
        {
          code: "healthy_daemon_absent_or_unschedulable_in_probe",
          severity: "error",
          worker_id: $id,
          detail: "daemon snapshot marks the worker healthy, but probe state is missing or not schedulable"
        }
      else empty end,
      if ($queue_status == "provided" and $probe_row != null and ($probe_row.schedulable // false) == true and ($queue_row == null or ($queue_row.schedulable // false) != true)) then
        {
          code: "selector_drift_probe_schedulable_queue_blocked",
          severity: "error",
          worker_id: $id,
          detail: "probe snapshot says the worker is schedulable, but queue diagnostics do not admit it"
        }
      else empty end,
      if ((($queue[0].drained_workers // []) | index($id)) != null and $daemon_row == null) then
        {
          code: "drained_worker_missing_from_daemon",
          severity: "error",
          worker_id: $id,
          detail: "queue diagnostics still track the worker as drained, but daemon state no longer reports it"
        }
      else empty end
    ];
  (union_worker_ids) as $worker_ids
  | ($worker_ids | map(
      . as $id
      | (daemon_row($id)) as $d
      | (probe_row($id)) as $p
      | (queue_row($id)) as $q
      | {
          worker_id: $id,
          daemon_present: ($d != null),
          daemon_status: ($d.status // null),
          daemon_drained: ($d.drained // false),
          probe_present: ($p != null),
          probe_status: ($p.status // null),
          probe_schedulable: ($p.schedulable // false),
          queue_present: ($q != null),
          queue_schedulable: ($q.schedulable // false),
          queue_selection_reason: ($q.selection_reason // null),
          findings: row_findings($id; $d; $p; $q)
        }
    )) as $rows
  | ([$rows[].findings[]?] | sort_by(.code, .worker_id)) as $row_findings
  | (if $incident_status == "provided" and ($incident[0].live_remote_compile // false) == true then
       [
         {
           code: "ghost_job_live_remote_compile",
           severity: "error",
           worker_id: (($incident[0].remote_worker_id // "") | if . == "" then null else . end),
           detail: "incident evidence still shows a live remote compile after completion or cancellation"
         }
       ]
     else
       []
     end) as $incident_findings
  | ($row_findings + $incident_findings) as $findings
  | {
      schema_version: "franken-engine.rch-worker-truth-parity-report.v1",
      decision: (if ($findings | length) == 0 then "pass" else "fail_closed" end),
      queue_snapshot_status: $queue_status,
      incident_snapshot_status: $incident_status,
      daemon_worker_count: (($daemon[0].workers // []) | length),
      probe_worker_count: (($probe[0].workers // []) | length),
      queue_worker_count: (($queue[0].workers // []) | length),
      drift_count: ($findings | length),
      ghost_job_detected: any($incident_findings[]?; .code == "ghost_job_live_remote_compile"),
      queue_decision: ($queue[0].decision // null),
      queue_reason: ($queue[0].reason // null),
      worker_rows: $rows,
      findings: $findings,
      incident_evidence: {
        status: ($incident[0].status // null),
        failure_kind: ($incident[0].failure_kind // null),
        remote_worker_id: (($incident[0].remote_worker_id // "") | if . == "" then null else . end),
        live_remote_compile: ($incident[0].live_remote_compile // false)
      },
      artifact_paths: {
        worker_truth_report_json: $report_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $summary_path
      }
    }
' >"$report_tmp"
mv "$report_tmp" "$report_path"

write_event "worker_truth_parity_completed" "$(jq -r '.decision + " with " + (.drift_count | tostring) + " finding(s)"' "$report_path")"

{
  printf '# RCH Worker Truth Parity Ledger\n\n'
  printf '%s\n' "- Decision: \`$(jq -r '.decision' "$report_path")\`"
  printf '%s\n' "- Drift findings: \`$(jq -r '.drift_count' "$report_path")\`"
  printf '%s\n' "- Daemon workers: \`$(jq -r '.daemon_worker_count' "$report_path")\`"
  printf '%s\n' "- Probe workers: \`$(jq -r '.probe_worker_count' "$report_path")\`"
  printf '%s\n' "- Queue workers: \`$(jq -r '.queue_worker_count' "$report_path")\`"
  printf '%s\n' "- Ghost-job detected: \`$(jq -r '.ghost_job_detected' "$report_path")\`"
  printf '\n## Findings\n\n'
  if [[ "$(jq '.findings | length' "$report_path")" -eq 0 ]]; then
    printf -- '- no parity drift detected\n'
  else
    jq -r '
      .findings[]
      | "- [`" + .severity + "`] `" + .code + "`"
        + (if .worker_id == null then "" else " on `" + .worker_id + "`" end)
        + ": " + .detail
    ' "$report_path"
  fi
  printf '\n## Worker Rows\n\n'
  jq -r '
    .worker_rows[]
    | "- `\(.worker_id)`: daemon=\(.daemon_status // "missing"), probe=\(.probe_status // "missing"), probe_schedulable=\(.probe_schedulable), queue_schedulable=\(.queue_schedulable), daemon_drained=\(.daemon_drained)"
  ' "$report_path"
} >"$summary_tmp"
mv "$summary_tmp" "$summary_path"

printf 'worker_truth_report_json=%s\n' "$report_path"
printf 'worker_truth_report_md=%s\n' "$summary_path"

if [[ "$(jq -r '.decision' "$report_path")" == "pass" ]]; then
  exit 0
fi
exit 42
