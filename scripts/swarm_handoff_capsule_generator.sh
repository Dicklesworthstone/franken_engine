#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_HANDOFF_CAPSULE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-handoff-capsule}"
run_id="${SWARM_HANDOFF_CAPSULE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_HANDOFF_CAPSULE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${SWARM_HANDOFF_CAPSULE_SOURCE_REVISION:-}"
case_id="manual"
generated_epoch_seconds="${SWARM_HANDOFF_CAPSULE_GENERATED_EPOCH_SECONDS:-$(date -u +%s)}"
git_status_json=""
br_state_json=""
owned_paths_json=""
recent_commits_json=""
rch_jobs_json=""
validation_receipts_json=""
mail_health_json=""
operator_notes_json=""
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_handoff_capsule_generator.sh --git-status-json FILE --br-state-json FILE [OPTIONS]

Builds a deterministic, read-only handoff capsule for compaction, agent takeover,
or dirty multi-agent sessions. Inputs are preserved JSON snapshots; file contents
are never read by default.

Required:
  --git-status-json FILE             Branch/divergence and dirty path snapshot.
  --br-state-json FILE               Ready/in-progress/active bead summary.

Optional:
  --owned-paths-json FILE            Paths owned by the current agent/session.
  --recent-commits-json FILE         Recent commit summaries.
  --rch-jobs-json FILE               Active RCH process/job snapshot.
  --validation-receipts-json FILE    Validation receipts and transcript digests.
  --mail-health-json FILE            Agent Mail health snapshot or captured error.
  --operator-notes-json FILE         Note metadata; note bodies are not copied.
  --case-id ID
  --source-revision REV
  --generated-epoch-seconds N
  --output-dir DIR

Artifacts:
  swarm_handoff_capsule.json
  swarm_handoff_capsule.md
  handoff_commands.txt
  events.jsonl

Exit codes:
  0   ready or degraded capsule emitted
  42  blocked capsule emitted
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --git-status-json)
      git_status_json="${2:-}"
      shift 2
      ;;
    --br-state-json)
      br_state_json="${2:-}"
      shift 2
      ;;
    --owned-paths-json)
      owned_paths_json="${2:-}"
      shift 2
      ;;
    --recent-commits-json)
      recent_commits_json="${2:-}"
      shift 2
      ;;
    --rch-jobs-json)
      rch_jobs_json="${2:-}"
      shift 2
      ;;
    --validation-receipts-json)
      validation_receipts_json="${2:-}"
      shift 2
      ;;
    --mail-health-json)
      mail_health_json="${2:-}"
      shift 2
      ;;
    --operator-notes-json)
      operator_notes_json="${2:-}"
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
    --generated-epoch-seconds)
      generated_epoch_seconds="${2:-}"
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
  printf 'jq is required for swarm handoff capsule generation\n' >&2
  exit 2
fi
if [[ -z "$git_status_json" || -z "$br_state_json" ]]; then
  printf 'handoff capsule requires --git-status-json and --br-state-json\n' >&2
  usage
  exit 64
fi
if ! [[ "$generated_epoch_seconds" =~ ^[0-9]+$ ]]; then
  printf 'generated epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

validate_json() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_optional_json() {
  local path="$1"
  local label="$2"
  if [[ -n "$path" ]]; then
    validate_json "$path" "$label"
  fi
}

validate_json "$git_status_json" "git status"
validate_json "$br_state_json" "br state"
validate_optional_json "$owned_paths_json" "owned paths"
validate_optional_json "$recent_commits_json" "recent commits"
validate_optional_json "$rch_jobs_json" "RCH jobs"
validate_optional_json "$validation_receipts_json" "validation receipts"
validate_optional_json "$mail_health_json" "mail health"
validate_optional_json "$operator_notes_json" "operator notes"

mkdir -p "$run_dir"
capsule_json="${run_dir}/swarm_handoff_capsule.json"
capsule_md="${run_dir}/swarm_handoff_capsule.md"
commands_path="${run_dir}/handoff_commands.txt"
events_path="${run_dir}/events.jsonl"

git_normalized="${run_dir}/git_status.normalized.json"
br_normalized="${run_dir}/br_state.normalized.json"
owned_normalized="${run_dir}/owned_paths.normalized.json"
commits_normalized="${run_dir}/recent_commits.normalized.json"
rch_normalized="${run_dir}/rch_jobs.normalized.json"
receipts_normalized="${run_dir}/validation_receipts.normalized.json"
mail_normalized="${run_dir}/mail_health.normalized.json"
notes_normalized="${run_dir}/operator_notes.normalized.json"

for artifact_path in "$capsule_json" "$capsule_md" "$commands_path" "$events_path" \
  "$git_normalized" "$br_normalized" "$owned_normalized" "$commits_normalized" "$rch_normalized" \
  "$receipts_normalized" "$mail_normalized" "$notes_normalized"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$git_status_json" >"$git_normalized"
jq -cS . "$br_state_json" >"$br_normalized"
if [[ -n "$owned_paths_json" ]]; then
  jq -cS . "$owned_paths_json" >"$owned_normalized"
else
  printf '{"owned_paths":[]}\n' >"$owned_normalized"
fi
if [[ -n "$recent_commits_json" ]]; then
  jq -cS . "$recent_commits_json" >"$commits_normalized"
else
  printf '{"commits":[]}\n' >"$commits_normalized"
fi
if [[ -n "$rch_jobs_json" ]]; then
  jq -cS . "$rch_jobs_json" >"$rch_normalized"
else
  printf '{"jobs":[]}\n' >"$rch_normalized"
fi
if [[ -n "$validation_receipts_json" ]]; then
  jq -cS . "$validation_receipts_json" >"$receipts_normalized"
else
  printf '{"receipts":[]}\n' >"$receipts_normalized"
fi
if [[ -n "$mail_health_json" ]]; then
  jq -cS . "$mail_health_json" >"$mail_normalized"
else
  printf '{"status":"missing","health_level":"unknown"}\n' >"$mail_normalized"
fi
if [[ -n "$operator_notes_json" ]]; then
  jq -cS . "$operator_notes_json" >"$notes_normalized"
else
  printf '{"notes":[]}\n' >"$notes_normalized"
fi

: >"$events_path"
printf './scripts/swarm_handoff_capsule_generator.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -nc --arg event "started" --arg case_id "$case_id" --arg artifact "$capsule_json" \
  '{event:$event, case_id:$case_id, artifact:$artifact}' >>"$events_path"

# shellcheck disable=SC2094 # The output path is embedded as capsule data; jq does not read it.
jq -S -n \
  --slurpfile git_status "$git_normalized" \
  --slurpfile br_state "$br_normalized" \
  --slurpfile owned "$owned_normalized" \
  --slurpfile commits "$commits_normalized" \
  --slurpfile rch "$rch_normalized" \
  --slurpfile receipts "$receipts_normalized" \
  --slurpfile mail "$mail_normalized" \
  --slurpfile notes "$notes_normalized" \
  --arg schema_version "franken-engine.swarm-handoff-capsule.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --argjson generated_epoch_seconds "$generated_epoch_seconds" \
  --arg capsule_json "$capsule_json" \
  --arg capsule_md "$capsule_md" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def doc($v): if ($v | type) == "array" then ($v[0] // {}) else ($v // {}) end;
  def rows($v; $key): if (doc($v) | type) == "array" then doc($v) else arr(doc($v)[$key]) end;
  def token($v): ($v | tostring | ascii_downcase | gsub("[^a-z0-9_]+"; "_") | gsub("^_+|_+$"; ""));
  def low($v): ($v // "" | tostring | ascii_downcase);
  def owned_paths:
    (if (doc($owned) | type) == "array" then doc($owned) else arr(doc($owned).owned_paths) end)
    | map(tostring)
    | unique
    | sort;
  def dirty_paths: arr(doc($git_status).dirty_paths) | map({
      path:(.path // .file // ""),
      status:(.status // .code // "unknown"),
      owner:(.owner // null)
    }) | sort_by(.path, .status);
  def is_owned($row):
    ((owned_paths | index($row.path)) != null)
    or (($row.owner // "") != "" and ($row.owner // "") == (doc($br_state).agent_name // doc($br_state).current_agent // ""));
  def br_ready: rows($br_state; "ready") | sort_by(.id // "", .title // "");
  def br_in_progress:
    if (doc($br_state).in_progress | type) == "object" and (doc($br_state).in_progress.issues | type) == "array" then
      doc($br_state).in_progress.issues
    else rows($br_state; "in_progress") end
    | sort_by(.id // "", .assignee // "");
  def recent_commits:
    rows($commits; "commits")
    | map({
        commit:(.commit // .hash // .short_hash // ""),
        subject:(.subject // .title // ""),
        author:(.author // ""),
        timestamp:(.timestamp // .authored_at // null)
      })
    | sort_by(.commit, .subject);
  def rch_jobs:
    rows($rch; "jobs")
    | map({
        job_id:(.job_id // .pid // .id // ""),
        command:(.command // .cmd // ""),
        status:(.status // "unknown"),
        owner:(.owner // .agent // null),
        started_at:(.started_at // null)
      })
    | sort_by(.job_id, .command);
  def validation_receipts:
    rows($receipts; "receipts")
    | map({
        receipt_id:(.receipt_id // .id // ""),
        command_id:(.command_id // .command // ""),
        status:(.status // "unknown"),
        source_revision:(.source_revision // null),
        transcript_digest:(.transcript_digest // .digest // null),
        artifact_path:(.artifact_path // .path // null),
        reuse_eligible:(.reuse_eligible // true)
      })
    | sort_by(.receipt_id, .command_id);
  def note_metadata:
    rows($notes; "notes")
    | map({
        note_id:(.note_id // .id // ""),
        source:(.source // null),
        digest:(.digest // .content_digest // null)
      })
    | sort_by(.note_id);
  def mail_doc: doc($mail);
  def mail_status: low(mail_doc.status // mail_doc.health_level // mail_doc.recovery.mode // "unknown");
  def mail_decision:
    if mail_status | IN("ok","green","healthy") then "available"
    elif mail_status | IN("missing","unknown") then "missing_optional"
    else "degraded" end;
  def branch_status: {
    branch:(doc($git_status).branch // "unknown"),
    main_ref:(doc($git_status).main_ref // "origin/main"),
    ahead:((doc($git_status).ahead // 0) | tonumber),
    behind:((doc($git_status).behind // 0) | tonumber),
    source_revision:$source_revision
  };
  (dirty_paths | map(select(is_owned(.)))) as $owned_dirty
  | (dirty_paths | map(select(is_owned(.) | not))) as $unrelated_dirty
  | (validation_receipts | map(select(((low(.status) | IN("passed","ok","success")) | not) or (.reuse_eligible != true)))) as $bad_receipts
  | (rch_jobs | map(select((low(.status) | IN("done","complete","completed","exited")) | not))) as $active_rch
  | ([
      if mail_decision == "degraded" then {code:"FE-IW3-HANDOFF-MAIL-DEGRADED", detail:"Agent Mail is unavailable or corrupt; use br state as continuity anchor"} else empty end,
      if ($unrelated_dirty | length) > 0 then {code:"FE-IW3-HANDOFF-UNRELATED-DIRTY", detail:"Dirty paths outside current ownership require human/agent review"} else empty end,
      if ($active_rch | length) > 0 then {code:"FE-IW3-HANDOFF-ACTIVE-RCH", detail:"Active RCH jobs should be considered before starting more heavy proof work"} else empty end
    ]) as $degraded
  | ([
      if ($bad_receipts | length) > 0 then {code:"FE-IW3-HANDOFF-BAD-PROOF", detail:"A validation receipt is failed, stale, or not reuse-eligible"} else empty end,
      if (doc($git_status).branch // "") == "" then {code:"FE-IW3-HANDOFF-MISSING-BRANCH", detail:"Git branch snapshot is missing"} else empty end
    ]) as $blocked
  | {
      schema_version:$schema_version,
      capsule_id:("swarm-handoff-" + token($case_id + "-" + $source_revision)),
      case_id:$case_id,
      generated_epoch_seconds:$generated_epoch_seconds,
      source_revision:$source_revision,
      decision:(if ($blocked | length) > 0 then "blocked" elif ($degraded | length) > 0 then "degraded" else "ready" end),
      branch_status:branch_status,
      dirty_worktree:{
        owned_paths:owned_paths,
        owned_dirty_paths:$owned_dirty,
        unrelated_dirty_paths:$unrelated_dirty,
        owned_dirty_count:($owned_dirty | length),
        unrelated_dirty_count:($unrelated_dirty | length)
      },
      bead_state:{
        active_bead_id:(doc($br_state).active_bead_id // null),
        agent_name:(doc($br_state).agent_name // doc($br_state).current_agent // null),
        ready:br_ready,
        in_progress:br_in_progress,
        ready_count:(br_ready | length),
        in_progress_count:(br_in_progress | length)
      },
      recent_commits:recent_commits,
      rch_jobs:{
        active_count:($active_rch | length),
        jobs:rch_jobs
      },
      validation_receipts:{
        bad_count:($bad_receipts | length),
        receipts:validation_receipts
      },
      agent_mail:{
        decision:mail_decision,
        status:mail_status,
        recovery_mode:(mail_doc.recovery.mode // null),
        repair_allowed:false
      },
      operator_notes:{
        body_copied:false,
        notes:note_metadata
      },
      degraded_reasons:$degraded,
      blocked_reasons:$blocked,
      next_actions:([
        if ($blocked | length) > 0 then "Resolve blocked validation receipts or missing source state before handoff closeout." else empty end,
        if ($unrelated_dirty | length) > 0 then "Coordinate dirty paths outside current ownership before editing or committing overlap files." else empty end,
        if mail_decision == "degraded" then "Use br assignee/status as the visible soft lock while Agent Mail is red." else empty end,
        if ($active_rch | length) > 0 then "Wait for active RCH jobs or choose lightweight source-only work." else empty end,
        if ($blocked | length) == 0 and ($degraded | length) == 0 then "Capsule is ready for takeover; proceed from active bead and validation receipts." else empty end
      ]),
      artifacts:{
        capsule_json:$capsule_json,
        capsule_markdown:$capsule_md,
        commands:$commands_path,
        events:$events_path
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        reads_file_contents:false,
        mutates_br:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_git:false,
        mutates_remote_workers:false,
        deletes_or_overwrites_target_dirs:false
      }
    }
  ' >"$capsule_json"

jq -r '
  "# Swarm Handoff Capsule\n\n"
  + "- Capsule: `" + .capsule_id + "`\n"
  + "- Decision: `" + .decision + "`\n"
  + "- Branch: `" + .branch_status.branch + "` vs `" + .branch_status.main_ref + "`"
  + " (ahead " + (.branch_status.ahead | tostring) + ", behind " + (.branch_status.behind | tostring) + ")\n"
  + "- Active bead: `" + (.bead_state.active_bead_id // "none") + "`\n"
  + "- Dirty paths: owned " + (.dirty_worktree.owned_dirty_count | tostring)
  + ", unrelated " + (.dirty_worktree.unrelated_dirty_count | tostring) + "\n"
  + "- Active RCH jobs: " + (.rch_jobs.active_count | tostring) + "\n"
  + "- Agent Mail: `" + .agent_mail.decision + "` (`" + .agent_mail.status + "`)\n\n"
  + "## Next Actions\n\n"
  + (if (.next_actions | length) == 0 then "- None\n" else (.next_actions | map("- " + .) | join("\n")) + "\n" end)
  + "\n## Degraded Reasons\n\n"
  + (if (.degraded_reasons | length) == 0 then "- None\n" else (.degraded_reasons | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
  + "\n## Blocked Reasons\n\n"
  + (if (.blocked_reasons | length) == 0 then "- None\n" else (.blocked_reasons | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
  + "\n## Privacy Boundary\n\n"
  + "- File contents copied: `false`\n"
  + "- Operator note bodies copied: `false`\n"
' "$capsule_json" >"$capsule_md"

jq -nc --arg event "emitted" --arg case_id "$case_id" --arg artifact "$capsule_json" \
  '{event:$event, case_id:$case_id, artifact:$artifact}' >>"$events_path"

decision="$(jq -r '.decision' "$capsule_json")"
if [[ "$decision" == "blocked" ]]; then
  exit 42
fi
exit 0
