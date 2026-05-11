#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iw4-closed-bead-proof}"
run_id="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
bead_id="${IDEA_WIZARD_IV_CLOSED_BEAD_PROOF_BEAD_ID:-bd-vgj5t}"
max_beads=1000
recent_git_limit=500
original_args=("$@")

br_list_json=""
issues_jsonl=""
git_log_json=""
artifact_manifest_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_iv_closed_bead_proof_integrity.sh (--br-list-json FILE | --issues-jsonl FILE) [OPTIONS]

Emit closed_bead_proof_integrity.json from closed bead history. This surface is
advisory only: it never mutates beads, never runs Cargo, and never runs RCH.

Options:
  --br-list-json FILE
  --issues-jsonl FILE
  --git-log-json FILE
  --artifact-manifest-json FILE
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
  --max-beads N
  --recent-git-limit N
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-list-json)
      br_list_json="${2:-}"
      shift 2
      ;;
    --issues-jsonl)
      issues_jsonl="${2:-}"
      shift 2
      ;;
    --git-log-json)
      git_log_json="${2:-}"
      shift 2
      ;;
    --artifact-manifest-json)
      artifact_manifest_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --generated-at-utc)
      generated_at_utc="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --max-beads)
      max_beads="${2:-}"
      shift 2
      ;;
    --recent-git-limit)
      recent_git_limit="${2:-}"
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
  printf 'jq is required for closed bead proof integrity normalization\n' >&2
  exit 2
fi
if [[ -z "$br_list_json" && -z "$issues_jsonl" ]]; then
  printf 'closed bead proof integrity requires --br-list-json or --issues-jsonl\n' >&2
  usage
  exit 64
fi
if ! [[ "$max_beads" =~ ^[0-9]+$ ]] || [[ "$max_beads" -eq 0 ]]; then
  printf 'max beads must be a positive integer\n' >&2
  exit 64
fi
if ! [[ "$recent_git_limit" =~ ^[0-9]+$ ]] || [[ "$recent_git_limit" -eq 0 ]]; then
  printf 'recent git limit must be a positive integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

validate_json_if_supplied() {
  local path="$1"
  local label="$2"
  if [[ -z "$path" ]]; then
    return 0
  fi
  if [[ ! -f "$path" ]]; then
    printf '%s JSON not found: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf '%s JSON is malformed: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_json_if_supplied "$br_list_json" "br-list"
validate_json_if_supplied "$git_log_json" "git-log"
validate_json_if_supplied "$artifact_manifest_json" "artifact-manifest"
if [[ -n "$issues_jsonl" ]]; then
  if [[ ! -f "$issues_jsonl" ]]; then
    printf 'issues JSONL not found: %s\n' "$issues_jsonl" >&2
    exit 64
  fi
  if ! jq empty "$issues_jsonl" >/dev/null 2>&1; then
    printf 'issues JSONL is malformed: %s\n' "$issues_jsonl" >&2
    exit 64
  fi
fi

mkdir -p "$run_dir"
br_rows_json="${run_dir}/br_rows.normalized.json"
jsonl_rows_json="${run_dir}/issues_jsonl.normalized.json"
all_beads_json="${run_dir}/all_beads.normalized.json"
closed_beads_json="${run_dir}/closed_beads.normalized.json"
git_log_normalized="${run_dir}/git_log.normalized.json"
artifact_manifest_normalized="${run_dir}/artifact_manifest.normalized.json"
report_json="${run_dir}/closed_bead_proof_integrity.json"
weak_jsonl="${run_dir}/weak_evidence.jsonl"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
trace_ids_path="${run_dir}/trace_ids.json"
live_git_log_jsonl="${run_dir}/git_log.live.jsonl"
live_git_log_tsv="${run_dir}/git_log.live.tsv"

for artifact_path in \
  "$br_rows_json" \
  "$jsonl_rows_json" \
  "$all_beads_json" \
  "$closed_beads_json" \
  "$git_log_normalized" \
  "$artifact_manifest_normalized" \
  "$report_json" \
  "$weak_jsonl" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "$report_md" \
  "$trace_ids_path" \
  "$live_git_log_jsonl" \
  "$live_git_log_tsv"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
: >"$weak_jsonl"
printf './scripts/idea_wizard_iv_closed_bead_proof_integrity.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n\n# recommended validation command\n' >>"$commands_path"
printf 'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_closed_bead_proof CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine closed_bead_proof\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.idea-wizard-iv-closed-bead-proof.event.v1" \
    --arg event "$1" \
    --arg outcome "$2" \
    --arg detail "$3" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,outcome:$outcome,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

write_event "normalizer_start" "started" "normalizing closed bead proof evidence"

if [[ -n "$br_list_json" ]]; then
  jq '
    def rows:
      if type == "array" then .
      elif (.issues | type) == "array" then .issues
      elif (.result | type) == "array" then .result
      else []
      end;
    rows
  ' "$br_list_json" >"$br_rows_json"
else
  printf '[]\n' >"$br_rows_json"
fi

if [[ -n "$issues_jsonl" ]]; then
  jq -s '[.[] | select(type == "object")]' "$issues_jsonl" >"$jsonl_rows_json"
else
  printf '[]\n' >"$jsonl_rows_json"
fi

jq -s '
  add
  | map(select((.id // "") != ""))
  | unique_by(.id)
  | sort_by(.id)
' "$br_rows_json" "$jsonl_rows_json" >"$all_beads_json"

jq --argjson max_beads "$max_beads" '
  map(select((.status // "" | ascii_downcase) == "closed"))
  | sort_by((.priority // 999), (.updated_at // ""), (.id // ""))
  | .[0:$max_beads]
' "$all_beads_json" >"$closed_beads_json"

if [[ -n "$git_log_json" ]]; then
  jq '
    def rows:
      if type == "array" then .
      elif (.commits | type) == "array" then .commits
      elif (.result | type) == "array" then .result
      else []
      end;
    rows
    | map({
        commit: (.commit // .hash // .oid // ""),
        subject: (.subject // .message // .summary // ""),
        body: (.body // ""),
        committed_at: (.committed_at // .date // .timestamp // ""),
        scope: (.scope // "provided")
      })
    | map(select(.commit != "" or .subject != ""))
    | unique_by((.commit // "") + ":" + (.subject // ""))
  ' "$git_log_json" >"$git_log_normalized"
else
  : >"$live_git_log_jsonl"
  git -C "$root_dir" log --all --max-count="$recent_git_limit" --format='%H%x09%ct%x09%s' >"$live_git_log_tsv" 2>/dev/null || true
  while IFS=$'\t' read -r commit epoch subject; do
    [[ -z "${commit:-}" ]] && continue
    jq -nc \
      --arg commit "$commit" \
      --arg epoch "$epoch" \
      --arg subject "${subject:-}" \
      '{commit:$commit,committed_epoch:$epoch,subject:$subject,body:"",scope:"live-git-log"}' >>"$live_git_log_jsonl"
  done <"$live_git_log_tsv"
  jq -s 'unique_by(.commit)' "$live_git_log_jsonl" >"$git_log_normalized"
fi

if [[ -n "$artifact_manifest_json" ]]; then
  jq '
    if type == "array" then .
    elif (.artifacts | type) == "array" then .artifacts
    elif (.manifests | type) == "array" then .manifests
    elif (.entries | type) == "array" then .entries
    else [.]
    end
  ' "$artifact_manifest_json" >"$artifact_manifest_normalized"
else
  printf '[]\n' >"$artifact_manifest_normalized"
fi

jq -n \
  --slurpfile all_beads "$all_beads_json" \
  --slurpfile closed_beads "$closed_beads_json" \
  --slurpfile git_log "$git_log_normalized" \
  --slurpfile artifact_manifests "$artifact_manifest_normalized" \
  --arg schema_version "franken-engine.idea-wizard-iv-closed-bead-proof-integrity.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg report_json "$report_json" \
  --arg weak_jsonl "$weak_jsonl" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  --arg trace_ids_path "$trace_ids_path" \
  --arg closed_beads_json "$closed_beads_json" \
  --arg git_log_normalized "$git_log_normalized" \
  --arg br_list_json "$br_list_json" \
  --arg issues_jsonl "$issues_jsonl" \
  --arg git_log_json "$git_log_json" \
  --arg artifact_manifest_json "$artifact_manifest_json" '
    def arr($v): if ($v | type) == "array" then $v else [] end;
    def low($v): ($v // "" | tostring | ascii_downcase);
    def comment_text($c):
      if ($c | type) == "object" then ($c.body // $c.text // $c.comment // $c.message // "")
      else ($c // "" | tostring)
      end;
    def stopwords:
      ["franken","engine","swarm","autopilot","idea","wizard","closed","bead","proof","integrity","normalizer","contract","testing","validation","artifact","operator","control","plane","build","define","added","add","with","from"];
    def title_tokens($title):
      [ low($title)
        | gsub("[^a-z0-9]+"; " ")
        | split(" ")[] as $token
        | select(($token | length) >= 8)
        | select((stopwords | index($token)) | not)
        | $token
      ][0:6];
    def bead_text($b):
      ([ $b.id, $b.title, $b.description, $b.close_reason, $b.notes, $b.assignee, (arr($b.labels) | join(" ")) ]
      + [ arr($b.comments)[]? | comment_text(.) ])
      | map(. // "" | tostring)
      | join("\n");
    def commit_hash_present($text):
      low($text) | test("(^|[^0-9a-f])[0-9a-f]{7,40}([^0-9a-f]|$)");
    def validation_present($text):
      low($text) | test("rch exec|cargo (test|check|clippy|build)|bash [^\\n]*scripts/|jq empty|jq -e|git diff --check|validation passed|tests? passed|smoke");
    def bare_heavy_cargo_present($text):
      (low($text) | test("(^|[^a-z0-9_-])cargo (check|test|clippy|build)(\\s|$)"))
      and ((low($text) | contains("rch exec -- env cargo_target_dir=")) | not);
    def artifact_present($text):
      low($text) | test("run_manifest\\.json|events\\.jsonl|commands\\.txt|trace_ids\\.json|artifact|manifest|report\\.md|replay");
    def git_message($c): low(($c.subject // "") + "\n" + ($c.body // ""));
    ($all_beads[0] // []) as $all
    | ($closed_beads[0] // []) as $closed
    | ($git_log[0] // []) as $commits
    | ($artifact_manifests[0] // []) as $manifests
    | ($commits | map(git_message(.)) | join("\n")) as $git_blob
    | def direct_git_match($id):
        ($id | ascii_downcase) as $needle
        | ($git_blob | contains($needle));
      def ambiguous_git_match($title):
        (title_tokens($title)) as $tokens
        | (($tokens | length) > 0 and any($tokens[]?; $git_blob | contains(.)));
      def manifest_covers($id):
        any($manifests[]?;
          ((.bead_id // .id // .issue_id // "") == $id)
          or (arr(.covers) | index($id))
          or (arr(.covered_beads) | index($id))
          or (arr(.beads) | index($id))
          or ((.path // .artifact // "" | tostring) | contains($id))
        );
      def dependent_count($id):
        [ $all[]? | arr(.dependencies)[]? | select((.depends_on_id // "") == $id) ] | length;
      def analyze($b):
        ($b.id // "") as $id
        | bead_text($b) as $text
        | (commit_hash_present($text) or direct_git_match($id)) as $direct
        | validation_present($text) as $validation
        | (artifact_present($text) or manifest_covers($id)) as $artifact
        | ((($direct | not) and ambiguous_git_match($b.title // ""))) as $ambiguous
        | (bare_heavy_cargo_present($text)) as $bare_heavy
        | (($b.close_reason // "" | tostring) != "") as $has_close_reason
        | (if (($direct | not) and ($validation | not) and ($artifact | not)) then "high"
           elif ($direct | not) then "medium"
           else "low"
           end) as $risk_level
        | {
            id:$id,
            title:($b.title // ""),
            priority:($b.priority // null),
            status:($b.status // ""),
            assignee:($b.assignee // null),
            labels:(arr($b.labels) | sort),
            updated_at:($b.updated_at // null),
            closed_at:($b.closed_at // null),
            close_reason:($b.close_reason // ""),
            dependency_count:(arr($b.dependencies) | length),
            dependent_count:dependent_count($id),
            evidence_classes:([
              if $direct then "direct_commit_reference" else empty end,
              if $validation then "validation_command_present" else empty end,
              if $artifact then "artifact_manifest_present" else empty end,
              if ($has_close_reason and (($direct or $validation or $artifact or $ambiguous) | not)) then "close_reason_only" else empty end,
              if (($has_close_reason | not) and (($direct or $validation or $artifact or $ambiguous) | not)) then "no_evidence" else empty end,
              if $ambiguous then "stale_or_ambiguous_evidence" else empty end
            ] | sort),
            direct_commit_reference:$direct,
            validation_command_present:$validation,
            artifact_manifest_present:$artifact,
            stale_or_ambiguous_evidence:$ambiguous,
            bare_heavy_cargo_present:$bare_heavy,
            risk_level:$risk_level,
            risk_sort:(if $risk_level == "high" then 0 elif $risk_level == "medium" then 1 else 2 end),
            weak_evidence:($risk_level != "low"),
            reason_codes:([
              if ($direct | not) then "FE-IW4-WEAK-CLOSED-BEAD-PROOF" else empty end,
              if (($validation | not) and ($artifact | not)) then "closed_bead_missing_validation_or_artifact" else empty end,
              if (($direct | not) and $validation) then "closed_bead_missing_direct_commit" else empty end,
              if $bare_heavy then "FE-IW4-BARE-HEAVY-CARGO" else empty end,
              if $ambiguous then "closed_bead_title_only_git_match" else empty end
            ] | sort | unique)
          };
      ($closed | map(analyze(.)) | sort_by(.risk_sort, (.priority // 999), (.updated_at // ""), (.id // ""))) as $rows
      | ([
          if (($closed | length) == 0) then {code:"FE-IW4-NO-CLOSED-BEADS", detail:"No closed beads were available in the supplied sources."} else empty end
        ]) as $fail_closed_reasons
      | ($rows | map(select(.weak_evidence == true))) as $weak
      | {
          schema_version:$schema_version,
          bead_id:$bead_id,
          source_revision:$source_revision,
          generated_at_utc:$generated_at_utc,
          decision:(if ($fail_closed_reasons | length) > 0 then "degraded" elif ($weak | length) > 0 then "degraded" else "green" end),
          classification:(if ($fail_closed_reasons | length) > 0 then "tracker_blind_spot" elif ($weak | length) > 0 then "proof_integrity_gap" else "true_saturation" end),
          source_freshness:{
            br_list_json_present:($br_list_json != ""),
            issues_jsonl_present:($issues_jsonl != ""),
            provided_git_log_json_present:($git_log_json != ""),
            live_git_log_used:($git_log_json == ""),
            artifact_manifest_json_present:($artifact_manifest_json != ""),
            source_revision_required:true,
            source_revision_present:($source_revision != "" and $source_revision != "unknown")
          },
          closed_bead_count:($rows | length),
          weak_evidence_count:($weak | length),
          proof_strength_buckets:{
            direct_commit_reference:($rows | map(select(.evidence_classes | index("direct_commit_reference"))) | length),
            validation_command_present:($rows | map(select(.evidence_classes | index("validation_command_present"))) | length),
            artifact_manifest_present:($rows | map(select(.evidence_classes | index("artifact_manifest_present"))) | length),
            close_reason_only:($rows | map(select(.evidence_classes | index("close_reason_only"))) | length),
            no_evidence:($rows | map(select(.evidence_classes | index("no_evidence"))) | length),
            stale_or_ambiguous_evidence:($rows | map(select(.evidence_classes | index("stale_or_ambiguous_evidence"))) | length),
            bare_heavy_cargo_present:($rows | map(select(.bare_heavy_cargo_present == true)) | length)
          },
          degraded_reasons:($weak | map({bead_id:.id, risk_level, reason_codes, title}) | .[0:50]),
          fail_closed_reasons:$fail_closed_reasons,
          mutation_policy:{
            advisory_only:true,
            proof_only:true,
            mutates_br:false,
            claims_beads:false,
            reopens_beads:false,
            closes_beads:false,
            reassigns_beads:false,
            sends_agent_mail:false,
            repairs_agent_mail_db:false,
            runs_cargo:false,
            runs_rch:false,
            mutates_git:false,
            mutates_remote_workers:false,
            deletes_or_overwrites_target_dirs:false
          },
          rch_policy:{
            runs_rch:false,
            emits_commands_only:true,
            required_heavy_cargo_prefix:"rch exec -- env CARGO_TARGET_DIR=",
            recommended_validation_command:"rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_iw4_closed_bead_proof CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine closed_bead_proof"
          },
          sort_policy:{
            primary:"weak-evidence risk",
            secondary:"priority",
            tertiary:"updated_at",
            deterministic_tie_breaker:"id"
          },
          beads:$rows,
          artifact_paths:{
            closed_bead_proof_integrity_json:$report_json,
            weak_evidence_jsonl:$weak_jsonl,
            run_manifest_json:$manifest_path,
            events_jsonl:$events_path,
            commands_txt:$commands_path,
            trace_ids_json:$trace_ids_path,
            report_md:$report_md,
            closed_beads_normalized_json:$closed_beads_json,
            git_log_normalized_json:$git_log_normalized
          }
        }
  ' >"$report_json"

jq -c '.beads[]? | select(.weak_evidence == true)' "$report_json" >>"$weak_jsonl"
jq -c '.beads[]? | {schema_version:"franken-engine.idea-wizard-iv-closed-bead-proof.event.v1",event:"closed_bead_evaluated",outcome:.risk_level,bead_id:.id,evidence_classes:.evidence_classes,reason_codes:.reason_codes}' "$report_json" >>"$events_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-closed-bead-proof.run-manifest.v1" \
  --arg bead_id "$bead_id" \
  --arg source_revision "$source_revision" \
  --arg report_json "$report_json" \
  --arg weak_jsonl "$weak_jsonl" \
  --arg decision "$(jq -r '.decision' "$report_json")" \
  '{
    schema_version:$schema_version,
    bead_id:$bead_id,
    source_revision:$source_revision,
    decision:$decision,
    artifacts:{
      closed_bead_proof_integrity_json:$report_json,
      weak_evidence_jsonl:$weak_jsonl
    }
  }' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-iv-closed-bead-proof.trace-ids.v1" \
  --arg trace_id "iw4-closed-bead-proof-${run_id}" \
  --arg bead_id "$bead_id" \
  '{schema_version:$schema_version,trace_id:$trace_id,bead_id:$bead_id}' >"$trace_ids_path"

{
  printf '# IDEA-WIZARD-IV Closed-Bead Proof Integrity\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$report_json")"
  printf -- "- Classification: \`%s\`\n" "$(jq -r '.classification' "$report_json")"
  printf -- "- Closed beads: \`%s\`\n" "$(jq '.closed_bead_count' "$report_json")"
  printf -- "- Weak evidence: \`%s\`\n\n" "$(jq '.weak_evidence_count' "$report_json")"
  printf '## Proof Buckets\n\n'
  jq -r '.proof_strength_buckets | to_entries[] | "- `" + .key + "`: `" + (.value | tostring) + "`"' "$report_json"
  if [[ "$(jq '.weak_evidence_count' "$report_json")" -ne 0 ]]; then
    printf '\n## Weak Evidence\n\n'
    jq -r '.beads[]? | select(.weak_evidence == true) | "- `" + .id + "` (`" + .risk_level + "`): " + (.reason_codes | join(", "))' "$report_json"
  fi
} >"$report_md"

write_event "normalizer_complete" "$(jq -r '.decision' "$report_json")" "closed bead proof integrity report emitted"
printf 'closed_bead_proof_integrity=%s\n' "$report_json"
