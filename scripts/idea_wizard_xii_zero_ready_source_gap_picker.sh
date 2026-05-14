#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_XII_SOURCE_GAP_PICKER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-iwxii-source-gap-picker}"
run_id="${IDEA_WIZARD_XII_SOURCE_GAP_PICKER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_XII_SOURCE_GAP_PICKER_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_XII_SOURCE_GAP_PICKER_SOURCE_REVISION:-}"
generated_at_utc="${IDEA_WIZARD_XII_SOURCE_GAP_PICKER_GENERATED_AT_UTC:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
max_candidates=25
original_args=("$@")

br_ready_json=""
br_open_json=""
closed_beads_json=""
issues_jsonl=""
source_marker_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh --br-ready-json FILE --br-open-json FILE (--closed-beads-json FILE | --issues-jsonl FILE) --source-marker-json FILE [OPTIONS]

Build an advisory zero-ready source-gap picker from preserved tracker and
source-marker evidence. The picker never runs Cargo, never runs RCH, and never
mutates beads; it only emits proposed bead artifacts for review.

Required:
  --br-ready-json FILE       `br ready --json` snapshot
  --br-open-json FILE        `br list --status open --json` snapshot
  --closed-beads-json FILE   closed bead history snapshot
  --issues-jsonl FILE        .beads/issues.jsonl snapshot, used instead of closed-beads JSON
  --source-marker-json FILE  source gap markers from scan/proof surfaces

Options:
  --source-revision REV
  --generated-at-utc TIMESTAMP
  --output-dir DIR
  --max-candidates N

Exit codes:
  0   Zero-ready input was processed and artifacts were emitted
  42  Ready/open tracker input is non-empty, so source-gap picking is refused
  64  Invalid option or malformed/missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --br-ready-json)
      br_ready_json="${2:-}"
      shift 2
      ;;
    --br-open-json)
      br_open_json="${2:-}"
      shift 2
      ;;
    --closed-beads-json)
      closed_beads_json="${2:-}"
      shift 2
      ;;
    --issues-jsonl)
      issues_jsonl="${2:-}"
      shift 2
      ;;
    --source-marker-json)
      source_marker_json="${2:-}"
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
    --max-candidates)
      max_candidates="${2:-}"
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
  printf 'jq is required for zero-ready source-gap picking\n' >&2
  exit 2
fi
if [[ -z "$br_ready_json" || -z "$br_open_json" || -z "$source_marker_json" ]]; then
  printf 'source-gap picker requires br-ready, br-open, and source-marker JSON\n' >&2
  usage
  exit 64
fi
if [[ -z "$closed_beads_json" && -z "$issues_jsonl" ]]; then
  printf 'source-gap picker requires --closed-beads-json or --issues-jsonl\n' >&2
  usage
  exit 64
fi
if ! [[ "$max_candidates" =~ ^[0-9]+$ ]] || [[ "$max_candidates" -eq 0 ]]; then
  printf 'max candidates must be a positive integer\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

validate_json_file() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf '%s JSON not found: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf '%s JSON is malformed: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_json_file "$br_ready_json" "br-ready"
validate_json_file "$br_open_json" "br-open"
validate_json_file "$source_marker_json" "source-marker"
if [[ -n "$closed_beads_json" ]]; then
  validate_json_file "$closed_beads_json" "closed-beads"
fi
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
ready_normalized="${run_dir}/br_ready.normalized.json"
open_normalized="${run_dir}/br_open.normalized.json"
closed_normalized="${run_dir}/closed_beads.normalized.json"
source_markers_normalized="${run_dir}/source_markers.normalized.json"
report_json="${run_dir}/zero_ready_source_gap_picker.json"
proposed_beads_json="${run_dir}/proposed_beads.json"
suppressed_candidates_json="${run_dir}/suppressed_candidates.json"
br_commands_path="${run_dir}/br_commands.sh"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
trace_ids_path="${run_dir}/trace_ids.json"

for artifact_path in \
  "$ready_normalized" \
  "$open_normalized" \
  "$closed_normalized" \
  "$source_markers_normalized" \
  "$report_json" \
  "$proposed_beads_json" \
  "$suppressed_candidates_json" \
  "$br_commands_path" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "$report_md" \
  "$trace_ids_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_xii_zero_ready_source_gap_picker.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n\n# This run is advisory-only. Review br_commands.sh before creating any bead.\n' >>"$commands_path"

jq_rows_filter='
  def rows:
    if type == "array" then .
    elif (.issues | type) == "array" then .issues
    elif (.result | type) == "array" then .result
    else []
    end;
  rows
  | map({
      id:(.id // ""),
      title:(.title // ""),
      status:(.status // ""),
      priority:(.priority // null),
      issue_type:(.issue_type // .type // ""),
      assignee:(.assignee // ""),
      description:(.description // .body // ""),
      notes:(.notes // ""),
      close_reason:(.close_reason // ""),
      labels:(if (.labels | type) == "array" then .labels else [] end),
      updated_at:(.updated_at // ""),
      closed_at:(.closed_at // "")
    })
'

jq "$jq_rows_filter" "$br_ready_json" >"$ready_normalized"
jq "$jq_rows_filter" "$br_open_json" >"$open_normalized"
if [[ -n "$closed_beads_json" ]]; then
  jq "$jq_rows_filter | map(select(.status == \"closed\"))" "$closed_beads_json" >"$closed_normalized"
else
  jq -s '
    [ .[] | if type == "array" then .[] else . end ]
    | map({
        id:(.id // ""),
        title:(.title // ""),
        status:(.status // ""),
        priority:(.priority // null),
        issue_type:(.issue_type // .type // ""),
        assignee:(.assignee // ""),
        description:(.description // .body // ""),
        notes:(.notes // ""),
        close_reason:(.close_reason // ""),
        labels:(if (.labels | type) == "array" then .labels else [] end),
        updated_at:(.updated_at // ""),
        closed_at:(.closed_at // "")
      })
    | map(select(.status == "closed"))
  ' "$issues_jsonl" >"$closed_normalized"
fi

jq '
  def rows:
    if type == "array" then .
    elif (.markers | type) == "array" then .markers
    elif (.source_markers | type) == "array" then .source_markers
    elif (.result | type) == "array" then .result
    else []
    end;
  rows
  | map({
      bead_id:(.bead_id // ""),
      related_bead_ids:(
        if (.related_bead_ids | type) == "array" then .related_bead_ids
        else [(.related_bead_id // empty), (.bead_id // empty)] | map(select(. != "")) | unique
        end
      ),
      file:(.file // .path // ""),
      line:((.line // 0) | tonumber? // 0),
      marker:(.marker // .text // ""),
      marker_class:(.marker_class // .class // "source_gap_marker"),
      detail:(.detail // .message // ""),
      confidence:(.confidence // "medium"),
      suggested_next_bead_title:(.suggested_next_bead_title // .suggested_title // ""),
      validation_scope:(.validation_scope // ""),
      ignored:((.ignored // false) == true),
      negative_fixture:((.negative_fixture // false) == true)
    })
  | map(select(.ignored != true and .negative_fixture != true and .file != "" and .marker != ""))
' "$source_marker_json" >"$source_markers_normalized"

# shellcheck disable=SC2094 # report_json is passed as metadata and is not read by this jq invocation.
jq -n \
  --slurpfile ready "$ready_normalized" \
  --slurpfile open "$open_normalized" \
  --slurpfile closed "$closed_normalized" \
  --slurpfile markers "$source_markers_normalized" \
  --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-source-gap-picker.v1" \
  --arg source_revision "$source_revision" \
  --arg generated_at_utc "$generated_at_utc" \
  --arg report_json "$report_json" \
  --arg proposed_beads_json "$proposed_beads_json" \
  --arg suppressed_candidates_json "$suppressed_candidates_json" \
  --arg br_commands_path "$br_commands_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  --arg trace_ids_path "$trace_ids_path" \
  --arg source_markers_normalized "$source_markers_normalized" \
  --argjson max_candidates "$max_candidates" '
    def lower: tostring | ascii_downcase;
    def blob:
      ([.id,.title,.description,.notes,.close_reason] | map(. // "" | tostring) | join("\n"));
    def contains_nonempty($hay; $needle):
      ($needle | tostring | ascii_downcase) as $n
      | (($n | length) > 0 and (($hay | tostring | ascii_downcase) | contains($n)));
    def marker_high_signal:
      ((.marker_class | lower) | test("unsupported|not_implemented|todo|placeholder|stub|fail_closed|semantic"))
      or ((.marker | lower) | test("not yet implemented|unimplemented!|todo!|TODO|FIXME|placeholder|stub|fail closed"));
    def validation_scope_for:
      if (.validation_scope | length) > 0 then .validation_scope
      elif (.file | startswith("crates/franken-core/")) then
        "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_source_gap CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p franken-core <focused_filter>"
      elif (.file | startswith("crates/")) then
        "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_source_gap CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 cargo test -p frankenengine-engine <focused_filter>"
      elif (.file | startswith("scripts/")) then
        "bash -n <changed script>; shellcheck -x <changed script>; bash <focused smoke> check"
      else
        "git diff --check -- " + .file
      end;
    def priority_for:
      if ((.file | startswith("crates/franken-core/")) or ((.marker_class | lower) | test("unsupported|not_implemented|semantic"))) then 1
      elif (.file | startswith("crates/")) then 2
      else 3
      end;
    def validation_cost_for:
      if (.file | startswith("crates/franken-core/")) then "medium"
      elif (.file | startswith("crates/")) then "medium"
      elif (.file | startswith("scripts/")) then "low"
      else "low"
      end;
    def user_impact_for:
      if (.file | test("franken-core|baseline_interpreter|runtime|security|ifc")) then "high"
      elif (.file | startswith("crates/")) then "medium"
      else "low"
      end;
    def score_for:
      (if priority_for == 1 then 80 elif priority_for == 2 then 60 else 35 end)
      + (if user_impact_for == "high" then 20 elif user_impact_for == "medium" then 10 else 0 end)
      + (if validation_cost_for == "low" then 5 else 0 end);
    def slug:
      ((.file + ":" + (.line | tostring) + ":" + .marker)
      | ascii_downcase
      | gsub("[^a-z0-9]+"; "-")
      | sub("^-+"; "")
      | sub("-+$"; "")
      | .[0:72]);
    def title_for:
      if (.suggested_next_bead_title | length) > 0 then .suggested_next_bead_title
      else "[SOURCE-GAP] Resolve " + .marker_class + " in " + .file
      end;
    def body_for($closed_matches):
      "## What\nResolve or explicitly contract the source gap at `" + .file + ":" + (.line | tostring) + "`.\n\n"
      + "## Evidence\n"
      + "- Marker: `" + .marker + "`\n"
      + "- Marker class: `" + .marker_class + "`\n"
      + "- Confidence: `" + .confidence + "`\n"
      + (if (.detail | length) > 0 then "- Detail: " + .detail + "\n" else "" end)
      + (if (($closed_matches | length) > 0) then "- Related closed beads: `" + ($closed_matches | map(.id) | join("`, `")) + "`\n" else "" end)
      + "\n## Validation\n"
      + "- " + validation_scope_for + "\n\n"
      + "## Constraints\n"
      + "- Keep the fix under 60 minutes or leave this as an explicit blocker.\n"
      + "- Do not run local Cargo; use the repo-required rch shape for Rust validation.\n";
    ($ready[0] // []) as $ready_rows
    | ($open[0] // []) as $open_rows
    | ($closed[0] // []) as $closed_rows
    | ($markers[0] // []) as $marker_rows
    | (($ready_rows | length) + ($open_rows | length)) as $queue_count
    | def open_matches($m):
        ($ready_rows + $open_rows)
        | map(select(
            contains_nonempty(blob; $m.file)
            or contains_nonempty(blob; $m.marker)
            or (($m.suggested_next_bead_title | length) > 0 and contains_nonempty(blob; $m.suggested_next_bead_title))
          ));
      def closed_matches($m):
        $closed_rows
        | map(select(
            (.id as $closed_id | $closed_id != "" and ($closed_id == $m.bead_id or ($m.related_bead_ids | index($closed_id))))
            or (contains_nonempty(blob; $m.file) and contains_nonempty(blob; $m.marker))
          ));
      def enriched_marker:
        . as $m
        | (closed_matches($m)) as $closed_matches
        | (open_matches($m)) as $open_matches
        | ($m + {
            candidate_id:("zero-ready-gap-" + ($m | slug)),
            closed_bead_matches:$closed_matches,
            open_bead_matches:$open_matches,
            priority:($m | priority_for),
            issue_type:"bug",
            labels:["idea-wizard","semantic-debt","source-gap"],
            validation_scope:($m | validation_scope_for),
            validation_cost:($m | validation_cost_for),
            user_impact:($m | user_impact_for),
            under_60_minute_estimate:true,
            rank_score:($m | score_for),
            title:($m | title_for),
            body_md:($m | body_for($closed_matches))
          });
      ($marker_rows | map(enriched_marker)) as $candidates
    | ($candidates
        | map(select(
            $queue_count == 0
            and marker_high_signal
            and ((.open_bead_matches | length) == 0)
            and (
              ((.closed_bead_matches | length) == 0)
              or ((.suggested_next_bead_title | length) > 0)
              or (((.confidence | lower) == "high") and ((.marker_class | lower) | test("unsupported|not_implemented|fail_closed|semantic")))
            )
          ))
        | sort_by([-.rank_score, .file, .line, .marker])
        | .[0:$max_candidates]) as $proposals
    | ($candidates
        | map(select((.candidate_id as $id | ($proposals | map(.candidate_id) | index($id))) == null))
        | map(. + {
            suppression_reason:(
              if $queue_count != 0 then "nonzero_ready_or_open_queue"
              elif (.open_bead_matches | length) > 0 then "duplicate_open_or_ready_bead"
              elif (marker_high_signal | not) then "low_signal_marker"
              elif ((.closed_bead_matches | length) > 0) then "duplicate_closed_bead_without_followup_signal"
              else "not_selected"
              end)
          })) as $suppressed
    | {
        schema_version:$schema_version,
        source_revision:$source_revision,
        generated_at_utc:$generated_at_utc,
        decision:(if $queue_count != 0 then "not_zero_ready" elif ($proposals | length) > 0 then "proposals_emitted" else "no_actionable_source_gap" end),
        classification:(if $queue_count != 0 then "queue_not_empty" elif ($proposals | length) > 0 then "source_gap_candidates" else "true_zero_ready_no_source_gaps" end),
        ready_count:($ready_rows | length),
        open_count:($open_rows | length),
        closed_bead_count:($closed_rows | length),
        source_marker_count:($marker_rows | length),
        proposal_count:($proposals | length),
        suppressed_count:($suppressed | length),
        duplicate_suppressed_count:($suppressed | map(select(.suppression_reason | test("duplicate"))) | length),
        max_candidates:$max_candidates,
        ranking_policy:{
          safety:"prefer unsupported, not-implemented, fail-closed, placeholder, and TODO markers",
          user_impact:"runtime/core/security paths outrank script/docs markers",
          validation_cost:"low-cost script/docs checks rank slightly higher than medium-cost Rust checks",
          queue_policy:"refuse proposals unless br ready and open snapshots are both empty"
        },
        proposed_beads:$proposals,
        suppressed_candidates:$suppressed,
        mutation_policy:{
          advisory_only:true,
          creates_beads:false,
          mutates_br:false,
          runs_cargo:false,
          runs_rch:false,
          sends_agent_mail:false,
          touches_workers:false
        },
        artifact_paths:{
          zero_ready_source_gap_picker_json:$report_json,
          proposed_beads_json:$proposed_beads_json,
          suppressed_candidates_json:$suppressed_candidates_json,
          br_commands_sh:$br_commands_path,
          run_manifest_json:$manifest_path,
          events_jsonl:$events_path,
          commands_txt:$commands_path,
          report_md:$report_md,
          trace_ids_json:$trace_ids_path,
          source_markers_normalized_json:$source_markers_normalized
        }
      }
  ' >"$report_json"

jq '.proposed_beads' "$report_json" >"$proposed_beads_json"
jq '.suppressed_candidates' "$report_json" >"$suppressed_candidates_json"

{
  printf '#!/usr/bin/env bash\n'
  printf 'set -euo pipefail\n\n'
  printf '# Review-only transcript generated by idea_wizard_xii_zero_ready_source_gap_picker.sh.\n'
  printf '# These commands were not run by the picker.\n\n'
  jq -r '
    .proposed_beads[]
    | "br create " + (.title | @sh) + " -p " + (.priority | tostring) + " -t " + (.issue_type | @sh) + " --description " + (.body_md | @sh)
  ' "$report_json"
} >"$br_commands_path"

jq -c '.proposed_beads[]? | {schema_version:"franken-engine.idea-wizard-xii-source-gap-picker.event.v1",event:"source_gap_candidate_proposed",outcome:"candidate",candidate_id,title,priority,file,line,marker_class,rank_score}' "$report_json" >>"$events_path"
jq -c '.suppressed_candidates[]? | {schema_version:"franken-engine.idea-wizard-xii-source-gap-picker.event.v1",event:"source_gap_candidate_suppressed",outcome:.suppression_reason,candidate_id,title,file,line,marker_class}' "$report_json" >>"$events_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-source-gap-picker-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg report_json "$report_json" \
  --arg proposed_beads_json "$proposed_beads_json" \
  --arg suppressed_candidates_json "$suppressed_candidates_json" \
  --arg br_commands_path "$br_commands_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" \
  --arg trace_ids_path "$trace_ids_path" \
  '{
    schema_version:$schema_version,
    source_revision:$source_revision,
    artifact_paths:{
      zero_ready_source_gap_picker_json:$report_json,
      proposed_beads_json:$proposed_beads_json,
      suppressed_candidates_json:$suppressed_candidates_json,
      br_commands_sh:$br_commands_path,
      events_jsonl:$events_path,
      commands_txt:$commands_path,
      report_md:$report_md,
      trace_ids_json:$trace_ids_path
    },
    mutation_policy:{
      advisory_only:true,
      creates_beads:false,
      mutates_br:false,
      runs_cargo:false,
      runs_rch:false
    }
  }' >"$manifest_path"

jq -n \
  --arg schema_version "franken-engine.idea-wizard-xii-zero-ready-source-gap-picker-trace-ids.v1" \
  --arg trace_id "iwxii-source-gap-picker-${run_id}" \
  --arg source_revision "$source_revision" \
  '{schema_version:$schema_version,trace_id:$trace_id,source_revision:$source_revision}' >"$trace_ids_path"

jq -r '
  "# IDEA-WIZARD-XII Zero-Ready Source-Gap Picker",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Classification: `" + .classification + "`"),
  ("- Ready count: `" + (.ready_count | tostring) + "`"),
  ("- Open count: `" + (.open_count | tostring) + "`"),
  ("- Source markers: `" + (.source_marker_count | tostring) + "`"),
  ("- Proposed beads: `" + (.proposal_count | tostring) + "`"),
  ("- Suppressed candidates: `" + (.suppressed_count | tostring) + "`"),
  "",
  "## Proposed Beads",
  "",
  (if (.proposed_beads | length) == 0 then
    "none"
  else
    (.proposed_beads[]
      | "- `" + .candidate_id + "` P" + (.priority | tostring) + " `" + .title + "` from `" + .file + ":" + (.line | tostring) + "`")
  end),
  "",
  "## Suppressed Candidates",
  "",
  (if (.suppressed_candidates | length) == 0 then
    "none"
  else
    (.suppressed_candidates[]
      | "- `" + .candidate_id + "` `" + .suppression_reason + "` from `" + .file + ":" + (.line | tostring) + "`")
  end)
' "$report_json" >"$report_md"

printf 'zero_ready_source_gap_picker=%s\n' "$report_json"
printf 'proposed_beads=%s\n' "$proposed_beads_json"
printf 'br_commands=%s\n' "$br_commands_path"

if jq -e '.decision == "not_zero_ready"' "$report_json" >/dev/null; then
  exit 42
fi
exit 0
