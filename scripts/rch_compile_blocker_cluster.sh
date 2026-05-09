#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${RCH_COMPILE_BLOCKER_CLUSTER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-rch-compile-blocker-cluster}"
run_id="${RCH_COMPILE_BLOCKER_CLUSTER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${RCH_COMPILE_BLOCKER_CLUSTER_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

transcript_path=""
metadata_json=""
source_revision="${RCH_COMPILE_BLOCKER_CLUSTER_SOURCE_REVISION:-}"
case_id_override=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/rch_compile_blocker_cluster.sh --transcript FILE --metadata-json FILE [OPTIONS]

Clusters preserved rch-backed Cargo/rustc output into conservative blocker
proposal groups. The analyzer is advisory-only: it does not run Cargo, invoke
rch, create beads, mutate files outside the output directory, or inspect live
workers.

Required inputs:
  --transcript FILE       Captured rch stdout/stderr snippet
  --metadata-json FILE    Command metadata JSON with command, scope, worker, target

Options:
  --output-dir DIR
  --source-revision REV
  --case-id ID

Artifacts:
  compile_blocker_clusters.json
  proposed_beads.md
  run_manifest.json
  commands.txt
  events.jsonl
  report.md

Exit codes:
  0   Analyzer emitted clusters or an explicit no-blocker result
  42  Input is contaminated or too incomplete for blocker proposals
  64  Invalid option or malformed/missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --transcript)
      transcript_path="${2:-}"
      shift 2
      ;;
    --metadata-json)
      metadata_json="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id_override="${2:-}"
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

if [[ -z "$transcript_path" || -z "$metadata_json" ]]; then
  printf 'compile blocker cluster requires --transcript and --metadata-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for compile blocker clustering\n' >&2
  exit 2
fi
if [[ ! -f "$transcript_path" ]]; then
  printf 'transcript not found: %s\n' "$transcript_path" >&2
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
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
clusters_path="${run_dir}/compile_blocker_clusters.json"
proposals_path="${run_dir}/proposed_beads.md"
manifest_path="${run_dir}/run_manifest.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
metadata_normalized_path="${run_dir}/command_metadata.normalized.json"
transcript_excerpt_path="${run_dir}/transcript_excerpt.txt"
diagnostics_tsv_path="${run_dir}/diagnostics.tsv"
diagnostics_json_path="${run_dir}/diagnostics.json"
first_errors_path="${run_dir}/first_error_lines.txt"
clusters_tmp="${clusters_path}.tmp"
manifest_tmp="${manifest_path}.tmp"

for artifact_path in \
  "$clusters_path" \
  "$proposals_path" \
  "$manifest_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path" \
  "$metadata_normalized_path" \
  "$transcript_excerpt_path" \
  "$diagnostics_tsv_path" \
  "$diagnostics_json_path" \
  "$first_errors_path" \
  "$clusters_tmp" \
  "$manifest_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/rch_compile_blocker_cluster.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"
  local evidence_path="$4"

  jq -nc \
    --arg schema_version "franken-engine.rch-compile-blocker-cluster.event.v1" \
    --arg component "rch_compile_blocker_cluster" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg evidence_path "$evidence_path" \
    '{
      schema_version: $schema_version,
      component: $component,
      event: $event,
      outcome: $outcome,
      detail: $detail,
      evidence_path: $evidence_path
    }' >>"$events_path"
}

has_marker() {
  local pattern="$1"
  grep -Eiq "$pattern" "$transcript_path"
}

bool_from_marker() {
  local pattern="$1"
  if has_marker "$pattern"; then
    printf 'true'
  else
    printf 'false'
  fi
}

jq -cS . "$metadata_json" >"$metadata_normalized_path"
sed -n '1,260p' "$transcript_path" >"$transcript_excerpt_path"

awk '
  BEGIN {
    pending = 0
    current_error = ""
    current_code = ""
  }
  /^error\[[^]]+\]:/ || /^error:/ {
    current_error = $0
    current_code = ""
    if ($0 ~ /^error\[[^]]+\]:/) {
      current_code = $0
      sub(/^error\[/, "", current_code)
      sub(/\]:.*/, "", current_code)
    }
    pending = 1
    next
  }
  pending == 1 && /^[[:space:]]+-->/ {
    path = $0
    sub(/^[[:space:]]+-->[[:space:]]*/, "", path)
    split(path, parts, ":")
    printf "%s\t%s\t%s\n", current_code, parts[1], current_error
    pending = 0
    next
  }
  END {
    if (pending == 1) {
      printf "%s\t%s\t%s\n", current_code, "", current_error
    }
  }
' "$transcript_path" >"$diagnostics_tsv_path"

awk '
  BEGIN { count = 0 }
  /^(error(\[[^]]+\])?:|error:)/ || /^[[:space:]]+-->/ {
    print
    count++
    if (count >= 12) {
      exit
    }
  }
' "$transcript_path" >"$first_errors_path"

jq -R -s '
  split("\n")
  | map(select(length > 0))
  | map(split("\t"))
  | map({
      error_code: (.[0] // ""),
      file_path: (.[1] // ""),
      first_error: (.[2] // "")
    })
' "$diagnostics_tsv_path" >"$diagnostics_json_path"

write_event "input.loaded" "ok" "normalized command metadata" "$metadata_json"
write_event "diagnostics.extracted" "ok" "rustc diagnostics extracted from transcript" "$diagnostics_json_path"

command_text="$(jq -r '.command // .validation_command // ""' "$metadata_normalized_path")"
worker_id="$(jq -r '.worker_id // .selected_worker // .worker // ""' "$metadata_normalized_path")"
build_id="$(jq -r '.build_id // .build // ""' "$metadata_normalized_path")"
target_dir="$(jq -r '.target_dir // .cargo_target_dir // ""' "$metadata_normalized_path")"
package_name="$(jq -r '.package // .package_name // ""' "$metadata_normalized_path")"
target_name="$(jq -r '.target // .target_name // ""' "$metadata_normalized_path")"
validation_scope="$(jq -r '.validation_scope // ""' "$metadata_normalized_path")"
exit_code="$(jq -r 'if (.exit_code // .remote_exit_code // null) == null then "" else ((.exit_code // .remote_exit_code) | tostring) end' "$metadata_normalized_path")"
intended_target_path="$(jq -r '.intended_target_path // ""' "$metadata_normalized_path")"
intended_target_marker="$(jq -r '.intended_target_marker // ""' "$metadata_normalized_path")"
case_id="$(jq -r '.case_id // ""' "$metadata_normalized_path")"
if [[ -n "$case_id_override" ]]; then
  case_id="$case_id_override"
fi

metadata_truncated="$(jq -r 'if (.transcript_truncated // false) == true then "true" else "false" end' "$metadata_normalized_path")"
local_fallback_observed="$(bool_from_marker 'local fallback|fallback to local|falling back to local|Executing command locally|running locally|Failed to query daemon|refusing local fallback|RCH-E326|\[RCH\] local')"
toolchain_blocker_observed="$(bool_from_marker 'cargo-clippy.*not installed|component .*not installed|toolchain.*missing|command not found: (cargo|rustc)|(cargo|rustc): command not found|linker .*not found|No such file or directory.*(cargo|rustc)')"
truncated_output_observed="$metadata_truncated"
if [[ "$truncated_output_observed" != "true" ]] && has_marker 'output truncated|tokens truncated|truncated after|log truncated'; then
  truncated_output_observed=true
fi

tests_reached_intended_target=false
if [[ "$local_fallback_observed" == "true" || "$toolchain_blocker_observed" == "true" || "$truncated_output_observed" == "true" ]]; then
  tests_reached_intended_target=false
elif [[ -n "$intended_target_path" ]] && grep -Fq "$intended_target_path" "$diagnostics_tsv_path"; then
  tests_reached_intended_target=true
elif [[ -n "$intended_target_marker" ]] && grep -Fq "$intended_target_marker" "$transcript_path"; then
  tests_reached_intended_target=true
fi

jq -n \
  --slurpfile metadata "$metadata_normalized_path" \
  --slurpfile diagnostics "$diagnostics_json_path" \
  --rawfile first_errors "$first_errors_path" \
  --arg schema_version "franken-engine.rch-compile-blocker-clusters.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg command "$command_text" \
  --arg worker_id "$worker_id" \
  --arg build_id "$build_id" \
  --arg target_dir "$target_dir" \
  --arg package_name "$package_name" \
  --arg target_name "$target_name" \
  --arg validation_scope "$validation_scope" \
  --arg exit_code "$exit_code" \
  --arg intended_target_path "$intended_target_path" \
  --arg transcript_path "$transcript_path" \
  --arg metadata_json "$metadata_json" \
  --arg clusters_path "$clusters_path" \
  --arg proposals_path "$proposals_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --argjson tests_reached_intended_target "$tests_reached_intended_target" \
  --argjson local_fallback_observed "$local_fallback_observed" \
  --argjson toolchain_blocker_observed "$toolchain_blocker_observed" \
  --argjson truncated_output_observed "$truncated_output_observed" \
  '
  def arr($value): if ($value | type) == "array" then $value else [] end;
  def nonempty($value): (($value // "") | tostring | length) > 0;
  def starts_any($path; $prefixes): any($prefixes[]?; . as $prefix | ($path | startswith($prefix)));
  def clean_codes($rows):
    ($rows | map(.error_code // "") | map(select(length > 0)) | unique);
  def first_lines: ($first_errors | split("\n") | map(select(length > 0)));
  def family_for($row):
    if (($row.file_path // "") | test("(^|/)tests?/"))
       and ((["E0061", "E0599", "E0308"] | index($row.error_code // "")) != null)
    then "stale_test_api"
    elif nonempty($row.error_code) then ("rustc_" + $row.error_code)
    else "rustc_unknown"
    end;
  def disposition_for($file; $family; $touched):
    if ($file | length) == 0 then "infra_toolchain_blocker"
    elif starts_any($file; $touched) or ($intended_target_path != "" and ($file | startswith($intended_target_path))) then "block_current_bead"
    elif $family == "stale_test_api" then "file_follow_up"
    else "file_follow_up"
    end;
  def title_for($disposition; $file; $codes; $family):
    if $disposition == "block_current_bead" then
      "[COMPILE-BLOCKER] Fix touched target " + ($file // "unknown") + " " + (($codes | join(",")) // "rustc")
    elif $family == "stale_test_api" then
      "[COMPILE-BLOCKER] Refresh stale test API in " + ($file // "unknown")
    elif $disposition == "infra_toolchain_blocker" then
      "[COMPILE-BLOCKER] Resolve remote proof infrastructure blocker"
    else
      "[COMPILE-BLOCKER] Fix unrelated current-head error in " + ($file // "unknown")
    end;
  def body_for($title; $disposition; $file; $codes; $diagnostics):
    "## What\n"
    + $title
    + "\n\n## Evidence\n"
    + "- Command: `" + $command + "`\n"
    + "- Worker: `" + (if $worker_id == "" then "unknown" else $worker_id end) + "`\n"
    + "- Validation scope: `" + (if $validation_scope == "" then "unspecified" else $validation_scope end) + "`\n"
    + "- Package/target: `" + (if $package_name == "" then "unknown" else $package_name end) + "/" + (if $target_name == "" then "unknown" else $target_name end) + "`\n"
    + "- File: `" + (if $file == "" then "unknown" else $file end) + "`\n"
    + "- Error codes: `" + (if ($codes | length) == 0 then "none" else ($codes | join(",")) end) + "`\n"
    + "- Disposition: `" + $disposition + "`\n\n"
    + "## First Error Lines\n"
    + (if ($diagnostics | length) == 0 then "none captured\n" else ($diagnostics | map("- `" + . + "`") | join("\n")) + "\n" end)
    + "\n## Acceptance\n"
    + "- Reproduce with the exact command above or a narrower rch-backed command.\n"
    + "- Do not close from truncated or local_fallback output.\n";
  ($metadata[0]) as $meta
  | ($diagnostics[0]) as $rows
  | arr($meta.touched_paths) as $touched_paths
  | (
      if $local_fallback_observed then
        [{
          cluster_id: "infra-localfb",
          disposition: "infra_toolchain_blocker",
          confidence: "high",
          error_family: "local_fallback_contamination",
          file_path: null,
          error_codes: [],
          first_diagnostics: first_lines,
          proposed_bead: {
            title: "[COMPILE-BLOCKER] Refuse contaminated local_fallback proof",
            priority: 2,
            issue_type: "bug",
            body_md: body_for("[COMPILE-BLOCKER] Refuse contaminated local_fallback proof"; "infra_toolchain_blocker"; ""; []; first_lines)
          }
        }]
      elif $toolchain_blocker_observed then
        [{
          cluster_id: "infra-worker-toolchain",
          disposition: "infra_toolchain_blocker",
          confidence: "high",
          error_family: "worker_toolchain_missing",
          file_path: null,
          error_codes: clean_codes($rows),
          first_diagnostics: first_lines,
          proposed_bead: {
            title: "[COMPILE-BLOCKER] Repair remote worker toolchain for proof command",
            priority: 2,
            issue_type: "bug",
            body_md: body_for("[COMPILE-BLOCKER] Repair remote worker toolchain for proof command"; "infra_toolchain_blocker"; ""; clean_codes($rows); first_lines)
          }
        }]
      elif $truncated_output_observed then
        [{
          cluster_id: "infra-truncated-output",
          disposition: "infra_toolchain_blocker",
          confidence: "low",
          error_family: "truncated_output",
          file_path: null,
          error_codes: clean_codes($rows),
          first_diagnostics: first_lines,
          proposed_bead: {
            title: "[COMPILE-BLOCKER] Reproduce truncated compile output before filing source bugs",
            priority: 2,
            issue_type: "bug",
            body_md: body_for("[COMPILE-BLOCKER] Reproduce truncated compile output before filing source bugs"; "infra_toolchain_blocker"; ""; clean_codes($rows); first_lines)
          }
        }]
      else
        ($rows
          | group_by(.file_path)
          | to_entries
          | map(
              .value as $group
              | ($group[0]) as $first
              | (family_for($first)) as $family
              | (disposition_for(($first.file_path // ""); $family; $touched_paths)) as $disposition
              | (clean_codes($group)) as $codes
              | ($group | map(.first_error) | unique | .[0:4]) as $diagnostics_for_file
              | (title_for($disposition; ($first.file_path // ""); $codes; $family)) as $title
              | {
                  cluster_id: ("cluster-" + ((.key + 1) | tostring)),
                  disposition: $disposition,
                  confidence: (if $tests_reached_intended_target or $disposition == "file_follow_up" then "medium" else "low" end),
                  error_family: $family,
                  file_path: (if ($first.file_path // "") == "" then null else $first.file_path end),
                  error_codes: $codes,
                  first_diagnostics: $diagnostics_for_file,
                  proposed_bead: {
                    title: $title,
                    priority: 2,
                    issue_type: "bug",
                    body_md: body_for($title; $disposition; ($first.file_path // ""); $codes; $diagnostics_for_file)
                  }
                }
            ))
      end
    ) as $clusters
  | {
      schema_version: $schema_version,
      case_id: (if $case_id == "" then null else $case_id end),
      source_revision: $source_revision,
      decision: (
        if $local_fallback_observed or $toolchain_blocker_observed or $truncated_output_observed then "fail_closed"
        elif ($clusters | length) > 0 then "clustered"
        else "no_blocker"
        end
      ),
      command_metadata: {
        command: $command,
        worker_id: (if $worker_id == "" then null else $worker_id end),
        build_id: (if $build_id == "" then null else $build_id end),
        target_dir: (if $target_dir == "" then null else $target_dir end),
        package: (if $package_name == "" then null else $package_name end),
        target: (if $target_name == "" then null else $target_name end),
        validation_scope: (if $validation_scope == "" then null else $validation_scope end),
        exit_code: (if $exit_code == "" then null else ($exit_code | tonumber) end)
      },
      evidence_health: {
        local_fallback_observed: $local_fallback_observed,
        toolchain_blocker_observed: $toolchain_blocker_observed,
        truncated_output_observed: $truncated_output_observed,
        tests_reached_intended_target: $tests_reached_intended_target,
        intended_target_path: (if $intended_target_path == "" then null else $intended_target_path end),
        diagnostic_count: ($rows | length)
      },
      cluster_counts: {
        total: ($clusters | length),
        block_current_bead: ($clusters | map(select(.disposition == "block_current_bead")) | length),
        file_follow_up: ($clusters | map(select(.disposition == "file_follow_up")) | length),
        infra_toolchain_blocker: ($clusters | map(select(.disposition == "infra_toolchain_blocker")) | length)
      },
      clusters: $clusters,
      input_artifacts: {
        transcript: $transcript_path,
        metadata_json: $metadata_json
      },
      artifact_paths: {
        compile_blocker_clusters_json: $clusters_path,
        proposed_beads_md: $proposals_path,
        run_manifest_json: $manifest_path,
        commands_txt: $commands_path,
        events_jsonl: $events_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        creates_beads: false,
        mutates_beads: false,
        sends_agent_mail: false,
        changes_workers: false
      }
    }' >"$clusters_tmp"
mv "$clusters_tmp" "$clusters_path"

jq -r '
  "# Proposed Compile Blocker Beads",
  "",
  "These are draft proposals only. Review before running `br create`.",
  "",
  (if (.clusters | length) == 0 then
    "No compile blocker proposals were generated."
  else
    (.clusters[]
      | "## " + .proposed_bead.title
        + "\n\n- Disposition: `" + .disposition + "`"
        + "\n- Confidence: `" + .confidence + "`"
        + "\n- Error family: `" + .error_family + "`"
        + "\n\nSuggested bead body:\n\n" + .proposed_bead.body_md)
  end)
' "$clusters_path" >"$proposals_path"

jq -n \
  --arg schema_version "franken-engine.rch-compile-blocker-cluster-run-manifest.v1" \
  --arg source_revision "$source_revision" \
  --arg clusters_path "$clusters_path" \
  --arg proposals_path "$proposals_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg diagnostics_json_path "$diagnostics_json_path" \
  --arg transcript_excerpt_path "$transcript_excerpt_path" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    artifact_paths: {
      compile_blocker_clusters_json: $clusters_path,
      proposed_beads_md: $proposals_path,
      run_manifest_json: $manifest_path,
      commands_txt: $commands_path,
      events_jsonl: $events_path,
      report_md: $report_path,
      diagnostics_json: $diagnostics_json_path,
      transcript_excerpt_txt: $transcript_excerpt_path
    },
    mutation_policy: {
      fixture_fed_only: true,
      advisory_only: true,
      runs_cargo: false,
      runs_rch: false,
      creates_beads: false,
      mutates_br: false,
      sends_agent_mail: false,
      mutates_remote_workers: false
    }
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

jq -r '
  "# RCH Compile Blocker Cluster Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Command: `" + .command_metadata.command + "`"),
  ("- Worker: `" + (.command_metadata.worker_id // "none") + "`"),
  ("- Validation scope: `" + (.command_metadata.validation_scope // "unspecified") + "`"),
  ("- Tests reached intended target: `" + (.evidence_health.tests_reached_intended_target | tostring) + "`"),
  ("- Local fallback observed: `" + (.evidence_health.local_fallback_observed | tostring) + "`"),
  ("- Truncated output observed: `" + (.evidence_health.truncated_output_observed | tostring) + "`"),
  "",
  "## Cluster Counts",
  "",
  ("- Total: `" + (.cluster_counts.total | tostring) + "`"),
  ("- Block current bead: `" + (.cluster_counts.block_current_bead | tostring) + "`"),
  ("- File follow-up: `" + (.cluster_counts.file_follow_up | tostring) + "`"),
  ("- Infra/toolchain blocker: `" + (.cluster_counts.infra_toolchain_blocker | tostring) + "`"),
  "",
  "## Clusters",
  "",
  (if (.clusters | length) == 0 then
    "none"
  else
    (.clusters[]
      | "- `" + .cluster_id + "` " + .disposition + " " + (.file_path // "infra") + " " + (.error_codes | join(",")))
  end)
' "$clusters_path" >"$report_path"

write_event "clusters.written" "ok" "$(jq -r '.decision' "$clusters_path")" "$clusters_path"
write_event "proposals.written" "ok" "draft proposed beads emitted" "$proposals_path"

printf 'compile_blocker_clusters=%s\n' "$clusters_path"
printf 'compile_blocker_proposed_beads=%s\n' "$proposals_path"
printf 'compile_blocker_report=%s\n' "$report_path"

if jq -e '.decision == "fail_closed"' "$clusters_path" >/dev/null; then
  exit 42
fi
exit 0
