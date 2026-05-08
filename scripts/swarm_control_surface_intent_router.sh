#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CONTROL_SURFACE_INTENT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-intent}"
run_id="${SWARM_CONTROL_SURFACE_INTENT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_INTENT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

catalog_json=""
intent_json=""
bead_status_json=""
operator_constraints_json=""
source_revision="${SWARM_CONTROL_SURFACE_INTENT_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_control_surface_intent_router.sh --catalog-json FILE --intent-json FILE [OPTIONS]

Route explicit operator intent and symptom tags to ranked SWARM-CTRL-XVII/XVIII
control surfaces. The router is advisory-only and does not query live br,
Agent Mail, rch, cargo, git, or workers.

Required:
  --catalog-json FILE
  --intent-json FILE

Optional:
  --bead-status-json FILE
  --operator-constraints-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_control_surface_intent_plan.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  plan emitted with at least one recommendation
  42 fail-closed routing problem
  64 invalid arguments or malformed input JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --catalog-json)
      catalog_json="${2:-}"
      shift 2
      ;;
    --intent-json)
      intent_json="${2:-}"
      shift 2
      ;;
    --bead-status-json)
      bead_status_json="${2:-}"
      shift 2
      ;;
    --operator-constraints-json)
      operator_constraints_json="${2:-}"
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
  printf 'jq is required for control-surface intent routing\n' >&2
  exit 2
fi
if [[ -z "$catalog_json" || -z "$intent_json" ]]; then
  printf '--catalog-json and --intent-json are required\n' >&2
  usage
  exit 64
fi
for input in "$catalog_json" "$intent_json" "$bead_status_json" "$operator_constraints_json"; do
  if [[ -n "$input" ]]; then
    if [[ ! -f "$input" ]]; then
      printf 'input file does not exist: %s\n' "$input" >&2
      exit 64
    fi
    if ! jq empty "$input" >/dev/null 2>&1; then
      printf 'input is not valid JSON: %s\n' "$input" >&2
      exit 64
    fi
  fi
done
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi
if ! jq -e '(.surfaces | type == "array") and (.decision | type == "string")' "$catalog_json" >/dev/null; then
  printf 'catalog JSON must contain decision and surfaces array\n' >&2
  exit 64
fi
if ! jq -e '((.intent_tags // []) | type == "array") and ((.symptom_tags // []) | type == "array")' "$intent_json" >/dev/null; then
  printf 'intent JSON must contain array intent_tags and symptom_tags when present\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
plan_path="${run_dir}/swarm_control_surface_intent_plan.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

: >"$events_path"
: >"$fail_closed_reasons_jsonl"

printf './scripts/swarm_control_surface_intent_router.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-control-surface-intent.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

fail_closed_count=0

append_reason() {
  local code="$1"
  local surface_id="$2"
  local detail="$3"

  jq -nc \
    --arg code "$code" \
    --arg surface_id "$surface_id" \
    --arg detail "$detail" \
    '{code:$code,surface_id:$surface_id,detail:$detail}' >>"$fail_closed_reasons_jsonl"
  fail_closed_count=$((fail_closed_count + 1))
  write_event "fail_closed" "${surface_id}:${code}:${detail}"
}

candidate_path="${run_dir}/candidate_surfaces.json"
# shellcheck disable=SC2094
jq -n \
  --slurpfile catalog "$catalog_json" \
  --slurpfile intent "$intent_json" \
  '
  def arr($x): if $x == null then [] else $x end;
  def intersect($a; $b): [$a[] as $x | select($b | index($x))];
  def expanded_for($tag):
    if ((["remote-proof-residency", "resident-remote-proof", "remote-proof-bundle"] | index($tag)) != null) then
      ["resident-proof", "remote-proof", "bundle-executor", "proof-reuse"]
    elif ((["artifact-retrieval", "remote-proof-artifact-retrieval", "mirror-retrieval"] | index($tag)) != null) then
      ["artifact-mirror", "remote-proof", "handoff"]
    elif ((["archive-export", "remote-proof-archive-export"] | index($tag)) != null) then
      ["archive-export", "remote-proof", "handoff"]
    elif ((["proof-cost-pressure", "proof-cost", "expensive-proof-lane"] | index($tag)) != null) then
      ["proof-economy", "policy", "cost", "admission"]
    elif ((["proof-reuse-uncertainty", "proof-reuse", "proof-economy-replay", "trace-shape-drift"] | index($tag)) != null) then
      ["proof-economy", "replay-trace", "normalizer", "determinism"]
    elif ((["counterfactual-proof-cost", "scheduler-what-if"] | index($tag)) != null) then
      ["proof-economy", "counterfactual", "what-if", "operator-report"]
    elif ((["build-storm", "build-storm-qos", "build-storm-backlog", "qos-resource-pressure", "resource-pressure"] | index($tag)) != null) then
      ["build-storm", "qos", "batching", "admission", "resource-pressure", "worker-capability", "toolchain", "proof-routing"]
    elif ((["toolchain-mismatch", "worker-toolchain-mismatch", "worker-capability-drift"] | index($tag)) != null) then
      ["worker-capability", "toolchain", "normalizer", "proof-routing", "resource-pressure"]
    elif ((["sticky-worker-reuse", "sticky-worker", "sticky-worker-lease", "worker-sticky-reuse", "warm-target-lease"] | index($tag)) != null) then
      ["sticky-worker", "lease", "reuse", "warm-target", "locality"]
    elif ((["warm-target-roi", "warm-target-reuse"] | index($tag)) != null) then
      ["warm-target", "roi", "eviction", "locality"]
    elif ((["prefetch-roi", "warm-target-prefetch", "prefetch-cost"] | index($tag)) != null) then
      ["warm-target", "prefetch", "roi", "operator-advisory", "locality"]
    elif ((["local-fallback-contamination", "remote-proof-validation-contaminated", "rch-local-fallback"] | index($tag)) != null) then
      ["rch", "stall", "local-fallback", "remote-proof", "rehabilitation", "remote-proof-classifier", "fail-closed"]
    else
      []
    end;
  def expand_tags($tags):
    ($tags // []) as $base
    | ($base + ([$base[]? as $tag | expanded_for($tag)[]?]))
    | unique;
  ($catalog[0].surfaces // []) as $surfaces
  | (expand_tags($intent[0].intent_tags // [])) as $intent_tags
  | (expand_tags($intent[0].symptom_tags // [])) as $symptom_tags
  | [
      $surfaces[]
      | . as $surface
      | (intersect(arr($surface.intent_tags); $intent_tags)) as $matched_intents
      | (intersect(arr($surface.symptom_tags); $symptom_tags)) as $matched_symptoms
      | (($matched_intents | length) * 10 + ($matched_symptoms | length) * 5) as $score
      | select($score > 0)
      | {
          surface_id: $surface.surface_id,
          score: $score,
          matched_intent_tags: $matched_intents,
          matched_symptom_tags: $matched_symptoms,
          purpose: $surface.purpose,
          implementation_script: $surface.implementation_script,
          smoke_script: $surface.smoke_script,
          contract_json: $surface.contract_json,
          runbook_doc: $surface.runbook_doc,
          owning_bead_id: $surface.owning_bead_id,
          required_inputs: ($surface.required_inputs // []),
          emitted_artifacts: ($surface.emitted_artifacts // []),
          validation_commands: ($surface.validation_commands // []),
          mutation_policy: ($surface.mutation_policy // {}),
          upstream_surface_ids: ($surface.upstream_surface_ids // []),
          downstream_surface_ids: ($surface.downstream_surface_ids // []),
          operator_status_section: $surface.operator_status_section
        }
    ]
  | sort_by([-.score, .surface_id])
  ' >"$candidate_path"

candidate_count="$(jq 'length' "$candidate_path")"
if [[ "$candidate_count" -eq 0 ]]; then
  append_reason "FE-SWARM-INTENT-NO-MATCH" "catalog" "no catalog surface matched requested intent or symptom tags"
fi
if [[ "$(jq -r '.decision' "$catalog_json")" == "fail_closed" ]]; then
  append_reason "FE-SWARM-INTENT-CATALOG-FAIL-CLOSED" "catalog" "normalized catalog is already fail_closed"
fi

top_candidates_path="${run_dir}/top_candidates.json"
jq '.[0:3]' "$candidate_path" >"$top_candidates_path"

top_count="$(jq 'length' "$top_candidates_path")"
for ((idx = 0; idx < top_count; idx++)); do
  row="$(jq -c ".[$idx]" "$top_candidates_path")"
  surface_id="$(jq -r '.surface_id // "unknown"' <<<"$row")"

  for required_field in implementation_script smoke_script contract_json emitted_artifacts validation_commands; do
    if ! jq -e --arg field "$required_field" '
      has($field)
      and (.[$field] != null)
      and (if (.[$field] | type) == "array" then (.[$field] | length > 0) else (.[$field] | length > 0) end)
    ' <<<"$row" >/dev/null; then
      append_reason "FE-SWARM-INTENT-MISSING-REQUIRED-ARTIFACT" "$surface_id" "candidate missing ${required_field}"
    fi
  done

  if jq -e '
    (.mutation_policy // {}) as $m
    | any([
        "mutates_br",
        "claims_beads",
        "reassigns_beads",
        "closes_beads",
        "releases_reservations",
        "sends_agent_mail",
        "queries_live_agent_mail",
        "mutates_git",
        "runs_cargo",
        "runs_rch",
        "mutates_remote_workers",
        "changes_live_queue_policy",
        "replaces_operator_status_report"
      ][]; $m[.] == true)
  ' <<<"$row" >/dev/null; then
    append_reason "FE-SWARM-INTENT-UNSAFE-MUTATION-POLICY" "$surface_id" "candidate claims unsupported live mutation"
  fi

  if jq -e '
    [.validation_commands[]? | select(
      test("(^|[[:space:]])cargo (check|test|clippy|run)")
      and (startswith("rch exec -- env CARGO_TARGET_DIR=") | not)
    )] | length > 0
  ' <<<"$row" >/dev/null; then
    append_reason "FE-SWARM-INTENT-BARE-HEAVY-CARGO" "$surface_id" "recommended commands include bare heavy Cargo"
  fi
done

if [[ "$top_count" -gt 1 ]]; then
  policy_fingerprints="$(jq -r '[.[] | (.mutation_policy | tostring)] | unique | length' "$top_candidates_path")"
  if [[ "$policy_fingerprints" -gt 1 ]]; then
    append_reason "FE-SWARM-INTENT-CONFLICTING-MUTATION-POLICY" "top_candidates" "matched surfaces disagree on mutation policy"
  fi
fi

if [[ "$fail_closed_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
else
  decision="pass"
  exit_code=0
fi

jq -s . "$fail_closed_reasons_jsonl" >"${run_dir}/fail_closed_reasons.json"

constraints_expr='{}'
if [[ -n "$operator_constraints_json" ]]; then
  constraints_expr="$(jq -c . "$operator_constraints_json")"
fi

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-control-surface-intent-plan.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg catalog_json "$catalog_json" \
  --arg intent_json "$intent_json" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$markdown_path" \
  --arg plan_json "$plan_path" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson operator_constraints "$constraints_expr" \
  --slurpfile recommendations "$top_candidates_path" \
  --slurpfile fail_closed_reasons "${run_dir}/fail_closed_reasons.json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    catalog_json: $catalog_json,
    intent_json: $intent_json,
    operator_constraints: $operator_constraints,
    recommendations: $recommendations[0],
    advisory_commands: ([$recommendations[0][]?.validation_commands[]?] | unique),
    artifacts_to_preserve: ([$recommendations[0][]?.emitted_artifacts[]?] | unique),
    blocked_reasons: [],
    degraded_reasons: [],
    fail_closed_reasons: $fail_closed_reasons[0],
    fail_closed_count: $fail_closed_count,
    duplicate_new_work_warnings: (
      if (($recommendations[0] | length) > 0) then
        ["A matching catalog surface already exists; extend or relate new work instead of creating an unlinked duplicate."]
      else [] end
    ),
    artifact_paths: {
      swarm_control_surface_intent_plan_json: $plan_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      changes_live_queue_policy: false
    }
  }' >"$plan_path"

{
  printf '# Swarm Control-Surface Intent Plan\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- recommendations: \`%s\`\n" "$top_count"
  printf -- "- fail_closed reasons: \`%s\`\n" "$fail_closed_count"
  printf -- "- plan: \`%s\`\n" "$plan_path"
} >"$markdown_path"

write_event "intent_plan_emitted" "$decision"
exit "$exit_code"
