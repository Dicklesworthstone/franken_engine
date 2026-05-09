#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${IDEA_WIZARD_PLAN_QUALITY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-idea-wizard-plan-quality}"
run_id="${IDEA_WIZARD_PLAN_QUALITY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${IDEA_WIZARD_PLAN_QUALITY_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${IDEA_WIZARD_PLAN_QUALITY_SOURCE_REVISION:-}"
original_args=("$@")

beads_json=""
bv_plan_json=""
parent_id="bd-ep8y0"
first_actionable_id="bd-ep8y0.1"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/idea_wizard_plan_quality_gate.sh --beads-json FILE [OPTIONS]

Checks an idea-wizard bead set in plan space. The gate is advisory-only and
does not replace br/bv: it reads saved bead/graph JSON and emits checklist
diagnostics for future agents.

Required:
  --beads-json FILE

Options:
  --bv-plan-json FILE
  --parent-id ID
  --first-actionable-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  plan_quality_gate_report.json
  plan_quality_checklist.md
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   plan-space quality checks pass
  42  blockers or warnings found
  64  invalid input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --beads-json)
      beads_json="${2:-}"
      shift 2
      ;;
    --bv-plan-json)
      bv_plan_json="${2:-}"
      shift 2
      ;;
    --parent-id)
      parent_id="${2:-}"
      shift 2
      ;;
    --first-actionable-id)
      first_actionable_id="${2:-}"
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

if [[ -z "$beads_json" ]]; then
  printf 'missing required --beads-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for idea-wizard plan quality gate\n' >&2
  exit 2
fi
if [[ ! -f "$beads_json" ]]; then
  printf 'beads JSON not found: %s\n' "$beads_json" >&2
  exit 64
fi
if ! jq empty "$beads_json" >/dev/null 2>&1; then
  printf 'invalid beads JSON: %s\n' "$beads_json" >&2
  exit 64
fi
if [[ -n "$bv_plan_json" && ! -f "$bv_plan_json" ]]; then
  printf 'bv plan JSON not found: %s\n' "$bv_plan_json" >&2
  exit 64
fi
if [[ -n "$bv_plan_json" ]] && ! jq empty "$bv_plan_json" >/dev/null 2>&1; then
  printf 'invalid bv plan JSON: %s\n' "$bv_plan_json" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/plan_quality_gate_report.json"
checklist_md="${run_dir}/plan_quality_checklist.md"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
report_tmp="${report_json}.tmp"

for artifact_path in "$report_json" "$checklist_md" "$events_path" "$commands_path" "$report_md" "$report_tmp"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/idea_wizard_plan_quality_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

bv_arg=()
if [[ -n "$bv_plan_json" ]]; then
  bv_arg=(--slurpfile bv "$bv_plan_json")
else
  bv_arg=(--argjson bv '[]')
fi

jq -n \
  --slurpfile beads "$beads_json" \
  "${bv_arg[@]}" \
  --arg schema_version "franken-engine.idea-wizard-plan-quality-report.v1" \
  --arg parent_id "$parent_id" \
  --arg first_actionable_id "$first_actionable_id" \
  --arg source_revision "$source_revision" \
  --arg beads_json "$beads_json" \
  --arg bv_plan_json "$bv_plan_json" \
  --arg report_json "$report_json" \
  --arg checklist_md "$checklist_md" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def issue_rows:
    ($beads[0].issues // $beads[0]);
  def deps:
    ($beads[0].dependencies // []);
  def closed_authorities:
    ($beads[0].closed_authority_ids // ["bd-eozx0", "bd-x82vp"]);
  def text($issue):
    (($issue.title // "") + " " + ($issue.description // "") + " " + (($issue.labels // []) | join(" "))) | ascii_downcase;
  def title_text($issue):
    ($issue.title // "") | ascii_downcase;
  def desc_text($issue):
    ($issue.description // "") | ascii_downcase;
  def has($issue; $pattern): (text($issue) | test($pattern));
  def diag($severity; $code; $id; $detail; $remediation):
    {severity:$severity, code:$code, bead_id:$id, detail:$detail, remediation:$remediation};
  def role($issue):
    if (title_text($issue) | test("contract|profile|capture profile")) then "contract_profile"
    elif (title_text($issue) | test("docs|readme|claim|freshness|operator")) then "docs_claim"
    elif (title_text($issue) | test("e2e|smoke|golden|test")) then "test_e2e"
    elif (title_text($issue) | test("add|wire|capture|cluster|doctor|gate|implement")) then "implementation"
    else "unspecified" end;
  def has_validation($issue):
    has($issue; "rch|validation|verify|smoke|e2e|shellcheck|cargo");
  def has_e2e_logging($issue):
    has($issue; "e2e|smoke|golden|logging|report|events\\.jsonl|commands\\.txt");
  def has_claim_safeguard($issue):
    if has($issue; "claim|readme|operator") then (desc_text($issue) | test("downgrade|hypothesis|target|observed|claim-language|proof-state")) else true end;
  def no_mutation_guard($issue):
    has($issue; "non-goal|non-goals|advisory|read-only|does not|do not|never mutates|no mutation|mutate");
  def mentions_authority($issue):
    has($issue; "bd-eozx0|bd-x82vp|upstream authority|canonical");
  def duplicates_authority($issue):
    has($issue; "duplicate contract|parallel planner|second planner|replace bd-eozx0|replace bd-x82vp");
  def child_issues:
    [issue_rows[] | select((.id // "") | startswith($parent_id + ".")) | select((.id // "") != $parent_id)];
  def parent_issue:
    [issue_rows[] | select((.id // "") == $parent_id)][0] // {};
  def first_plan_item:
    if ($bv | type) == "array" and ($bv | length) > 0 then
      [$bv[0].plan.tracks[]?.items[]?.id][0] // null
    else null end;
  def has_cycle:
    any(deps[]?; .child == .parent)
    or ([deps[]? as $a | deps[]? | select(.child == $a.parent and .parent == $a.child)] | length > 0);
  def depends_on($child; $parent):
    any(deps[]?; .child == $child and .parent == $parent);

  child_issues as $children
  | parent_issue as $parent
  | ($children | map(. + {
      role: role(.),
      has_validation: has_validation(.),
      has_e2e_logging: has_e2e_logging(.),
      has_claim_language_safeguard: has_claim_safeguard(.),
      has_non_mutation_guard: no_mutation_guard(.),
      mentions_upstream_authority: mentions_authority(.),
      duplicate_authority_claim: duplicates_authority(.)
    })) as $checklist
  | ([
      if ($children | length) == 0 then diag("error"; "missing_child_beads"; $parent_id; "no child beads found for idea-wizard plan"; "Export the child bead set before running the gate.") else empty end,
      if ($checklist | map(select(.role == "contract_profile")) | length) == 0 then diag("error"; "missing_contract_profile_bead"; $parent_id; "no child bead maps to contract/profile responsibility"; "Add or tag a contract/profile bead.") else empty end,
      if ($checklist | map(select(.role == "implementation")) | length) == 0 then diag("error"; "missing_implementation_bead"; $parent_id; "no child bead maps to implementation responsibility"; "Add or tag an implementation bead.") else empty end,
      if ($checklist | map(select(.role == "test_e2e")) | length) == 0 then diag("error"; "missing_test_e2e_bead"; $parent_id; "no child bead maps to test/e2e responsibility"; "Add explicit e2e/smoke/golden coverage bead.") else empty end,
      if ($checklist | map(select(.role == "docs_claim")) | length) == 0 then diag("error"; "missing_docs_claim_bead"; $parent_id; "no child bead maps to docs/claim wording responsibility"; "Add claim/docs freshness coverage.") else empty end,
      if (text($parent) | test("non-goals") | not) then diag("error"; "missing_parent_non_goals"; $parent_id; "parent bead lacks explicit non-goals"; "Document non-goals before implementation.") else empty end,
      if ($checklist | any(.has_validation | not)) then diag("error"; "missing_validation_wording"; $parent_id; "one or more child beads lack validation wording"; "Add rch-only or shell/e2e validation expectations.") else empty end,
      if ($checklist | any(.has_e2e_logging | not)) then diag("error"; "missing_e2e_logging"; $parent_id; "one or more child beads lack e2e/logging/report expectations"; "Add events/report/commands or smoke/golden logging expectations.") else empty end,
      if ($checklist | any(.has_claim_language_safeguard | not)) then diag("error"; "missing_claim_language_safeguard"; $parent_id; "claim/docs child bead lacks downgrade or proof-state safeguards"; "Require target/hypothesis/observed wording safeguards.") else empty end,
      if ($checklist | any(.has_non_mutation_guard | not)) then diag("warning"; "missing_non_mutation_guard"; $parent_id; "one or more child beads lack explicit advisory/read-only or no-mutation wording"; "Add non-mutation wording before coding.") else empty end,
      if ($checklist | any(.duplicate_authority_claim)) then diag("error"; "duplicate_upstream_authority_claim"; $parent_id; "a child bead appears to duplicate existing closed authority " + (closed_authorities | join(",")); "Reuse the closed authority instead of creating a parallel contract/planner.") else empty end,
      if ($checklist | any(.mentions_upstream_authority) | not) then diag("error"; "missing_upstream_authority_reuse"; $parent_id; "child beads do not explicitly reuse existing upstream authority such as bd-eozx0/bd-x82vp"; "Mention canonical upstream authority in relevant beads.") else empty end,
      if has_cycle then diag("error"; "dependency_cycle"; $parent_id; "dependency graph contains an intentional or accidental cycle"; "Fix the br dependency edges before implementation.") else empty end,
      if (depends_on($first_actionable_id; $parent_id) | not) then diag("error"; "first_actionable_not_parented"; $first_actionable_id; "first actionable implementation bead is not linked to the parent"; "Add dependency/parent-child edge so the first implementation bead is ordered.") else empty end,
      if (first_plan_item != null and first_plan_item != $first_actionable_id and first_plan_item != $parent_id) then diag("warning"; "bv_first_pick_mismatch"; first_plan_item; "bv plan first item does not match expected first actionable implementation bead"; "Review bv graph output before starting implementation.") else empty end
    ]) as $diagnostics
  | {
      schema_version: $schema_version,
      parent_id: $parent_id,
      source_revision: $source_revision,
      beads_json: $beads_json,
      bv_plan_json: (if $bv_plan_json == "" then null else $bv_plan_json end),
      closed_authority_ids: closed_authorities,
      first_actionable_id: $first_actionable_id,
      decision: (if any($diagnostics[]; .severity == "error") then "fail" elif any($diagnostics[]; .severity == "warning") then "warn" else "pass" end),
      child_count: ($children | length),
      role_counts: {
        contract_profile: ($checklist | map(select(.role == "contract_profile")) | length),
        implementation: ($checklist | map(select(.role == "implementation")) | length),
        test_e2e: ($checklist | map(select(.role == "test_e2e")) | length),
        docs_claim: ($checklist | map(select(.role == "docs_claim")) | length),
        unspecified: ($checklist | map(select(.role == "unspecified")) | length)
      },
      checklist: $checklist,
      diagnostics: $diagnostics,
      diagnostic_counts: {
        total: ($diagnostics | length),
        errors: ($diagnostics | map(select(.severity == "error")) | length),
        warnings: ($diagnostics | map(select(.severity == "warning")) | length)
      },
      artifact_paths: {
        plan_quality_gate_report_json: $report_json,
        plan_quality_checklist_md: $checklist_md,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      },
      non_mutation_attestation: {
        reads_only: true,
        replaces_br_or_bv: false,
        creates_beads: false,
        mutates_beads: false,
        runs_cargo: false,
        runs_rch: false
      }
    }
' >"$report_tmp"
mv "$report_tmp" "$report_json"

jq -r '
  "# Idea-Wizard Plan Quality Checklist",
  "",
  ("Parent: `" + .parent_id + "`"),
  ("Decision: `" + .decision + "`"),
  "",
  "| Bead | Role | Validation | E2E/logging | Claim safeguard | No-mutation | Authority reuse |",
  "| --- | --- | --- | --- | --- | --- | --- |",
  (.checklist[]
    | "| `" + .id + "` | `" + .role + "` | `" + (.has_validation | tostring) + "` | `" + (.has_e2e_logging | tostring) + "` | `" + (.has_claim_language_safeguard | tostring) + "` | `" + (.has_non_mutation_guard | tostring) + "` | `" + (.mentions_upstream_authority | tostring) + "` |"),
  "",
  "## Diagnostics",
  "",
  (if (.diagnostics | length) == 0 then
    "none"
  else
    (.diagnostics[]
      | "- `" + .severity + "` `" + .code + "` `" + .bead_id + "`: " + .detail + " Remediation: " + .remediation)
  end)
' "$report_json" >"$checklist_md"

jq -r '
  "# Idea-Wizard Plan Quality Report",
  "",
  ("- Decision: `" + .decision + "`"),
  ("- Child beads: `" + (.child_count | tostring) + "`"),
  ("- Errors: `" + (.diagnostic_counts.errors | tostring) + "`"),
  ("- Warnings: `" + (.diagnostic_counts.warnings | tostring) + "`"),
  "",
  "## Role Counts",
  "",
  (.role_counts | to_entries[] | "- `" + .key + "`: `" + (.value | tostring) + "`")
' "$report_json" >"$report_md"

jq -c '
  .diagnostics[]
  | {
      schema_version: "franken-engine.idea-wizard-plan-quality.event.v1",
      component: "idea_wizard_plan_quality_gate",
      event: "diagnostic.emitted",
      severity,
      code,
      bead_id,
      detail
    }
' "$report_json" >"$events_path"
if [[ ! -s "$events_path" ]]; then
  jq -nc '{
    schema_version: "franken-engine.idea-wizard-plan-quality.event.v1",
    component: "idea_wizard_plan_quality_gate",
    event: "plan_quality_passed",
    severity: "info",
    code: null,
    bead_id: null,
    detail: "plan quality gate passed"
  }' >"$events_path"
fi

printf 'idea_wizard_plan_quality_report=%s\n' "$report_json"
printf 'idea_wizard_plan_quality_checklist=%s\n' "$checklist_md"
printf 'idea_wizard_plan_quality_events=%s\n' "$events_path"

if jq -e '.decision != "pass"' "$report_json" >/dev/null; then
  exit 42
fi
exit 0
