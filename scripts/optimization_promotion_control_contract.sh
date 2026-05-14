#!/usr/bin/env bash
set -euo pipefail

artifact_root="${OPTIMIZATION_PROMOTION_CONTROL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-optimization-promotion-control}"
run_id="${OPTIMIZATION_PROMOTION_CONTROL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${OPTIMIZATION_PROMOTION_CONTROL_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${OPTIMIZATION_PROMOTION_CONTROL_SOURCE_REVISION:-unknown}"
input_json=""
original_args=("$@")

usage() {
  cat >&2 <<'USAGE'
Usage: ./scripts/optimization_promotion_control_contract.sh --input-json FILE [OPTIONS]

Build a source-only optimization promotion-control contract report from saved
JSON evidence. The command never runs Cargo/RCH and never mutates runtime
policy, br, Agent Mail, reservations, workers, or benchmark claims.

Required:
  --input-json FILE

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  optimization_promotion_control_contract.json
  optimization_promotion_surface_inventory.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0   contract report emitted with pass decision
  42  missing, stale, contradictory, synthetic, or unsafe evidence failed closed
  64  invalid input or arguments
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --input-json)
      input_json="${2:-}"
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

if [[ -z "$input_json" ]]; then
  printf 'missing required --input-json\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "$input_json" >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for optimization promotion-control contract\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for optimization promotion-control contract\n' >&2
  exit 2
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(git rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/optimization_promotion_control_contract.json"
report_json_tmp="${report_json}.tmp"
inventory_json="${run_dir}/optimization_promotion_surface_inventory.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"
normalized_input="${run_dir}/input.normalized.json"

jq -cS . "$input_json" >"$normalized_input"
input_hash="$(sha256sum "$normalized_input" | awk '{print $1}')"

printf './scripts/optimization_promotion_control_contract.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.optimization-promotion-control.event.v1" \
    --arg trace_id "trace-optimization-promotion-control-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    '{schema_version:$schema_version,trace_id:$trace_id,component:$component,event:$event,outcome:$outcome,error_code:(if $error_code == "" then null else $error_code end)}' \
    >>"$events_path"
}

write_event "optimization_promotion_control_contract" "input_loaded" "captured" ""

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_json "$input_json" \
  --arg normalized_input "$normalized_input" \
  --arg input_hash "$input_hash" \
  --arg report_json "$report_json" \
  --arg inventory_json "$inventory_json" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_md "$report_md" '
  def src: $input[0];
  def required_surfaces: [
    "proof_specialization_receipt",
    "specialization_lane_gate",
    "specialization_rollback_gate",
    "performance_regression_gate",
    "safe_mode_fallback",
    "cross_workload_transfer",
    "real_hot_path_evidence"
  ];
  def required_families: [
    "real_hot_path_evidence",
    "proof_specialization_receipt",
    "semantic_parity",
    "rollback_health",
    "safe_mode_fallback",
    "cross_workload_transfer",
    "performance_regression"
  ];
  def required_states: [
    "observe",
    "promote",
    "pin",
    "demote",
    "quarantine",
    "fail_closed"
  ];
  def failure($code; $source_id; $detail; $remediation):
    {code:$code, source_id:$source_id, detail:$detail, remediation:$remediation};
  def surfaces: (src.surfaces // []);
  def present_surface_ids:
    [surfaces[] | select((.present // false) == true) | .surface_id];
  def families: (src.evidence_families // []);
  def states: (src.promotion_states // []);
  def mutation: (src.mutation_policy // {});
  (
    []
    + ((required_surfaces - present_surface_ids)
        | map(failure("FE-OPT-PROMO-MISSING-SURFACE"; .;
            "required promotion-control surface is absent";
            "Add or refresh the existing surface before composing promotion decisions.")))
    + ([surfaces[]
        | select((.present // false) == true)
        | select((.freshness // "fresh") != "fresh")
        | failure("FE-OPT-PROMO-STALE-SURFACE"; (.surface_id // "unknown_surface");
            ("surface freshness is " + (.freshness // "unknown"));
            "Refresh this evidence before promotion-control composition.")])
    + ((required_families - families)
        | map(failure("FE-OPT-PROMO-MISSING-EVIDENCE-FAMILY"; .;
            "required evidence family is missing";
            "Provide the evidence family before promotion-control composition.")))
    + ((required_states - states)
        | map(failure("FE-OPT-PROMO-MISSING-STATE"; .;
            "required promotion state is missing";
            "Keep the full observe/promote/pin/demote/quarantine/fail_closed state machine.")))
    + (if
        mutation.advisory_only != true
        or mutation.proof_only != true
        or mutation.fixture_fed_only != true
        or mutation.mutates_runtime_policy != false
        or mutation.mutates_br != false
        or mutation.sends_agent_mail != false
        or mutation.releases_reservations != false
        or mutation.runs_cargo != false
        or mutation.runs_rch != false
        or mutation.mutates_remote_workers != false
        or mutation.publishes_benchmark_claims != false
      then [failure("FE-OPT-PROMO-UNSAFE-MUTATION-POLICY"; "mutation_policy";
        "promotion-control input permits a forbidden mutation or heavy command";
        "Set the contract to advisory/proof/fixture-fed only and forbid runtime, br, mail, reservation, worker, Cargo, RCH, and claim mutation.")]
      else [] end)
    + ([(src.contradictions // [])[]
        | failure("FE-OPT-PROMO-CONTRADICTORY-EVIDENCE"; (.source_id // "contradiction");
            (.detail // "contradictory promotion evidence");
            (.remediation // "Resolve contradictory evidence before promotion-control composition."))])
    + (if
        (src.contamination.synthetic_only // false) == true
        or any(surfaces[]?; (.contamination // "") == "synthetic_only")
      then [failure("FE-OPT-PROMO-SYNTHETIC-CONTAMINATION"; "contamination";
        "synthetic-only evidence cannot support promotion-control decisions";
        "Replace synthetic-only material with real or explicitly fixture-scoped evidence.")]
      else [] end)
  ) as $failures
  | {
      schema_version: "franken-engine.optimization-promotion-control.report.v1",
      bead_id: "bd-sisok",
      parent_bead_id: "bd-xg3d6",
      component: "optimization_promotion_control_contract",
      source_revision: $source_revision,
      input: {
        path: $input_json,
        normalized_path: $normalized_input,
        sha256: $input_hash,
        schema_version: (src.schema_version // null),
        case_id: (src.case_id // null)
      },
      decision: (if ($failures | length) == 0 then "pass" else "fail_closed" end),
      promotion_states: required_states,
      required_evidence_families: required_families,
      fail_closed_reasons: $failures,
      mutation_policy: mutation,
      artifact_paths: {
        report_json: $report_json,
        inventory_json: $inventory_json,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_md
      }
    }
  ' >"$report_json_tmp"
mv "$report_json_tmp" "$report_json"

jq -n \
  --slurpfile input "$normalized_input" \
  --arg source_revision "$source_revision" \
  --arg input_hash "$input_hash" '
  def src: $input[0];
  {
    schema_version: "franken-engine.optimization-promotion-control.inventory.v1",
    bead_id: "bd-sisok",
    source_revision: $source_revision,
    input_sha256: $input_hash,
    surfaces: [
      (src.surfaces // [])[]
      | {
          surface_id,
          owner_kind: (.owner_kind // "unknown"),
          path: (.path // null),
          present: (.present // false),
          freshness: (.freshness // "unknown"),
          promotion_role: (.promotion_role // "unspecified"),
          required_for_states: (.required_for_states // [])
        }
    ],
    evidence_families: (src.evidence_families // []),
    promotion_states: (src.promotion_states // [])
  }
  ' >"$inventory_json"

jq -r '
  "# Optimization Promotion-Control Contract\n\n"
  + "- Decision: `" + .decision + "`\n"
  + "- Source revision: `" + .source_revision + "`\n"
  + "- Input hash: `" + .input.sha256 + "`\n"
  + "- Fail-closed reasons: `" + ((.fail_closed_reasons | length) | tostring) + "`\n\n"
  + "## Required Evidence Families\n"
  + (.required_evidence_families | map("- `" + . + "`") | join("\n"))
  + "\n\n## Promotion States\n"
  + (.promotion_states | map("- `" + . + "`") | join("\n"))
  + "\n"
' "$report_json" >"$report_md"

decision="$(jq -r '.decision' "$report_json")"
if [[ "$decision" == "pass" ]]; then
  write_event "optimization_promotion_control_contract" "report_emitted" "pass" ""
  exit 0
fi

first_error="$(jq -r '.fail_closed_reasons[0].code // "FE-OPT-PROMO-FAIL-CLOSED"' "$report_json")"
write_event "optimization_promotion_control_contract" "report_emitted" "fail_closed" "$first_error"
exit 42
