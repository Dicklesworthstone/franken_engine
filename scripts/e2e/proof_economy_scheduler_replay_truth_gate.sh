#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
gate="${root_dir}/scripts/rch_policy_compliance_gate.sh"
artifact_root="${PROOF_ECONOMY_TRUTH_GATE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-truth-gate}"
run_id="${PROOF_ECONOMY_TRUTH_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_TRUTH_GATE_RUN_DIR:-${artifact_root}/${run_id}}"

drill_report_json=""
docs_path=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/proof_economy_scheduler_replay_truth_gate.sh --drill-report-json FILE --docs-path FILE [OPTIONS]

Validates the proof-economy scheduler replay drill report and docs truth claims.
Rejects bare heavy Cargo examples, missing artifact references, and missing
brownout/fair-share dashboard fields.

Required:
  --drill-report-json FILE
  --docs-path FILE

Optional:
  --output-dir DIR

Artifacts:
  truth_gate_report.json
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --drill-report-json)
      drill_report_json="${2:-}"
      shift 2
      ;;
    --docs-path)
      docs_path="${2:-}"
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

if [[ -z "$drill_report_json" || -z "$docs_path" ]]; then
  printf 'truth gate requires --drill-report-json and --docs-path\n' >&2
  usage
  exit 64
fi
if [[ ! -f "$drill_report_json" ]]; then
  printf 'missing drill report JSON: %s\n' "$drill_report_json" >&2
  exit 64
fi
if [[ ! -f "$docs_path" ]]; then
  printf 'missing docs path: %s\n' "$docs_path" >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-economy-scheduler-replay-drill-report.v1"' \
  "$drill_report_json" >/dev/null; then
  printf 'drill report must use franken-engine.proof-economy-scheduler-replay-drill-report.v1\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
findings_jsonl="${run_dir}/findings.jsonl"
report_path="${run_dir}/truth_gate_report.json"
scope_file="${run_dir}/scope.txt"
: >"$findings_jsonl"

add_finding() {
  jq -nc \
    --arg severity "$1" \
    --arg code "$2" \
    --arg message "$3" \
    '{severity: $severity, code: $code, message: $message}' >>"$findings_jsonl"
}

printf '%s\n' "$docs_path" >"$scope_file"
if ! "$gate" --output-dir "${run_dir}/rch-policy" --scope-file "$scope_file" >/dev/null; then
  add_finding "error" "bare_heavy_cargo_example" "Docs contain a heavy Cargo command that is not rch-wrapped."
fi

while IFS= read -r path; do
  if [[ -z "$path" || ! -f "$path" ]]; then
    add_finding "error" "missing_artifact_reference" "Drill report references a missing artifact path: ${path:-<empty>}"
  fi
done < <(jq -r '.artifact_paths | to_entries[] | .value // ""' "$drill_report_json")

if ! jq -e '.proofs.fair_share_improves_queue_health == true' "$drill_report_json" >/dev/null; then
  add_finding "error" "missing_fair_share_field" "Drill report does not prove fair-share queue-health improvement."
fi
if ! jq -e '.dashboard_fields.brownout_state and .dashboard_fields.fair_share_score_millionths' \
  "$drill_report_json" >/dev/null; then
  add_finding "error" "missing_brownout_or_fair_share_dashboard_field" \
    "Drill report is missing required brownout or fair-share dashboard fields."
fi

jq -s \
  --arg schema_version "franken-engine.proof-economy-scheduler-replay-truth-gate-report.v1" \
  --arg drill_report_json "$drill_report_json" \
  '{
    schema_version: $schema_version,
    drill_report_json: $drill_report_json,
    policy_decision: (if length == 0 then "pass" else "fail_closed" end),
    findings: .,
    summary: {
      finding_count: length
    }
  }' "$findings_jsonl" >"$report_path"

printf 'proof_economy_scheduler_replay_truth_gate_report=%s\n' "$report_path"
if [[ "$(jq -r '.policy_decision' "$report_path")" == "fail_closed" ]]; then
  exit 42
fi
