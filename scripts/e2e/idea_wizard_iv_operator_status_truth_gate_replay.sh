#!/usr/bin/env bash
set -euo pipefail

bundle_dir=""
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-dir) bundle_dir="${2:-}"; shift 2 ;;
    -h|--help) printf 'Usage: %s --bundle-dir DIR\n' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; exit 64 ;;
  esac
done
if [[ -z "$bundle_dir" ]]; then
  printf 'missing --bundle-dir\n' >&2
  exit 64
fi
report="${bundle_dir}/operator_truth_gate_report.json"
status="${bundle_dir}/operator_status.md"
manifest="${bundle_dir}/run_manifest.json"
commands="${bundle_dir}/commands.txt"
trace_ids="${bundle_dir}/trace_ids.json"
for path in "$report" "$status" "$manifest" "$commands" "$trace_ids"; do
  [[ -f "$path" ]] || { printf 'missing operator bundle artifact: %s\n' "$path" >&2; exit 42; }
done
jq -e '
  .schema_version == "franken-engine.idea-wizard-iv-operator-truth-gate.v1"
  and (.claim_sensitivity_checks.advisory_mode_required == true)
  and (.observed_claims | type) == "object"
  and (.targeted_claims | type) == "array"
  and (.violations | type) == "array"
  and .mutation_policy.mutates_br == false
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "$report" >/dev/null || {
  printf 'operator truth gate report failed replay validation\n' >&2
  exit 42
}
printf 'PASS idea-wizard-iv-operator-truth-gate-replay %s\n' "$report"
