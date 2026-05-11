#!/usr/bin/env bash
set -euo pipefail

bundle_dir=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/idea_wizard_iv_zero_ready_saturation_replay.sh --bundle-dir DIR

Validate a preserved IDEA-WIZARD-IV zero-ready saturation drill bundle without
rerunning child scripts or heavy validation.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
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

if [[ -z "$bundle_dir" ]]; then
  usage
  exit 64
fi
report="${bundle_dir}/saturation_convergence_report.json"
manifest="${bundle_dir}/run_manifest.json"
events="${bundle_dir}/events.jsonl"
commands="${bundle_dir}/commands.txt"
trace_ids="${bundle_dir}/trace_ids.json"

for path in "$report" "$manifest" "$events" "$commands" "$trace_ids"; do
  if [[ ! -f "$path" ]]; then
    printf 'missing preserved bundle artifact: %s\n' "$path" >&2
    exit 42
  fi
done
if ! jq empty "$report" "$manifest" "$trace_ids" >/dev/null 2>&1; then
  printf 'preserved bundle JSON is malformed\n' >&2
  exit 42
fi

jq -e '
  .schema_version == "franken-engine.idea-wizard-iv-zero-ready-saturation-report.v1"
  and (.child_reports | type) == "array"
  and (.child_reports | length) == 4
  and (.artifact_paths.saturation_convergence_report_json | type) == "string"
  and .mutation_policy.mutates_br == false
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
  and (.decision | IN("green","degraded","fail_closed"))
' "$report" >/dev/null || {
  printf 'preserved saturation convergence report failed replay validation\n' >&2
  exit 42
}

missing_child_count="$(
  jq '[.child_reports[]? | select((.path // "") == "" or (.decision // "missing") == "missing")] | length' "$report"
)"
if [[ "$missing_child_count" -ne 0 ]]; then
  printf 'preserved bundle has missing child reports: %s\n' "$missing_child_count" >&2
  exit 42
fi

printf 'PASS idea-wizard-iv-zero-ready-replay %s\n' "$report"
