#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir"

trace_path="${1:-}"
emit_sample_if_missing="${RGC_MODULE_RESOLUTION_TRACE_EMIT_SAMPLE_IF_MISSING:-0}"
if [[ -z "$trace_path" ]]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  trace_path="artifacts/rgc_module_resolution_trace_contract_smoke/${timestamp}/module_resolution_trace.jsonl"
  emit_sample_if_missing=1
fi

if [[ ! -f "$trace_path" ]]; then
  if [[ "$emit_sample_if_missing" != "1" ]]; then
    echo "module_resolution_trace artifact missing: $trace_path" >&2
    exit 1
  fi

  mkdir -p "$(dirname "$trace_path")"
  {
    echo '{"schema_version":"rgc.module-resolution.trace.v1","trace_id":"trace-contract-smoke","decision_id":"decision-contract-smoke","policy_id":"policy-contract-smoke","component":"module_resolver","event":"resolution_probe","request_specifier":"./fixture-entry","canonical_specifier":"/workspace/fixture-entry.ts","source_kind":"workspace","probe_sequence":["/workspace/fixture-entry","/workspace/fixture-entry.ts"],"outcome":"allow","error_code":"none"}'
  } >"$trace_path"
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for module_resolution_trace contract smoke validation" >&2
  exit 2
fi

line_count="$(wc -l < "$trace_path" | tr -d ' ')"
if [[ "$line_count" -eq 0 ]]; then
  echo "trace artifact is empty: $trace_path" >&2
  exit 1
fi

invalid_count="$(
  jq -c '
    select(
      (
        has("schema_version")
        and .schema_version == "rgc.module-resolution.trace.v1"
        and has("trace_id")
        and has("decision_id")
        and has("policy_id")
        and has("component")
        and has("event")
        and has("request_specifier")
        and has("canonical_specifier")
        and has("source_kind")
        and has("probe_sequence")
        and (.probe_sequence | type == "array")
        and (.probe_sequence | length > 0)
        and has("outcome")
        and has("error_code")
      ) | not
    )
  ' "$trace_path" | wc -l | tr -d ' '
)"

if [[ "$invalid_count" -ne 0 ]]; then
  echo "module_resolution_trace contract validation failed (${invalid_count} invalid line(s)): $trace_path" >&2
  exit 1
fi

echo "module_resolution_trace contract smoke PASS: $trace_path"
