#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
log_path="${script_dir}/sample_exhaustion_log.json"

expected="$(jq -r '.expected_sequence | join(",")' "${log_path}")"
actual="$(jq -r '.events | sort_by(.timestamp_ns) | map(.action) | join(",")' "${log_path}")"

if [[ "${actual}" != "${expected}" ]]; then
  echo "expected action sequence ${expected}, got ${actual}" >&2
  exit 1
fi

timestamps_are_sorted="$(
  jq -r '
    [.events | sort_by(.timestamp_ns) | .[].timestamp_ns]
    as $ts
    | if ($ts | length) < 2 then "true"
      else ([range(0; ($ts | length) - 1) | $ts[.] <= $ts[. + 1]] | all | tostring)
      end
  ' "${log_path}"
)"

if [[ "${timestamps_are_sorted}" != "true" ]]; then
  echo "timestamps are not monotonic" >&2
  exit 1
fi

api_gap="$(jq -r '.events[-1].basis.status' "${log_path}")"
if [[ "${api_gap}" != "api_gap" ]]; then
  echo "expected final terminate step to be marked as api_gap" >&2
  exit 1
fi

echo "verified deterministic sequence: ${actual}"
