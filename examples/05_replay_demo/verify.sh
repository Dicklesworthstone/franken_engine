#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"
frankenctl_bin="${FRANKENCTL_BIN:-${repo_root}/target/release/frankenctl}"
sample_trace="${script_dir}/sample_trace.json"
source_file="${script_dir}/replay_input.js"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/franken-replay-demo.XXXXXX")"
run_report="${work_dir}/run_report.json"
replay_report="${work_dir}/replay_report.json"
changed_source_report="${work_dir}/changed_source_report.json"
changed_policy_report="${work_dir}/changed_policy_report.json"

if [[ ! -x "$frankenctl_bin" ]]; then
    echo "frankenctl binary is not executable: $frankenctl_bin" >&2
    exit 2
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Required jq binary not found" >&2
    exit 2
fi

echo "FrankenEngine Deterministic Replay Verification"
echo "=============================================="

echo "Producing a live frankenctl run report..."
"$frankenctl_bin" run \
    --input "$source_file" \
    --extension-id replay-demo \
    --out "$run_report"

echo "Re-executing the embedded JavaScript in strict mode..."
"$frankenctl_bin" replay run \
    --trace "$run_report" \
    --mode strict \
    --out "$replay_report"

jq -e '
    .replay_kind == "reexecution" and
    .ir3_hash_match == true and
    .unsigned_execution_content_match == true and
    .randomness_transcript_match == true and
    .divergence_count == 0 and
    .complete == true
' "$replay_report" >/dev/null

echo "Checking that a changed source diverges..."
jq '.replay_input.source = "const answer = 40 + 3;\n"' \
    "$run_report" >"$changed_source_report"
if "$frankenctl_bin" replay run --trace "$changed_source_report" --mode strict; then
    echo "FAILURE: strict replay accepted changed JavaScript source" >&2
    exit 1
fi

echo "Checking that a changed policy diverges..."
jq '.replay_input.policy_id = "frankenctl.replay.changed-policy"' \
    "$run_report" >"$changed_policy_report"
if "$frankenctl_bin" replay run --trace "$changed_policy_report" --mode strict; then
    echo "FAILURE: strict replay accepted changed policy" >&2
    exit 1
fi

echo "Checking that the synthetic one-event trace cannot self-certify..."
if "$frankenctl_bin" replay run --trace "$sample_trace" --mode strict; then
    echo "FAILURE: synthetic trace self-comparison was accepted" >&2
    exit 1
fi

echo "Checking the explicit two-trace comparison mode..."
"$frankenctl_bin" replay run \
    --trace "$sample_trace" \
    --compare-trace "$sample_trace" \
    --mode strict >/dev/null

echo "SUCCESS: live JavaScript re-execution matched IR3 and unsigned execution content."
echo "Artifacts retained at: $work_dir"
