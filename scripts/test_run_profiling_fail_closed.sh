#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TMPDIR:-/tmp}/franken_run_profiling_fail_closed_$$"
artifact_dir="$workspace/profiling_evidence"
log_file="$workspace/profiling.jsonl"
stdout_log="$workspace/stdout.log"
stderr_log="$workspace/stderr.log"

mkdir -p "$workspace"

set +e
FRANKENCTL_BIN="$workspace/no-frankenctl" \
FRANKEN_PROFILE_ARTIFACTS_DIR="$artifact_dir" \
FRANKEN_PROFILE_LOG="$log_file" \
bash "$repo_root/scripts/run_profiling.sh" > "$stdout_log" 2> "$stderr_log"
status=$?
set -e

if [[ $status -eq 0 ]]; then
    echo "expected missing frankenctl to fail closed" >&2
    exit 1
fi

if [[ -e "$artifact_dir/optimization_targets.json" ]]; then
    echo "missing frankenctl emitted an authoritative optimization report" >&2
    exit 1
fi

if compgen -G "$artifact_dir/*_profile.json" > /dev/null; then
    echo "missing frankenctl emitted profile artifacts" >&2
    exit 1
fi

if [[ ! -f "$artifact_dir/degraded_non_authoritative.json" ]]; then
    echo "missing frankenctl did not emit a non-authoritative degraded marker" >&2
    exit 1
fi

if ! grep -q '"authoritative": false' "$artifact_dir/degraded_non_authoritative.json"; then
    echo "degraded marker is not explicitly non-authoritative" >&2
    exit 1
fi

if ! grep -q '"reason": "frankenctl_missing"' "$artifact_dir/degraded_non_authoritative.json"; then
    echo "degraded marker does not record frankenctl_missing" >&2
    exit 1
fi

echo "run_profiling fail-closed regression passed"
