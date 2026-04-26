#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${TMPDIR:-/tmp}/franken_run_profiling_fail_closed_$$"
artifact_dir="$workspace/profiling_evidence"
log_file="$workspace/profiling.jsonl"
stdout_log="$workspace/stdout.log"
stderr_log="$workspace/stderr.log"
unsupported_workspace="$workspace/unsupported"
unsupported_artifact_dir="$unsupported_workspace/profiling_evidence"
unsupported_log_file="$unsupported_workspace/profiling.jsonl"
unsupported_stdout_log="$unsupported_workspace/stdout.log"
unsupported_stderr_log="$unsupported_workspace/stderr.log"
unsupported_frankenctl="$unsupported_workspace/frankenctl"

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

mkdir -p "$unsupported_workspace"
cat > "$unsupported_frankenctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "run" && "${2:-}" == "--help" ]]; then
    cat <<'HELP'
run usage:
  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]
HELP
    exit 0
fi

echo "unexpected invocation: $*" >&2
exit 2
EOF
chmod +x "$unsupported_frankenctl"

set +e
FRANKENCTL_BIN="$unsupported_frankenctl" \
FRANKEN_PROFILE_ARTIFACTS_DIR="$unsupported_artifact_dir" \
FRANKEN_PROFILE_LOG="$unsupported_log_file" \
bash "$repo_root/scripts/run_profiling.sh" > "$unsupported_stdout_log" 2> "$unsupported_stderr_log"
unsupported_status=$?
set -e

if [[ $unsupported_status -eq 0 ]]; then
    echo "expected unsupported profiling surface to fail closed" >&2
    exit 1
fi

if [[ -e "$unsupported_artifact_dir/optimization_targets.json" ]]; then
    echo "unsupported profiling surface emitted an authoritative optimization report" >&2
    exit 1
fi

if compgen -G "$unsupported_artifact_dir/*_profile.json" > /dev/null; then
    echo "unsupported profiling surface emitted profile artifacts" >&2
    exit 1
fi

if [[ ! -f "$unsupported_artifact_dir/degraded_non_authoritative.json" ]]; then
    echo "unsupported profiling surface did not emit a non-authoritative degraded marker" >&2
    exit 1
fi

if ! grep -q '"reason": "runtime_profiling_unavailable"' "$unsupported_artifact_dir/degraded_non_authoritative.json"; then
    echo "degraded marker does not record runtime_profiling_unavailable" >&2
    exit 1
fi

if ! grep -q '"cli_supports_runtime_profiling": false' "$unsupported_artifact_dir/degraded_non_authoritative.json"; then
    echo "degraded marker does not record missing runtime profiling CLI support" >&2
    exit 1
fi

if ! grep -q '"engine_hooks_implemented": false' "$unsupported_artifact_dir/degraded_non_authoritative.json"; then
    echo "degraded marker does not record missing engine profiling hooks" >&2
    exit 1
fi

echo "run_profiling fail-closed regression passed"
