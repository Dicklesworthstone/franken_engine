#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
script_path="${root_dir}/scripts/benchmarks/throughput_baselines.sh"

if [[ ! -x "$script_path" ]]; then
  echo "missing benchmark script: $script_path" >&2
  exit 1
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/throughput-baselines-placeholder-smoke.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

fake_node="${tmp_dir}/fake_node.sh"
fake_bun="${tmp_dir}/fake_bun.sh"

cat >"$fake_node" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "v99.0.0-test-node"
  exit 0
fi
workload="$(basename "${1:-missing}" .js)"
case "$workload" in
  fibonacci) ops=4010 ;;
  strings) ops=5020 ;;
  arrays) ops=6030 ;;
  objects) ops=7040 ;;
  functions) ops=8050 ;;
  *) echo "unknown workload" >&2; exit 1 ;;
esac
printf '{"workload":"%s","iterations":42,"duration_ms":1000,"ops_per_second":%s}\n' "$workload" "$ops"
EOF

cat >"$fake_bun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "1.0.0-test-bun"
  exit 0
fi
workload="$(basename "${1:-missing}" .js)"
case "$workload" in
  fibonacci) ops=9010 ;;
  strings) ops=10020 ;;
  arrays) ops=11030 ;;
  objects) ops=12040 ;;
  functions) ops=13050 ;;
  *) echo "unknown workload" >&2; exit 1 ;;
esac
printf '{"workload":"%s","iterations":84,"duration_ms":1000,"ops_per_second":%s}\n' "$workload" "$ops"
EOF

chmod +x "$fake_node" "$fake_bun"

assert_no_bare_cargo() {
  local commands_path="$1"
  if rg -n '(^|[[:space:]])cargo([[:space:]]|$)' "$commands_path" >/dev/null; then
    echo "bare cargo detected in commands.txt: $commands_path" >&2
    exit 1
  fi
}

partial_dir="${tmp_dir}/partial"
partial_output="${tmp_dir}/partial-output.json"
THROUGHPUT_BASELINES_NODE_BIN="$fake_node" \
THROUGHPUT_BASELINES_BUN_BIN="$fake_bun" \
THROUGHPUT_BASELINES_FRANKENCTL_BIN="${tmp_dir}/missing-frankenctl" \
THROUGHPUT_BASELINES_ARTIFACT_ROOT="$partial_dir" \
THROUGHPUT_BASELINES_OUTPUT_FILE="$partial_output" \
THROUGHPUT_BASELINES_RUN_ID="partial" \
THROUGHPUT_BASELINES_GENERATED_AT="2026-05-06T00:00:00Z" \
  "$script_path"

partial_manifest="${partial_dir}/partial/throughput_baseline_measurements_v1.json"
partial_commands="${partial_dir}/partial/commands.txt"

jq -e '
  .decision == "partial_blocked"
  and .has_live_measurements == true
  and .has_complete_runtime_measurements == false
  and .runtimes.node.measurement_status == "observed"
  and .runtimes.bun.measurement_status == "observed"
  and .runtimes.frankenengine.measurement_status == "blocked"
  and .runtimes.frankenengine.baseline_ops_per_second == 0
  and .runtimes.frankenengine.workload_results == {}
  and .runtimes.node.workload_results.fibonacci == 4010
  and .runtimes.bun.workload_results.functions == 13050
' "$partial_manifest" >/dev/null

if rg -n '"ops_per_second":(1800|2500|3200)\b' "$partial_manifest" >/dev/null; then
  echo "placeholder ops/sec leaked into partial manifest" >&2
  exit 1
fi

assert_no_bare_cargo "$partial_commands"

blocked_dir="${tmp_dir}/blocked"
blocked_output="${tmp_dir}/blocked-output.json"
set +e
THROUGHPUT_BASELINES_NODE_BIN="${tmp_dir}/missing-node" \
THROUGHPUT_BASELINES_BUN_BIN="$fake_bun" \
THROUGHPUT_BASELINES_FRANKENCTL_BIN="${tmp_dir}/missing-frankenctl" \
THROUGHPUT_BASELINES_ARTIFACT_ROOT="$blocked_dir" \
THROUGHPUT_BASELINES_OUTPUT_FILE="$blocked_output" \
THROUGHPUT_BASELINES_RUN_ID="blocked" \
THROUGHPUT_BASELINES_GENERATED_AT="2026-05-06T00:00:00Z" \
  "$script_path"
blocked_rc=$?
set -e

if [[ "$blocked_rc" -ne 42 ]]; then
  echo "expected fail-closed exit 42 when node runtime is unavailable, got $blocked_rc" >&2
  exit 1
fi

blocked_manifest="${blocked_dir}/blocked/throughput_baseline_measurements_v1.json"
blocked_commands="${blocked_dir}/blocked/commands.txt"

jq -e '
  .decision == "fail_closed"
  and .has_live_measurements == false
  and .runtimes.node.measurement_status == "blocked"
  and .runtimes.node.baseline_ops_per_second == 0
  and (.runtimes.node.blockers | length) == 1
' "$blocked_manifest" >/dev/null

if [[ -f "$blocked_output" ]]; then
  echo "fail-closed run should not publish the output manifest" >&2
  exit 1
fi

assert_no_bare_cargo "$blocked_commands"

echo "PASS throughput baseline placeholder smoke"
