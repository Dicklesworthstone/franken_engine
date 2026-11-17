#!/usr/bin/env bash
# bd-9vouw.59: Deterministic virtual clock E2E smoke & Node delta comparison.
#
# Runs timer ordering, busy-wait termination, Date subtraction, and strict replay
# (both default fixed epoch and `--clock-epoch now`), logging observed Date.now()
# and performance.now() deltas alongside Node's into a timestamped artifact dir.
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root_dir" || exit 2

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${1:-artifacts/virtual_clock_smoke/${timestamp}-$$}"
mkdir -p "$run_dir"

frankenctl_bin="${FRANKENCTL_BIN:-}"
if [[ -z "$frankenctl_bin" ]]; then
  for candidate in \
    "target2/cli_bins/debug/frankenctl" \
    "target/debug/frankenctl" \
    "target/release/frankenctl"; do
    if [[ -x "$candidate" ]]; then
      frankenctl_bin="$candidate"
      break
    fi
  done
fi

if [[ -z "$frankenctl_bin" || ! -x "$frankenctl_bin" ]]; then
  target_dir="${RCH_TARGET_BASE:-target2}/virtual_clock_smoke_bin"
  if command -v rch >/dev/null 2>&1 && [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
    RCH_TOPOLOGY_PATHS_PRESENT=1 rch exec -- env \
      RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly-2026-09-21}" \
      CARGO_TARGET_DIR="$target_dir" \
      cargo build -j 2 -p frankenengine-engine --bin frankenctl
  else
    CARGO_TARGET_DIR="$target_dir" cargo build -p frankenengine-engine --bin frankenctl
  fi
  frankenctl_bin="${target_dir}/debug/frankenctl"
fi

probe_js="${run_dir}/clock_probe.js"
cat >"$probe_js" <<'EOF'
const a = Date.now();
const p0 = performance.now();
let s = 0;
for (let i = 0; i < 200000; i++) { s += i; }
const b = Date.now();
const busyStart = Date.now();
let spins = 0;
while (Date.now() - busyStart < 50) { spins++; }
const busyElapsed = Date.now() - busyStart;
const days = (new Date(2020, 0, 11) - new Date(2020, 0, 1)) / 864e5;
console.log(JSON.stringify({
  kind: "sync",
  start_ms: a,
  loop_delta_ms: b - a,
  busy_elapsed_ms: busyElapsed,
  busy_spins: spins,
  date_diff_days: days,
  iso: new Date(a).toISOString()
}));
setTimeout(() => {
  console.log(JSON.stringify({
    kind: "t100",
    date_delta_ms: Date.now() - a,
    perf_delta_ms: performance.now() - p0
  }));
}, 100);
setTimeout(() => {
  console.log(JSON.stringify({
    kind: "t5",
    date_delta_ms: Date.now() - a,
    perf_delta_ms: performance.now() - p0
  }));
}, 5);
EOF

"$frankenctl_bin" run \
  --input "$probe_js" \
  --extension-id clock-smoke-fixed \
  --instruction-budget 50000000 \
  --out "${run_dir}/fixed.run.json" >"${run_dir}/fixed.stdout.json"

"$frankenctl_bin" replay run \
  --trace "${run_dir}/fixed.run.json" \
  --mode strict \
  --out "${run_dir}/fixed.replay.json" >"${run_dir}/fixed.replay.stdout.json"

"$frankenctl_bin" run \
  --input "$probe_js" \
  --extension-id clock-smoke-now \
  --clock-epoch now \
  --instruction-budget 50000000 \
  --out "${run_dir}/now.run.json" >"${run_dir}/now.stdout.json"

"$frankenctl_bin" replay run \
  --trace "${run_dir}/now.run.json" \
  --mode strict \
  --out "${run_dir}/now.replay.json" >"${run_dir}/now.replay.stdout.json"

node_lines="[]"
if command -v node >/dev/null 2>&1; then
  NO_COLOR=1 node "$probe_js" >"${run_dir}/node.jsonl"
  node_lines="$(jq -s '.' "${run_dir}/node.jsonl")"
fi

jq -n \
  --slurpfile fixed_run "${run_dir}/fixed.run.json" \
  --slurpfile fixed_replay "${run_dir}/fixed.replay.json" \
  --slurpfile now_run "${run_dir}/now.run.json" \
  --slurpfile now_replay "${run_dir}/now.replay.json" \
  --argjson node_events "$node_lines" \
  '{
    schema_version: "franken-engine.virtual-clock-smoke.v1",
    fixed_epoch_events: ($fixed_run[0].console_output | map(.message | fromjson)),
    fixed_strict_replay_complete: $fixed_replay[0].complete,
    now_epoch_ms: $now_run[0].replay_input.clock_epoch_ms,
    now_epoch_events: ($now_run[0].console_output | map(.message | fromjson)),
    now_strict_replay_complete: $now_replay[0].complete,
    node_events: $node_events
  }' >"${run_dir}/comparison_summary.json"

jq -e '
  .fixed_strict_replay_complete == true
  and .now_strict_replay_complete == true
  and (.fixed_epoch_events | length == 3)
  and (.fixed_epoch_events[0].kind == "sync")
  and (.fixed_epoch_events[0].start_ms == 1767225600000)
  and (.fixed_epoch_events[0].busy_elapsed_ms >= 50)
  and (.fixed_epoch_events[0].date_diff_days == 10)
  and (.fixed_epoch_events[1].kind == "t5")
  and (.fixed_epoch_events[1].date_delta_ms >= 5)
  and (.fixed_epoch_events[1].perf_delta_ms >= 5)
  and (.fixed_epoch_events[2].kind == "t100")
  and (.fixed_epoch_events[2].date_delta_ms >= 100)
  and (.fixed_epoch_events[2].perf_delta_ms >= 100)
  and (.now_epoch_ms >= 1767225600000)
' "${run_dir}/comparison_summary.json" >/dev/null

echo "virtual_clock_smoke: PASS (${run_dir}/comparison_summary.json)"
