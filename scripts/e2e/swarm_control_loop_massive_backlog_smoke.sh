#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_path="${root_dir}/crates/franken-engine/tests/swarm_control_loop_integration.rs"
source_path="${root_dir}/crates/franken-engine/src/swarm_control_loop.rs"
failures=0

record_pass() {
  printf 'PASS swarm-control-loop-massive-backlog %s\n' "$1"
}

record_failure() {
  printf 'FAIL swarm-control-loop-massive-backlog %s\n' "$1" >&2
  failures=$((failures + 1))
}

relative_path() {
  local path="$1"
  printf '%s\n' "${path#"$root_dir"/}"
}

require_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    record_pass "$(relative_path "$path") exists"
  else
    record_failure "$(relative_path "$path") missing"
  fi
}

require_literal() {
  local path="$1"
  local literal="$2"
  local label="$3"
  if grep -Fq "$literal" "$path"; then
    record_pass "$label"
  else
    record_failure "$label"
  fi
}

run_check() {
  require_file "$source_path"
  require_file "$test_path"

  require_literal "$test_path" 'const MASSIVE_BACKLOG_TASKS: usize = 4_096;' '4096-task hard-cap evidence constant'
  require_literal "$test_path" 'const MASSIVE_BACKLOG_QUEUE_DEPTH: usize = 64;' '64-entry queue evidence constant'
  require_literal "$test_path" 'fn make_scored_backlog_task(ordinal: usize) -> TaskNode' 'deterministic scored backlog fixture helper'
  require_literal "$test_path" 'fn add_scored_backlog(ctrl: &mut SwarmControlLoop, count: usize, reverse: bool)' 'forward and reverse insertion fixture helper'
  require_literal "$test_path" 'fn massive_backlog_recompute_bounds_queue_and_preserves_deterministic_order()' 'large graph ordering test'
  require_literal "$test_path" 'fn massive_backlog_hash_and_rationale_stable_across_insert_order()' 'deterministic hash and rationale stability test'
  require_literal "$test_path" 'fn massive_backlog_risk_budget_conservation_across_low_health_iterations()' 'risk-budget conservation test'
  require_literal "$test_path" 'fn massive_backlog_rejects_task_past_hard_cap_without_growth()' 'hard-cap fail-closed test'
  require_literal "$test_path" 'assert_eq!(artifact.queue.len(), MASSIVE_BACKLOG_QUEUE_DEPTH);' 'queue remains bounded at configured depth'
  require_literal "$test_path" 'assert_eq!(artifact.queue[0].task_id, "task-4095");' 'highest scoring task leads queue'
  require_literal "$test_path" 'artifact.queue[MASSIVE_BACKLOG_QUEUE_DEPTH - 1].task_id' '64th ranked task is deterministic'
  require_literal "$test_path" 'repeated.rationale_deltas.is_empty()' 'unchanged backlog has no rationale churn'
  require_literal "$test_path" 'artifact.risk_budget.remaining_millionths + artifact.risk_budget.consumed_millionths' 'risk budget conservation assertion'
  require_literal "$test_path" 'ControlLoopError::TooManyTasks { count, max }' 'hard cap reports structured error'
  require_literal "$source_path" 'config.conservative_threshold_millionths < 0' 'negative conservative threshold rejected'
  require_literal "$source_path" 'config.conservative_threshold_millionths > MILLION' 'over-budget conservative threshold rejected'

  if [[ "$failures" -eq 0 ]]; then
    record_pass 'all static scale evidence checks passed'
  else
    record_failure "${failures} static scale evidence checks failed"
  fi
}

usage() {
  cat <<'USAGE'
Usage: scripts/e2e/swarm_control_loop_massive_backlog_smoke.sh [check|selftest]

Static fallback smoke for bd-2ivmm. It inspects the checked-in Rust source and
test evidence for massive-backlog control-loop conformance without touching live
workers, queues, bead state, or reservation state.
USAGE
}

mode="${1:-check}"
case "$mode" in
  check|selftest)
    run_check
    ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ "$failures" -ne 0 ]]; then
  exit 1
fi
