#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

trials=100
artifact_root="${RED_TEAM_REPEATED_TRIAL_ARTIFACT_ROOT:-artifacts/red_team_repeated_trial_harness}"
run_id="${RED_TEAM_REPEATED_TRIAL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
code_revision="${RED_TEAM_REPEATED_TRIAL_CODE_REVISION:-$(git rev-parse HEAD 2>/dev/null || printf unknown)}"
timeout_seconds="${RED_TEAM_COMPROMISE_RATE_TIMEOUT_SECONDS:-20}"
scenario="all"
runtime="all"
replay=false
harness_output=""

usage() {
  cat <<'EOF'
usage:
  run_bd_28otw_attacker_harness.sh [--trials N] [--artifact-root PATH] [--run-id ID]
      [--code-revision SHA] [--timeout-seconds SECONDS]
  run_bd_28otw_attacker_harness.sh --replay --harness-output PATH
      [--scenario ID|all] [--runtime node|bun|franken_engine|all] [--trials N]

Normal mode executes the ten-scenario receipt-bound Node/Bun/FrankenEngine
comparator corpus N times, then emits and verifies a
franken-engine.red-team-harness-output.v1 bundle. The repetitions establish
outcome stability and replayability; they are not independent statistical
samples. Production evidence requires at least 100 stability repetitions per
runtime and distinct scenario.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --trials)
      trials="${2:?--trials requires a value}"
      shift 2
      ;;
    --artifact-root)
      artifact_root="${2:?--artifact-root requires a value}"
      shift 2
      ;;
    --run-id)
      run_id="${2:?--run-id requires a value}"
      shift 2
      ;;
    --code-revision)
      code_revision="${2:?--code-revision requires a value}"
      shift 2
      ;;
    --timeout-seconds)
      timeout_seconds="${2:?--timeout-seconds requires a value}"
      shift 2
      ;;
    --scenario)
      scenario="${2:?--scenario requires a value}"
      shift 2
      ;;
    --runtime)
      runtime="${2:?--runtime requires a value}"
      shift 2
      ;;
    --replay)
      replay=true
      shift
      ;;
    --harness-output)
      harness_output="${2:?--harness-output requires a value}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$trials" =~ ^[1-9][0-9]*$ ]]; then
  printf '%s\n' '--trials must be a positive integer' >&2
  exit 2
fi
if [[ ! "$timeout_seconds" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  printf '%s\n' '--timeout-seconds must be a positive number' >&2
  exit 2
fi
if [[ "$runtime" != "all" && "$runtime" != "node" && "$runtime" != "bun" && "$runtime" != "franken_engine" ]]; then
  printf 'unsupported --runtime: %s\n' "$runtime" >&2
  exit 2
fi
if [[ ! "$run_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
  printf '%s\n' '--run-id may contain only letters, digits, dot, underscore, and hyphen' >&2
  exit 2
fi
if [[ "$trials" -lt 100 && "${RED_TEAM_HARNESS_ALLOW_TEST_MINIMUM:-false}" != "true" ]]; then
  printf 'production stability evidence requires at least 100 repetitions; got %s\n' "$trials" >&2
  exit 2
fi

if [[ "$replay" == "true" ]]; then
  if [[ -z "$harness_output" ]]; then
    printf '%s\n' '--replay requires --harness-output' >&2
    exit 2
  fi
  exec python3 scripts/aggregate_red_team_trials.py verify \
    --root "$root_dir" \
    --harness-output "$harness_output" \
    --scenario "$scenario" \
    --runtime "$runtime" \
    --minimum-trials "$trials"
fi

if [[ "$scenario" != "all" || "$runtime" != "all" ]]; then
  printf '%s\n' '--scenario and --runtime filters are replay-only; normal campaigns must execute the complete matrix' >&2
  exit 2
fi

if [[ "$artifact_root" != /* ]]; then
  artifact_root="$root_dir/$artifact_root"
fi
run_dir="$artifact_root/$run_id"
trial_root="$run_dir/trials"
aggregate_dir="$run_dir/aggregate"
scenario_dir="$root_dir/crates/franken-engine/tests/red_team_scenarios"
mkdir -p "$trial_root" "$aggregate_dir"

verification_command="./scripts/run_bd_28otw_attacker_harness.sh --trials $trials --artifact-root ${artifact_root#"$root_dir"/} --run-id $run_id --code-revision $code_revision --timeout-seconds $timeout_seconds"
printf '%s\n' "$verification_command" >"$run_dir/commands.txt"
printf '%s\n' 'red_team_corpus=red_team_security_critical_compromise_v2' >"$run_dir/corpus.txt"
printf '%s\n' 'repetition_role=stability_and_replay_not_independent_sampling' >"$run_dir/repetition_semantics.txt"

for ((trial = 1; trial <= trials; trial++)); do
  trial_id="$(printf 'trial-%04d' "$trial")"
  trial_dir="$trial_root/$trial_id"
  rm -rf "$trial_dir"
  set +e
  python3 scripts/red_team_compromise_rate_corpus.py \
    --root "$root_dir" \
    --bundle-dir "$trial_dir" \
    --scenario-dir "$scenario_dir" \
    --variant "$trial_id" \
    --code-revision "$code_revision" \
    --verification-command "$verification_command" \
    --timeout-seconds "$timeout_seconds"
  comparator_exit=$?
  set -e
  status="$(python3 - "$trial_dir/bundle_status.json" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except Exception as error:
    print(f"invalid:{type(error).__name__}:{error}")
else:
    print(value.get("status", "missing"))
PY
)"
  if [[ "$status" != "pass" && "$status" != "fail" ]]; then
    printf 'repetition %s did not produce measurement evidence (status=%s, exit=%s)\n' \
      "$trial_id" "$status" "$comparator_exit" >&2
    exit 1
  fi
  if ((trial == 1 || trial == trials || trial % 10 == 0)); then
    printf 'completed %s/%s receipt-bound stability repetitions (status=%s)\n' \
      "$trial" "$trials" "$status"
  fi
done

python3 scripts/aggregate_red_team_trials.py aggregate \
  --root "$root_dir" \
  --trial-root "$trial_root" \
  --output-dir "$aggregate_dir" \
  --code-revision "$code_revision" \
  --verification-command "$verification_command" \
  --minimum-trials "$trials"

harness_output="$aggregate_dir/harness_output.json"
python3 scripts/aggregate_red_team_trials.py verify \
  --root "$root_dir" \
  --harness-output "$harness_output" \
  --scenario all \
  --runtime all \
  --minimum-trials "$trials"

printf 'red_team_repeated_trial_run_dir=%s\n' "$run_dir"
printf 'red_team_harness_output=%s\n' "$harness_output"
