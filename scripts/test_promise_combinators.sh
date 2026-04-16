#!/usr/bin/env bash
set -euo pipefail
LOG="artifacts/test_promise_combinators_$(date +%s).jsonl"

run_test() {
  local name=$1 js=$2
  echo "$js" > "/tmp/fe_pc_${name}.js"
  frankenctl run --input "/tmp/fe_pc_${name}.js" --out "/tmp/fe_pc_${name}.json" 2>&1
  echo "{\"test\":\"$name\",\"exit\":$?,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
}

echo "Running Promise combinator E2E tests..."

run_test "all_fulfilled" "Promise.all([Promise.resolve(1), Promise.resolve(2)]).then(v => v);"
run_test "all_one_reject" "Promise.all([Promise.resolve(1), Promise.reject('err')]).catch(e => e);"
run_test "race_first_wins" "Promise.race([Promise.resolve('fast'), Promise.resolve('slow')]).then(v => v);"
run_test "allSettled_mixed" "Promise.allSettled([Promise.resolve(1), Promise.reject('e')]).then(v => v);"
run_test "any_first_fulfill" "Promise.any([Promise.reject('a'), Promise.resolve('b')]).then(v => v);"
run_test "any_all_reject" "Promise.any([Promise.reject('a'), Promise.reject('b')]).catch(e => e);"

echo "Results logged to: $LOG"
rm -f /tmp/fe_pc_*.js /tmp/fe_pc_*.json

echo "Promise combinator E2E tests completed successfully"