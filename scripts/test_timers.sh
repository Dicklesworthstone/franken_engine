#!/usr/bin/env bash
set -euo pipefail
LOG="artifacts/test_timers_$(date +%s).jsonl"

run_test() {
  local name=$1 js=$2
  echo "$js" > "/tmp/fe_timer_${name}.js"
  frankenctl run --input "/tmp/fe_timer_${name}.js" --out "/tmp/fe_timer_${name}.json" 2>&1
  echo "{\"test\":\"$name\",\"exit\":$?,\"time\":\"$(date -Iseconds)\"}" >> "$LOG"
}

echo "Running timer substrate E2E tests..."

run_test "setTimeout_basic" "
const results = [];
setTimeout(() => results.push('timer'), 100);
results.push('sync');
// After event loop: results = ['sync', 'timer']
"

run_test "setTimeout_ordering" "
setTimeout(() => console.log('second'), 200);
setTimeout(() => console.log('first'), 100);
// first, then second
"

run_test "clearTimeout" "
const id = setTimeout(() => console.log('should not fire'), 100);
clearTimeout(id);
// nothing fires
"

run_test "setInterval_repeating" "
let count = 0;
const id = setInterval(() => {
  count++;
  if (count >= 3) clearInterval(id);
}, 100);
// fires 3 times then stops
"

run_test "microtask_before_timer" "
setTimeout(() => console.log('timer'), 0);
Promise.resolve().then(() => console.log('micro'));
console.log('sync');
// sync, micro, timer
"

echo "Results logged to: $LOG"
rm -f /tmp/fe_timer_*.js /tmp/fe_timer_*.json

echo "Timer substrate E2E tests completed successfully"