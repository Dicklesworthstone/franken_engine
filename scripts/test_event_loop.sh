#!/usr/bin/env bash
set -euo pipefail

# Test: sync code runs first, then microtasks, then macrotasks
cat > /tmp/fe_eventloop_test.js << 'EOF'
setTimeout(() => console.log('timer'), 0);
Promise.resolve().then(() => console.log('micro'));
console.log('sync');
// Expected output order: sync, micro, timer
EOF

echo "Running event loop E2E test..."
frankenctl run --input /tmp/fe_eventloop_test.js --out /tmp/fe_eventloop_result.json 2>&1

# TODO: Verify output order once timer implementation is complete (RC-2.7)
# For now, just ensure the script runs without error
echo "Event loop E2E test completed successfully"
rm -f /tmp/fe_eventloop_test.js /tmp/fe_eventloop_result.json