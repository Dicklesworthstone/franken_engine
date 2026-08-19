#!/bin/bash
source scripts/validate_shadow_daemon_claims.sh

# Test the function directly
echo "Testing check_command_examples function:"
check_command_examples scripts/validate_shadow_daemon_claims.sh "test script"
echo "Function test completed"

# Test the export and subprocess call
echo "Testing exported function in subprocess:"
export -f check_command_examples
bash -c 'check_command_examples scripts/validate_shadow_daemon_claims.sh "subprocess test"'
echo "Subprocess test completed"
