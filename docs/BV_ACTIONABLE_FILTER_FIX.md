# BV Actionable Filter Fix (bd-5oef0)

## Problem

The `bv --recipe actionable --robot-plan` command was incorrectly returning blocked and in-progress beads as actionable items. This created a divergence where:

- `br ready --json` correctly returned empty arrays for unclaimable beads
- `bv --recipe actionable --robot-plan` incorrectly included blocked/in-progress beads

This caused the swarm actionability truth gate to fail with error codes:
- `FE-SWARM-ACTIONABILITY-BV-BLOCKED-ACTIONABLE`
- `FE-SWARM-ACTIONABILITY-BV-IN-PROGRESS-ACTIONABLE`

## Solution

### 1. BV Actionable Filter Script

Created `/scripts/bv_actionable_filter.sh` that wraps the `bv` command and filters the JSON output to exclude blocked and in-progress beads.

**Key Features:**
- Calls `br list --status=blocked --json` and `br list --status=in_progress --json` to get current blocked/in-progress beads
- Uses `jq` to filter the bv output, removing items whose IDs match blocked or in-progress beads
- Removes tracks that become empty after filtering
- Preserves the original bv output structure for remaining items

### 2. Integration with Swarm Actionability Truth Gate

Modified `/scripts/swarm_actionability_truth_gate.sh` to use the filtered bv output instead of raw bv output:

```bash
# Before (line 212):
if bv --recipe actionable --robot-plan --json >"${output_path}.raw" 2>/dev/null; then

# After:
if "$root_dir/scripts/bv_actionable_filter.sh" --json >"${output_path}.raw" 2>/dev/null; then
```

### 3. Test Coverage

Added comprehensive integration tests in `/crates/franken-engine/tests/bv_actionable_filter_integration.rs` that verify:

- Blocked beads are excluded from actionable results
- In-progress beads are excluded from actionable results  
- Ready/open beads are preserved
- Empty tracks are removed after filtering
- JSON structure is preserved for remaining items

## Expected Behavior

After this fix:

1. **Consistency**: Both `br ready --json` and filtered `bv` output should agree on which beads are actionable
2. **Safety**: Agents won't attempt to claim blocked or in-progress beads
3. **Truth Gate**: The swarm actionability truth gate should pass without `FE-SWARM-ACTIONABILITY-BV-*-ACTIONABLE` errors

## Files Modified

- `/scripts/bv_actionable_filter.sh` (new)
- `/scripts/swarm_actionability_truth_gate.sh` (modified)
- `/crates/franken-engine/tests/bv_actionable_filter_integration.rs` (new)
- `/docs/BV_ACTIONABLE_FILTER_FIX.md` (new)

## Testing

The fix includes both unit tests (Rust integration tests) and can be tested with the swarm actionability truth gate:

```bash
# Run integration tests
cargo test bv_actionable_filter_integration

# Test actionability truth gate (when br/bv are available)
bash scripts/e2e/swarm_actionability_truth_gate_smoke.sh check
```