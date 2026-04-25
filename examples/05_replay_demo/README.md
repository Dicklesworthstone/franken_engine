# FrankenEngine Deterministic Replay Demo

This directory demonstrates the frankenctl replay capability - a core deterministic incident replay feature (#2 in impossible-by-default capabilities).

## Overview

The deterministic replay system captures nondeterminism traces during execution and can replay them bit-stably. This enables:

- Incident reproduction from captured traces
- Deterministic debugging across environments
- Failover verification and testing

## Files

- `sample_trace.json` - Example nondeterminism trace with one LaneSelectionRandom event
- `verify.sh` - Verification script that demonstrates byte-identical replay output
- `README.md` - This file

## Usage

Run the verification script to test replay determinism:

```bash
./verify.sh
```

Or manually test replay:

```bash
# Run replay twice
cargo run --bin frankenctl -- replay run --trace sample_trace.json --mode strict --out output1.json
cargo run --bin frankenctl -- replay run --trace sample_trace.json --mode strict --out output2.json

# Verify outputs are identical
diff output1.json output2.json && echo "Replay is deterministic!" || echo "Replay diverged!"
```

## Trace Format

The trace follows the `NondeterminismTrace` schema with:

- `session_id`: Unique identifier for the replay session
- `events`: Array of captured nondeterminism events
- `next_sequence`: Next expected sequence number
- `capture_started_vts`/`capture_ended_vts`: Virtual timestamps

Each event captures:
- `sequence`: Order of the event
- `source`: Type of nondeterminism (LaneSelectionRandom, TimerRead, etc.)
- `value`: Captured deterministic value as byte array
- `virtual_ts`: Virtual timestamp
- `component`: Component that produced the event

## Replay Modes

- `strict`: Exact replay, fails on any divergence
- `best-effort`: Continues on minor divergences
- `validate`: Validation mode for testing

## Success Criteria

✅ Replaying the same trace twice produces byte-identical output
✅ No divergences reported (divergence_count: 0)
✅ Complete replay (complete: true)