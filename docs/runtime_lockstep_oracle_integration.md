# Runtime Lockstep Oracle Integration

This document describes the integration between the runtime comparison benchmarks (Node.js and Bun) and the lockstep oracle for differential checking against FrankenEngine.

## Overview

The runtime lockstep oracle integration enables automated differential analysis between FrankenEngine and other JavaScript runtimes (Node.js and Bun). This builds upon the existing lockstep oracle infrastructure originally designed for React vs FrankenEngine comparisons.

## Architecture

The integration consists of several key components:

1. **Extended Lockstep Oracle** (`frx_lockstep_oracle.rs`):
   - `run_node_lockstep_oracle()` - Compare Node.js traces against FrankenEngine
   - `run_bun_lockstep_oracle()` - Compare Bun traces against FrankenEngine
   - `create_runtime_benchmark_trace()` - Generate trace files from benchmark results

2. **Runtime Helpers** (`runtime_lockstep_helpers.rs`):
   - High-level coordination functions
   - Trace generation utilities
   - Configuration management

3. **Orchestrator CLI** (`runtime_lockstep_orchestrator`):
   - Command-line interface for running benchmarks with lockstep analysis
   - Supports Node, Bun, or comprehensive analysis modes

4. **Modified Benchmarks** (when available):
   - Enhanced `comparative_node.rs` and `comparative_bun.rs` benchmarks
   - Generate trace files during benchmark execution
   - Integration with lockstep oracle pipeline

## Trace Format

Runtime benchmark traces use the same `FrxObservableTrace` format as React traces, enabling reuse of the existing lockstep oracle infrastructure:

```json
{
  "schema_version": "frx.react.observable.trace.v1",
  "trace_id": "trace-Node.js-numeric_loop-20260521T194823Z",
  "decision_id": "decision-Node.js-numeric_loop-20260521T194823Z",
  "policy_id": "policy-runtime-comparison-Node.js-v1",
  "component": "runtime_comparison_benchmark",
  "scenario_id": "benchmark-numeric_loop",
  "fixture_ref": "numeric_loop",
  "seed": 42,
  "events": [
    {
      "seq": 1,
      "phase": "execution",
      "actor": "Node.js",
      "event": "start",
      "decision_path": "benchmark/numeric_loop",
      "timing_us": 0,
      "outcome": "ok"
    },
    {
      "seq": 2,
      "phase": "execution",
      "actor": "Node.js",
      "event": "console_output:49995000",
      "decision_path": "benchmark/numeric_loop",
      "timing_us": 2500,
      "outcome": "ok"
    },
    {
      "seq": 3,
      "phase": "execution",
      "actor": "Node.js",
      "event": "completion",
      "decision_path": "benchmark/numeric_loop",
      "timing_us": 2500,
      "outcome": "ok"
    }
  ],
  "outcome": "ok",
  "error_code": null
}
```

### Trace Events

Each runtime execution generates three types of events:

1. **Start Event**: Marks the beginning of workload execution
2. **Console Output Event**: Captures stdout from the runtime (if present)
3. **Completion Event**: Records the final execution state and timing

## Usage

### Direct API Usage

```rust
use frankenengine_engine::runtime_lockstep_helpers::*;
use frankenengine_engine::frx_lockstep_oracle::*;

// Create trace from benchmark result
let result = RuntimeBenchmarkResult {
    stdout: "42".to_string(),
    stderr: "".to_string(),
    wall_time_ns: 1_000_000,
    peak_rss_bytes: 4096,
    exit_success: true,
    exit_code: Some(0),
};

let trace_path = PathBuf::from("/tmp/workload.trace.json");
create_runtime_benchmark_trace("test_workload", "Node.js", result, &trace_path)?;

// Run lockstep oracle comparison
let context = FrxLockstepRunContext::deterministic("trace-id", "decision-id", "policy-id");
let report = run_node_lockstep_oracle(&node_traces_dir, &franken_traces_dir, context, None)?;
```

### CLI Usage

```bash
# Run Node.js benchmarks with lockstep analysis
runtime-lockstep-orchestrator node --traces-dir /tmp/lockstep --output-dir ./reports

# Run Bun benchmarks with lockstep analysis
runtime-lockstep-orchestrator bun --traces-dir /tmp/lockstep --output-dir ./reports

# Run comprehensive analysis (both Node and Bun)
runtime-lockstep-orchestrator all --traces-dir /tmp/lockstep --output-dir ./reports

# Analyze existing trace files
runtime-lockstep-orchestrator analyze --traces-dir /tmp/lockstep --runtime all

# Verify trace completeness
runtime-lockstep-orchestrator verify --traces-dir /tmp/lockstep --workloads "numeric_loop,json_roundtrip"
```

### Benchmark Integration

The enhanced benchmarks can be controlled via environment variables:

```bash
# Enable lockstep oracle integration
export RUNTIME_LOCKSTEP_ENABLED=1
export RUNTIME_LOCKSTEP_TRACES_DIR=/tmp/lockstep_traces

# Optional: filter to specific workload
export RUNTIME_LOCKSTEP_WORKLOAD_FILTER=numeric_loop

# Run benchmarks
cargo bench -p frankenengine-engine --bench comparative_node
cargo bench -p frankenengine-engine --bench comparative_bun
```

## Configuration

### RuntimeLockstepConfig

```rust
pub struct RuntimeLockstepConfig {
    /// Base directory for storing trace files
    pub traces_base_dir: PathBuf,
    /// Whether to run lockstep oracle after generating traces
    pub run_oracle: bool,
    /// Whether to clean up trace files after oracle run
    pub cleanup_traces: bool,
}
```

### Directory Structure

```
traces_base_dir/
├── node_traces/
│   ├── numeric_loop.trace.json
│   ├── json_roundtrip.trace.json
│   └── array_indexing.trace.json
├── bun_traces/
│   ├── numeric_loop.trace.json
│   ├── json_roundtrip.trace.json
│   └── array_indexing.trace.json
└── franken_traces/
    ├── numeric_loop.trace.json
    ├── json_roundtrip.trace.json
    └── array_indexing.trace.json
```

## Divergence Detection

The lockstep oracle can detect several types of divergences between runtimes:

1. **Console Output Differences**: Different stdout content
2. **Execution State Differences**: Success vs failure outcomes
3. **Event Sequence Differences**: Different execution ordering
4. **Timing Anomalies**: Significant performance differences

### Example Divergence Report

```json
{
  "fixture_ref": "numeric_loop",
  "scenario_id": "benchmark-numeric_loop", 
  "react_trace_id": "trace-Node.js-numeric_loop-20260521T194823Z",
  "franken_trace_id": "trace-FrankenEngine-numeric_loop-20260521T194823Z",
  "pass": false,
  "divergence": {
    "class": "event_sequence",
    "message": "Console output differs: Node.js='42', FrankenEngine='84'",
    "event_index": 2,
    "react_signature": {
      "seq": 2,
      "phase": "execution",
      "event": "console_output:42",
      "decision_path": "benchmark/numeric_loop",
      "outcome": "ok"
    },
    "franken_signature": {
      "seq": 2,
      "phase": "execution", 
      "event": "console_output:84",
      "decision_path": "benchmark/numeric_loop",
      "outcome": "ok"
    }
  }
}
```

## Implementation Status (bd-cixqu.9.1)

### ✅ Completed

- Extended `frx_lockstep_oracle.rs` with Node/Bun support functions
- Created `runtime_lockstep_helpers.rs` for high-level coordination
- Added comprehensive integration tests
- Created `runtime_lockstep_orchestrator` CLI tool
- Documentation and usage examples

### 🔄 Pending (blocked on file reservations)

- Integration with `comparative_node.rs` benchmark
- Integration with `comparative_bun.rs` benchmark  
- End-to-end testing with actual benchmark runs

The core lockstep oracle infrastructure is ready, and the benchmark integration can be completed once file access is available.

## Testing

### Unit Tests

```bash
cargo test -p frankenengine-engine frx_lockstep_oracle::tests::runtime
cargo test -p frankenengine-engine runtime_lockstep_helpers::tests
```

### Integration Tests

```bash
cargo test -p frankenengine-engine --test runtime_lockstep_oracle_integration
```

### End-to-End Testing

```bash
# Test CLI orchestrator
runtime-lockstep-orchestrator verify --traces-dir ./test_traces --workloads "test_workload"

# Test with mock traces
runtime-lockstep-orchestrator analyze --traces-dir ./test_traces --runtime all
```

## Future Enhancements

1. **Performance Analysis Integration**: Correlate divergences with performance metrics
2. **Regression Detection**: Automated alerts for new divergences
3. **Workload Coverage**: Expand to more JavaScript language features
4. **Statistical Analysis**: Aggregate divergence trends over time
5. **CI/CD Integration**: Automated lockstep oracle runs in build pipeline

## Related Files

- `crates/franken-engine/src/frx_lockstep_oracle.rs` - Core lockstep oracle
- `crates/franken-engine/src/runtime_lockstep_helpers.rs` - Helper utilities
- `crates/franken-engine/src/bin/runtime_lockstep_orchestrator.rs` - CLI tool
- `crates/franken-engine/tests/runtime_lockstep_oracle_integration.rs` - Integration tests
- `crates/franken-engine/benches/comparative_node.rs` - Node.js benchmarks
- `crates/franken-engine/benches/comparative_bun.rs` - Bun benchmarks
- `benchmarks/runtime_comparison/` - Benchmark workload definitions