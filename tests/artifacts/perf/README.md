# Performance Artifacts Directory

This directory contains performance measurement artifacts for the FrankenEngine project.

## Directory Structure

```
tests/artifacts/perf/
├── baselines/                   # Committed performance baselines
│   └── <git-sha>/              # Baseline for specific git commit
│       ├── criterion_<fn>_estimates.json × 8  # Criterion estimates for each benchmark function
│       ├── baseline_summary.json              # Aggregated baseline summary
│       ├── fingerprint.json                   # Build/environment fingerprint
│       └── README.md                          # Conditions and wins for this baseline
├── <run-id>/                   # Ad-hoc profiling runs
│   └── perf_data/             # Performance profiling data (perf record output)
└── README.md                  # This file
```

## Baselines

A **baseline** is a Criterion benchmark run committed at a specific git SHA under controlled conditions. Baselines serve as reference points for performance regression detection.

### What constitutes a baseline:
- Clean git working directory at a specific SHA
- Consistent hardware/environment conditions
- Full benchmark suite completion with no failures
- Criterion estimates exported to JSON format

### Adding a new baseline:
```bash
scripts/perf/freeze_baseline.sh <git-sha>
```

This script copies the current Criterion estimates into `baselines/<git-sha>/` with appropriate metadata.

### Retention policy:
- Keep the last 12 baselines for historical comparison
- Always keep the current claim-matrix anchor baseline
- Older baselines may be archived or removed

### Regression gates:
Performance regression gates consume baselines to detect significant performance changes between commits. The gate compares current benchmark results against the most recent applicable baseline.

## Ad-hoc profiling runs:

The `<run-id>/` directories contain detailed profiling data from specific performance investigation sessions. These are typically generated during development and may be cleaned up periodically.

Run IDs follow the format: `YYYYMMDDTHHMMSSZ-<description>` for timestamped profiling sessions.