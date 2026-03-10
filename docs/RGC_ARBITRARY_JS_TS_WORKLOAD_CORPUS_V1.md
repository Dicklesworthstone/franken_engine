# RGC Arbitrary JS/TS Workload Corpus v1

This document is the dependency-safe workload-selection contract for `bd-1lsy.8.4.1`.
It does not claim that the full arbitrary-JS/TS benchmark gate is unblocked. It
defines the minimum family roster, provenance requirements, observability
variants, and replay expectations that later implementation beads must satisfy
before supremacy or parity claims can rely on the corpus.

## Required Family Roster

| Family ID | Why users care | Bootstrap anchors |
| --- | --- | --- |
| `regex-unicode-text` | Text-heavy services and CLI pipelines fail credibility if unicode and regex-heavy paths are absent. | `parser_benchmark_protocol`, `lockstep_runtime_pins` |
| `string-transform-pipelines` | Build tools and ETL-style code spend disproportionate time in chained string transforms. | `parser_benchmark_protocol`, `benchmark_e2e_harness` |
| `npm-resolution-graphs` | Real package startup cost is dominated by graph shape and resolution churn, not isolated loops. | `extension_heavy_matrix`, `lockstep_runtime_pins` |
| `allocation-churn-iterators` | Iterator-heavy code stresses allocation, object shape churn, and GC-visible pressure. | `benchmark_e2e_harness`, `extension_heavy_matrix` |
| `megamorphic-branch-dispatch` | Dynamic apps hit branchy, shape-unstable dispatch rather than monomorphic toy loops. | `benchmark_e2e_harness`, `extension_heavy_golden_outputs` |
| `vectorizable-builtin-kernels` | Numeric and builtin-heavy kernels are required for honest speedup claims. | `parser_benchmark_protocol`, `benchmark_harness_method` |
| `effect-hostcall-spikes` | Hostcall bursts and policy transitions are user-visible bottlenecks in extension-heavy workloads. | `security_conformance_manifest`, `extension_heavy_matrix` |
| `required-native-addon-packages` | Node ecosystem credibility requires explicit native-addon coverage rather than silent exclusion. | `native_addon_membrane_suite`, `benchmark_harness_method` |
| `startup-storm-cold-image` | Fresh-process startup remains a first-order product metric. | `extension_heavy_matrix`, `benchmark_e2e_harness` |
| `startup-storm-warm-image` | Warm-image or primed-cache starts must be separated from cold-start claims. | `extension_heavy_matrix`, `benchmark_harness_method` |
| `cache-miss-metadata-stressors` | Metadata and index misses often dominate real-world wall clock even when compute is light. | `extension_heavy_matrix`, `benchmark_e2e_harness` |
| `observability-sensitive-variants` | Performance claims must survive exact capture, budgeted telemetry, and incident mode. | `benchmark_harness_method`, `extension_heavy_golden_outputs` |
| `parse-heavy-pipelines` | Parse cost must be visible for bundlers, loaders, and server boot paths. | `parser_benchmark_protocol`, `benchmark_harness_method` |
| `async-orchestration` | Promise scheduling, streaming, and effect ordering shape user-visible latency. | `react_behavior_corpus`, `lockstep_runtime_pins` |
| `module-graph-transitions` | Import/require graph churn and graph-shape transitions are unavoidable in JS deployment reality. | `react_behavior_corpus`, `lockstep_runtime_pins` |
| `ts-normalization-heavy` | TypeScript ingestion and normalization cost must be represented directly. | `react_behavior_corpus`, `parser_benchmark_protocol` |

## Provenance Contract

Every promoted workload family entry must carry:

- `source_kind`
- `source_locator`
- `selection_rationale`
- `user_value_justification`
- `baseline_targets`
- `observability_variants`

Every `source_locator` must resolve to a checked-in repo path. Missing sources are
fail-closed for this contract.

## Observability Variants

Every family is curated against the same three observability modes:

- `exact_capture`
- `budgeted_telemetry`
- `incident_mode`

The observability variant matrix must explicitly cover:

- `parse-heavy-pipelines`
- `async-orchestration`
- `module-graph-transitions`
- `ts-normalization-heavy`

## Replay and Operator Verification

Heavy verification is `rch`-only:

```bash
./scripts/run_rgc_arbitrary_js_ts_workload_corpus.sh ci
./scripts/e2e/rgc_arbitrary_js_ts_workload_corpus_replay.sh ci
```

Inspect the latest artifact bundle under
`artifacts/rgc_arbitrary_js_ts_workload_corpus/<timestamp>/`:

- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `step_logs/step_*.log`

## Failure Semantics

The contract fails closed if:

- a required family is missing or duplicated
- a bootstrap source is missing, duplicated, or points outside the repo contract
- the observability variant set is incomplete
- `rch` falls back to local execution for heavy validation
- the remote exit marker is missing or non-zero

