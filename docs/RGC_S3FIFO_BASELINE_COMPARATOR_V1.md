# RGC S3-FIFO Baseline Comparator V1

## Purpose

`bd-1lsy.7.20.1` is the honesty gate for the S3-FIFO cache lane. Before any
policy replacement work lands, FrankenEngine needs a deterministic corpus,
baseline report, and adoption wedge that make the incumbent comparator explicit.
This lane does not claim that S3-FIFO already wins every workload. It records
the current incumbent (`single_queue_fifo`), replays a representative cache
corpus, and emits the exact artifacts later implementation beads will inherit.

The intent is narrow and fail-closed:

- name the incumbent policy directly
- capture the cache surfaces that S3-FIFO is allowed to replace
- preserve the cache surfaces that remain untouched
- publish stable replay artifacts for operator triage and future regressions

## Comparator Artifacts

The emitted comparator bundle must contain these deterministic artifacts:

- `cache_trace_corpus_manifest.json`
- `cache_policy_baseline_report.json`
- `s3fifo_adoption_wedge_contract.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `trace_ids.json`
- `env.json`
- `manifest.json`
- `repro.lock`

`cache_trace_corpus_manifest.json` defines the workload corpus.
`cache_policy_baseline_report.json` records the incumbent-versus-candidate
comparison.
`s3fifo_adoption_wedge_contract.json` records the narrow replacement boundary:
which cache surfaces are replaced, which ones remain untouched, and which win
metrics are allowed to justify adoption.

## Default Corpus

The default corpus intentionally spans five cache behaviors:

- `cold_compile`
- `warm_run`
- `package_graph`
- `react_app`
- `scan_heavy`

Those traces are not synthetic vanity wins. They exercise cold-start reuse,
steady-state reuse, package graph churn, React entry behavior, and pollution
pressure from scan-heavy access patterns. The comparator keeps the corpus order
stable and hashes the full manifest so future edits cannot silently rewrite the
baseline.

## Adoption Wedge

The current S3-FIFO wedge is deliberately conservative. Replaced surfaces are:

- bounded cache residency comparator
- future persistent cache admission policy
- future AOT artifact cache admission policy

Untouched surfaces remain:

- module invalidation semantics
- trust revocation semantics
- snapshot fastpath readers

The win metrics are currently:

- `hit_rate_millionths`
- `hot_retention_millionths`
- `scan_pollution_millionths`

That keeps the comparison honest. If a future candidate improves hot retention
but regresses scan resistance, the report must say so rather than hiding behind
aggregate optimism.

## Verification

Heavy verification is `rch`-only:

```bash
./scripts/run_s3fifo_baseline_comparator_suite.sh ci
./scripts/e2e/s3fifo_baseline_comparator_replay.sh ci
```

The library surface lives in:

- `crates/franken-engine/src/module_cache.rs`
- `crates/franken-engine/src/bin/franken_s3fifo_baseline_comparator.rs`
- `crates/franken-engine/tests/module_cache_integration.rs`

The deterministic contract fixture lives in:

- `docs/rgc_s3fifo_baseline_comparator_v1.json`

Artifacts are emitted under
`artifacts/s3fifo_baseline_comparator/<timestamp>/`. If the corpus hash,
baseline policy name, candidate policy name, or required artifact set changes,
the contract must be updated explicitly instead of drifting through ad hoc
benchmark scripts.
