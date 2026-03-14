# RGC Supremacy Cell Matrix V1

## Purpose

`bd-1lsy.8.5.1` defines the supremacy board that later V8-claim gates will
consume. The point is not to create another optimistic benchmark summary; the
point is to make every declared claim surface explicit enough that later gates
can fail closed. A runtime does not beat V8 "across the board" because it won a
few hot-loop charts. It earns that language only if the full declared board is
green on shipped paths and none of the side constraints are red.

This document is dependency-safe prework. Upstream lanes still own the final
React cohort corpus, native React lowering, and publication-grade benchmark
evidence. This matrix exists now so those later lanes inherit one stable board
definition instead of inventing incompatible ones.

## Matrix Dimensions

The board is indexed by six dimensions:

- `workload_family`
- `environment`
- `entry_mode`
- `warm_state`
- `measurement_family`
- `interference_profile`

These dimensions are deliberately narrow. They are enough to distinguish
cold-start versus warm behavior, shipped CLI/library paths versus native React
paths, and isolated benchmarks versus mixed-board interference cases.

## Required Families

The required board families are:

- parse/compile
- cold-start
- warm throughput
- async
- module graphs
- npm cohorts
- React compile
- React SSR
- React client
- mixed-package
- tail-latency
- memory pressure

The board is incomplete if any one of those families is missing. React matters
because the later shipped claim surfaces explicitly include React compile, SSR,
and client entry paths. Cold-start matters because startup wins can disappear
once a board is forced to include resolver, cache, and hydration costs.

## Interference Model

Mixed-package cells are first-class, not post-hoc annotations. The matrix
records pairings where cache reuse, scheduler queue pressure, worker-thread
contention, or memory-bandwidth contention can distort a naive average.

Current rule families include:

- module-graph versus npm cohort cache contention
- async versus mixed-package scheduler contention
- React SSR versus React client bundle/hydration contention
- mixed-board frontend contention
- tail-latency scheduler pressure
- memory-pressure cross-family contention

The interference model exists because a board can otherwise look universally
green by isolating the easy cells and hiding the hard coupled ones. This matrix
prevents that.

## Tail Decomposition

Tail-latency cells must carry decomposition axes rather than a single p99
number. The current contract requires stage-level attribution across parse,
compile, module load, queue delay, render, hydration, and GC pause. That is the
minimum detail needed to explain whether a tail regression came from frontend
work, scheduler backlog, React render pressure, or reclamation spikes.

Without this decomposition, a benchmark board can "win" on median throughput
while still regressing the operator-visible p95/p99 paths that users actually
feel.

## Verification

The contract artifact lives in:

- `crates/franken-engine/tests/fixtures/supremacy_cell_matrix_v1.json`

The validation target lives in:

- `crates/franken-engine/src/supremacy_cell_matrix.rs`
- `crates/franken-engine/tests/supremacy_cell_matrix.rs`

The deterministic runner lives in:

- `scripts/run_supremacy_cell_matrix_suite.sh`
- `scripts/e2e/supremacy_cell_matrix_replay.sh`

Heavy verification remains `rch`-only:

```bash
./scripts/run_supremacy_cell_matrix_suite.sh ci
./scripts/e2e/supremacy_cell_matrix_replay.sh ci
```

The runner defaults heavy `CARGO_TARGET_DIR` output to the repo-local path
`target_rch_supremacy_cell_matrix_uid<uid>` rather than `/tmp`, so remote
artifact replay does not depend on ephemeral temp-root state.

Artifacts are emitted under `artifacts/supremacy_cell_matrix/<timestamp>/` and
must include:

- `supremacy_cell_matrix.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`

If any declared family, interference rule, or tail decomposition axis is
missing, the board is not publication-ready and later supremacy wording must
stay fail-closed.
