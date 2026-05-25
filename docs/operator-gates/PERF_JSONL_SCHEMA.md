# PERF JSONL Schema (canonical reference)

Definitive reference for the `perf.profile.*` and `perf.regression.*` JSON Lines
event shapes emitted by the performance-measurement infrastructure and consumed
by the bootstrap-CI tool, the regression gate, and the hot-path render scripts.

This document is the **single source of truth**: previously each PERF-H[N] bead
duplicated the event shapes inline. Producers and consumers MUST conform to the
shapes pinned here; any new field is added here first.

## Bead anchors

- This document: **bd-o4cbn.8.3** (PERF-INFRA.3 — canonical PERF JSONL schema home).
- Track parent: **bd-o4cbn.8** (PERF-INFRA — persistent perf measurement infrastructure).
- Producers / consumers:
  - `scripts/perf/hyperfine_to_perf_jsonl.py` — emits `perf.profile.span_summary`.
  - `scripts/perf/regression_gate.sh` — emits `perf.regression.diff`.
  - `scripts/perf/bootstrap_ci.py` — BCa paired CI; fills the `bca_*` / `delta_pct`
    fields on `perf.profile.span_summary` (bd-o4cbn.12.1, PERF-ARTIFACT-1.1).
  - Smoke / bench wrappers — emit `run_start`, `sample_collected`,
    `hypothesis_evaluated`, and `run_complete`.

## General conformance rules

1. **One object per line.** Every line is a single JSON object terminated by `\n`.
   The file is JSON Lines (`.jsonl`); parsers MUST accept trailing newlines and
   skip blank lines.
2. **Timestamps.** `ts` is always RFC3339 UTC with a `Z` suffix and no numeric
   offset, e.g. `2026-05-21T12:34:56Z`.
3. **Bead IDs.** `bead` follows the project shape `bd-<base36>(\.<n>)*`
   (e.g. `bd-o4cbn.8.3`); legacy human aliases such as `PERF-H1.4` are also
   accepted in the `bead` field for back-compatibility with pre-migration runs.
4. **Numeric units are encoded in the suffix:**
   - `_ns` — integer nanoseconds (no floats).
   - `_ms` — float milliseconds (used only by the startup p95 variant).
   - `_pct` — float percent.
   - `_sec` — float seconds.
   Durations on the hot path are reported in `_ns` integers; only the
   startup-microbench p95 path uses `_ms` floats.
5. **Required vs optional.** Fields marked *optional* below MAY be absent; all
   other listed fields are REQUIRED for that event type. Consumers MUST tolerate
   unknown extra fields (forward-compatible).
6. **Determinism.** Statistical fields produced by `bootstrap_ci.py` are computed
   with a fixed RNG seed (default 42), so a given `(data, seed, resamples)` triple
   yields a bit-identical interval on every run.

## Event catalog

### `perf.profile.run_start`

Emitted exactly once per smoke / bench invocation, at the start.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.profile.run_start`. |
| `bead` | string | yes | Owning bead id. |
| `scenario_id` | string | yes | Unique per-script scenario label (e.g. `h1_smoke`). |
| `git_sha` | string | yes | Exact HEAD sha at run time. |
| `fingerprint_hash` | string | yes | SHA-256 of the run `fingerprint.json`. |
| `build_profile` | string | yes | Cargo profile (`bench`, `release`, …). |
| `rustc_version` | string | yes | Full `rustc --version` string. |
| `baseline_id` | string | yes | Criterion baseline being compared against (e.g. `pass1`). |
| `run_id` | string | yes | Run directory name, e.g. `20260521T123456Z-h1-smoke`. |

### `perf.profile.sample_collected`

One per sub-bench, emitted after Criterion sampling completes.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.profile.sample_collected`. |
| `bead` | string | yes | Owning bead id. |
| `sub_bench` | string | yes | Sub-benchmark name (e.g. `evidence_ledger_bundle`). |
| `sample_count` | int | yes | Number of Criterion samples. |
| `duration_sec` | float | yes | Wall-time spent sampling this sub-bench. |
| `iterations_per_sample` | int | yes | Inner iterations Criterion ran per sample. |

### `perf.profile.span_summary`

One per sub-bench, carrying the statistical summary. Consumed by
`render_hotspot_table.py` and the regression gate. The `bca_*` /
`baseline_mean_ns` / `delta_pct` / `verdict_at_5pct_threshold` block is *optional*
and is filled in by `bootstrap_ci.py` after a paired comparison.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.profile.span_summary`. |
| `bead` | string | yes | Owning bead id. |
| `scenario_id` | string | yes | Scenario label. |
| `sub_bench` | string | yes | Sub-benchmark name. |
| `span` | string | yes | Alias of `sub_bench` (legacy compatibility). |
| `mean_ns` | int | yes | Mean. |
| `median_ns` | int | yes | Median. |
| `p50_ns` | int | yes | 50th percentile. |
| `p95_ns` | int | yes | 95th percentile. |
| `p99_ns` | int | yes | 99th percentile. |
| `p999_ns` | int | yes | 99.9th percentile. |
| `std_dev_ns` | int | yes | Standard deviation. |
| `cv_pct` | float | yes | Coefficient of variation = `std_dev/mean*100`. |
| `ci95_low_ns` | int | yes | Lower bound of the normal-approx 95% CI (`mean − 1.96·sem`). |
| `ci95_high_ns` | int | yes | Upper bound of the normal-approx 95% CI (`mean + 1.96·sem`). |
| `baseline_mean_ns` | int | no | Baseline mean for the paired comparison. |
| `delta_pct` | float | no | Relative change vs baseline, `(cur − base)/base·100`. |
| `bca_ci95_low_pct` | float | no | BCa lower bound of the relative-change CI. |
| `bca_ci95_high_pct` | float | no | BCa upper bound of the relative-change CI. |
| `verdict_at_5pct_threshold` | string | no | `win_significant` \| `regression_significant` \| `inconclusive`. |
| `category` | string | no | Cost category (`CPU`, `ALLOC`, `IO`, …). |
| `evidence` | string | no | Pointer to the supporting flat-profile artifact (`path:line`). |

### `perf.profile.hypothesis_evaluated`

Emitted by the attestation sweep (ARTIFACT-1.4), one per hypothesis.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.profile.hypothesis_evaluated`. |
| `bead` | string | yes | Owning bead id. |
| `hypothesis` | string | yes | Human-readable hypothesis statement. |
| `verdict` | string | yes | `supports` \| `rejects` \| `inconclusive`. |
| `evidence` | string | yes | Path to the attestation artifact directory. |

### `perf.profile.run_complete`

Emitted exactly once per invocation, at the end.

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.profile.run_complete`. |
| `bead` | string | yes | Owning bead id. |
| `duration_sec` | float | yes | Total wall-time of the run. |
| `artifacts_written` | array<string> | yes | Paths of all artifacts emitted by the run. |
| `verdict` | string | yes | `pass` \| `fail`. |
| `fail_reasons` | array<string> | yes | Empty on pass; one entry per failure otherwise. |

### `perf.regression.diff`

Emitted by `scripts/perf/regression_gate.sh`, one per sub-bench compared, into
`regressions.jsonl`. Two shape variants share the same `event` tag:

**Nanosecond variant** (Criterion mean point-estimate comparison):

| Field | Type | Req | Meaning |
|---|---|---|---|
| `ts` | string | yes | RFC3339 UTC. |
| `event` | string | yes | Literal `perf.regression.diff`. |
| `sub_bench` | string | yes | Sub-benchmark name. |
| `baseline_ns` | int \| null | yes | Baseline mean; `null` when unavailable/unparsable. |
| `current_ns` | int \| null | yes | Current mean; `null` when unavailable/unparsable. |
| `delta_pct` | float \| null | yes | `(current − baseline)/baseline·100`; `null` when undefined. |
| `threshold_pct` | float | yes | Regression threshold in percent. |
| `verdict` | string | yes | `ok` \| `regression` \| `missing` \| `unparsable` \| `baseline_nonpositive`. |

**Startup p95 variant** (millisecond startup-microbench comparison): identical to
the above except `baseline_ns`/`current_ns` are replaced by `baseline_ms` /
`current_ms` (float \| null), and `sub_bench` is prefixed `startup_`.

## Worked example

```jsonl
{"ts":"2026-05-21T12:34:56Z","event":"perf.profile.run_start","bead":"bd-o4cbn.1.6","scenario_id":"h1_smoke","git_sha":"f883f45f…","fingerprint_hash":"…","build_profile":"bench","rustc_version":"rustc 1.97.0-nightly (…)","baseline_id":"pass1","run_id":"20260521T123456Z-h1-smoke"}
{"ts":"2026-05-21T12:35:02Z","event":"perf.profile.sample_collected","bead":"bd-o4cbn.1.4","sub_bench":"evidence_ledger_bundle","sample_count":100,"duration_sec":6.04,"iterations_per_sample":25000}
{"ts":"2026-05-21T12:35:02Z","event":"perf.profile.span_summary","bead":"bd-o4cbn.1.4","scenario_id":"h1_smoke","sub_bench":"evidence_ledger_bundle","span":"evidence_ledger_bundle","mean_ns":108542,"median_ns":107821,"p50_ns":107821,"p95_ns":112301,"p99_ns":115044,"p999_ns":118702,"std_dev_ns":2104,"cv_pct":1.94,"ci95_low_ns":108102,"ci95_high_ns":108982}
{"ts":"2026-05-21T12:40:09Z","event":"perf.regression.diff","sub_bench":"evidence_ledger_bundle","baseline_ns":225150,"current_ns":108542,"delta_pct":-51.79,"threshold_pct":5.0,"verdict":"ok"}
{"ts":"2026-05-21T12:40:10Z","event":"perf.profile.run_complete","bead":"bd-o4cbn.1.6","duration_sec":312.5,"artifacts_written":["tests/artifacts/perf/h1_smoke/<ts>/events.jsonl","tests/artifacts/perf/h1_smoke/<ts>/summary.md"],"verdict":"pass","fail_reasons":[]}
```

## Validation

A line is schema-conformant when:
1. it parses as a single JSON object,
2. its `event` is one of the catalog tags above,
3. every REQUIRED field for that tag is present with the listed type, and
4. all `_ns` fields are integers and all `_pct`/`_sec`/`_ms` fields are numbers.

Consumers (`bootstrap_ci.py`, `regression_gate.sh`) reject non-conformant lines
fail-closed rather than silently skipping them, except blank/whitespace lines
which are ignored per rule 1.
