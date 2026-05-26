# RUNBOOK — Re-profile FrankenEngine (Phase-1 perf protocol)

> **Bead:** PERF-INFRA.7 (`bd-o4cbn.8.7`), parent `bd-o4cbn.8` (PERF-INFRA).
> **Goal:** let any future agent re-run the full Phase-1 profiling +
> regression-gate protocol **from this file alone**, with no prior session
> notes. Every command below is copy-pasteable.

This runbook documents the *measurement* protocol that produced the frozen
**pass1** baseline (`tests/artifacts/perf/20260520T214829Z-prof-pass1/`) and how
to reproduce it, diff against it, and promote or reject the result. It does **not**
do optimization work — that is the `extreme-software-optimization` skill, handed
off from the `profiling-software-performance` skill (see §2).

---

## 0. TL;DR (the happy path)

```bash
cd /data/projects/franken_engine

# 0a. Pick a run id and create the artifact dir.
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-reprofile"
RUN_DIR="tests/artifacts/perf/${RUN_ID}"
mkdir -p "$RUN_DIR"

# 0b. (Optional) raise the one approved kernel knob; record + arrange revert.
#     See §3. Skip if you cannot sudo — the pass1 host needed only this.
#     sudo sysctl -w kernel.perf_event_mlock_kb=32768

# 0c. Build the bench locally (bypass rch), pass1 flags. See §4.
RCH_CARGO_WRAPPER_BYPASS=1 \
RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
CARGO_INCREMENTAL=0 \
/home/ubuntu/.cargo/bin/cargo bench --bench hot_paths --no-run

# 0d. Run the Criterion group, diffing against the frozen pass1 baseline. See §5.
HOT="$(ls target/release/deps/hot_paths-* | grep -v '\.d$' | sort | tail -1)"
"$HOT" --bench --baseline pass1 real_runtime_hot_paths | tee "$RUN_DIR/bench_output.txt"

# 0e. Gate against a frozen baseline (fails closed on regression). See §6.
scripts/perf/regression_gate.sh \
    --baseline tests/artifacts/perf/baselines/<anchor-git-sha>/ \
    --current  target/criterion/real_runtime_hot_paths/ \
    --threshold-pct 5 \
    --out "$RUN_DIR/regressions/"

# 0f. If a real win cleared all five gate criteria (§7), update the baseline doc
#     and (optionally) freeze a new baseline. See §6.2 + §7.
```

---

## 1. When to re-profile

Re-profile when any of these is true:

1. **After an `H[N]` or `ALIEN-N` optimization lands** (`bd-o4cbn.*`) — confirm
   the claimed speedup on committed artifacts before promoting it in
   `docs/PERFORMANCE_BASELINE.md`.
2. **On a disputed perf claim** — someone asserts a speedup/regression without a
   reproducible bundle. Re-profile to settle it with numbers.
3. **On a suspected regression** — e.g. the no-regression gate (criterion 4 of
   "what counts as a perf win") trips, or a sub-bench drifts. Example: the open
   `baseline_value_string_clone +15.93%` regression (`bd-o4cbn.15`) was caught
   this way during H6.4 E2E and must be **bisected** between pass1
   (2026-05-20) and HEAD with a focused re-profile.
4. **Before promoting a "win"** to `PERFORMANCE_BASELINE.md` — the 5-criteria
   gate in §7 requires fresh measured evidence.

**One lever per run.** When confirming an optimization, change exactly one thing
between the "before" and "after" runs; otherwise attribution is impossible.

---

## 2. Invoke the profiling skill (what produced pass1)

pass1 was produced by applying the **`profiling-software-performance`** skill
end-to-end to franken_engine as a *measurement-only* pass (no optimization). Its
seven numbered stages are preserved verbatim in
`tests/artifacts/perf/20260520T214829Z-prof-pass1/`:

| Stage | Artifact | Purpose |
|---|---|---|
| 1 | `01_DEFINE.md` | scenario, metrics, budgets, golden contract |
| 2 | `02_ENVIRONMENT.md` + `fingerprint.json` + `kernel_restore.sh` | host facts, kernel state record, **revert script** |
| 3 | `03_BASELINE.md` + `baseline_summary.json` + 8× `criterion_*_estimates.json` | per-sub-bench baseline (mean, median, std, 95% CI, CV, ops/s) |
| 4 | `04_INSTRUMENT.md` | instrumentation decision + rationale |
| 5 | `05_PROFILE_PLAN.md` + `05_PROFILE_RESULTS.md` + `perf_data/` + `samply_*.json.gz` + `peak_rss.txt` | CPU profiles (`perf record -F 4000 --call-graph fp`, samply) |
| 6 | `06_HOTSPOT_TABLE.md` + `06_HYPOTHESIS_LEDGER.md` | ranked top-10 hotspots (file:line) + hypothesis ledger |
| 7 | `07_HANDOFF.md` | hand-off contract to `extreme-software-optimization` |

To re-run the full skill, in a Claude Code session at the project root:

```
/profiling-software-performance
```

Then follow the skill's stage prompts. Tell it: **measurement-only**, target
bench `hot_paths` (group `real_runtime_hot_paths`), persist stage artifacts under
`tests/artifacts/perf/<run-id>/` (§5), and reuse the build/env discipline in §3–§4
(it must build the binary **on the same host that runs it** — no rch remote build).
The skill hands off ranked hotspots to `extreme-software-optimization`; the
confirmation protocol for any candidate lever is in §6.1.

The hot-path bench lives at `crates/franken-engine/benches/hot_paths.rs`; its
Criterion group is `real_runtime_hot_paths` with 8 sub-benches:
`parser_arena_materialization`, `lowering_pipeline_ir3`,
`baseline_interpreter_eval`, `baseline_value_string_clone`,
`iterator_protocol_trace`, `scheduler_queue_commit`,
`evidence_ledger_bundle`, `transport_certificate_serialization`.

---

## 3. Kernel knobs + revert script

**Principle: zero destructive actions, zero un-reverted kernel mutations.** The
pass1 host (AMD EPYC 7282, 64 threads, kernel 6.17.0-22) was already in the
approved profiling-friendly state, so only ONE knob was changed.

| Knob | Approved value | pass1 action |
|---|---|---|
| `kernel.perf_event_paranoid` | `1` | already there → no change |
| `kernel.kptr_restrict` | `0` | already there → no change |
| `kernel.nmi_watchdog` | `0` | already there → no change |
| `kernel.perf_event_mlock_kb` | `32768` | **raised 516 → 32768** (only change) |
| `cpufreq scaling_governor` | n/a | absent on this AMD platform → treat freq variance as noise |
| `intel_pstate/no_turbo` | n/a | Intel-only → n/a |
| THP | `madvise` | not modified |

Read current state before changing anything:

```bash
for k in kernel.perf_event_paranoid kernel.kptr_restrict kernel.nmi_watchdog kernel.perf_event_mlock_kb; do
  printf '%s = %s\n' "$k" "$(sysctl -n $k 2>/dev/null)"
done
```

Apply the one knob (needs sudo; skip if unavailable — `perf record` will still
work, just with a smaller mlock budget):

```bash
sudo sysctl -w kernel.perf_event_mlock_kb=32768
```

**Revert script.** pass1 wrote a `kernel_restore.sh` recording the prior value;
re-generate one for your run and run it when finished:

```bash
cat > "$RUN_DIR/kernel_restore.sh" <<EOF
#!/usr/bin/env bash
# Revert kernel knobs touched during $RUN_ID back to pre-run values.
set -euo pipefail
sudo sysctl -w kernel.perf_event_mlock_kb=$(sysctl -n kernel.perf_event_mlock_kb)
EOF
chmod +x "$RUN_DIR/kernel_restore.sh"
# ... run the profile ...
# "$RUN_DIR/kernel_restore.sh"   # when done
```

**No CPU pinning / isolcpus / cgroup** was used (the box is otherwise idle and
boot-flag changes were not approved). If you need tighter variance and have
approval, `taskset -c <cpus>` the bench process; document it in your run's
`02_ENVIRONMENT.md` so the comparison surface stays apples-to-apples.

---

## 4. Bypass the rch wrapper (build locally)

The project ships a shell wrapper at `/home/ubuntu/.local/bin/cargo` that
auto-routes `cargo build|check|test|clippy|bench` through `rch exec` onto remote
build workers when invoked from the project root. **For a measurement pass you
MUST build on the same host that runs the bench** — remote-built artifacts time
differently and the rch pipeline can be `degraded`/slow.

Bypass it two ways together (belt and suspenders):

1. `RCH_CARGO_WRAPPER_BYPASS=1` — tells the wrapper to run locally.
2. Call cargo by **absolute path** `/home/ubuntu/.cargo/bin/cargo` — sidesteps
   the `~/.local/bin/cargo` shim on `$PATH` entirely.

The exact pass1 build command (recorded for replay):

```bash
RCH_CARGO_WRAPPER_BYPASS=1 \
RUSTFLAGS="-C force-frame-pointers=yes -C linker=cc" \
CARGO_INCREMENTAL=0 \
/home/ubuntu/.cargo/bin/cargo bench --bench hot_paths --no-run
```

Why each flag:

- `-C force-frame-pointers=yes` — frame pointers are the default unwind path for
  `perf record --call-graph fp` (no `--call-graph dwarf` needed).
- `-C linker=cc` — works around the project's documented nightly-`lld` breakage
  (see `memory/MEMORY.md`).
- `CARGO_INCREMENTAL=0` — matches the disk-pressure mitigation; per-agent
  incremental caches otherwise balloon to 100+ GB.
- The measurement build profile (already in the workspace root `Cargo.toml`)
  keeps symbols for the profiler:

  ```toml
  [profile.bench]
  debug = "line-tables-only"   # DWARF for stack unwinding, no size blow-up
  strip = false                # symbol resolver needs RIP → fn names
  ```

---

## 5. Where to persist artifacts

```
tests/artifacts/perf/
├── baselines/<git-sha>/          # FROZEN, committed baselines (regression anchors)
│   ├── criterion_<fn>_estimates.json × 8
│   ├── baseline_summary.json
│   ├── fingerprint.json
│   └── README.md
├── <run-id>/                     # ad-hoc profiling/reprofile runs (this run)
│   ├── 01_DEFINE.md … 07_HANDOFF.md   # if running the full skill
│   ├── kernel_restore.sh
│   ├── bench_output.txt
│   ├── regressions/              # regression_gate.sh output
│   └── perf_data/                # perf record output (full skill only)
└── README.md
```

- **Run id format:** `YYYYMMDDTHHMMSSZ-<description>` (e.g.
  `20260520T214829Z-prof-pass1`). Use `date -u +%Y%m%dT%H%M%SZ`.
- Ad-hoc run dirs are working artifacts and may be GC'd; **frozen baselines under
  `baselines/<git-sha>/` are committed and retained** (keep the last 12 + always
  the current claim-matrix anchor — see `tests/artifacts/perf/README.md`).

Freeze the current Criterion run as a committed baseline:

```bash
# Requires a clean working tree at <git-sha> and a completed `cargo bench` run
# (target/criterion/ populated). Fails if the baseline already exists.
scripts/perf/freeze_baseline.sh <git-sha>
# -> writes tests/artifacts/perf/baselines/<git-sha>/{criterion_*_estimates.json,
#    baseline_summary.json, fingerprint.json, README.md}
```

---

## 6. Diff against the pinned baseline

### 6.1 Criterion in-process A/B (one lever, apples-to-apples)

Criterion stores named baselines under `target/criterion/`. The confirmation
recipe for any single optimization lever:

```bash
HOT="$(ls target/release/deps/hot_paths-* | grep -v '\.d$' | sort | tail -1)"

# 1. Save the "before" snapshot once (pass1 is already saved).
"$HOT" --bench --save-baseline pass1 real_runtime_hot_paths

# 2. Apply exactly ONE lever, rebuild (§4).

# 3. Re-run, diffing against the saved baseline; Criterion prints % change + p-value.
"$HOT" --bench --baseline pass1 real_runtime_hot_paths | tee "$RUN_DIR/bench_output.txt"
```

### 6.2 The fail-closed regression gate

`scripts/perf/regression_gate.sh` diffs a current Criterion dir against a
**frozen** baseline dir and exits non-zero if any sub-bench regresses past the
threshold:

```bash
scripts/perf/regression_gate.sh \
    --baseline tests/artifacts/perf/baselines/<anchor-git-sha>/ \
    --current  target/criterion/real_runtime_hot_paths/ \
    --threshold-pct 5 \
    --out      "$RUN_DIR/regressions/"
# Optional cold-start layer (PERF-INFRA.8):
#    --startup-current <hyperfine.json> --startup-threshold-pct 10
```

Outputs under `--out`: `regressions.jsonl` (one `perf.regression.diff` event per
sub-bench) + `regression_report.md`. **Exit codes:** `0` none regressed · `1` at
least one regressed · `2` usage/env error (missing baseline, bad args, no `jq`).

Per-`H[N]` validators wrap this same flow with the pass1 flags baked in — copy
one as a template for a new optimization:

- `scripts/perf/h1_bench_validate.sh` — H1 (default-key cache) ≥ target drop.
- `scripts/perf/h6_bench_validate.sh` — H6 (capacity hints); builds `hot_paths`
  with the §4 flags, runs the group with `--save-baseline post_h6`, diffs
  `--baseline pass1`, emits `summary.md` with a per-criterion verdict.
- `scripts/perf/honest_gate.sh` — the 14-question honest-gate walker
  (criterion 3 below); `honest_gate.sh selftest` runs build-free.

Cold-start wall-clock (outside Criterion) uses
`scripts/perf/hyperfine_ab.sh <bin_a> <bin_b> <args...>` (3 warmup + 20 sampled
runs) → `tests/artifacts/perf/hyperfine/<ts>/`, convertible via
`scripts/perf/hyperfine_to_perf_jsonl.py`.

---

## 7. Update `docs/PERFORMANCE_BASELINE.md`

A measured number is recorded as a **MEASUREMENT**; it is only promoted to a
**WIN** after all five criteria below hold on committed artifacts (the
"What counts as a perf win" gate, `bd-o4cbn.12.3`). **No partial credit.**

1. **Magnitude.** Point estimate improves by **≥ 5 %** on the target sub-bench.
2. **Confidence.** The **BCa 95 % CI** upper bound on that improvement is still
   below 0 % (i.e. the win is statistically real, not noise). Use
   `scripts/perf/bootstrap_ci.py`.
3. **Bench truthfulness.** The honest-gate score is **≥ 12 / 14**, scored by
   `scripts/perf/honest_gate.sh` (PERF-ARTIFACT-1.2), emitting an
   `attestation_v1.json` (schema `franken-engine.honest-gate-attestation.v1`).
4. **Determinism preserved.** The replay-coverage gate (PERF-H1.5,
   `bd-o4cbn.1.5`) **and** the metamorphic suite are green on a **fresh bundle**
   from the optimised build. A speedup that perturbs replay semantics or
   bit-stable canonical output is **not** a win, regardless of magnitude.
5. **Variance envelope.** Coefficient of variation `CV = std / mean` is within
   the documented envelope (pass1 reference ≈ 1.3 %; treat CV > 10 % as untrusted
   and re-run on a quieter host).

When promoting, edit `docs/PERFORMANCE_BASELINE.md`:

- Update the relevant measurement row/table with the new mean ± 95 % CI, the
  before→after delta, the run-id, and the git SHA.
- Cite the gate evidence: the honest-gate attestation path, the BCa CI, the
  replay/metamorphic green bundle, and the CV.
- If a **regression** is found instead (e.g. `bd-o4cbn.15`), record it as a
  MEASUREMENT with the failing criterion, file/keep a regression bead, and do
  **not** promote the surrounding sweep as a win until attributed and fixed.

If the new run is a clean, controlled baseline, also freeze it (§5,
`freeze_baseline.sh <git-sha>`) and update the claim-matrix anchor.

---

## 8. Quick reference (paths)

| Thing | Path |
|---|---|
| Hot-path bench | `crates/franken-engine/benches/hot_paths.rs` (group `real_runtime_hot_paths`) |
| Frozen baselines | `tests/artifacts/perf/baselines/<git-sha>/` |
| pass1 reference run | `tests/artifacts/perf/20260520T214829Z-prof-pass1/` |
| Freeze a baseline | `scripts/perf/freeze_baseline.sh <git-sha>` |
| Regression gate | `scripts/perf/regression_gate.sh` |
| Per-H validators | `scripts/perf/h1_bench_validate.sh`, `scripts/perf/h6_bench_validate.sh` |
| Honest-gate walker | `scripts/perf/honest_gate.sh` |
| Bootstrap CI | `scripts/perf/bootstrap_ci.py` |
| Cold-start A/B | `scripts/perf/hyperfine_ab.sh`, `scripts/perf/bench_startup.sh` |
| Baseline doc | `docs/PERFORMANCE_BASELINE.md` |
| Artifacts index | `tests/artifacts/perf/README.md` |
