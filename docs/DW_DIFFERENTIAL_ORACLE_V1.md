# Differential Oracle — Test+Verify Capstone (E2.TEST)

> Operator companion for `scripts/run_dw_differential_oracle.sh`.
> Machine-readable contract: [`docs/dw_differential_oracle_v1.json`](./dw_differential_oracle_v1.json).
> Owning bead: `bd-fqlfw.2.8` (E2.TEST, CONSENSUS #1).

The differential oracle runs the same JavaScript program through multiple
backends — the native `franken-engine` lane, the extracted `franken-core` lane,
and (when present) reference runtimes Node and Bun — then canonicalizes each
backend's observable result and classifies any disagreement. This gate is the
**test + verify capstone** for that subsystem: it proves the oracle's
canonicalization, divergence taxonomy, case minimizer, content-addressed bundle,
degraded fail-closed path, and the FE-CLAIM-010 Node/Bun denominator posture all
hold, and it persists a real, re-verifiable oracle bundle for inspection.

## Running the gate

```bash
# Full capstone: verification test suite + a live franken+core corpus.
./scripts/run_dw_differential_oracle.sh ci

# Just the test suite (no live corpus) or just the live corpus:
./scripts/run_dw_differential_oracle.sh test
./scripts/run_dw_differential_oracle.sh corpus

# Compile-only smoke.
./scripts/run_dw_differential_oracle.sh check
```

Heavy Cargo work routes through `rch` by default. When `rch` workers are
unavailable, set `DW_RUN_LOCAL=1` to build locally; the gate emits the same
content-addressed bundle either way. The live corpus uses the first available
`frankenctl` binary (`$DW_FRANKENCTL_BIN`, then `target/release/frankenctl`, then
`target/debug/frankenctl`); if none is present the corpus step is recorded as
`skip` (the test steps already exercise the CLI path) — never a silent pass.

Each run writes an audit bundle under `artifacts/dw_differential_oracle/<ts>/`
(`run_manifest.json`, `events.jsonl`, `commands.txt`, `steps/`, and a live
`oracle_corpus/` directory). Re-verify it byte-identically with:

```bash
./scripts/e2e/dw_differential_oracle_replay.sh bundle            # latest
./scripts/e2e/dw_differential_oracle_replay.sh bundle <run_dir>  # explicit
```

The replay wrapper checks the recorded `commands.txt` / `events.jsonl` sha256
against fresh hashes and, when a `frankenctl` binary is available, re-runs
`frankenctl oracle report` on every persisted `oracle_corpus/<case>/` bundle to
recompute its content-addressed manifest sha256.

## Producing and reading an oracle bundle

```bash
# Run a single case across the two hermetic in-process lanes.
frankenctl oracle run ./case.js --engines franken,core --bundle ./out --json

# Re-verify the preserved bundle (byte-identical integrity + verdict).
frankenctl oracle report ./out --json
```

A bundle directory contains:

| File | What it carries |
|---|---|
| `manifest.json` | `franken-engine.oracle-run-bundle.v1`: case id, source sha256, semantic verdict, divergence count, degraded flag, selected backends, host facts, sha256-indexed artifacts, and a content-addressed `bundle_id`. |
| `report.json` | the full `DifferentialOracleReport`: per-backend receipts (status, value, stdout/stderr hashes, timing), the canonicalization report, and the divergence taxonomy report. sha256-addressed by the manifest. |
| `repro.lock` | `franken-engine.repro-lock.v1`: the re-run command and the **determinism contract**. The reproducible assertion is the *semantic verdict* over canonical structured values and exception classes — **not** raw wall-clock timing. |
| `degraded_receipt.json` | present only when a requested reference runtime was unavailable (see *Degraded path*). |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | consensus — all applicable lanes agree on the semantic verdict |
| `2` | io / usage error |
| `3` | divergence — a classified semantic divergence was found |
| `4` | insufficient-data or degraded — fewer than two applicable lanes reached a comparable verdict, or a requested reference runtime was unavailable |

> Note: a `consensus` verdict can still report a non-zero `divergence_count`.
> Cosmetic, non-semantic differences (e.g. a lane that renders a console stream
> while another reports the completion value) are recorded as findings but do not
> change the semantic verdict. Always read `semantic_verdict` / `exit_code`, not
> the raw finding count.

## The divergence taxonomy

Every classified divergence is tagged with exactly one class. The seven classes
are a published contract (the capstone fails if the enum drifts from this list):

| Class | Meaning |
|---|---|
| `parser` | the lanes disagree at the parse stage. |
| `lowering` | the lanes parse identically but lower to different executable IR. |
| `runtime` | both lanes complete but produce different structured values or exception classes. |
| `module_resolution` | the lanes resolve an import/module specifier differently. |
| `hostcall_policy` | the lanes apply different capability/hostcall policy on the same edge. |
| `intentional_security_divergence` | FrankenEngine deliberately diverges from a reference runtime to enforce a security boundary. Carries a `waiver_id`; **not a defect**. |
| `reference_runtime_bug` | the FrankenEngine lanes agree and the reference runtime (Node/Bun) is the outlier. Attributed to the reference, not the engine. |

To read a divergence: find the finding's `class`, its `message`, the
`affected_backends` vs `reference_backends`, the `evidence_group_hashes` (which
canonical observation groups disagreed), the `remediation_hint`, and — for an
`intentional_security_divergence` — the `waiver_id`.

## The engine↔core free internal oracle

The `franken-engine` ↔ `franken-core` pair is an *internal twin*: two independent
implementations of the same semantics. Running a corpus through them is a free
bug-finder — any classified divergence is a real defect in one of the two lanes.
The harness reports each defect with a **minimized reproducer** (delta-debugging
that accepts a reduction only when the classification is byte-identical, so it
never minimizes the divergence class away), and the capstone independently
re-runs each minimized reproducer to confirm it reproduces the same signature.

```bash
# (library surface) run the seed corpus through the internal twin oracle:
#   run_engine_core_differential_oracle(default_engine_core_corpus(), 256)
```

## Degraded path (denominator unavailable)

When you request a reference runtime that is not installed (e.g. Node on a host
without it), the oracle does **not** silently drop the lane and claim consensus.
It marks the run degraded, exits non-zero (`4`), and writes a
`degraded_receipt.json`:

```bash
frankenctl oracle run ./case.js --engines franken,node \
  --node-bin /path/that/does/not/exist --bundle ./out --json
# exit 4; ./out/degraded_receipt.json error_code = FE-REPRO-0007
```

A degraded run means *we don't know* whether the engine agrees with the
reference — distinct from *we know it diverges*. Both are evidence states; the
gate refuses to conflate them.

## Node/Bun denominator and FE-CLAIM-010

The cross-runtime throughput claim (`FE-CLAIM-010`, ">= 3x weighted-geometric-mean
throughput versus Node and Bun") is **TARGETED**, not observed. A measured,
fairness-compliant denominator is linked at
[`docs/perf/e2_denominator_bundle_v1`](./perf/e2_denominator_bundle_v1) (with a
`repro.lock` partner). On that corpus the native baseline interpreter's geomean
throughput is **920 millionths of Node and 791 millionths of Bun** (~1087× /
~1264× slower) — `meets_3x_floor = false`. The claim therefore stays TARGETED,
backed by a measured, repro.lock-addressed denominator rather than absence of
data. Promotion to OBSERVED requires the engine to actually clear the 3× floor.
The denominator is separately gated by
`scripts/run_e2_denominator_bundle_gate.sh ci`.

The oracle will not fabricate a denominator: a single-lane run cannot reach a
cross-runtime verdict and reports `insufficient_data` (exit 4), and the
claim-to-proof matrix rejects simulated (`hot_paths_simulation`) or mock
(`MockCertificate`) evidence as backing for the claim.

## Reproducing a result from `repro.lock`

```bash
# 1. read the recipe
jq . ./out/repro.lock
# 2. re-run the recorded command against the same source
frankenctl oracle run ./case.js --engines franken,core --bundle ./out2
# 3. assert the reproducible semantic verdict matches
frankenctl oracle report ./out2 --json | jq .semantic_verdict
```

The semantic verdict is deterministic in the (source, selected backends) pair;
per-backend wall-clock timing is not, which is why `repro.lock` pins the verdict
and not the timing.
