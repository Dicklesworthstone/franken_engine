# test262 ES2020 — CI Markdown Scoreboard

> Closes audit findings **FIND-6** (`bd-k6n7w`) and **FIND-16** (`bd-7ojyd`).
>
> Pair: [`scripts/test262_markdown_scoreboard.py`](../../scripts/test262_markdown_scoreboard.py).

The release gate at
[`scripts/run_test262_es2020_gate.sh`](../../scripts/run_test262_es2020_gate.sh)
emits a three-tier JSON artifact bundle per run:

| Tier | Path inside `<run_dir>` | Purpose |
| --- | --- | --- |
| Gate | `run_manifest.json` (v2 schema, bash-emitted) | Outcome + step log + fingerprints + pointers |
| Runner | `test262_runner/<run_id>/run_manifest.json` | Per-run pass/fail/waived counts + hashes |
| HWM | `test262_runner/<run_id>/test262_hwm.json` | High-water-mark snapshot |

These artifacts are reviewable by humans only with `jq` incantations.
The audit (FIND-6 / FIND-16) called out that CI never converts them
into a Markdown scoreboard that reviewers can glance at in a PR
comment or attached artifact.

## What landed

`scripts/test262_markdown_scoreboard.py` reads the v2 gate manifest,
follows its `runner_artifacts.runner_manifest` +
`runner_artifacts.canonical_high_water_mark` pointers, and emits a
single Markdown document with four sections:

1. **Summary** — gate outcome, timestamp, mode, toolchain, run id, and
   a `≥ 0.95` promotion-threshold verdict.
2. **Counts** — `total / passed / failed / waived / timed_out / crashed
   / blocked_failures` + the derived **pass rate**, plus the runner's
   own `pass_regression_warning` field when present.
3. **Fingerprints** — `profile_hash`, `waiver_hash`, `pin_hash`,
   `env_fingerprint`. The script flags HWM `profile_hash` drift inline
   when the high-water-mark snapshot doesn't match the current run's
   `profile_hash` (a strong signal that either the profile changed and
   the HWM is stale, or that the HWM loader picked the wrong snapshot).
4. **Cross-references** — back to the spec-pin / coverage /
   traceability docs so the reviewer can drill in.

## Usage

```bash
python3 scripts/test262_markdown_scoreboard.py \
    --gate-manifest artifacts/test262_es2020_gate/<timestamp>/run_manifest.json \
    --output       artifacts/test262_es2020_gate/<timestamp>/SCOREBOARD.md \
    --update-symlink
```

- `--output -` (the default) writes to stdout, suitable for piping
  into a PR comment.
- `--output <path>` writes the file and (with `--update-symlink`)
  refreshes `<artifact-root>/latest_SCOREBOARD.md` to point at the new
  scoreboard, which is the file CI should upload as the readable
  artifact.
- The script exits non-zero when the gate `outcome` is `blocked`,
  which can be chained into CI's failure path.
- Only the Python standard library is required — runs on any
  `python3`.

### Failure-mode behaviour

| Symptom | Script behaviour |
| --- | --- |
| Gate manifest missing | exit 1, error to stderr |
| Gate manifest malformed JSON | exit 1, error with parse offset |
| Runner manifest pointer missing | warning to stderr, scoreboard zero-fills counts (still emits Markdown so reviewers see the gate metadata at least) |
| HWM pointer missing | scoreboard omits HWM section quietly |
| HWM `profile_hash` ≠ runner `profile_hash` | scoreboard prints an inline ⚠ drift note |
| Gate `outcome == "blocked"` | scoreboard emits normally, then script exits 1 |

## Wiring into CI (not landed by this commit)

The script is **not** invoked by `scripts/run_test262_es2020_gate.sh`
in this commit — that script is touched by every conformance-gate run
in flight and editing it risks colliding with active gate work. The
intended hook is a tail step that runs after `write_manifest`:

```bash
python3 scripts/test262_markdown_scoreboard.py \
    --gate-manifest "$manifest_path" \
    --output "${run_dir}/SCOREBOARD.md" \
    --update-symlink || true
```

`|| true` keeps a scoreboard-render failure from blocking the gate
itself — the scoreboard is downstream observability, not enforcement.

A follow-up bead should land the wiring + an `actions/upload-artifact`
step (or equivalent) that surfaces `latest_SCOREBOARD.md` in the CI
job summary. That follow-up may collapse into FIND-20
(`bd-13rib` — full compliance-report generator) once that bead picks
up the underlying schema.

## Cross-references

- Audit epic: `bd-85qfs`.
- Spec target: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md).
- Aggregate coverage: [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md).
- Per-clause traceability:
  [`docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md).
- Gate script: [`scripts/run_test262_es2020_gate.sh`](../../scripts/run_test262_es2020_gate.sh).
- Follow-up — full compliance-report generator: `bd-13rib` (FIND-20).
