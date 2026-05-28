# ECMA-262 ES2020 — Compliance Report Generator

> Closes audit finding **FIND-20** (`bd-13rib`).
>
> Pair: [`scripts/test262_compliance_report.py`](../../scripts/test262_compliance_report.py).
>
> Companion / earlier scope: [`docs/conformance/CI_SCOREBOARD.md`](./CI_SCOREBOARD.md)
> (`bd-k6n7w` + `bd-7ojyd`, FIND-6/16) renders a per-run scoreboard;
> this report renders the cross-harness compliance matrix.

The audit (`bd-85qfs`) flagged that every coverage-, scoreboard-, and
matrix-promotion gap downstream of it depended on **one** missing
artefact: a single tool that consumes the harness sources + the gate
artefacts and emits a load-bearing compliance matrix. This document
records the script that fills that gap and the schema of its outputs.

## What landed

`scripts/test262_compliance_report.py` is a pure-stdlib Python script
that:

1. Reads every `tests/*_test262_conformance.rs` file under the
   provided `--tests-root` and extracts every tagged test case (any of
   `es_section` / `es2020_section` / `spec_section` — see FIND-12
   `bd-cd0px` for why those three names exist).
2. Optionally folds in `--gate-manifest <path>` from a
   `scripts/run_test262_es2020_gate.sh` v2 run manifest so the latest
   gate run's pass/total/outcome lands in the Summary section.
3. Emits Markdown to `--output <path>` (or stdout, the default).
4. Optionally emits a machine-readable JSON sidecar at `--json <path>`
   for matrix-promotion gates, CI badges, and downstream consumers.

## Output shape

The Markdown report carries four sections:

| Section | Contents |
| --- | --- |
| Headline counts | harness count, distinct §-section count, total tagged cases, MUST / SHOULD / unresolved tier breakdown |
| Latest gate run (when `--gate-manifest` is supplied) | outcome, passed/total, pass rate, 0.95-threshold verdict |
| Per-harness summary | each harness → field-name variant + tagged case count |
| §-section → covering harness/test ids | the load-bearing compliance matrix: every section the engine claims to cover, every harness that anchors it, every test id |

The JSON sidecar exposes the same data as a `{headline counts, section_index,
per_harness_*}` shape; matrix-promotion gates should consume the JSON
rather than re-parse the Markdown.

## Usage

```bash
# Renderable preview to stdout:
python3 scripts/test262_compliance_report.py

# Markdown + JSON sidecar (for CI artefact upload):
python3 scripts/test262_compliance_report.py \
    --tests-root crates/franken-engine/tests \
    --output docs/conformance/COMPLIANCE_REPORT_LATEST.md \
    --json   artifacts/test262_compliance_report.json

# Folded with a gate run summary:
python3 scripts/test262_compliance_report.py \
    --gate-manifest artifacts/test262_es2020_gate/<timestamp>/run_manifest.json \
    --output       artifacts/test262_es2020_gate/<timestamp>/COMPLIANCE_REPORT.md
```

The script requires only `python3` + the standard library — no
external deps, runs anywhere CI can invoke `python3`.

## Failure-mode behaviour

| Symptom | Script behaviour |
| --- | --- |
| `--tests-root` missing / not a directory | exit 1 with clear error |
| Tagged case has `id:` outside the 400-char extractor window | falls back to the section row marker `(no resolved ids)`; the section is still counted |
| Case has a §-section tag but no `requirement_level` | counted under "unresolved-level"; surfaced as `?` in the breakdown column (FIND-12 cross-cut) |
| `--gate-manifest` missing | exit 1 with the gate's path in the error message |
| `--gate-manifest` malformed JSON | exit 1 with parse offset |
| `runner_artifacts.runner_manifest` pointer dangles | runner counts default to zero; Summary section still emits (the gate row is best-effort) |

## Relationship to the other conformance docs

This is the **machine-driven, regenerate-on-every-run** counterpart to
the hand-maintained matrices that closed FIND-2 (`bd-p1n62`) and
FIND-13 + FIND-25 (`bd-04uo3` + `bd-euwqz`). Until this script lands,
the matrices in [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md)
and [`docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md)
explicitly note they are "hand-extracted until FIND-20 ships". With
FIND-20 now closed, those hand-maintained matrices should be diffed
against this script's JSON output on every PR that touches a harness;
a diff is a stale-doc bug to file.

The per-run scoreboard
([`docs/conformance/CI_SCOREBOARD.md`](./CI_SCOREBOARD.md)) and this
report are intentionally split: the scoreboard speaks for one gate run
(pass / fail / outcome counts), this report speaks for the **whole
engine's** compliance shape (the §-section coverage matrix +
per-harness ownership). A reviewer needs both: the scoreboard to know
"did this PR break a test", this report to know "what does the engine
claim to cover".

## Cross-references

- Audit epic: `bd-85qfs` — Conformance test harness audit.
- Companion script: `scripts/test262_markdown_scoreboard.py` (FIND-6/16).
- Spec pin: [`docs/ECMA262_CONFORMANCE_TARGET.md`](../ECMA262_CONFORMANCE_TARGET.md).
- Hand matrices that this script supersedes for live runs:
  [`docs/conformance/ECMA262_COVERAGE.md`](./ECMA262_COVERAGE.md),
  [`docs/conformance/SPEC_TO_TEST_TRACEABILITY.md`](./SPEC_TO_TEST_TRACEABILITY.md),
  [`docs/conformance/SHOULD_COVERAGE.md`](./SHOULD_COVERAGE.md).
- Field-name drift tracking: `bd-cd0px` (FIND-12).
- Round-trip oracle the per-harness `report` types will consume:
  `bd-wrmld` (FIND-22).
