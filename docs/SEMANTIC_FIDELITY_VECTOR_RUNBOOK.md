# Semantic Fidelity Vector Runbook

Status: operator and contributor runbook for `bd-mihky.9`

This runbook explains how to add, validate, interpret, and triage semantic
fidelity vectors for builtin and error-class behavior. It is scoped to the
`bd-mihky` workbench and does not make a general ECMAScript conformance claim.

Related references:

- Inventory: `docs/SEMANTIC_FIDELITY_WORKBENCH_INVENTORY.md`
- Fixture schema: `docs/SEMANTIC_FIDELITY_VECTOR_SCHEMA_V1.md`
- Machine-readable schema: `docs/semantic_fidelity_vector_schema_v1.json`
- Runner: `scripts/semantic_fidelity_workbench.py`
- Gate wrapper: `scripts/run_semantic_fidelity_workbench.sh`
- Replay wrapper: `scripts/e2e/semantic_fidelity_workbench_replay.sh`
- Smoke harness: `scripts/e2e/semantic_fidelity_workbench_smoke.sh`

## Rules From AGENTS.md

Follow the repository agent rules before changing vectors or runner code:

- Do not delete files or directories without explicit written user permission.
- Do not run destructive Git or filesystem commands.
- Do not strengthen README or PLAN claim language from fixture evidence alone.
- Do not import Node, Bun, V8, QuickJS, or binding-led runtimes into core
  execution.
- Do not run local Cargo for this lane. If a future semantic-fidelity change
  requires Cargo, run it through `rch` with a unique `CARGO_TARGET_DIR`.

Build-free Python, shell, `jq`, and replay checks may run locally. Cargo-heavy
checks must be remote-only through `rch`.

## Vector Naming

Use stable, searchable IDs:

```text
semfid-<surface>-<operation>-<case>
```

Examples:

- `semfid-string-repeat-negative-count-range-error`
- `semfid-string-repeat-fractional-count-tointeger`
- `semfid-classification-03-degraded-missing-runtime`
- `semfid-malformed-source-hash-repeat-negative`

Keep `semantic_family` broad enough for route grouping but narrow enough to
avoid unrelated behavior in one bucket. Current useful families include:

- `string_repeat_range`
- `string_from_code_point_range`
- `string_from_char_code_touint16`
- `number_digits_range`
- `array_length_range`
- `string_index_tointeger`
- `runner_classification`

## Fixture Authoring Flow

1. Pick the observable behavior.
2. Pick the route under test.
3. Add the vector to a suite under `scripts/testdata/semantic_fidelity_workbench/`.
4. Compute `source_sha256`, `route_metadata_sha256`, and `expectation_sha256`
   using the runner's length-prefixed hash function.
5. Add provenance links to existing tests, docs, or beads.
6. Add remediation metadata:
   - `existing_bead_refs` when a known bead owns the failure.
   - `suggested_next_action: "propose_followup_bead"` when no existing bead is known.
   - `suggested_next_action: "record_degraded_oracle"` for optional missing oracles.
7. Run the smoke command in this runbook.

Do not use placeholder hashes in real fixtures. The documentation example in
`SEMANTIC_FIDELITY_VECTOR_SCHEMA_V1.md` uses zero hashes only to show shape.

## Route Kinds

Use `source_eval` for FrankenEngine source-string routes and `node_oracle` or
`bun_oracle` for external oracle subprocesses. External runtimes are reference
oracles only; they are not core execution paths.

If a route cannot run yet, use `expected_unknown` or `unsupported` and preserve
the route metadata. Do not mark it as passed. The workbench records these as
declared non-execution, and auto-triage classifies them separately from
confirmed failures.

## Examples

### RangeError Vector

`scripts/testdata/semantic_fidelity_workbench/rangeerror_tointeger_suite.json`
contains RangeError vectors such as:

```text
semfid-string-repeat-negative-count-range-error
```

Expected shape:

- `semantic_family`: `string_repeat_range`
- `route_kind`: `node_oracle`
- `expectation.kind`: `js_error`
- `expectation.error_class`: `RangeError`
- remediation links to `bd-xulus` or the owning semantic-fidelity bead

If the route returns a normal value or the wrong error class, the runner emits
`fail_closed` with `expected_error_class_mismatch`.

### Normal Value Vector

The same suite includes normal-value checks such as:

```text
semfid-string-repeat-fractional-count-tointeger
```

Expected shape:

- `expectation.kind`: `normal`
- `expectation.value`: exact stringified result, for example `xx`
- failure code: `expected_value_mismatch`

Use normal-value vectors for ToIntegerOrInfinity and wrapping behavior. Keep
stringification explicit because the runner records `actual_outcome.value` as
a string for deterministic JSON comparison.

### Degraded External Oracle Vector

`scripts/testdata/semantic_fidelity_workbench/classification_suite.json`
contains:

```text
semfid-classification-03-degraded-missing-runtime
```

This vector names an external runtime that is intentionally absent. The runner
must not treat the missing runtime as pass or as a semantic failure. It emits:

- `outcome`: `degraded`
- `reason_codes`: `external_oracle_unavailable`
- `evidence_classification`: `degraded_external_oracle`
- auto-triage action: `record_degraded_oracle`

Use this pattern when an optional oracle is unavailable but the bundle still
needs an auditable receipt.

### Malformed Fixture

`scripts/testdata/semantic_fidelity_workbench/malformed_hash_suite.json`
contains a source-hash mismatch. It must fail closed before vector execution:

- `decision`: `fail_closed`
- `validation_errors[0].code`: `source_hash_mismatch`
- `vector_results.jsonl`: empty
- replay wrapper: nonzero

Use malformed fixtures only for validator tests. They are not evidence for JS
behavior.

## Running The Workbench

Build-free smoke:

```bash
scripts/run_semantic_fidelity_workbench.sh smoke selftest /tmp/franken-engine-semantic-fidelity-runbook-smoke
```

Run a specific suite:

```bash
SEMANTIC_FIDELITY_NOW_UTC=2030-01-01T00:00:00Z \
SEMANTIC_FIDELITY_SUITE=scripts/testdata/semantic_fidelity_workbench/rangeerror_tointeger_suite.json \
  scripts/run_semantic_fidelity_workbench.sh ci /tmp/franken-engine-semantic-fidelity-rangeerror
```

Replay a preserved complete bundle:

```bash
scripts/e2e/semantic_fidelity_workbench_replay.sh /tmp/franken-engine-semantic-fidelity-rangeerror
```

Run JSON/static checks:

```bash
jq empty docs/semantic_fidelity_vector_schema_v1.json scripts/testdata/semantic_fidelity_workbench/*.json
bash -n scripts/run_semantic_fidelity_workbench.sh scripts/e2e/semantic_fidelity_workbench_replay.sh scripts/e2e/semantic_fidelity_workbench_smoke.sh
python3 -m py_compile scripts/semantic_fidelity_workbench.py
python3 scripts/semantic_fidelity_workbench.py --self-test
```

If a future vector requires Rust execution proof, use `rch`, for example:

```bash
RCH_REQUIRE_REMOTE=1 rch diagnose --dry-run --json -- \
  env CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=/tmp/rch_target_semfid_<bead> \
  cargo test -p frankenengine-engine --test <test_target> -- --nocapture
```

Only run the actual `rch exec` command after the dry-run admits remote
execution. Do not run the Cargo command locally.

## Interpreting Artifacts

Each accepted run emits:

- `run_manifest.json`: suite identity, decision, artifact paths, command
- `events.jsonl`: structured run and vector events
- `vector_results.jsonl`: one structured row per executed or declared vector
- `path_parity_report.json`: builtin/family/route grouping and route
  disagreement by source hash
- `auto_triage_report.json`: existing-bead links, suggested bead text, and
  unsupported/degraded classification
- `commands.txt`: exact runner command
- `summary.md`: human-readable summary

`path_parity_report.json` is source-hash scoped. It flags route disagreement
only when two routes for the same source hash produce different observations.
Different inputs in the same semantic family do not count as route disagreement.

`auto_triage_report.json` is advisory. It never creates, closes, or updates
beads by itself.

## Converting A Failure Into A Bead

For a confirmed failure:

1. Open `auto_triage_report.json`.
2. Find the entry with `triage_classification == "confirmed_failure"`.
3. If `triage_action == "link_existing_bead"`, update or comment on the named
   bead instead of creating a duplicate.
4. If `triage_action == "suggest_new_bead"`, use the suggested title and
   description as the bead draft.
5. Preserve the validation commands from `validation_commands`.
6. Mark unsupported or degraded surfaces honestly; do not turn them into
   confirmed semantic failures.

Suggested bead text must include:

- background
- route
- vector ID
- expected result
- actual result
- first divergence
- exact validation command

## Relationship To E7, YTBG, And bd-xulus

This workbench feeds route-aware evidence into larger tracks:

- E7 (`bd-fqlfw.7`) owns the broader conformance frontier. Semantic-fidelity
  vectors provide small builtin/error-class evidence for that frontier.
- YTBG (`bd-8enww.*`) owns BotGuard and error-object/catchability needs.
  Link YTBG when a vector proves TypeError/RangeError identity or catchability
  gaps relevant to that track.
- `bd-xulus` owns the current error-class fidelity vein. Link it when a vector
  falls into the known RangeError/ToIntegerOrInfinity drift family.

Do not duplicate these tracks. Add a new bead only when auto-triage cannot link
the failure to an existing owner.

## Closeout Checklist

Before closing a semantic-fidelity vector bead:

1. Run the smoke command copied above.
2. Run the JSON/static checks copied above.
3. Run `git diff --check` on touched docs, scripts, and fixtures.
4. If Cargo was needed, include the exact `rch diagnose` and `rch exec`
   commands and first blocker or final verdict.
5. Close the bead with the proof commands.
6. Send Agent Mail with the changed surfaces and validation results.
