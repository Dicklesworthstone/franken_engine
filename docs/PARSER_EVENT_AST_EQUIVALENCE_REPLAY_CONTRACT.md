# Parser Event->AST Equivalence and Deterministic Replay Contract (`bd-2mds.1.4.4`)

This contract defines the core equivalence harness between parser event-stream
semantics and materialized AST semantics, plus deterministic replay requirements
for failure classes consumed by downstream parser quality lanes.

## Scope

This lane is implemented by:

- `docs/PARSER_EVENT_AST_EQUIVALENCE_REPLAY_CONTRACT.md`
- `crates/franken-engine/tests/fixtures/parser_event_ast_equivalence_v1.json`
- `crates/franken-engine/tests/parser_event_ast_equivalence.rs`
- `scripts/run_parser_event_ast_equivalence.sh`
- `scripts/e2e/parser_event_ast_equivalence_replay.sh`

## Contract Version

- `schema_version`: `franken-engine.parser-event-ast-equivalence.v1`
- `contract_version`: `1.0.0`

## Core Equivalence Contract

For every success case:

1. Parse with `parse_with_event_ir` to produce canonical parse result and Event IR.
2. Materialize AST from the Event IR via `materialize_from_source`.
3. Require deterministic parity:
   - materialized AST canonical hash equals parser AST canonical hash
   - materialized statement-node count equals expected statement count
4. Require witness stability across reruns:
   - Event IR canonical hash is stable for identical input/goal
   - materialized root node id and statement-node witnesses are stable

## Failure Contract and Taxonomy

Required deterministic failure classes in this core phase:

- parse failure with empty source: `empty_source`
- materialization failure from failed event stream: `parse_failed_event_stream`
- tamper-detection failure for statement payload hash: `statement_hash_mismatch`

Every failure path must produce a replayable command contract and stable error
classification.

## Structured Log Contract

Required event keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

## Deterministic Replay Contract

One-command replay wrapper:

```bash
./scripts/e2e/parser_event_ast_equivalence_replay.sh
./scripts/e2e/parser_event_ast_equivalence_replay.sh full
./scripts/e2e/parser_event_ast_equivalence_replay.sh matrix
```

Scenario-specific replay commands (all deterministic):

```bash
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=parity ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=malformed ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=tamper ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=replay ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=full ./scripts/run_parser_event_ast_equivalence.sh test
PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=matrix ./scripts/run_parser_event_ast_equivalence.sh test
```

Matrix scenario (`bd-2mds.1.4.4.2`) enforces deterministic coverage metadata:
- corpus tiers: `core`, `edge`, `adversarial`
- seed sweep: `17`, `43`, `101`
- cross-architecture targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`

## Deterministic Execution Contract

All heavy Rust checks/tests for this lane run via `rch`.

Fail-closed wrapper requirements:
- reject any `rch` local-fallback path (`running locally`, `RCH-E326`, or
  equivalent fallback markers)
- reject missing remote exit markers and explicit non-zero remote exit markers
- reject artifact-retrieval failures (`Artifact retrieval failed`, rsync
  artifact errors)
- allow recovery only when the remote command explicitly finished with
  `exit=0` and the only follow-on problem is a recoverable artifact timeout

Canonical gate command:

```bash
./scripts/run_parser_event_ast_equivalence.sh ci
```

Modes:

- `check`: compile focused event->AST equivalence test target
- `test`: execute scenario-focused deterministic tests
- `clippy`: lint focused target with `-D warnings`
- `ci`: check + scenario test + clippy

## Required Artifacts

Each run emits:

- `artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json`
- `artifacts/parser_event_ast_equivalence/<timestamp>/events.jsonl`
- `artifacts/parser_event_ast_equivalence/<timestamp>/commands.txt`
- `artifacts/parser_event_ast_equivalence/<timestamp>/matrix_summary.json`

The manifest includes deterministic environment fingerprints, replay command,
scenario, and pass/fail outcome.

Default manifest bead tracking uses `bd-2mds.1.4.4`. Override per run when
needed:

```bash
PARSER_EVENT_AST_EQUIVALENCE_BEAD_ID=bd-2mds.1.4.4.2 \
  PARSER_EVENT_AST_EQUIVALENCE_SCENARIO=parity \
  ./scripts/run_parser_event_ast_equivalence.sh test
```

## Operator Verification

```bash
./scripts/run_parser_event_ast_equivalence.sh ci
cat artifacts/parser_event_ast_equivalence/<timestamp>/run_manifest.json
cat artifacts/parser_event_ast_equivalence/<timestamp>/events.jsonl
cat artifacts/parser_event_ast_equivalence/<timestamp>/commands.txt
cat artifacts/parser_event_ast_equivalence/<timestamp>/matrix_summary.json
./scripts/e2e/parser_event_ast_equivalence_replay.sh
./scripts/e2e/parser_event_ast_equivalence_replay.sh full
./scripts/e2e/parser_event_ast_equivalence_replay.sh matrix
```
