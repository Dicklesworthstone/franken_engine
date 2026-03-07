# Metamorphic Testing (bd-1lsy.9.3)

This document defines the metamorphic test framework for parser, IR, and execution invariants.

## Relation Catalog

Source of truth: `crates/franken-metamorphic/metamorphic_relations.toml`

Catalog coverage:
- parser: whitespace, comment, parenthesization, ASI-equivalence, unicode escape equivalence, source-position independence
- IR: lowering determinism, optimization idempotence, capability preservation, dead-code insertion invariance, constant-folding equivalence
- execution: evaluation-order determinism, GC-timing independence, stack-depth independence, prototype-chain equivalence, promise-resolution order stability

Each relation carries:
- `subsystem`
- `oracle`
- `budget_pairs` (default `1000`)
- `enabled`

## Runner

Use the suite wrapper (heavy cargo paths routed through `rch`):

```bash
./scripts/run_metamorphic_suite.sh check
./scripts/run_metamorphic_suite.sh test
./scripts/run_metamorphic_suite.sh ci
./scripts/e2e/metamorphic_suite_replay.sh ci
```

`rch` is required for this runner. If `rch` is unavailable, the script fails
closed with `FE-META-RCH-0002` and still emits deterministic run artifacts
(`run_manifest.json`, `events.jsonl`, `commands.txt`) with failure metadata.

Environment overrides:
- `METAMORPHIC_PAIRS` (default `1000`, applied per enabled relation)
- `METAMORPHIC_SEED` (default `1`)
- `METAMORPHIC_RELATIONS` (optional comma-separated enabled relation IDs; example: `parser_whitespace_invariance,ir_lowering_determinism`)
- `RUSTUP_TOOLCHAIN` (default `nightly`)
- `CARGO_TARGET_DIR` (default `/tmp/rch_target_franken_engine_metamorphic`)

Relation filter semantics:
- Filters are passed as repeated `--relation` arguments to the runner.
- Duplicate relation IDs are deduplicated (first-seen order preserved).
- Unknown relation IDs fail closed even when other IDs are valid.

## Failure Minimization

When a relation diverges, the framework first shrinks recorded generator choices
when replay is supported, then applies deterministic ddmin reduction over the
resulting pair and writes:

- `metamorphic_failure_{relation}_{hash}.json`

Payload fields:
- `relation_id`
- `seed`
- `input_source`
- `variant_source`
- `expected_equivalence`
- `actual_divergence`
- `minimized`

## Artifacts

Each run writes deterministic metadata under:

- `artifacts/metamorphic/<timestamp>/run_manifest.json`
- `artifacts/metamorphic/<timestamp>/events.jsonl`
- `artifacts/metamorphic/<timestamp>/relation_events.jsonl`
- `artifacts/metamorphic/<timestamp>/metamorphic_evidence.jsonl`
- `artifacts/metamorphic/<timestamp>/seed_transcript.jsonl`
- `artifacts/metamorphic/<timestamp>/seed_manifest.json`
- `artifacts/metamorphic/<timestamp>/property_generator_catalog.json`
- `artifacts/metamorphic/<timestamp>/generator_choice_stream_schema.json`
- `artifacts/metamorphic/<timestamp>/shrinker_verdict_report.json`
- `artifacts/metamorphic/<timestamp>/minimized_property_counterexamples.jsonl`
- `artifacts/metamorphic/<timestamp>/triage_report.json`
- `artifacts/metamorphic/<timestamp>/repro_governance_actions.json`
- `artifacts/metamorphic/<timestamp>/trace_ids.json`
- `artifacts/metamorphic/<timestamp>/env.json`
- `artifacts/metamorphic/<timestamp>/manifest.json`
- `artifacts/metamorphic/<timestamp>/repro.lock`
- `artifacts/metamorphic/<timestamp>/failures/`
- `artifacts/metamorphic/<timestamp>/commands.txt`

`run_manifest.json` pins `bead_id=bd-1lsy.9.3` and includes a deterministic
`replay_command` field for operator reruns.

`property_generator_catalog.json` makes the adoption wedge explicit: the same
recorded generators are consumable by metamorphic, fuzz, and differential lanes
without changing the external command surface.

Evidence rows include stable governance fields:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`

Plus relation metrics:
- `relation_id`
- `subsystem`
- `oracle`
- `pairs_tested`
- `violations_found`
- `min_failure_size`
- `duration_us`
- `relation_catalog_hash`
- `seed`
- `environment_fingerprint`

A `suite_summary` row is appended with aggregate totals.

Seed transcript rows capture deterministic pair-seed replay metadata:
- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event` (`pair_seed_evaluated`)
- `relation_id`
- `subsystem`
- `pair_index`
- `run_seed`
- `outcome`
- `error_code`

Seed manifest rows capture deterministic campaign scheduling metadata:
- `schema_version`
- `relation_catalog_hash`
- `corpus_version`
- `base_seed`
- `relation_seed_schedule[]` (`relation_id`, `pairs_tested`, `start_seed`, `end_seed`, `schedule_policy`)

Property-generator catalog rows capture the recorded generator inventory:
- `relation_id`
- `generator_id`
- `sample_choice_count`
- `replay_supported`
- `shrink_strategy`
- `consumers`

Choice-stream schema rows capture the replay contract for each relation:
- `relation_id`
- `generator_id`
- `fields[]` (`index`, `label`, `strategy`, `min_value`, `max_value`)

Shrinker verdict rows capture stage-by-stage reduction decisions:
- `relation_id`
- `pair_index`
- `generator_id`
- `original_size_metric`
- `minimized_size_metric`
- `choice_stream_reduced`
- `ddmin_reduced`
- `verdicts[]`

Minimized property counterexample rows capture replayable failing cases:
- `relation_id`
- `pair_index`
- `generator_id`
- `original_pair`
- `minimized_pair`
- `original_choice_stream`
- `replayable_choice_stream`
- `property_contract`

Triage report rows capture severity-classified and owner-routed findings:
- `counterexample_id`
- `finding_class` (`correctness|security|determinism`)
- `severity` (`medium|high|critical`)
- `priority` (`p2|p1|p0`)
- `owner_assignment` (`owner_track`, `owner_hint`, `escalation_required`)
- `minimized_reproduction_id`
- `deterministic_evidence_link`
- `replay_command`

Repro governance actions rows map deterministic findings to follow-up bead IDs:
- `action` (`create`)
- `bead_id` (`bd-auto-<fingerprint-prefix>`)
- `fingerprint` (`sha256:<...>`, deduplicated)
- `counterexample_id`
- `priority`
- `owner_track`
- `owner_hint`
- `deterministic_evidence_link`
- `replay_command`
- `minimized_reproduction_id`

## Meta-Tests

The crate includes infrastructure self-tests for:
- relation soundness on a curated deterministic seed set
- generator coverage >= 99%
- minimizer effectiveness (<= 20 AST-node metric)
- deterministic reruns for identical seeds
- strict budget enforcement

## Structured Failure Semantics

- Non-zero relation violations emit `FE-META-0001` and fail the suite.
- Unknown relation filter IDs emit a deterministic runner error and fail the suite.
- No suppression mechanism is implemented; CI remains zero-violation.

## Operator Verification

After a run:

```bash
cat artifacts/metamorphic/<timestamp>/run_manifest.json
cat artifacts/metamorphic/<timestamp>/events.jsonl
cat artifacts/metamorphic/<timestamp>/relation_events.jsonl
cat artifacts/metamorphic/<timestamp>/metamorphic_evidence.jsonl
cat artifacts/metamorphic/<timestamp>/seed_transcript.jsonl
cat artifacts/metamorphic/<timestamp>/seed_manifest.json
cat artifacts/metamorphic/<timestamp>/property_generator_catalog.json
cat artifacts/metamorphic/<timestamp>/generator_choice_stream_schema.json
cat artifacts/metamorphic/<timestamp>/shrinker_verdict_report.json
cat artifacts/metamorphic/<timestamp>/minimized_property_counterexamples.jsonl
cat artifacts/metamorphic/<timestamp>/triage_report.json
cat artifacts/metamorphic/<timestamp>/repro_governance_actions.json
cat artifacts/metamorphic/<timestamp>/trace_ids.json
cat artifacts/metamorphic/<timestamp>/env.json
cat artifacts/metamorphic/<timestamp>/manifest.json
cat artifacts/metamorphic/<timestamp>/repro.lock
ls artifacts/metamorphic/<timestamp>/failures
./scripts/e2e/metamorphic_suite_replay.sh ci
```
