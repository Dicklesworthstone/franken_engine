# Proof Reuse Cache Planner

`scripts/proof_reuse_cache_planner.sh` consumes a typed proof-evidence query
report plus one or more `franken-engine.proof-freshness-decay-report.v1`
artifacts and emits a conservative
`franken-engine.proof-reuse-cache-plan.v1` receipt.

The planner answers one operator question: which proofs can be reused for the
current source state, and which ones must be refreshed before a claim is
published or replayed?

## Inputs

- `--proof-index-json`: required proof-evidence query report with `rows[]`
- `--freshness-report`: repeatable freshness receipts for the candidate
  artifacts
- `--expected-source-revision`: revision required for reuse
- `--changed-path`: repeatable changed source path used for path invalidation

## Output Fields

- `proof_cache_decision`: one of `cache_hit`, `partial_refresh`,
  `refresh_required`, or `fail_closed`
- `cache_hit_artifacts`: reusable proof artifacts
- `required_refreshes`: artifacts that must be rerun before reuse
- `invalid_artifacts`: fail-closed rows with missing identity, missing freshness
  evidence, incomplete freshness fields, or invalid heavy refresh commands
- `invalidated_paths`: changed paths that force refresh
- `refresh_commands`: deduplicated refresh commands

The planner fails closed when proof identity, source revision, covered paths,
freshness state, or refresh-command requirements are missing. Heavy refresh
commands must already be `rch`-wrapped with an explicit `CARGO_TARGET_DIR=...`.

## Shell-Only Reuse Example

When the freshness report is still `fresh` and the underlying proof is
shell-only, the planner can emit a pure cache hit without any cargo refresh:

```bash
./scripts/proof_reuse_cache_planner.sh \
  --proof-index-json artifacts/proof_evidence_index/latest/query.json \
  --freshness-report artifacts/proof_freshness_decay_gate/latest/shell-proof.json \
  --expected-source-revision "$(git rev-parse HEAD)" \
  --changed-path scripts/e2e/proof_cost_history_index_smoke.sh
```

If the resulting `proof_cache_decision` is `cache_hit`, operators can reuse the
existing shell proof artifact and record the planner receipt in the evidence
bundle without running cargo.

## Heavy Proof Refresh Example

When an indexed heavy proof is stale, superseded, or invalidated by changed
paths, the planner emits the preserved refresh command. Those commands must keep
the remote shape below:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_proof_reuse \
  cargo test -p frankenengine-engine --test proof_evidence_index_integration -- --nocapture
```

The planner does not execute that command. It only records the refresh
requirement and preserves the operator-ready command string in
`refresh_commands`.

## Smoke Validation

The planner’s deterministic fixture suite lives at:

```bash
bash -n scripts/proof_reuse_cache_planner.sh
bash -n scripts/e2e/proof_reuse_cache_planner_smoke.sh
./scripts/e2e/proof_reuse_cache_planner_smoke.sh check
./scripts/e2e/proof_reuse_cache_planner_smoke.sh selftest
```

The smoke suite covers:

- exact cache hit
- stale-by-time miss
- stale-by-source miss
- changed-path invalidation
- incomplete artifact fail-closed
- superseded artifact refresh
- mixed partial-hit refresh planning
