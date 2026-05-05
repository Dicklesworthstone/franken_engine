# Proof Freshness Decay Gate

`scripts/proof_freshness_decay_gate.sh` classifies whether an existing proof
artifact can be reused for the current source state. It emits
`franken-engine.proof-freshness-decay-report.v1` with:

- `fresh`: source revision, schema, covered paths, freshness deadline, and
  supersession checks all allow reuse.
- `stale_by_time`: the artifact exceeded its declared freshness deadline.
- `stale_by_source_revision`: the artifact was generated from another revision.
- `stale_by_changed_path`: a changed path overlaps a path covered by the proof.
- `mismatched`: the artifact schema does not match the required schema.
- `incomplete`: required proof identity, source revision, or freshness fields are
  missing.
- `superseded`: newer evidence has replaced the artifact.

The gate is a classifier only. It does not execute proof commands, restart rch,
or mutate workers. Any non-`fresh` state exits nonzero so claim promotion fails
closed.

Example freshness check:

```bash
./scripts/proof_freshness_decay_gate.sh \
  --artifact artifacts/focused_proof_runner/latest/proof_cost_manifest.json \
  --expected-source-revision "$(git rev-parse HEAD)" \
  --expected-schema-version franken-engine.proof-artifact-manifest.v1 \
  --changed-path crates/franken-engine/src/proof_evidence_index.rs
```

When the report is not `fresh`, refresh heavy proof artifacts through rch with an
explicit target dir:

```bash
rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_proof_freshness CARGO_INCREMENTAL=0 cargo test -p frankenengine-engine --test proof_evidence_index_integration proof_cost_history -- --nocapture
```

For shell-only proof surfaces, rerun the existing gate directly and then classify
the new manifest:

```bash
./scripts/e2e/proof_cost_history_index_smoke.sh check
./scripts/proof_freshness_decay_gate.sh \
  --artifact artifacts/proof_cost_history_index_smoke/latest/manifest.json \
  --expected-source-revision "$(git rev-parse HEAD)"
```
