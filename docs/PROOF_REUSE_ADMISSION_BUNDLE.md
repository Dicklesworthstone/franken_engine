# Proof Reuse Admission Bundle

Bead: `bd-yb8kk`

`scripts/proof_reuse_admission_bundle.sh` wraps the existing
`scripts/proof_reuse_cache_planner.sh` and emits a read-only
`franken-engine.proof-reuse-admission-bundle.v1` artifact for proof admission.
It does not replace the cache planner, shard planner, cache-miss forensic
ledger, or remote retention contract; it records how those existing proof
economy surfaces feed an admission decision.

The bundle never runs Cargo, never invokes rch, and never mutates br, Agent
Mail, workers, queues, target directories, or archive state.

## Classifications

Each indexed proof artifact is classified as one of:

- `reusable`: source revision/hash, command fingerprint, command policy,
  target-dir policy, artifact role, freshness, and changed-path compatibility
  are all proven.
- `refresh_required`: reuse is blocked by stale source evidence, changed-path
  overlap, local fallback evidence, anonymous ownership, or missing required
  compatibility proof.
- `invalid`: evidence is malformed, uses unsupported artifact roles, or carries
  a direct heavy Cargo command instead of the required `rch exec -- env
  CARGO_TARGET_DIR=...` shape.
- `unknown`: the proof index exists but required freshness evidence is absent,
  so no reuse is admitted.

## Usage

```bash
./scripts/proof_reuse_admission_bundle.sh \
  --proof-index-json artifacts/proof_evidence_index/latest/query.json \
  --freshness-report artifacts/proof_freshness_decay_gate/latest/proof.json \
  --expected-source-revision "$(git rev-parse HEAD)" \
  --changed-path crates/franken-engine/src/lib.rs \
  --output-dir /tmp/proof-reuse-admission
```

## Artifacts

- `proof_reuse_admission_bundle.json`
- `admission_rows.jsonl`
- `proof_reuse_cache/proof_cache_plan.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/proof_reuse_admission_bundle_contract_v1.json scripts/testdata/proof_reuse_admission_bundle/cases.json
bash -n scripts/proof_reuse_admission_bundle.sh scripts/e2e/proof_reuse_admission_bundle_smoke.sh
shellcheck -x scripts/proof_reuse_admission_bundle.sh scripts/e2e/proof_reuse_admission_bundle_smoke.sh
bash scripts/e2e/proof_reuse_admission_bundle_smoke.sh check
bash scripts/e2e/proof_reuse_admission_bundle_smoke.sh selftest
bash scripts/e2e/proof_reuse_cache_planner_smoke.sh check
git diff --check -- scripts/proof_reuse_admission_bundle.sh scripts/e2e/proof_reuse_admission_bundle_smoke.sh scripts/testdata/proof_reuse_admission_bundle/cases.json docs/proof_reuse_admission_bundle_contract_v1.json docs/PROOF_REUSE_ADMISSION_BUNDLE.md
```
