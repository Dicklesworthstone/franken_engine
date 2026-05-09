# Swarm Proof Artifact Index

`bd-ua5n2.4`

`scripts/swarm_proof_artifact_index.sh` builds an advisory, append-only style
index over prior proof artifacts and verdict receipts. It never runs Cargo or
RCH.
It never runs Cargo or RCH.

Each row records the proof fingerprint, prior verdict, source revision,
dependency closure fingerprint, RCH version, toolchain, TTL, artifact bundle
state, reuse eligibility, invalidation reasons, and remediation.

## Reuse Policy

Proof is reusable only when:

- prior verdict status is `passed`
- TTL has not expired
- source revision, dependency closure, toolchain, and RCH version still match
- retrieval is complete
- required artifact bundle members are present
- dirty state is known
- no local fallback contamination was observed

Failed, expired, incomplete, drifted, unknown-dirty, and contaminated rows are
preserved as negative reuse refusal receipts. They are evidence, not green proof.

## Validation

```bash
jq empty docs/swarm_proof_artifact_index_contract_v1.json scripts/testdata/swarm_proof_artifact_index/cases.json
bash -n scripts/swarm_proof_artifact_index.sh
bash -n scripts/e2e/swarm_proof_artifact_index_smoke.sh
bash scripts/e2e/swarm_proof_artifact_index_smoke.sh check
bash scripts/e2e/swarm_proof_artifact_index_smoke.sh selftest
git diff --check -- docs/swarm_proof_artifact_index_contract_v1.json docs/SWARM_PROOF_ARTIFACT_INDEX.md scripts/swarm_proof_artifact_index.sh scripts/testdata/swarm_proof_artifact_index/cases.json scripts/e2e/swarm_proof_artifact_index_smoke.sh
```
