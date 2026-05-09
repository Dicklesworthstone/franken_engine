# Swarm Proof Equivalence Classifier

`bd-ua5n2.3`

`scripts/swarm_proof_equivalence_classifier.sh` compares a candidate proof
receipt/request against the proof surface currently being requested. It emits a
deterministic verdict and stable classifier hash without executing Cargo or RCH.
It never runs Cargo or RCH.

## Verdicts

- `reuse_allowed`: the candidate and requested proof surfaces are identical.
- `rerun_required`: source revision or dependency closure changed.
- `reuse_refused`: the candidate is contaminated, narrower than requested, has
  env mismatch, dirty-lane mismatch, or a different test filter.
- `human_review`: the candidate is broader than requested or the overlap is
  uncertain.

The classifier refuses shell wrappers, bare Cargo, and local fallback evidence as
contaminated command shapes.

## Compared Fields

- normalized command argv
- command kind
- package, target kind, target name, and test filter
- feature flags
- accepted env allowlist
- source revision or git commit
- dependency closure roots
- dirty paths
- target-dir policy
- RCH posture

Partial-overlap diagnostics include candidate/requested target ranks and command
text. A narrower candidate never satisfies a wider request.

## Artifacts

Each run emits:

- `equivalence_report.json`
- `reuse_refusal_receipt.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

`reuse_refusal_receipt.json` is also used for non-green rerun and human-review
verdicts so downstream broker lanes can explain why reuse was not accepted.

## Validation

```bash
jq empty scripts/testdata/swarm_proof_equivalence_classifier/cases.json
bash -n scripts/swarm_proof_equivalence_classifier.sh
bash -n scripts/e2e/swarm_proof_equivalence_classifier_smoke.sh
bash scripts/e2e/swarm_proof_equivalence_classifier_smoke.sh check
bash scripts/e2e/swarm_proof_equivalence_classifier_smoke.sh selftest
git diff --check -- scripts/swarm_proof_equivalence_classifier.sh docs/SWARM_PROOF_EQUIVALENCE_CLASSIFIER.md scripts/testdata/swarm_proof_equivalence_classifier/cases.json scripts/e2e/swarm_proof_equivalence_classifier_smoke.sh
```
