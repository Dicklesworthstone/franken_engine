# Swarm Proof Template Miner

`bd-ua5n2.10`

`scripts/swarm_proof_template_miner.sh` mines preserved proof-broker history for
stable validation templates. It consumes proof artifact-index rows,
reuse/refusal receipts, chaos replay outcomes, and no-mock lifecycle bundles,
then emits promotion candidates or non-promotion receipts with deterministic
candidate ids and source proof links.

The miner is advisory-only. It never runs Cargo or RCH, never mutates br or
Agent Mail, and never edits `AGENTS.md` or scripts automatically.

## Promotion Policy

Promotion requires enough current successful evidence plus enough refusal
history to explain where the template does not apply. Templates remain
non-promoted when evidence is insufficient, stale artifacts are present,
failure history is contradictory, local fallback contamination appears, or the
history is a stable non-promotion.

## Validation

```bash
jq empty docs/swarm_proof_template_miner_contract_v1.json scripts/testdata/swarm_proof_template_miner/cases.json
bash -n scripts/swarm_proof_template_miner.sh
bash -n scripts/e2e/swarm_proof_template_miner_smoke.sh
bash scripts/e2e/swarm_proof_template_miner_smoke.sh check
bash scripts/e2e/swarm_proof_template_miner_smoke.sh selftest
git diff --check -- scripts/swarm_proof_template_miner.sh docs/SWARM_PROOF_TEMPLATE_MINER.md docs/swarm_proof_template_miner_contract_v1.json scripts/testdata/swarm_proof_template_miner/cases.json scripts/e2e/swarm_proof_template_miner_smoke.sh
```
