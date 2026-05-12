# Proof Economy Control Tower

Bead: `bd-i36b4`

`scripts/proof_economy_control_tower.sh` is the documented operator entry point
for the proof-economy workflow. It composes three existing proof artifacts:

- `franken-engine.proof-reuse-admission-bundle.v1`
- `franken-engine.proof-queue-tail-latency-rescue-receipt.v1`
- `franken-engine.agent-run-evidence-index.v1`

The entry point is a script wrapper, not a new `frankenctl` command. That keeps
the shipped CLI surface unchanged while giving operators a stable report and
replay command.

## Usage

```bash
./scripts/proof_economy_control_tower.sh \
  --proof-reuse-admission-json /path/to/proof_reuse_admission_bundle.json \
  --tail-latency-rescue-json /path/to/tail_latency_rescue_receipt.json \
  --agent-run-evidence-index-json /path/to/agent_run_evidence_index.json \
  --output-dir /tmp/proof-economy-control-tower
```

The wrapper is read-only. It does not run Cargo, invoke rch, query live Agent
Mail, mutate br, release reservations, send mail, change queue policy, or
mutate workers.

## Artifacts

- `proof_economy_control_tower_report.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

## Validation

```bash
jq empty docs/proof_economy_control_tower_contract_v1.json scripts/testdata/proof_economy_control_tower/cases.json
bash -n scripts/proof_economy_control_tower.sh scripts/e2e/proof_economy_control_tower_smoke.sh
shellcheck -x scripts/proof_economy_control_tower.sh scripts/e2e/proof_economy_control_tower_smoke.sh
bash scripts/e2e/proof_economy_control_tower_smoke.sh check
bash scripts/e2e/proof_economy_control_tower_smoke.sh selftest
git diff --check -- scripts/proof_economy_control_tower.sh scripts/e2e/proof_economy_control_tower_smoke.sh scripts/testdata/proof_economy_control_tower/cases.json docs/proof_economy_control_tower_contract_v1.json docs/PROOF_ECONOMY_CONTROL_TOWER.md
```
