# Swarm Proof Broker No-Mock Drill

`bd-ua5n2.8`

`scripts/e2e/swarm_proof_broker_no_mock_drill.sh` composes the proof-broker
lane into a lifecycle bundle and fail-closed truth gate. Replay mode consumes a
preserved bundle. Live mode captures local br, git, and RCH metadata where
available and marks missing Agent Mail evidence as a failure instead of filling
synthetic context.

The drill never runs Cargo or RCH, never mutates br, never sends Agent Mail, and
never mutates remote workers. It writes the required final bundle members:
`run_manifest.json`, `events.jsonl`, `commands.txt`, `trace_ids.json`,
`request_capture.json`, `equivalence_report.json`, `artifact_index.json`,
`batch_plan.json`, `chaos_scenarios.json`, `operator_status_bundle.json`, and
`truth_gate_report.json`.

## Truth Gate

The truth gate fails closed on stale br/bv snapshots, missing Agent Mail
evidence, local fallback contamination, incomplete RCH artifact retrieval, dirty
paths outside the claimed lane, hidden reuse refusal, unsupported shell-wrapped
cargo commands, stale proof rejection, and under-specified replay bundles.

Fixtures cover healthy reuse, duplicate storm coalescing, stale proof rejection,
local fallback quarantine, and replay rejection for under-specified bundles.
Replay mode consumes a preserved bundle.

## Validation

```bash
jq empty docs/swarm_proof_broker_no_mock_drill_contract_v1.json scripts/testdata/swarm_proof_broker_no_mock_drill/cases.json
bash -n scripts/e2e/swarm_proof_broker_no_mock_drill.sh
bash -n scripts/e2e/swarm_proof_broker_no_mock_drill_smoke.sh
bash scripts/e2e/swarm_proof_broker_no_mock_drill_smoke.sh check
bash scripts/e2e/swarm_proof_broker_no_mock_drill_smoke.sh selftest
git diff --check -- scripts/e2e/swarm_proof_broker_no_mock_drill.sh scripts/e2e/swarm_proof_broker_no_mock_drill_smoke.sh docs/SWARM_PROOF_BROKER_NO_MOCK_DRILL.md docs/swarm_proof_broker_no_mock_drill_contract_v1.json scripts/testdata/swarm_proof_broker_no_mock_drill/cases.json
```
