# RCH Validation Control Plane No-Mock Smoke

`bd-7r53m.5`

`scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh` composes the shipped
RCH validation control-plane surfaces without starting Cargo or RCH:

- `scripts/e2e/swarm_proof_command_preflight_smoke.sh`
- `scripts/e2e/swarm_validation_admission_recommender_smoke.sh`
- `scripts/e2e/rch_validation_evidence_ledger_smoke.sh`
- `scripts/verify_rch_validation_evidence_ledger.sh`

The selftest reads checked-in transcript fixtures from
`scripts/testdata/rch_validation_control_plane_no_mock/fixtures.json`, captures
an active-process snapshot fixture, runs the real admission recommender, writes a
ledger JSON into the run directory, verifies it, and emits a report with:

- input snapshot path
- selected validation action
- reason code
- admission recommendation artifact path
- generated ledger artifact path

Validation:

```bash
jq empty scripts/testdata/rch_validation_control_plane_no_mock/fixtures.json
bash -n scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh
bash scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh check
bash scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh selftest
git diff --check -- scripts/e2e/rch_validation_control_plane_no_mock_smoke.sh scripts/testdata/rch_validation_control_plane_no_mock/fixtures.json docs/RCH_VALIDATION_CONTROL_PLANE_NO_MOCK_SMOKE.md
```
