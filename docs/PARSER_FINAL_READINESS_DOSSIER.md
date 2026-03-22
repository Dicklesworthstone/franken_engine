# Parser Final Readiness Dossier (`bd-2mds.1.8.4`)

This document defines the deterministic, machine-checkable final readiness dossier
contract for parser supremacy declaration workflows.

## Contract Version

- `schema_version`: `franken-engine.parser-final-readiness-dossier.v1`
- `dossier_version`: `0.1.0`
- `log_schema_version`: `franken-engine.parser-log-event.v1`

## Required Evidence Linkage

Each dossier must include immutable artifact references for every required gate:

- correctness (`PSRP-08.2`)
- performance (`PSRP-08.3`)
- cross-architecture reproducibility (`PSRP-07.4`)
- operator/developer runbook (`PSRP-10.4`)
- supremacy criteria contract (`PSRP-08.1`)

Every evidence entry must include:

- `evidence_id`
- `status` (`pass|in_progress|fail|missing`)
- `required` (`true|false`)
- `manifest_path`
- `replay_command`

## Risk Register Contract

Residual risks are ranked deterministically and include:

- `risk_id`
- `severity` (`critical|high|medium|low`)
- `likelihood_millionths`
- `impact_millionths`
- `owner`
- `mitigation`
- `trigger_threshold`
- `rollback_trigger_id`
- `status` (`open|mitigated|accepted`)

Open-risk scoring is deterministic and used for hold/fail posture decisions.

## Rollback Posture Contract

Rollback posture must define explicit triggers and deterministic recovery commands.
Each trigger must include:

- `trigger_id`
- `metric`
- `comparison` (`>|>=|<|<=`)
- `threshold_millionths`
- `recovery_command`
- `blast_radius_assumption`

Every open residual risk must reference an existing rollback trigger.

## Independent Verification Contract

Independent verification entries must include:

- `verifier_id`
- `outcome` (`pass|hold|fail`)
- `manifest_path`
- `replay_command`
- `signed_off`

A minimum verifier floor is enforced by gate policy.

## Deterministic Claim Replay Coverage

Each major claim in the dossier must include one-command replay entries:

- `claim_id`
- `replay_command`
- `expected_outcome`

Replay commands must be non-empty and unique.

## Structured Log Contract

Readiness-gate completion logs must include:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `dossier_id`
- `risk_register_hash`
- `replay_command`

`risk_register_hash` is computed deterministically as `sha256` over canonical
`residual_risks` rows sorted by `risk_id`, using fields:
`risk_id|severity|likelihood_millionths|impact_millionths|owner|status|rollback_trigger_id|trigger_threshold`.

## Deterministic Execution Contract

All heavy Rust checks/tests run through `rch`.

Canonical command:

```bash
./scripts/run_parser_final_readiness_dossier.sh ci
```

Modes:

- `check`: compile focused readiness dossier test target
- `test`: run focused readiness dossier tests
- `clippy`: lint focused readiness dossier target with `-D warnings`
- `ci`: check + test + clippy

The replay wrapper reruns the selected mode, then prints the latest complete
artifact bundle and warns when the newest directory is incomplete so operators
do not get stranded on partial failure output:

```bash
./scripts/e2e/parser_final_readiness_dossier_replay.sh check
```

## Required Artifacts

Each run must publish:

- `artifacts/parser_final_readiness_dossier/<timestamp>/run_manifest.json`
- `artifacts/parser_final_readiness_dossier/<timestamp>/events.jsonl`
- `artifacts/parser_final_readiness_dossier/<timestamp>/commands.txt`
- `artifacts/parser_final_readiness_dossier/<timestamp>/step_logs/step_*.log`

`run_manifest.json` must include:

- schema/version identifiers
- bead id, dossier version, mode, target-dir, git commit
- deterministic environment fingerprint
- blocked dependency inventory
- deterministic risk-register hash
- deterministic replay command
- command transcript, per-step logs, and outcome

## Operator Verification

```bash
./scripts/run_parser_final_readiness_dossier.sh ci
cat artifacts/parser_final_readiness_dossier/<timestamp>/run_manifest.json
cat artifacts/parser_final_readiness_dossier/<timestamp>/events.jsonl
cat artifacts/parser_final_readiness_dossier/<timestamp>/commands.txt
./scripts/e2e/parser_final_readiness_dossier_replay.sh ci
```
