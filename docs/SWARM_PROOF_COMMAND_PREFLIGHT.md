# Swarm Proof Command Preflight

`bd-ua5n2.9`

`scripts/swarm_proof_command_preflight.sh` classifies command text before the
proof broker schedules, deduplicates, or reuses a proof. It is advisory-only and
never executes the command under inspection.

## Decisions

- `proof_safe`: direct `rch exec -- env ... cargo ...` proof with an isolated
  `CARGO_TARGET_DIR`, only allowlisted env names, and required visibility
  context when requested.
- `proof_unsafe`: a command shape that must not be used as proof evidence.
- `needs_human_review`: a command shape outside the cheap classifier contract.
- `non_heavy_read_only`: lightweight gates such as `jq`, `bash -n`, `shellcheck`,
  or `git diff --check`.

Unsafe and human-review decisions exit `42`. Safe and read-only decisions exit
`0`.

## Rejections

The preflight rejects:

- shell-wrapped Cargo or RCH commands such as `bash -lc "rch exec -- cargo ..."`
- bare local Cargo
- heavy RCH Cargo commands without `CARGO_TARGET_DIR=...`
- unsupported env leakage inside `rch exec -- env`
- missing `RCH_VISIBILITY=...` when captured evidence requires visibility
- unrecognized heavy command shapes

Every rejection includes remediation text and, when possible, a pasteable direct
RCH command with `/tmp/rch_target_franken_engine_<safe_bead_id>`.

## Inputs

```bash
./scripts/swarm_proof_command_preflight.sh --command 'rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_franken_engine_bd cargo test -p frankenengine-engine --lib'
```

`--command-json` expects one command object with `command`, optional `case_id`,
and optional `context` fields such as `bead_id` and
`evidence_requires_visibility`. The smoke harness feeds each checked-in fixture
case to the script individually.

## Artifacts

Each run emits:

- `preflight_report.json`
- `run_manifest.json`
- `events.jsonl`
- `commands.txt`
- `report.md`

The machine-readable contract is
`docs/swarm_proof_command_preflight_contract_v1.json`.

## Validation

```bash
jq empty docs/swarm_proof_command_preflight_contract_v1.json scripts/testdata/swarm_proof_command_preflight/cases.json
bash -n scripts/swarm_proof_command_preflight.sh
bash -n scripts/e2e/swarm_proof_command_preflight_smoke.sh
bash scripts/e2e/swarm_proof_command_preflight_smoke.sh check
bash scripts/e2e/swarm_proof_command_preflight_smoke.sh selftest
git diff --check -- scripts/swarm_proof_command_preflight.sh docs/SWARM_PROOF_COMMAND_PREFLIGHT.md docs/swarm_proof_command_preflight_contract_v1.json scripts/testdata/swarm_proof_command_preflight/cases.json scripts/e2e/swarm_proof_command_preflight_smoke.sh
```
