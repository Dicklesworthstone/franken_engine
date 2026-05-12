# Proof Pipeline Release Gate (`bd-2rx`)

This runbook defines the deterministic release gate for proof-carrying
optimization pipeline readiness (Section 10.9 item 4).

## Scope

This gate validates delivered pipeline behavior from 10.12. It does not
implement optimization passes.

## Pass Criteria

All conditions must pass:

1. Every expected optimization pass has a proof artifact.
2. Each artifact includes required bundle fields:
   - `optimization_pass`
   - `pre_ir_hash` + `post_ir_hash`
   - `proof_hash`
   - `verifier_version`
   - `proof_generation_time_ns`
   - `verification_time_ns`
   - `ir_diff_size_bytes`
   - `replay_command`
3. Any failed proof cannot be applied; it must trigger fallback with a
   non-empty fallback receipt ID.
4. Independent replay verification must succeed for verified proofs.
5. Replay-time multiplier must be <= `5.0x` (`5_000_000` millionths).
6. Artifact bundle must be content-addressed (`cas://<archive_root_hex>/...`) with
   a non-zero root, and the URI root component must match `archive_root`.
7. Comprehensive test/e2e/logging evidence must be present and pass fail-closed
   quality thresholds:
   - unit coverage >= `900_000` millionths
   - mutation score >= `850_000` millionths
   - executed failure-mode tests >= required failure-mode tests
   - executed e2e scenarios >= required e2e scenarios
   - structured logging artifacts present and fresh
   - trace-correlated structured logs available for deterministic replay

## Failure Codes

- `missing_proof_artifact`
- `missing_bundle_field`
- `proof_verification_failed`
- `fallback_path_invalid`
- `independent_replay_failed`
- `replay_multiplier_exceeded`
- `archive_not_content_addressed`
- `missing_test_evidence`
- `test_evidence_below_threshold`
- `logging_artifacts_missing`
- `logging_artifacts_stale`
- `logging_artifacts_uncorrelated`

## Structured Log Fields

Gate output logs emit stable keys:

- `trace_id`
- `decision_id`
- `policy_id`
- `component`
- `event`
- `outcome`
- `error_code`
- `optimization_pass`
- `proof_status`
- `proof_hash`
- `fallback_triggered`
- `verification_time_ns`
- `ir_diff_size_bytes`

Test/e2e/logging quality failures are emitted via deterministic gate findings and
surface through `release_gate_decision.error_code` plus finding details.

## Operator Commands (RCH Required)

```bash
./scripts/run_proof_pipeline_release_gate.sh
```

This script runs:

1. `cargo test -p frankenengine-engine --lib proof_release_gate::tests::`
2. `cargo test -p frankenengine-engine --test proof_release_gate_integration`
3. `cargo clippy -p frankenengine-engine --lib --test proof_release_gate_integration -- -D warnings`
4. `cargo check -p frankenengine-engine --lib`

Both are offloaded via `rch exec`.

## Rollback/Fallback Activation

Rollback/fallback must activate when any optimization proof is invalid.
Acceptance evidence requires:

1. `optimization_applied=false` for failing proof artifacts.
2. `fallback_triggered=true`.
3. Non-empty `fallback_receipt_id`.
4. Release decision marked `pass=false`.

## Reproducibility Notes

- Decision IDs are deterministic hashes over canonicalized gate inputs,
  findings, and replay multiplier.
- Run artifacts are compatible with content-addressed evidence/replay pathways.
