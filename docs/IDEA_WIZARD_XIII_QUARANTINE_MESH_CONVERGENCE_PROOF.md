# IDEA-WIZARD-XIII Quarantine Mesh Convergence Proof

`bd-ly6hp.3` adds the first promotion candidate for `FE-CLAIM-005`: the
fleet immune-system quarantine claim. It is intentionally limited to the live
quarantine mesh bounded-convergence subset and does not claim de-escalation or
full production fleet orchestration.

The proof wrapper runs the existing `examples/07_quarantine_mesh/demo.sh`
surface, which in turn executes `franken-quarantine-mesh-demo` through `rch`.
The demo uses Cargo's normal remote target directory by default so worker
caches can be reused; set `QUARANTINE_MESH_DEMO_CARGO_TARGET_DIR` only when a
run needs an isolated target directory.
The demo emits the real signed revocation and fleet immune protocol path used
by the example:

- signed revocation chain application on each mesh instance;
- fleet evidence and quarantine intents through `fleet_immune_protocol`;
- per-instance checkpoint convergence;
- bounded SLO evaluation.

## Artifacts

The wrapper writes a proof bundle containing:

- `live_quarantine_mesh_log.json`;
- `live_quarantine_mesh_convergence_report.json`;
- `peer_attempts.jsonl`;
- `partial_failure_degraded_fixture.json`;
- `total_failure_degraded_fixture.json`;
- `replay_verifier_report.json`;
- `commands.txt`, `events.jsonl`, `run_manifest.json`, and `report.md`.

The report includes the fields required by the claim-promotion contract:
`peer_count`, `attempted_targets`, `failed_targets`, `convergence_ms`,
`slo_threshold_ms`, `permanent_ratchet`, and `de_escalation_supported`.

## Downgrade Boundary

This proof can only support `live_quarantine_mesh_bounded_convergence_only`.
Containment is modeled as a permanent ratchet:

- `permanent_ratchet` is `true`;
- `de_escalation_supported` is `false`;
- partial and total propagation failure fixtures must remain `degraded`.

README wording about fleet-wide quarantine must keep the de-escalation
limitation until a separate recovery/re-attestation proof exists.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh
bash -n scripts/e2e/idea_wizard_xiii_quarantine_mesh_convergence_proof_smoke.sh
jq empty docs/idea_wizard_xiii_quarantine_mesh_convergence_proof_v1.json examples/07_quarantine_mesh/sample_propagation_log.json
bash scripts/e2e/idea_wizard_xiii_quarantine_mesh_convergence_proof_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_quarantine_mesh_convergence_proof_smoke.sh selftest
shellcheck -x scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh scripts/e2e/idea_wizard_xiii_quarantine_mesh_convergence_proof_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XIII_QUARANTINE_MESH_CONVERGENCE_PROOF.md docs/idea_wizard_xiii_quarantine_mesh_convergence_proof_v1.json scripts/idea_wizard_xiii_quarantine_mesh_convergence_proof.sh scripts/e2e/idea_wizard_xiii_quarantine_mesh_convergence_proof_smoke.sh
```
