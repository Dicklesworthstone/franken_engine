# IDEA-WIZARD-XIII Capability-Typed Ambient-Authority Proof

`bd-ly6hp.4` adds the first promotion candidate for `FE-CLAIM-006`: capability-
typed execution and ambient-authority rejection. The proof is intentionally
limited to the current `capability_typed_manifest_ir_hostcall_v1` subset. It
does not claim that typed TypeScript-to-IR onboarding is shipped.

The proof wrapper runs the focused integration test
`capability_typed_onboarding_proof_emits_runtime_result` through `rch`. That
test binds a minimal manifest input to an IR hostcall, grants the runtime base
capabilities `vm_dispatch` and `heap_allocate`, grants manifest-requested
`fs_read`, and exercises runtime enforcement in `baseline_interpreter`:

- a declared `fs:read` hostcall succeeds when `fs_read` is granted;
- implicit filesystem authority is rejected when `fs_read` is absent;
- implicit network authority is rejected when `network_egress` is absent;
- unknown ambient hostcall authority is rejected fail-closed.

It also audits source fixtures with `ambient_authority` so direct filesystem,
network, and process/hostcall authority produce machine-readable violations.

## Artifacts

The wrapper writes a proof bundle containing:

- `capability_typed_onboarding_report.json`;
- `runtime_enforcement_result.json`;
- `typed_input_or_manifest_fixture.json`;
- `ambient_filesystem_rejection_fixture.rs`;
- `ambient_network_rejection_fixture.rs`;
- `ambient_hostcall_rejection_fixture.rs`;
- `unsupported_syntax_fail_closed_fixture.json`;
- `stale_evidence_fail_closed_fixture.json`;
- `synthetic_evidence_fail_closed_fixture.json`;
- `missing_evidence_fail_closed_fixture.json`;
- `tampered_evidence_fail_closed_fixture.json`;
- `replay_verifier_report.json`;
- `commands.txt`, `events.jsonl`, `run_manifest.json`, and `report.md`.

The report includes the fields required by the claim-promotion contract:
`covered_input_subset`, `requested_capabilities`, `granted_capabilities`,
`denied_ambient_authority`, `runtime_enforcement_verdict`, and
`unsupported_contract`.

## Downgrade Boundary

This proof can only support `covered_capability_typed_input_subset_only`.
README wording must keep full capability-typed TypeScript onboarding as
hypothesis until a production typed source lowering path exists.

The unsupported boundary is explicit:

- `unsupported_contract.input_kind` is `typed_ts_to_ir`;
- `unsupported_contract.actual` is `fail_closed`;
- `unsupported_contract.diagnostic_code` is
  `capability_typed.unsupported_syntax`.

## Validation

```bash
bash -n scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh
bash -n scripts/e2e/idea_wizard_xiii_capability_typed_ambient_authority_proof_smoke.sh
jq empty docs/idea_wizard_xiii_capability_typed_ambient_authority_proof_v1.json
bash scripts/e2e/idea_wizard_xiii_capability_typed_ambient_authority_proof_smoke.sh check
bash scripts/e2e/idea_wizard_xiii_capability_typed_ambient_authority_proof_smoke.sh selftest
shellcheck -x scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh scripts/e2e/idea_wizard_xiii_capability_typed_ambient_authority_proof_smoke.sh
git diff --check -- docs/IDEA_WIZARD_XIII_CAPABILITY_TYPED_AMBIENT_AUTHORITY_PROOF.md docs/idea_wizard_xiii_capability_typed_ambient_authority_proof_v1.json scripts/idea_wizard_xiii_capability_typed_ambient_authority_proof.sh scripts/e2e/idea_wizard_xiii_capability_typed_ambient_authority_proof_smoke.sh crates/franken-engine/tests/capability_typed_ambient_authority_proof.rs
```
