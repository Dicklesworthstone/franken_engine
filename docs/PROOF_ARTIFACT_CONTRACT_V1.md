# Proof Artifact Contract V1

`franken-engine.proof-artifact-manifest.v1` is the shared artifact bundle for
user-facing proof gates and proof examples. A gate can keep its existing
domain-specific report, but every observed proof run should also emit this
standard bundle:

- `manifest.json`: bundle identity, commit hash, gate name, status, rerun
  command, artifact paths, related claims/beads, commands, artifact hashes,
  verifier outputs, and freshness metadata.
- `commands.txt`: command transcript for the run.
- `events.jsonl`: structured step log. Each row should include
  `schema_version`, `event_name`, `severity`, `step_id`, `command_id`,
  `artifact_path`, `artifact_sha256`, `exit_code`, `duration_ms`, `decision`,
  and `remediation`.
- `report.json`: machine-readable summary with status, event count, failure
  count, rerun command, report paths, and findings.
- `report.md`: human-readable summary for reviewers.
- `redaction_policy.json`: the redaction policy used before commands are copied
  into standard proof reports.
- `proof_cost_manifest.json`: optional focused-validation inventory using
  `franken-engine.proof-cost-manifest.v1`. It records the requested suite, the
  command hash, expected focus targets, observed compiled/linked targets,
  per-kind target counts, unexpected fan-out, and operator log lines that name
  dragged targets directly.

The Rust schema lives in `crates/franken-engine/src/proof_artifact.rs`. Shell
gates should source `scripts/lib/proof_artifact_contract.sh` and finish by
calling `proof_contract_write_standard_bundle` after their domain-specific
`events.jsonl` and source report are written.

The first wired gates are:

- `scripts/run_claim_to_proof_matrix_gate.sh`
- `scripts/e2e/readme_cli_workflow_smoke.sh`
- `examples/02_signed_decision_receipt/verify.sh`
- `scripts/e2e/proof_artifact_contract_smoke.sh`
- `scripts/e2e/runtime_security_model_proof_smoke.sh`
- `scripts/e2e/resource_certificate_formal_governance_smoke.sh`

New proof gates should prefer repository-relative artifact paths. The helper
normalizes paths under the repo root before writing the shared manifest so that
artifacts remain reproducible across local and remote runners.

Focused proof gates that are expensive or prone to hidden fan-out should emit a
proof-cost manifest next to the standard bundle. The manifest is intentionally
timestamp-free so reordering the same observed targets yields the same content
hash. Use it to distinguish a real source regression from an unrelated compile
surface pulled in by a nominally narrow `cargo test --test ...` command.

`scripts/focused_proof_runner.sh` is the standard wrapper for high-value
focused proofs. Callers provide the exact command, expected target names, and
the observed target inventory; the wrapper records worker, sync-root,
wall-time, and target-cardinality metadata, emits `proof_cost_manifest.json`,
and fails closed when the observed target surface contains a target outside the
declared focus set. The smoke contract lives at
`scripts/e2e/focused_proof_runner_smoke.sh`.

Rerun example:

```bash
./scripts/e2e/proof_artifact_contract_smoke.sh
```
