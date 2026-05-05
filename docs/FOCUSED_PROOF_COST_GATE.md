# Focused Proof Cost Gate

`scripts/focused_proof_cost_gate.sh` turns a focused proof-cost receipt into a
pass/fail budget decision. It consumes a
`franken-engine.proof-cost-manifest.v1` file emitted by
`scripts/focused_proof_runner.sh` and compares the observed target surface
against a `franken-engine.focused-proof-cost-budget.v1` budget.

The gate is intentionally downstream-only:

- `bd-fn2zh` defines the proof-cost manifest schema.
- `bd-fk5cb` emits focused proof bundles and `proof_cost_manifest.json`.
- `bd-ctebo` reads those receipts and emits diagnostics.

It does not call back into manifest generation, so the dependency direction is
acyclic.

## Budget Shape

```json
{
  "schema_version": "franken-engine.focused-proof-cost-budget.v1",
  "suite": "focused_proof_runner_smoke",
  "max_total_compiled_targets": 2,
  "max_total_linked_targets": 1,
  "max_unexpected_targets": 0,
  "max_targets_by_kind": {
    "lib": 1,
    "test": 1
  }
}
```

Unset numeric fields are ignored, except `max_unexpected_targets`, which
defaults to `0`. Budgets should stay specific to one `focused_suite` unless the
operator intentionally uses `"suite": "*"`.

## Rerun

```bash
./scripts/focused_proof_cost_gate.sh \
  artifacts/focused_proof_runner/<run>/proof_cost_manifest.json \
  docs/<suite>-focused-proof-budget.json \
  artifacts/focused_proof_cost_gate/<run>
```

The gate emits:

- `diagnostics.json`: machine-readable status, observed counts, breaches, and
  remediation notes.
- `events.jsonl`: one proof-artifact event for gate ingestion.
- `commands.txt`: exact gate command.
- `report.md`: human-readable triage report.

## Remediation

When the gate fails, inspect `proof_cost_manifest.json` first:

1. Read `operator_log` and `unexpected_targets`.
2. If the new target is legitimate, add it to the focused runner expected target
   set and update the budget in the same review with evidence.
3. If the new target is unrelated, narrow the `cargo test` command, split the
   proof suite, or remove the dependency that pulled it in.
4. Check worker and sync-root metadata in the focused runner source report so a
   remote-worker sync expansion is not mistaken for a source regression.
5. Rerun `scripts/focused_proof_runner.sh`, then rerun this gate before
   publishing or closing the proof.

Do not raise budgets just to make a noisy proof pass. A budget increase is a
claim that the broader compile surface is intentional and reviewed.
