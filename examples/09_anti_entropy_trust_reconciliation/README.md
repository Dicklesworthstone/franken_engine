# Anti-Entropy Trust Reconciliation

This example is a static demo of impossible-by-default capability #9:
distributed anti-entropy trust reconciliation with machine-verifiable repair
artifacts.

The real runtime primitive lives in
`crates/franken-engine/src/anti_entropy.rs`. It reconciles distributed
revocation events, checkpoint markers, and evidence entries with an IBLT path
and a deterministic sorted-list fallback when peeling fails.

This fixture makes the operator-facing artifact shape concrete. The
[`sample_reconciliation_report.json`](./sample_reconciliation_report.json)
records a reconciliation attempt where the compact sketch could not peel and
the runtime switched to deterministic fallback. The
[`repair_artifact.json`](./repair_artifact.json) records the exact fetch/send
repair actions, sorted hash-list evidence, and a fixed-width signature field.

The verifier is [`verify.sh`](./verify.sh). It is intentionally shell-only and
`jq`-only. It does not run Cargo, mutate live trust state, contact peers, or
touch `br`.

From the repository root, run:

```bash
./examples/09_anti_entropy_trust_reconciliation/verify.sh
```

Verification fails closed if the report loses its fallback event, if object
hashes are unsorted or malformed, if the repair artifact is not linked to the
same reconciliation id, if the repair action count does not match the symmetric
difference, or if the provenance signature field is malformed.
