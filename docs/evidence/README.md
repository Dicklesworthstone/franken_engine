# Committed Evidence Manifests (`docs/evidence/`)

This directory makes **"No artifact, no claim." (`FE-CLAIM-009`)** verifiable from a
fresh clone. It is the data foundation for the Claim-Evidence Integrity epic
(`bd-sde5e`), specifically CEI-B.1 (`bd-sde5e.2.1`).

## The problem this closes

Every OBSERVED claim in [`../claim_to_proof_matrix_v1.json`](../claim_to_proof_matrix_v1.json)
used to point its `artifact_path` into the **git-ignored** `artifacts/` tree. A
fresh clone (which never receives `artifacts/`) could not verify a single evidence
pointer, so the advisory soundness scorer in
`crates/franken-engine/src/claim_evidence_lattice.rs` correctly reported those rows
as `Unbacked` → ceiling `Hypothesis`, i.e. over-promoted relative to their
committed evidence.

## What is committed here

For each OBSERVED claim `FE-CLAIM-NNN`:

```
docs/evidence/FE-CLAIM-NNN/
├── env.json              # relocated reproducibility-bundle env capture
├── manifest.json         # relocated reproducibility-bundle manifest
├── repro.lock            # relocated reproducibility-bundle lock (+ primary-artifact hash)
└── evidence_manifest.json  # content-addressed index (this bead's deliverable)
```

`evidence_manifest.json` (schema `franken-engine.evidence-manifest.v1`) records:

- **`verifiable_inputs`** — the claim's git-tracked **primary artifact**, hashed
  from its `HEAD`-committed blob. This is the part a fresh clone re-hashes offline.
- **`bundle_files`** — `sha256` of each committed `env.json` / `manifest.json` /
  `repro.lock` sitting next to the manifest.
- **`receipt`** — the bundle manifest's `verification_result` and `generated_by`,
  mirrored **honestly**. Where the receipt is still `pending`/backfill, it says so;
  CEI-B.2 (`bd-sde5e.2.2`) re-emits real `passed` receipts from live gate runs.
  Until then the advisory lattice correctly scores these rows as
  *committed-but-not-yet-verified* (tier `Asserted`, ceiling `Target`).

The bundle files themselves are small summaries, not the multi-gigabyte raw
evidence; only content-addressed pointers are committed.

## Verifying offline

No access to `artifacts/` is required — every checked path is git-tracked:

```bash
# Re-hash every committed manifest's inputs and compare to the recorded hashes.
cargo run -p frankenengine-engine --bin franken_evidence_manifest -- verify

# Equivalent assertion in the test suite:
cargo test -p frankenengine-engine --test evidence_manifest_offline_verification
```

`verify` exits non-zero if any recorded content hash fails to re-verify, or if a
recorded-tracked input is missing from the index.

## Regenerating

`generate` copies the source reproducibility bundles into this tree and rewrites
the manifests. It is deterministic (no wall-clock reads) and idempotent:

```bash
cargo run -p frankenengine-engine --bin franken_evidence_manifest -- generate
git add docs/evidence
```

A primary artifact that legitimately changes (e.g. an edited gate script) will
change its recorded hash on the next `generate`; a stale hash is a *signal* that
the evidence needs a refresh, caught by `verify`.

## Related

- `crates/franken-engine/src/evidence_manifest.rs` — schema + offline verifier.
- `crates/franken-engine/src/claim_evidence_lattice.rs` — CEI-A.1 advisory scorer.
- CEI-A.3 (`bd-sde5e.1.3`) consumes these manifests to make the git-tracked +
  non-pending-receipt check a blocking gate.
