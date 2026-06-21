# Claim-Evidence Integrity Capstone — Operator Runbook

> CEI G.1 (`bd-sde5e.7.1`). The one button to assert *the project is not
> over-promising*. Owning epic: `bd-sde5e` (Claim-Evidence Integrity Restoration).

## What it is

`scripts/run_claim_evidence_integrity_capstone.sh` composes the four CEI
integrity checks into a single fail-closed meta-gate. It is **green only when all
four hold**, and one injected over-promotion turns exactly the responsible
sub-gate — and the capstone — **red**.

| Track | Sub-gate | Asserts |
|---|---|---|
| **A, C** | `run_claim_to_proof_matrix_gate.sh ci` | README/doc wording ≤ `matrix.allowed_state`; artifact-quality refusal of simulated/mock evidence; CEI A.2 whole-document claim consistency (no contradictory asserted states). |
| **A, B** | `run_claim_evidence_integrity.sh blocking` | CEI A.1/A.3 bidirectional lattice: every row's `asserted_state ≤ ceiling(evidence_tier)`, where the tier comes only from machine-checkable facts (artifact git-tracked, receipt `passed` and not backfill, committed `repro.lock`, zero-exit receipt, A.4 e-process freshness). |
| **B** | `run_claim_evidence_ledger_gate.sh ci` | CEI H.1 Merkle/MMR: the committed `docs/claim_evidence_ledger_root.txt` equals the root recomputed over the live matrix + committed per-claim manifests. A silent leaf edit moves the root and fails closed. |
| **D** | `run_test262_posture_consistency.sh ci` | CEI D.1/D.3: the honest Test262 posture (`full_suite_claim_allowed=false`, the `FE-CLAIM-TEST262` matrix row, and the README wording) all agree. |

## Run it

```bash
# Fail-closed (the contract): exits non-zero if any sub-gate is red.
./scripts/run_claim_evidence_integrity_capstone.sh ci

# Advisory: run every sub-gate, report the real verdict, always exit 0.
./scripts/run_claim_evidence_integrity_capstone.sh dev
```

Reuse a prebuilt audit binary to skip cargo builds in the sub-gates:

```bash
cargo build --release -p frankenengine-engine \
  --bin franken_evidence_manifest --bin franken_claim_evidence_ledger
FRANKEN_EVIDENCE_MANIFEST_BIN=target/release/franken_evidence_manifest \
FRANKEN_CLAIM_EVIDENCE_LEDGER_BIN=target/release/franken_claim_evidence_ledger \
  ./scripts/run_claim_evidence_integrity_capstone.sh ci
```

## What you get (standard bundle)

Every run writes a content-addressed bundle under
`artifacts/claim_evidence_integrity_capstone/<timestamp>/`:

- `run_manifest.json` — schema'd overall verdict, `composed_tracks`, and a
  `subgates[]` array with each sub-gate's `label`, `track`, `exit_code`,
  `verdict`, and `log` path + sha256.
- `summary.txt` — operator-readable roll-up.
- `events.jsonl` — structured trace events (one JSON object per line).
- `commands.txt` — every sub-gate command, in order.
- `step_logs/step_NNN_<label>.log` — each sub-gate's captured stdout/stderr.

## Triage: what a red verdict means

Read `summary.txt`; it names the failed sub-gate(s). Then open the matching
`step_logs/step_NNN_<label>.log`.

| Red sub-gate | Most likely cause | Fix |
|---|---|---|
| `claim_to_proof_matrix` | A README/doc sentence is worded stronger than its `allowed_state`, an OBSERVED artifact cites mock/simulated evidence, or two docs assert contradictory states for one claim. | Downgrade the wording (the gate emits exact `downgrade_text`), or reconcile the contradiction. |
| `bidirectional_lattice` | A row asserts more than its committed evidence licenses: untracked artifact, a `pending`/`backfill` receipt, a missing `repro.lock`, or stale-past-the-e-process evidence. | Commit the artifact / re-emit a real `passed` receipt (`scripts/reemit_evidence_receipts.py`), or downgrade the row. |
| `merkle_ledger` | The matrix or a committed manifest changed but the ledger root was not regenerated (a silent leaf edit). | After an intentional, evidence-consistent change, regenerate: `cargo run -q -p frankenengine-engine --bin franken_claim_evidence_ledger -- generate`. |
| `test262_posture` | The Test262 posture drifted across `docs/test262_compatibility_pass_rate_v1.json`, the `FE-CLAIM-TEST262` matrix row, and the README. | Re-align all three to `full_suite_claim_allowed=false` / `full-suite conformance is TARGETED`. |

## Regenerating after an intentional change

When you *intentionally* change a claim's state or its evidence (e.g. a CEI
downgrade or a re-emitted receipt), regenerate the derived artifacts **in this
order**, then re-run the capstone:

1. Re-emit receipts (if you re-ran a gate): `python3 scripts/reemit_evidence_receipts.py --only FE-CLAIM-XXX`
2. Regenerate the content-addressed evidence manifests: `franken_evidence_manifest generate`
3. Regenerate the Merkle ledger root: `franken_claim_evidence_ledger generate`
4. Re-run the capstone: `./scripts/run_claim_evidence_integrity_capstone.sh ci`

## Replay (determinism check)

`scripts/e2e/claim_evidence_integrity_capstone_replay.sh ci` re-runs the capstone
against the latest (or a pinned) bundle and confirms the overall verdict and the
per-sub-gate verdicts reproduce. It fails closed on an incomplete bundle. Exit
codes: `0` match, `1` no prior bundle, `2` incomplete bundle, `3` overall verdict
mismatch, `4` per-sub-gate verdict mismatch.

## No-mock acceptance drill

`crates/franken-engine/tests/claim_evidence_integrity_capstone_nomock.rs` (CEI
G.3, `bd-sde5e.7.3`) proves the capstone cannot be satisfied by fixtures: it
injects an over-promotion (e.g. flips a committed receipt to `pending`, or untracks
an artifact) into a throwaway worktree copy and asserts the capstone goes red,
then restores the tree.
