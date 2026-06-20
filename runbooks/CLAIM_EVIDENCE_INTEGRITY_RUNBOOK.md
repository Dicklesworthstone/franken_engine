# Claim-Evidence Integrity Gate — Operator Runbook

> CEI Track A (`bd-sde5e.1`). Capstone: `bd-sde5e.1.6`.
> Gate reference: [`docs/operator-gates/CLAIM_EVIDENCE_INTEGRITY_GATE_REFERENCE.md`](../docs/operator-gates/CLAIM_EVIDENCE_INTEGRITY_GATE_REFERENCE.md).

## What this gate enforces

The historical claim-to-proof gate (`scripts/run_claim_to_proof_matrix_gate.sh`)
only checks **one** direction of the constitutional contract (`RUNTIME_CHARTER.md`
§7):

```
README wording state  ≤  matrix.allowed_state          (already enforced)
```

The claim-evidence integrity gate closes the missing direction:

```
matrix.allowed_state  ≤  evidence actually committed     (this gate)
```

For every claim row it derives an **evidence tier** purely from machine-checkable
facts and refuses any row that asserts more than its evidence licenses:

| Fact (all must hold for the higher tier) | Source |
|---|---|
| artifact is git-tracked | `git ls-files docs/evidence/<CLAIM>` |
| `verification_result == passed` and **not** backfill-generated | bundle `manifest.json` |
| zero-exit run receipt | committed `repro.lock` `expected_outputs.exit_code == 0` |
| committed `repro.lock` partner present | `git ls-files .../repro.lock` |
| **fresh** by the A.4 e-process boundary | real age vs `FreshnessEProcess` |
| adversarially verified | A.5 corpus / Track H |

```
Unbacked < Asserted < Exercised < Reproduced < AdversariallyVerified
   |          |           |            |
Hypothesis  Target      Target      Observed  (= ceiling(tier))
```

A row is **over-promoted** (unsound) when `asserted_state > ceiling(tier)`.

### Freshness is principled, not a cliff (A.4)

Freshness is judged by an **anytime-valid e-process** (Ville's inequality), not a
fixed `age <= 30` cliff. Each elapsed day of non-reverification contributes a
log-likelihood-ratio increment `ln(1/α)/horizon` toward staleness; freshness is
rejected once the e-value reaches `1/α` (false-staleness-alarm probability `≤ α`).
With the default policy `(α = 0.05, horizon = 30)` the boundary is first crossed
on **day 31**, so a bundle is fresh through 30 days and stale at 31+. The policy
lives in the matrix as `freshness_eprocess_policy`; **per-claim freshness is
computed from committed-evidence timestamps, never authored.**

## Running the gate

```bash
# Advisory (default): lists over-promoted rows, exits 0.
scripts/run_claim_evidence_integrity.sh ci

# Blocking: exits 1 if any row over-promotes. Composed by the G.1 meta-gate.
scripts/run_claim_evidence_integrity.sh blocking
```

Skip the build with a prebuilt binary:

```bash
FRANKEN_EVIDENCE_MANIFEST_BIN=target/debug/franken_evidence_manifest \
  scripts/run_claim_evidence_integrity.sh ci
```

Each run writes a content-addressed **standard bundle** under
`artifacts/claim_evidence_integrity/<UTC-timestamp>/`:

```
run_manifest.json   verdict + coverage + over_promoted + per-file sha256 + git_rev
audit_report.txt    raw audit stdout (over-promotion list + coverage)
events.jsonl        structured trace events (gate.start … gate.end)
trace_ids.json      trace/decision/policy ids for cross-referencing
commands.txt        every command run, in order
step_logs/          per-step stdout/stderr (step_000 locate-bin, step_001 audit)
```

## Replay (drift detection)

```bash
# Re-run against the most-recent bundle and confirm the verdict is reproduced.
scripts/e2e/claim_evidence_integrity_replay.sh ci

# Pin a specific source bundle.
CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR=artifacts/claim_evidence_integrity/<ts> \
  scripts/e2e/claim_evidence_integrity_replay.sh ci
```

The replay wrapper **fails closed** (exit 2) on an incomplete bundle — a hollow
fixture cannot masquerade as a real run. Exit codes: `0` match · `1` no source
bundle · `2` incomplete bundle · `3` verdict mismatch · `4` coverage mismatch.

## End-to-end smoke

```bash
scripts/e2e/claim_evidence_integrity_gate_smoke.sh ci
```

Runs the gate, validates the complete bundle, checks the manifest content hashes,
replays, and proves the fail-closed property (a bundle missing an artifact is
rejected). Exit `0` on success.

## Reading the result

- `verdict`: `advisory_pass` (ci) or `pass`/`fail` (blocking).
- `over_promoted`: number of rows asserting more than their evidence licenses.
  A non-zero count in advisory mode is the honest drift signal that Tracks B–D
  are closing; it is **expected** until every OBSERVED row has committed,
  freshly-verified, reproducible evidence.

## Remediating an over-promoted row

For each `OVER-PROMOTED <CLAIM> asserts=observed but evidence tier=… ceiling=…`:

1. **Unbacked → artifact not git-tracked.** Commit the bundle under
   `docs/evidence/<CLAIM>/` (Track B.1). "No artifact, no claim."
2. **Asserted → verification pending / backfill.** Re-emit a real passing receipt
   from the live gate (Track B.2, `scripts/reemit_evidence_receipts.py`); never
   fake `verification_result`.
3. **Exercised → no committed `repro.lock` or stale.** Add the reproducibility
   partner (Track B.3), or refresh the bundle if the e-process flagged it stale.
4. **Genuinely cannot reach Observed.** Downgrade the matrix `allowed_state` to
   `target`/`hypothesis` and the README wording to match (Track C). Honesty is a
   valid fix.

After remediation, re-run the gate and confirm `over_promoted` dropped.

## Tests

| Layer | Location |
|---|---|
| A.1 scorer + lattices + coverage | `claim_evidence_lattice.rs` unit tests |
| A.2 whole-document consistency | `claim_evidence_lattice.rs` + `claim_evidence_lattice_integration.rs` |
| A.3 enforcement gate | `claim_evidence_integrity_gate.rs` |
| A.4 e-process freshness | `claim_evidence_lattice.rs` unit tests + `claim_evidence_freshness_eprocess.rs` |
| A.5 adversarial / metamorphic corpus | `claim_evidence_adversarial_corpus.rs` |
| A.6 capstone (real-data composition) | `claim_evidence_track_a_capstone.rs` |
| A.6 e2e (bundle + replay + fail-closed) | `scripts/e2e/claim_evidence_integrity_gate_smoke.sh` |

> Build note: the engine **lib-test** compile is memory-heavy and OOMs on the
> remote rch worker (SIGKILL). Run the lib/integration tests locally with
> `RCH_CARGO_WRAPPER_BYPASS=1` on a host with adequate RAM.
