# Gate Reference — Claim-Evidence Integrity (CEI Track A)

> Owning epic: `bd-sde5e` (CEI). Track A: `bd-sde5e.1`. Capstone: `bd-sde5e.1.6`.
> Operator runbook: [`runbooks/CLAIM_EVIDENCE_INTEGRITY_RUNBOOK.md`](../../runbooks/CLAIM_EVIDENCE_INTEGRITY_RUNBOOK.md).

## Purpose

Enforce the missing direction of the claim-to-proof contract
(`RUNTIME_CHARTER.md` §7): the matrix `allowed_state` of every claim row must not
exceed the evidence actually committed to the repository. The historical gate
checked only `README ≤ matrix`; this gate checks `matrix ≤ evidence`, closing the
soundness gap the 2026-06-18 reality check found.

## Components

| Bead | Component | Implementation |
|---|---|---|
| A.1 `bd-sde5e.1.1` | Evidence-tier scorer, claim/evidence lattices, coverage metric | `crates/franken-engine/src/claim_evidence_lattice.rs` |
| A.2 `bd-sde5e.1.2` | Whole-document claim-consistency index | same module (`scan_document_consistency`) |
| A.3 `bd-sde5e.1.3` | Enforcement gate (`audit [--blocking]`) | `crates/franken-engine/src/bin/franken_evidence_manifest.rs` |
| A.4 `bd-sde5e.1.4` | Principled freshness via e-process boundary | `claim_evidence_lattice.rs::FreshnessEProcess` |
| A.5 `bd-sde5e.1.5` | Adversarial + metamorphic self-audit corpus | `tests/claim_evidence_adversarial_corpus.rs` |
| A.6 `bd-sde5e.1.6` | Standard-bundle runner, replay wrapper, runbook, this reference | `scripts/run_claim_evidence_integrity.sh`, `scripts/e2e/claim_evidence_integrity_*` |

## Lattices

```
Claim assertion state:   Hypothesis < Target < Observed
Evidence tier:           Unbacked < Asserted < Exercised < Reproduced < AdversariallyVerified

ceiling(Unbacked)              = Hypothesis
ceiling(Asserted|Exercised)    = Target
ceiling(Reproduced|Adversarial)= Observed
```

`tier` is a monotone ladder over six positive facts; `ceiling` is non-decreasing.
A row is **sound** iff `asserted_state ≤ ceiling(tier(facts))`. The fraction of
sound rows is the content-addressed **claim-integrity-coverage**.

### Freshness e-process (A.4)

Freshness is an anytime-valid sequential test rather than a fixed cliff. With
policy `(α, horizon)`:

```
log_threshold = ln(1/α)                       # rejection boundary (Ville)
daily         = floor(ln(1/α) / horizon)      # per-day staleness log-LR
E_age         = exp(daily · age)              # product martingale e-value
fresh         ⇔ E_age < 1/α   ⇔ age < bound_days
```

Default `(α = 0.05, horizon = 30)` → `bound_days = 31` (fresh ≤ 30 days, stale at
31+), reproducing the legacy window as a *derived* consequence. The policy is
declared in `docs/claim_to_proof_matrix_v1.json :: freshness_eprocess_policy`;
per-claim `freshness_days` is **computed, never authored** (all null). Real age is
the manifest `generated_at_utc`, falling back to the artifact's git commit time.

## Invocation

```
scripts/run_claim_evidence_integrity.sh [ci|blocking] [run_dir]
```

| Mode | Behaviour | Exit |
|---|---|---|
| `ci` (default) | advisory: report over-promoted rows | always `0` |
| `blocking` | fail-closed: enforce `matrix ≤ evidence` | `0` sound · `1` any over-promotion |

### Environment

| Variable | Effect |
|---|---|
| `CLAIM_EVIDENCE_INTEGRITY_BLOCKING=1` | force blocking mode |
| `CLAIM_EVIDENCE_INTEGRITY_ARTIFACT_ROOT` | override `artifacts/claim_evidence_integrity` |
| `CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR` | pin the gate output dir (used by the replay wrapper) |
| `FRANKEN_EVIDENCE_MANIFEST_BIN` | prebuilt audit binary (skip the build) |

## Standard bundle

`artifacts/claim_evidence_integrity/<UTC-ts>/`:

| Artifact | Schema |
|---|---|
| `run_manifest.json` | `franken-engine.claim-evidence-integrity-gate.run-manifest.v1` |
| `events.jsonl` | `…-gate.event.v1` (one object per line) |
| `trace_ids.json` | `…-gate.trace-ids.v1` |
| `audit_report.txt` | raw audit stdout |
| `commands.txt` | commands run, in order |
| `step_logs/step_NNN.log` | per-step stdout/stderr |

`run_manifest.json` carries `verdict`, `coverage`, `over_promoted`,
`audit_exit_code`, `git_rev`, and a `content_hashes` map binding the bundle to its
bytes for replay/drift detection.

## Replay

```
scripts/e2e/claim_evidence_integrity_replay.sh [ci|blocking]
```

Re-runs the gate against a pinned (`CLAIM_EVIDENCE_INTEGRITY_REPLAY_RUN_DIR`) or
auto-detected latest bundle and compares `verdict` + `coverage` + `over_promoted`.
Emits `comparison_report.json`
(`franken-engine.claim-evidence-integrity-gate.replay-report.v1`).

| Exit | Meaning |
|---|---|
| 0 | verdict + coverage reproduced |
| 1 | no source bundle found |
| 2 | bundle incomplete (fail-closed) |
| 3 | verdict mismatch |
| 4 | coverage / over-promotion mismatch |

## End-to-end smoke

```
scripts/e2e/claim_evidence_integrity_gate_smoke.sh ci
```

Validates a complete bundle, manifest content hashes, replay reproduction, and the
fail-closed rejection of an incomplete bundle. Exit `0` on success, `1` on any
failed check, `2` on a missing prerequisite.

## GA-exit linkage

This gate is composed into the G.1 integrity meta-gate
(`bd-sde5e.7.1`) in **blocking** mode once Track B has re-emitted real receipts for
every OBSERVED row. Until then it runs advisory and its `over_promoted` count is
the honest drift signal tracked by Tracks B–D.
