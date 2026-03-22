# RGC-617C: Signature Drift Gate V1

> Gates adaptive performance claims and shipped behavior on regime signature
> drift and transition-budget compliance.

## Purpose

When FrankenEngine makes an adaptive performance claim (e.g., "throughput
improves under regime X"), the claim is only valid within the regime context
where it was measured. If the workload drifts into a different regime, or the
signature features shift beyond a tolerance threshold, or the runtime has
consumed its transition budget, the claim must be automatically downgraded or
blocked.

This gate converts regime geometry into product truth: unknown regimes,
excessive drift, or budget violations automatically downgrade claims and shipped
behavior.

## Contract

| Property | Value |
|---|---|
| Schema version | `franken-engine.signature-drift-gate.v1` |
| Module | `crates/franken-engine/src/signature_drift_gate.rs` |
| Binary | `franken_signature_drift_gate` |
| Runner | `scripts/run_rgc_signature_drift_gate.sh` |
| Replay | `scripts/e2e/rgc_signature_drift_gate_replay.sh` |
| Policy ID | `RGC-617C` |
| Bead | `bd-1lsy.7.17.3` |
| Parent bead | `bd-1lsy.7.17` (RGC-617) |

## Drift Measurement

Drift between a baseline and current signature snapshot is measured as:

- **L1 (Manhattan) drift**: sum of absolute per-feature differences across
  shared dimensions, in millionths.
- **L∞ (Chebyshev) drift**: maximum single-feature absolute difference.
- **Missing/new features**: features present in one snapshot but not the other.
- **Regime change**: whether the regime label changed between snapshots.

## Transition Budget

Each evaluation window has a fixed transition budget (default: 10). Each
detected regime transition consumes one unit. When the budget is exhausted,
claims are downgraded regardless of drift magnitude.

## Gate Verdicts

| Verdict | Meaning |
|---|---|
| `pass` | Drift and budget within limits; claim is valid |
| `downgrade` | One or two violations detected; claim scope is narrowed |
| `block` | Multiple severe violations; claim is invalid |
| `abstain` | Insufficient evidence to decide (low observations, no shared dimensions) |

## Downgrade Reasons

| Reason | Trigger |
|---|---|
| `excessive_l1_drift` | L1 drift exceeds `max_l1_drift_millionths` (default 150,000 = 15%) |
| `excessive_linf_drift` | Single-feature drift exceeds `max_linf_drift_millionths` (default 75,000 = 7.5%) |
| `transition_budget_exhausted` | Transitions consumed exceed `max_transitions` (default 10) |
| `regime_changed` | Regime label changed and `regime_change_triggers_downgrade` is true |
| `stale_baseline` | Baseline epoch is more than `max_staleness_epochs` (default 5) old |
| `insufficient_baseline_observations` | Baseline has fewer than `min_observations` (default 10) |
| `insufficient_current_observations` | Current snapshot has fewer than `min_observations` |
| `no_shared_dimensions` | No features in common between baseline and current |

## Evidence Corpus

The gate ships a built-in evidence corpus of 7 specimen families:

1. **Stable low drift** — passes (low L1, same regime, budget unused)
2. **Moderate drift** — passes (within thresholds)
3. **Excessive drift** — downgraded (L1 exceeds threshold)
4. **Regime change** — downgraded (regime label changed)
5. **Budget exhaustion** — downgraded (transitions exceed budget)
6. **Stale baseline** — downgraded (baseline too old)
7. **Insufficient data** — abstains (too few observations)

All specimens are verified against expected verdicts on every gate invocation.

## Claim Scope Ledger

The `ClaimScopeLedger` tracks the regime scope under which each claim is valid,
including:

- Valid regime at claim establishment
- Baseline signature hash
- Maximum passing drift observed
- Active/deactivated status
- Deactivation reason (if any)

Gate decisions are applied to the ledger via `apply_decision()`, which
deactivates claims on `block` verdicts and tracks drift history on `pass`.

## Runner Usage

```bash
# Full CI gate (check + run + validate artifacts)
./scripts/run_rgc_signature_drift_gate.sh ci

# Deterministic replay wrapper
./scripts/e2e/rgc_signature_drift_gate_replay.sh ci

# Override epoch
RGC_SIGNATURE_DRIFT_GATE_EPOCH=77 ./scripts/run_rgc_signature_drift_gate.sh ci
```

## Artifacts

Each invocation emits under `artifacts/rgc_signature_drift_gate/<timestamp>/`:

| File | Content |
|---|---|
| `run_manifest.json` | Trace/decision/policy IDs, epoch, artifact paths, replay command |
| `signature_drift_gate_report.json` | Full gate report with specimen verdicts and batch result |
| `trace_ids.json` | Component, policy, trace, decision, and run IDs |
| `events.jsonl` | Structured completion event |
| `commands.txt` | Exact executed command transcript |
| `summary.md` | Human-readable summary |
| `env.json` | Epoch, toolchain, source commit |
| `repro.lock` | Deterministic replay lock with manifest hash |

## Dependencies

- `bd-1lsy.7.17.2` (RGC-617B): Entropic policy morphing and transition-budget control
- `bd-1lsy.8.3` (RGC-703): Performance regression gate with culprit isolation

## Dependents

- `bd-1lsy.8.5.2` (RGC-705B): Supremacy verdicts with sequential statistics
