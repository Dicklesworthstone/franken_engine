# Conformal Calibration Drift Operator Surface

Operator runbook for interpreting conformal calibration drift warnings and
deciding when to retrain, demote, reset, or leave the runtime alone.

## Bead anchors

- Track parent: **bd-cixqu.33** (Track GG - conformal prediction).
- This document: **bd-cixqu.33.5** (GG.5 operator-runbook).
- Engine surfaces:
  - `crates/franken-engine/src/runtime_decision_theory.rs`
    (`ConformalCalibrator`, `CalibrationLedgerEntry`,
    `DemotionReason::CoverageViolation`).
  - `crates/franken-engine/src/hybrid_lane_router.rs`
    (`ConformalState`, `DemotionReason::ConformalViolation`).
  - `crates/franken-engine/src/expected_loss_selector.rs`
    (`AlienRiskEnvelope` conformal p-value, quantile, and e-value).
- Configuration surface:
  `crates/franken-engine/src/runtime_config.rs`
  (`DecisionThresholdsConfig`).

## What the warning means

A conformal calibration drift warning means recent observations no longer match
the coverage promise that made the current decision or routing policy safe to
use. It is not a throughput warning and it is not proof that the runtime is
wrong. It is evidence that the online validity monitor can no longer justify
adaptive behavior without new calibration evidence.

All conformal values are fixed-point millionths. `1_000_000` means `1.0`,
`900_000` means 90% coverage, `100_000` means 10% alpha, and `50_000` means
5% p-value. Do not re-derive operator decisions with floats.

## Signals to read

| Signal | Healthy reading | Drift reading | Engine action |
|---|---:|---:|---|
| `ConformalCalibrator::coverage_millionths()` | `>= 1_000_000 - alpha_millionths` after warmup | below target after warmup | marks the context uncalibrated |
| `CalibrationLedgerEntry.violation` | `false` | `true` | latest ledger row is the audit anchor |
| `ConformalCalibrator::violation_flagged()` | `false` | `true` | `DecisionContext` falls back safe with `coverage_violation` |
| `ConformalState::coverage_millionths()` | `>= target_coverage_millionths` after `min_observations` | below target after `min_observations` | adaptive router demotes to conservative |
| `AlienRiskEnvelope.conformal_p_value_millionths` | `> elevated_pvalue_millionths` | `<= elevated` or `<= critical` | recommends a stronger containment floor |
| `AlienRiskEnvelope.e_value_millionths` | near baseline | rising after misses | supports the drift warning |

The default decision thresholds treat p-values at or below `100_000` as
elevated and at or below `50_000` as critical. The default router coverage
target is `900_000` with a `100` observation rolling window and `20` observation
warmup. The default decision-context conformal alpha is `100_000`, with `50`
calibration observations required before enforcement and `5` consecutive misses
required before a violation is flagged.

## Diagnose

1. Confirm warmup. If the monitor has fewer observations than its configured
   `min_calibration_observations` or `min_observations`, the warning is
   informational only. Do not retrain from pre-warmup evidence.
2. Confirm the unit. Coverage, alpha, p-values, quantiles, and e-values are
   millionths. A report that says `0.9` has already converted for display; the
   persisted value should be `900_000`.
3. Read the latest calibration ledger entry. The fields that matter are
   `epoch`, `prediction_covered`, `running_coverage_millionths`,
   `e_value_millionths`, and `violation`.
4. Separate coverage drift from ordinary failures. In the hybrid router,
   `in_bounds` means the lane succeeded, emitted no compatibility errors, and
   did not enter safe mode. A low coverage reading caused by compatibility
   errors is still a valid conformal violation, but retraining the conformal
   model alone will not fix the underlying lane.
5. Check whether the runtime already demoted. `coverage_violation` in
   `DecisionContext` means fallback-safe is active. `ConformalViolation` in the
   hybrid router means adaptive routing has moved to conservative policy.

## Decide

| Condition | Operator decision |
|---|---|
| Below warmup only | Keep collecting observations. Do not reset or retrain. |
| One miss, coverage still above target | No action. Keep the ledger row. |
| Coverage below target but no violation flag yet | Freeze promotion of new adaptive lanes; collect enough evidence to distinguish noise from drift. |
| `violation_flagged == true` or router `ConformalViolation` | Keep fallback/conservative policy active. Open a retraining or recalibration task before re-promotion. |
| p-value `<= 100_000` and `> 50_000` | Treat as elevated. Prefer sandbox or conservative routing for affected policy decisions. |
| p-value `<= 50_000` | Treat as critical. Require operator approval before restoring adaptive behavior. |
| Coverage violation plus compatibility errors | Fix or quarantine the failing lane first; retrain only after compatibility is stable. |
| Coverage violation after an intentional policy change | Retrain against post-change observations. Do not mix pre-change calibration rows into the new baseline. |

## When to retrain

Retrain or recalibrate when the warning is post-warmup and tied to a stable
shift in the evidence stream:

- the latest ledger row has `violation: true`;
- consecutive misses reached `max_consecutive_violations`;
- rolling router coverage is below `target_coverage_millionths` after warmup;
- conformal p-value is at or below the configured elevated threshold;
- the same policy, lane, or extension family repeats the warning across more
  than one security epoch.

Do not retrain when the evidence is still warming up, when a single outlier has
not moved coverage below target, or when the root cause is a deterministic
compatibility failure. In those cases, keep the safe fallback, fix the cause, and
let the next calibration window supply evidence.

## Reset policy

`ConformalCalibrator::reset()` is operator-authorized state mutation. Use it only
after a new calibration baseline is accepted. A reset clears total predictions,
covered predictions, consecutive violations, e-value, violation flag, and the
in-memory ledger. Preserve the pre-reset ledger in the incident artifact before
resetting so the old warning remains auditable.

Never reset to make an active warning disappear. If fallback-safe or conservative
policy is active, reset is the last step after the retraining evidence has been
reviewed, not the first step in the response.

## Verification checklist

- The incident record names the affected policy, lane, extension family, epoch,
  and monitor surface.
- Coverage and p-value numbers are recorded in millionths.
- The latest calibration ledger row is attached or referenced.
- The response records whether the runtime demoted itself or the operator
  applied manual demotion.
- Any retraining decision names the post-change data window used for the new
  calibration baseline.
- Any reset records the operator approval and the preserved pre-reset ledger.

## What not to do

- Do not turn adaptive routing back on while `violation_flagged()` is true.
- Do not compare display floats against persisted millionths.
- Do not mix pre-change and post-change calibration windows after a policy or
  lane semantics change.
- Do not treat conformal drift as a generic performance alarm. It is a coverage
  validity alarm.
- Do not suppress a violation ledger row from reports. The row is the proof that
  the runtime failed closed.
