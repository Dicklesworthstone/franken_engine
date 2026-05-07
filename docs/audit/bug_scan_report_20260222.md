# FrankenEngine Comprehensive Bug Scan Report

**Date:** 2026-02-22
**Scanner:** PearlTower (Claude Opus 4.6)
**Scope:** All production (non-test) code in `crates/franken-engine/src/` and `crates/franken-extension-host/src/`

---

## Summary

**Total confirmed bugs found: ~65**

Bugs are categorized by severity and type below.

---

## HIGH SEVERITY

### 1. `capability_witness.rs:295` — Wilson score margin uses wrong constant (1000x too small)
```rust
let margin = 1_960 * disc_sqrt / denom;
```
**Bug:** Should be `1_960_000` (z=1.96 in millionths). Confidence intervals collapse to near-zero width, undermining all confidence-based gating.
**Fix:** `let margin = 1_960_000 * disc_sqrt / denom;`

### 2. `capability_witness.rs:288` — Wilson score correction term has wrong formula
```rust
let correction = z2_over_n * z2_over_n / 4 / n;
```
**Bug:** Computes `z^4/(4n^3)` instead of `z^2/(4n^2)`. Extra `/n` makes correction term n-times too small.
**Fix:** `let correction = z2_over_n * 1_000_000 / 4 / n;`

### 3. `capability_witness.rs:1126-1136,1783` — `verify_integrity()` fails for any post-build witness
**Bug:** `content_hash` is computed during `build()` in Draft state. After `transition_to` or `apply_promotion_theorem_report` changes lifecycle_state/metadata/proofs, `unsigned_bytes()` differs, so `verify_integrity()` always fails. Called in `index_witness` (line 1783), blocking indexing of promoted/active witnesses.
**Fix:** Reset to draft state before computing hash (like `verify_witness_synthesis_binding` does), or update hash on mutation.

### 4. `franken-extension-host/src/lib.rs:3181` — Wrong variable for `active_witness_ref` (copy-paste error)
```rust
context.policy_id.to_string(), // param: active_witness_ref -- BUG
```
**Bug:** `active_witness_ref` is set to `policy_id.to_string()`, duplicating the policy_id argument. Every capability escrow receipt has wrong `active_witness_ref`, and signatures are computed over incorrect data.
**Fix:** Pass the correct witness reference (e.g., `trace_ref.clone()`).

### 5. `franken-extension-host/src/lib.rs:1351-1353` — `transition_requires_manifest` blocks Terminate/Quarantine during Validating
```rust
fn transition_requires_manifest(transition: LifecycleTransition) -> bool {
    !matches!(transition, LifecycleTransition::Validate)
}
```
**Bug:** Returns `true` for `Terminate` and `Quarantine`, blocking safety-critical containment transitions from `Validating` state when no manifest is set. Misbehaving extensions cannot be terminated during validation.
**Fix:** Add `| LifecycleTransition::Terminate | LifecycleTransition::Quarantine | LifecycleTransition::Finalize` to the exclusion list.

### 6. `privacy_learning_contract.rs:1397-1441` — Delta DP fields missing from governance signature
**Bug:** `build_unsigned_view()` includes epsilon fields but omits `delta_per_epoch_millionths` and `lifetime_delta_budget_millionths`. Delta budget can be tampered with without invalidating the governance signature.
**Fix:** Add delta fields to the unsigned view map.

### 7. `privacy_learning_contract.rs:386-403` — `max_epochs()` ignores delta budget
**Bug:** Computes max epochs from epsilon only. Delta budget can exhaust before epsilon, allowing more epochs than privacy permits.
**Fix:** `eps_epochs.min(delta_epochs)`

### 8. `forensic_replayer.rs:888-908` — Suspended extensions cannot be Terminated or Quarantined
**Bug:** `ContainmentState::is_alive()` returns `false` for `Suspended`. Terminate/Quarantine actions check `is_alive()`, so they silently no-op on suspended extensions.
**Fix:** Use state-specific guards instead of `is_alive()`.

### 9. `containment_executor.rs:385-388` — `cooperative` flag inverted
```rust
let cooperative = matches!(action, ContainmentAction::Terminate | ContainmentAction::Quarantine);
```
**Bug:** `Terminate` and `Quarantine` are forced actions, not cooperative. Flag is backwards.
**Fix:** `let cooperative = !matches!(action, ContainmentAction::Terminate | ContainmentAction::Quarantine);`

### 10. `self_replacement.rs:787-793` — `GateVerdict::Inconclusive` is dead code
**Bug:** `all(passed)` and `any(!passed)` are logical complements for non-empty iterators. The `Inconclusive` branch is unreachable.
**Fix:** Check for empty `gate_results` first, returning `Inconclusive` for that case.

### 11. `reputation.rs:768-790` — Transitive revocation dependents never get trust degraded
**Bug:** BFS populates `transitively_affected` set but never applies trust degradation to those extensions. Only direct dependents are degraded.
**Fix:** Apply `transition_trust` to transitively affected extensions too.

### 12. `trust_economics.rs:292-303` — `asymmetry_violations` only checks Allow action
```rust
if action == ContainmentAction::Allow && malicious_loss < benign_loss {
```
**Bug:** Should check all actions, not just `Allow`. The `action == ContainmentAction::Allow &&` guard makes the invariant check nearly useless.
**Fix:** Remove the `action == ContainmentAction::Allow &&` guard.

### 13. `tee_attestation_policy.rs:536` — Revocation loop short-circuits on first Good
```rust
RevocationProbeStatus::Good => return Ok(()),
```
**Bug:** If source #1 says Good but source #2 says Revoked, the revocation is missed entirely.
**Fix:** Track `Good` seen but continue iterating all sources; fail if any is `Revoked`.

### 14. `extension_lifecycle_manager.rs:881-888` — `quarantine_on_timeout` applied on success path
**Bug:** When cooperative shutdown succeeds within grace period, `quarantine_on_timeout` still quarantines. The flag should only be consulted when the grace period expires.
**Fix:** Always finalize on the success path; check `quarantine_on_timeout` only in the timeout path.

### 15. `execution_orchestrator.rs:619` — Suspend mapped to Revocation saga
```rust
ContainmentAction::Suspend => Some(SagaType::Revocation),
```
**Bug:** Suspension is temporary; revocation is permanent. Wrong saga type.
**Fix:** `Some(SagaType::Suspension)`

---

## MEDIUM SEVERITY

### 16. `frankentui_adapter.rs:501,506` — `.min()` instead of `.max()` in refresh policy
**Bug:** `.min(5)` caps at 5 instead of enforcing a minimum of 5. `.min(60)` same issue.
**Fix:** Change to `.max(5)` and `.max(60)`.

### 17. `conformance_harness.rs:1963` — Minimizer uses original strings, not candidate-derived
**Bug:** `preserves_failure_class(expected, actual, failure_class)` always tests the unchanged originals, making minimization always strip to 1 segment.

### 18. `portfolio_governor.rs:886-895` — Friction score counts all artifacts, not distinct obligations
**Bug:** `completed_artifacts.len()` counts submissions, not distinct obligations met. Can produce 0 friction even if most obligations are unmet.

### 19. `proof_specialization_linkage.rs:143-145` — `proofs_valid_at` uses `<=` instead of `==`
**Bug:** Other epoch checks in the codebase require exact epoch match. `<=` is inconsistent.

### 20. `migration_contract.rs:245-250` — `VerificationFailed` is terminal, preventing rollback
**Bug:** If verification fails after partial data migration, rollback is impossible.

### 21. `attested_execution_cell.rs:35` — Typo in schema constant
```rust
const CELL_SCHEMA_DEF: &[u8] = b"AttstedExecutionCell.v1";  // missing 'e'
```

### 22. `anti_entropy.rs:961` — `current_rate_pct()` iterates full buffer instead of window
**Bug:** Should iterate `self.outcomes[..window_size]`, not `self.outcomes`.

### 23. `activation_lifecycle.rs:752` — `advance_rollout()` skips `Updating(Default)` state
**Bug:** Guard `next != RolloutPhase::Default` causes Ramp->Active, skipping Default phase.

### 24. `cancellation_lifecycle.rs:490` — `success: finalize_result.success || timeout_escalated`
**Bug:** Timeout escalation (failure) incorrectly makes success=true.

### 25. `safe_mode_fallback.rs:591` — `recover()` skips `Recovering` state
**Bug:** Transitions directly Active->Normal, bypassing the documented Recovering state.

### 26. `safe_mode_fallback.rs:1303-1304` — StaleData mapped to EvidenceUnavailable
**Bug:** Should be `EvidenceExpired`. Stale data is not missing data.

### 27. `adversarial_campaign.rs:1602` — Counterfactual hints clamp with `.min(0)`
**Bug:** All positive margins (detected campaigns) produce hint value 0. Should preserve raw delta.

### 28. `adversarial_campaign.rs:1687` — `is_near_miss` classifies full evasion as near-miss
**Bug:** When `undetected_steps == total_steps`, should not be "near miss".

### 29. `adversarial_campaign.rs:408-416` — Feedback dead zone for scores 25-70%
**Bug:** Both `amplification` and `decay` are 0 for mid-range evasion scores.

### 30. `adversarial_campaign.rs:2230-2231` — Suppression gate uses `<` instead of `<=`
**Bug:** Equal compromise rate (including both at 0) fails the gate.

### 31. `adversarial_campaign.rs:1710-1714` — Tie-breaking is dead code
**Bug:** `dimension < dominant` during forward BTreeMap iteration can never be true. Ties always resolve to `HostcallSequence`.

### 32. `adversarial_campaign.rs:619` — `novel_bonus` scaled to 150_000 not 1_000_000
**Bug:** Makes the 5% novel_technique weight effectively 0.75%.

### 33. `adversarial_campaign.rs:1571` — Regression gate uses wrong error code
**Bug:** Uses `ERR_INVALID_CALIBRATION` instead of a gate-specific error code.

### 34. `trust_card.rs:716-725` — `compute_risk_trend` missing degradation counting
**Bug:** Within non-degraded tiers: downward moves not counted. Within degraded tiers: all moves ignored.

### 35. `revocation_freshness.rs:483-488` — `Recovering` state allows all operations
**Bug:** `Recovering` should still restrict operations during holdoff period.

### 36. `revocation_freshness.rs:618-625` — Fresh->Degraded skips Stale state
**Bug:** Violates documented state machine `Fresh -> Stale -> Degraded`.

### 37. `session_hostcall_channel.rs:1173` — Session expiry uses `>` instead of `>=`
**Bug:** Session lives one tick longer than `max_lifetime_ticks`.

### 38. `session_hostcall_channel.rs:1194-1207` — Replay drop threshold off-by-one
**Bug:** `count >= threshold` triggers on count==threshold, but "threshold of 8" should trigger after 8.

### 39. `hostcall_telemetry.rs:624-628` — `denial_rate_millionths` uses `i64` for non-negative rate
**Bug:** `u64` cast to `i64` can overflow for large values, producing negative rates.

### 40. `hostcall_telemetry.rs:401` — Snapshot `record_id_at_snapshot` wrong for empty recorder
**Bug:** Empty recorder produces `record_id_at_snapshot: 0`, implying record 0 exists.

### 41. `idempotency_key.rs:469` — `advance_epoch` clears all entries
**Bug:** `retain(|_, entry| entry.epoch == new_epoch)` matches nothing since no entries have the new epoch yet.

### 42. `idempotency_key.rs:489-494` — `evict_expired` applies one computation's TTL to all
**Bug:** Uses the specified computation's TTL for all entries, ignoring per-computation TTLs.

### 43. `franken-extension-host/src/lib.rs:1121` — Cooperative termination deadline off-by-one
**Bug:** `<=` should be `<`; at exact deadline, forced termination is blocked.

### 44. `demotion_rollback.rs:232-247` — `zone` missing from canonical ID preimage
**Bug:** Two receipts in different zones with same fields collide.

### 45. `demotion_rollback.rs:830` — Divergence threshold uses `>` instead of `>=`
**Bug:** Allows `max_divergence_count + 1` divergences before triggering.

### 46. `migration_compatibility.rs:1596` — `declared_at` set to finalization time
**Bug:** Uses `self.current_tick` at finalization, not the original declaration tick.

### 47. `feature_parity_tracker.rs:418` — Error code `FE-FPT-0008` out of sequence
**Bug:** `WaiverNotFound` has code 0008 instead of 0002; subsequent codes shifted.

### 48. `slot_registry.rs:1538-1539` — `is_ga_ready()` allows PromotionCandidate slots
**Bug:** `delegate_count() == 0` doesn't catch PromotionCandidate status. Should check `native_count() == slots.len()`.

### 49. `slot_registry.rs:357` — `NonCore` Display uses underscore instead of kebab-case
**Bug:** `"non_core"` inconsistent with all other Display impls that use kebab-case.

### 50. `slot_registry.rs:991-1004` — `expected_value_score_millionths` stores weighted value
**Bug:** Stores `weighted_ev` (EV * weight / 1M) in field named for raw EV score.

### 51. `lowering_pipeline.rs:863-865` — `fs.read` returns `Label::Secret` (inconsistent)
**Bug:** `fs.write` returns `Label::Internal`. `fs.read` at `Secret` is inconsistent with other filesystem operations.

### 52. `key_attestation.rs:308` — `is_expired` uses `>=` (debatable)
**Bug:** Attestation expired at exactly `expires_at` tick. May want `>` for inclusive validity.

### 53. `tee_attestation_policy.rs:691` — Override expiry uses `>` instead of `>=`
**Bug:** Override at exactly the expiry epoch is still valid.

### 54. `tee_attestation_policy.rs:786-791` — Swapped expected/actual in OverrideTargetMismatch

### 55. `safe_mode_fallback.rs:610-614` — Wrong outcome for non-activate/non-recover phases
**Bug:** `validate_decision` phase gets outcome `"recovery_complete"` instead of `"safe_mode_active"`.

### 56. `execution_orchestrator.rs:587` — hostcall rate is count*1M, not a ratio
**Bug:** Missing division by total instructions; just scales count up by 1M.

### 57. `constrained_ambient_benchmark_lane.rs:551-553` — Wrong denominator in improvement
**Bug:** Divides by optimized instead of baseline. 1000->500ns latency shows 100% instead of 50%.

### 58. `constrained_ambient_benchmark_lane.rs:402` — `supports_uplift` uses `||` instead of `&&`
**Bug:** Accepts uplift if either throughput OR latency improved; should require both non-regressive.

### 59. `runtime_diagnostics_cli.rs:346-348` — Severity filter uses `==` instead of `>=`
**Bug:** Filtering for `Warning` excludes `Critical` records.

### 60. `gc.rs:546` — Zero budget returns pressure 0.0 instead of maximum
**Bug:** `budget_max_bytes == 0` returns `Some(0.0)`, meaning no GC pressure with zero budget.

### 61. `frankentui_adapter.rs:2476-2478` — `normalize_optional_non_empty` returns `Some("unknown")`
**Bug:** Should return `None` for empty/whitespace optional fields, not `Some("unknown")`.

### 62. `object_model.rs:1531-1536` — `check_delete` overly strict for non-extensible targets
**Bug:** Rejects deletion of configurable properties on non-extensible targets, not per ES2020 spec.

### 63. `control_plane_benchmark_split_gate.rs:669-673` — Evidence regression compared against wrong baseline
**Bug:** Uses `candidate_decision` instead of `candidate_baseline` as reference.

### 64. `proof_specialization_receipt.rs:489-491` — Wrong error variant for empty fallback_path
**Bug:** Returns `EmptyTransformationDescription` when the issue is empty fallback_path.

### 65. `revocation_enforcement.rs:477-492` — `check_token_batch` reports wrong `checks_performed`
**Bug:** Reports `tokens.len() * 2` but stats tracking records `tokens.len()`.

---

## LOW SEVERITY / DESIGN CONCERNS

- `bayesian_posterior.rs:543-548` — LLR step uses linear approximation, not log
- `bayesian_posterior.rs:173` — Dead code: zero-sum check after floor guarantees sum >= 400
- `benchmark_e2e.rs:138-139` — Percentile index can equal n for edge cases
- `shadow_ablation_engine.rs:1347-1364` — Empty `required_invariants` checks ALL invariants (strictness inversion)
- `conformance_catalog.rs:347` — Behavioral regression uses Warn instead of Block
- `conformance_vector_gen.rs:678-679` — Degraded vectors expected to fail (questionable)
- `promotion_gate_runner.rs:445` — Risk threshold `<= 2` should be `<= 1`
- `proof_release_gate.rs:59` — `ir_diff_size_bytes > 0` rejects valid no-op passes
- `proof_release_gate.rs:68-69` — `fallback_is_valid` unconditionally returns true for verified proofs
- `portfolio_governor.rs:64-75` — Risk-adjusted EV formula mixes fixed-point scales
- `object_model.rs:1341-1343` — SymbolRegistry doesn't populate `by_description` for well-known symbols
- `controller_interference_guard.rs:564-568` — Serialized writes use alphabetical order, not timescale
- `runtime_diagnostics_cli.rs:572-573` — Pressure capped at 1M, hiding over-budget magnitude
- `forensic_replayer.rs:445-452` — Non-monotonic timestamp check allows equal timestamps

---

*Report generated by 30+ parallel scan agents across ~120 source files.*
