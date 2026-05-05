#!/usr/bin/env bash
br update bd-1rf0 -d "## Overview
This epic captures the profound integration of the `/dp/asupersync` library and the 'fresh eyes' bug fixes into the FrankenEngine project. It ensures that the engine operates strictly on the canonical contracts designed in the asupersync libraries (eradicating local type forks) and corrects critical logic bugs in the probabilistic guardplane and native baseline execution lanes. The overarching goal is to achieve deterministic, mathematically rigorous runtime security for untrusted extension code.

## Key Deliverables
- Fix algorithm bug in Bayesian Online Change Point Detection (BOCPD)
- Fix Asymmetric Log-Likelihood Ratio (LLR) Approximation
- Fix Call Stack Exhaustion Fall Off in Baseline Interpreter
- Correct Halt Register Resolution in Baseline Interpreter
- Prevent Wrap-Around Underflow in Expected-Loss Confidence Interval Math
- Eradicate Local SchemaVersion Forks for asupersync Compliance

## Testing and Verification Requirements
- Every child task must implement comprehensive unit tests for normal and edge-case paths.
- End-to-end (e2e) test scripts must be written to exercise lifecycle transitions, error recovery, and invariant enforcement.
- Structured logging with detailed, stable fields (`trace_id`, `decision_id`, `policy_id`, `component`, `event`, `outcome`, `error_code`) must be emitted and asserted in tests to guarantee post-implementation correctness and forensic auditability."

br update bd-2ww1 -d "## Background
The ChangePointDetector is responsible for identifying regime shifts in extension behavior.

## Problem
It was being updated with a single, uniform mean_likelihood for all run lengths. In a normalized distribution, a uniform scalar cancels out completely during normalization, meaning the incoming telemetry data had zero effect on the change point probability.

## Fix
Modify the update mechanism to supply two distinct likelihoods: `predictive_continuation` (likelihood under the converged posterior) and `predictive_new` (likelihood under the default prior). This allows the detector to accurately weigh continuing the old regime vs starting a new one.

## Testing and Validation Requirements
- **Unit Tests:** Verify that supplying different likelihoods for continuation vs new regime correctly shifts the change point probability. Test boundary conditions (extremely high/low likelihoods).
- **E2E Tests:** Simulate an extension undergoing a behavior regime shift and assert that the change point is detected and reported accurately in the logs.
- **Logging:** Ensure the system emits structured logs during a regime shift with detailed metrics for verification."

br update bd-21bz -d "## Background
`cumulative_llr_millionths` tracks the evidence weight between benign and malicious states.

## Problem
The Taylor approximation used a fixed denominator (L_benign), creating a massive asymmetry. Malicious evidence drove the LLR step up by +9,000,000, while equally strong benign evidence only reduced it by -900,000, heavily biasing the guardplane toward accumulating false malicious risk.

## Fix
Replace this with a symmetric piecewise approximation that uses the larger of the two likelihoods as the denominator, ensuring evidence is weighted equally in both directions without floating-point math.

## Testing and Validation Requirements
- **Unit Tests:** Provide symmetric benign and malicious evidence and assert that the LLR approximation correctly balances out.
- **E2E Tests:** Execute long-running extension simulations to ensure that accumulated LLR does not drift due to approximation asymmetries over time.
- **Logging:** Emit the LLR steps in structured logs to verify runtime calculation accuracy."

br update bd-1a3t -d "## Background
The baseline interpreter evaluates IR3 flat instructions.

## Problem
When the instruction pointer (IP) fell off the end of the instruction stream, the engine assumed the entire program had finished and terminated the sandbox. If this happened inside a nested function call (e.g. a missing explicit Return instruction), it would catastrophically terminate the entire execution rather than returning to the caller.

## Fix
Update the bounds-checking logic. Falling off the end of a function now cleanly pops the current `CallFrame`, sets the return register to `Value::Undefined`, and resumes the caller. It only terminates execution if the call stack is completely empty.

## Testing and Validation Requirements
- **Unit Tests:** Create IR3 instruction sequences with missing returns in nested functions to ensure graceful fallback.
- **E2E Tests:** Run comprehensive execution scripts that trigger edge cases in instruction fall-offs to assert stability.
- **Logging:** Add detailed telemetry tracing the call stack pop events due to stream exhaustion."

br update bd-gxnb -d "## Background
The Halt instruction serves as a normal termination, returning the value of register 0 (r0).

## Problem
The implementation accessed `self.registers.first()`, grabbing r0 from the global, flat register array (the top-level genesis frame). If a Halt executed inside a nested function, it returned the wrong frame's r0.

## Fix
Update the termination handler to correctly use `self.read_reg(0)`, which properly resolves against the current frame's `register_base`.

## Testing and Validation Requirements
- **Unit Tests:** Execute `Halt` instructions within deeply nested functions to ensure the returned register matches the local frame context.
- **E2E Tests:** Verify system-level correctness by executing full IR payloads ending with nested halts.
- **Logging:** Log the resolved register values at termination for diagnostic verification."

br update bd-1sp1 -d "## Background
The expected loss selector computes a confidence margin between the selected action and the runner-up.

## Problem
The code evaluated `(runner_up_loss.abs_diff(selected_loss) as i64) / 10`. The `abs_diff` yields a `u64`. In adversarial scenarios where expected losses are pushed to opposite extremes, the difference could exceed `i64::MAX`, causing the cast to wrap into a negative number and permanently corrupting the confidence interval.

## Fix
Correct the order of operations to divide the `u64` by 10 BEFORE casting to `i64` (`(abs_diff / 10) as i64`). Since `u64::MAX / 10` comfortably fits inside an `i64`, this permanently mitigates the wrap-around risk.

## Testing and Validation Requirements
- **Unit Tests:** Craft edge-case loss inputs that trigger the `u64` overflow threshold and verify that the confidence interval remains positive and mathematically sound.
- **E2E Tests:** Provide adversarial telemetry designed to maximize expected loss differentials and verify system robustness.
- **Logging:** Log the calculated confidence intervals to provide transparency over expected-loss determinations."

br update bd-44z9 -d "## Background
ADR-0001 requires that canonical control-plane types (`Cx`, `TraceId`, `SchemaVersion`, etc.) be imported strictly from `/dp/asupersync` with zero local forks.

## Problem
Migration debt remained. `evidence_ledger.rs`, `proof_schema.rs`, and `remote_computation_registry.rs` maintained localized, fragmented 16-bit and 32-bit implementations of `SchemaVersion`, violating the strict split-contract defined in the repository charter.

## Fix
Completely eradicate the local `SchemaVersion` structs. Route all modules to use `crate::control_plane::SchemaVersion`. Build `SchemaVersionExt` traits to handle compatibility logic gracefully, and replace local constants (e.g. `V1_0`, `V1_1`) with factory constructors. Clear the allowlist in `scripts/check_no_local_control_plane_type_forks.sh`. The project is now 100% compliant with ADR-0001.

## Testing and Validation Requirements
- **Unit Tests:** Ensure all modules utilizing `SchemaVersion` correctly leverage the canonical `/dp/asupersync` implementation. Check compatibility edge cases.
- **E2E Tests:** Replay legacy evidence entries to ensure that schema version parsing remains backward-compatible without local forks.
- **Logging:** Capture schema version metadata in structured logs for validation."

br sync --flush-only
