# Metamorphic Testing for Deterministic Replay

## Problem Statement

**Oracle Problem:** Cannot predict exact state sequences for complex scheduler operations, but we know relationships that must hold between inputs and outputs under transformations.

**Existing Property:** P-DETERM-01 "Deterministic Replay Fidelity" - identical traces produce identical state sequences.

## Metamorphic Relations (MR) Strength Matrix

| MR | Description | Fault Sensitivity | Independence | Cost | Score | Category |
|----|------------|-------------------|--------------|------|--------|----------|
| **MR1** | Identity replay | 5 | 5 | 1 | **25.0** | Equivalence |
| **MR2** | Subsequence monotonic | 3 | 4 | 1 | **12.0** | Inclusive |
| **MR3** | Action permutation | 4 | 4 | 2 | **8.0** | Permutative |
| **MR4** | Replay composition | 4 | 3 | 3 | **4.0** | Additive |
| **MR5** | State idempotence | 3 | 3 | 2 | **4.5** | Invertive |

*Rule: Only implement Score ≥ 2.0*

## Metamorphic Relations

### MR1: Identity Replay (Core Property)
```
f(actions) = f(actions)
```
Same action sequence must always produce same state sequence.

**Catches:** Non-determinism, race conditions, state corruption

### MR2: Subsequence Monotonic 
```
f(prefix(actions)) ⊆ f(actions)
```
Prefix replay produces prefix of full state sequence.

**Catches:** State progression bugs, incorrect prefix handling

### MR3: Action Permutation Invariance
```
f(valid + noise₁ + noise₂) = f(valid + noise₂ + noise₁)
```
Invalid actions in different orders don't affect determinism.

**Catches:** Order-dependent processing bugs, spurious state changes

### MR4: Replay Composition
```
f(seq₁ + seq₂) includes states from f(seq₁) and f(seq₂)
```
Combined sequences preserve component behaviors.

**Catches:** Composition interference, state transition bugs

### MR5: State Idempotence
```
f(actions, final_state) = final_state
```
Actions from terminal states don't create spurious transitions.

**Catches:** State machine convergence bugs, infinite loops

## Composite Relations

**MR1 ∘ MR2:** Identity replay + Subsequence monotonic
- Tests that prefixes are deterministically reproducible
- Catches bugs that individual MRs miss

## Property-Based Testing

Uses `proptest` with:
- Random action sequences (1-10 actions)
- Valid transition labels from automaton alphabet  
- Invalid action injection for robustness testing
- Comprehensive prefix/composition testing

## Validation

Each MR validated through mutation testing:
- Plant known bugs (non-determinism, truncation, etc.)
- Verify MR suite catches planted mutations
- Ensure no blind spots in fault detection

## Usage

```bash
# Run all metamorphic tests
cargo test scheduler_replay_metamorphic --lib

# Run specific relation
cargo test mr_identity_replay_determinism --lib

# Run with verbose output
cargo test scheduler_replay_metamorphic --lib -- --nocapture
```