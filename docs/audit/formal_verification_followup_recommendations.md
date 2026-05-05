# Formal Verification Followup Recommendations

Based on bd-csnqb audit, the following FOLLOWUP beads could be created to actually implement formal mathematical proofs for downgraded claims:

## High Priority (Core Security Claims)

### [FOLLOWUP] Add Lean proof for capability-typed IR preservation
- **Scope**: Implement formal proof that capability annotations are preserved through all lowering stages
- **Evidence**: Lean/Coq proof files showing type preservation invariants
- **Dependencies**: Formal specification of capability type system
- **Effort**: ~4-6 weeks for experienced formal verification engineer

### [FOLLOWUP] Add TLA+ specification for policy monotonicity
- **Scope**: Formal specification and proof of monotonic safety constraints in policy evaluation
- **Evidence**: TLA+ models with safety/liveness proofs
- **Dependencies**: Formal policy semantics specification
- **Effort**: ~3-4 weeks for TLA+ expert

## Medium Priority (Performance Claims)

### [FOLLOWUP] Add Coq proofs for optimization equivalence
- **Scope**: Mathematical proofs that fast-path optimizations are behaviorally equivalent
- **Evidence**: Coq proofs showing isomorphism between optimized/unoptimized paths
- **Dependencies**: Formal operational semantics for execution paths
- **Effort**: ~2-3 weeks per optimization class

## Lower Priority (Aspirational Features)

### [FOLLOWUP] Implement Policy Theorem Engine with Lean backend
- **Scope**: Build actual theorem-backed policy compilation with formal verification
- **Evidence**: Lean theorem prover integration with policy compiler
- **Dependencies**: All above formal specifications
- **Effort**: ~8-12 weeks major undertaking

### [FOLLOWUP] Add proof-carrying compilation infrastructure
- **Scope**: Implement actual proof-carrying code with machine-checkable witnesses
- **Evidence**: Formal verification toolchain producing checkable proofs
- **Dependencies**: Core type system proofs
- **Effort**: ~6-10 weeks major undertaking

## Recommendation

These represent substantial formal verification engineering efforts. Consider:

1. **Partner with formal verification experts** (academic collaboration)
2. **Start with smaller scopes** (single function proofs before whole-system proofs)
3. **Use existing tools** (Lean, Coq, TLA+) rather than building custom verification
4. **Focus on highest-impact security properties** first

## Alternative: Keep as Hypotheses

The current HYPOTHESIS downgrading is also a valid long-term approach if formal verification is not a priority. The downgraded language is honest about the current proof status while preserving the vision for future formal work.