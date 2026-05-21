# ADR-0006: IFC Formal Proof Strategy - Label Propagation vs Secure Multi-Execution

- Status: Accepted
- Date: 2026-05-21
- Owners: FrankenEngine Security Team + Track G maintainers
- Plan references: Reality-check refinement-pass-5, Track MM evaluation
- Related beads: `bd-cixqu.7.1`, FE-CLAIM-015 (IFC declassification receipts)

## Context

FrankenEngine requires information flow control (IFC) with formal non-interference guarantees for signed declassification receipts (FE-CLAIM-015). Two primary implementation strategies exist:

1. **Label Propagation**: Explicit tracking of security labels through runtime, requiring formal proof that the label propagation rules maintain non-interference properties
2. **Secure Multi-Execution (SME)**: Running multiple program copies at different security levels, where non-interference holds by construction (Devriese & Piessens 2010)

Track MM identified SME as an ALTERNATIVE strategy, not an addition. This ADR selects one approach; the rejected alternative becomes a reference implementation for comparison.

## Decision

**FrankenEngine adopts Label Propagation as the primary IFC strategy**, with SME maintained as a reference implementation for formal verification cross-validation.

## Rationale

### Label Propagation Advantages
- **Runtime Performance**: Single execution with label tracking has lower computational overhead than running multiple program copies
- **Memory Efficiency**: O(n) memory usage vs O(k*n) where k = number of security levels
- **Deterministic Replay Compatibility**: Single execution trace simplifies deterministic replay requirements (FE-CLAIM-013)
- **Extension Host Integration**: Easier to integrate with existing JavaScript/TypeScript runtime without fundamental execution model changes

### Secure Multi-Execution Advantages  
- **Formal Proof Simplicity**: Non-interference holds by construction; no complex label propagation proof required
- **Implementation Confidence**: Harder to introduce subtle IFC bugs when isolation is structural
- **Academic Precedent**: Well-studied approach with established correctness properties

### Trade-off Analysis

| Factor | Label Propagation | Secure Multi-Execution | Winner |
|--------|------------------|------------------------|---------|
| Runtime Performance | ~5-10% overhead | ~200-400% overhead | LP |
| Memory Usage | ~10-20% increase | ~300-500% increase | LP |
| Proof Complexity | High (requires careful analysis) | Low (by construction) | SME |
| Implementation Risk | Medium (label tracking bugs) | Low (isolation bugs obvious) | SME |
| Deterministic Replay | Natural fit | Complex (sync multiple executions) | LP |
| Extension Compatibility | High | Low (requires execution model changes) | LP |

### FrankenEngine-Specific Factors

1. **Performance Requirements**: FE-CLAIM-010 requires ≥3x throughput vs Node/Bun; SME overhead conflicts with this goal
2. **Deterministic Replay**: FE-CLAIM-013 mandates 100% replay coverage; single execution simplifies replay artifacts
3. **Extension Ecosystem**: Existing JavaScript/TypeScript tooling assumes single execution model
4. **Red-team Resistance**: FE-CLAIM-011 requires containment under adversarial workloads; SME isolation is robust but LP with capability restrictions achieves similar protection

## Implementation Strategy

### Primary: Label Propagation
- Implement explicit label tracking in IR execution engine
- Add label propagation rules to `declassification_engine.rs`
- Formal proof via external verification (Lean 4, per Track G.1 ADR)
- Runtime label validation with fail-closed policy on violations

### Reference: Secure Multi-Execution  
- Maintain SME implementation in `secure_multi_execution_reference.rs`
- Use for cross-validation of label propagation correctness
- Enable via compile-time feature flag for formal verification scenarios
- Document performance characteristics for future trade-off evaluation

## Verification Plan

1. **Formal Proof**: Label propagation non-interference proof in chosen proof assistant
2. **Cross-Validation**: Compare LP and SME outputs on identical workloads  
3. **Performance Validation**: Confirm LP meets FE-CLAIM-010 throughput requirements
4. **Security Testing**: Red-team evaluation of label propagation under adversarial inputs

## Consequences

### Positive
- Runtime performance compatible with FE-CLAIM-010 targets
- Natural integration with deterministic replay infrastructure  
- Simplified execution model for extension compatibility
- Reference SME implementation provides verification confidence

### Negative  
- Complex formal proof burden for label propagation correctness
- Risk of subtle label tracking bugs during implementation
- Additional engineering effort to maintain both LP and reference SME

### Risk Mitigation
- Extensive property-based testing of label propagation rules
- SME cross-validation catches LP implementation errors
- External formal verification team reviews proof obligations
- Fail-closed policy ensures security violations halt execution

## References

- Devriese, D., & Piessens, F. (2010). "Noninterference through secure multi-execution." IEEE S&P
- Sabelfeld, A., & Myers, A. C. (2003). "Language-based information-flow security." IEEE Journal on Selected Areas in Communications
- FE-CLAIM-015: "Deterministic information-flow confinement with signed declassification receipts"
- Track MM evaluation: Alternative implementation strategies analysis