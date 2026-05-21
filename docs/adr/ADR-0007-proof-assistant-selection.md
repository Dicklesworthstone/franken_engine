# ADR-0007: Proof Assistant Selection for Formal Verification

- Status: Accepted
- Date: 2026-05-21
- Owners: FrankenEngine Formal Methods Team + Track G maintainers
- Plan references: Reality-check refinement-pass-5, IFC formal proof requirements
- Related beads: `bd-cixqu.7.2`, ADR-0006 (IFC strategy), FE-CLAIM-015, FE-CLAIM-017

## Context

FrankenEngine requires formal verification for critical security properties, including:
- Information flow control non-interference (ADR-0006 label propagation proof)
- Proof-carrying compilation contracts (FE-CLAIM-017)  
- Mathematical security decision specifications (FE-CLAIM-016)
- Policy evaluation formal semantics (FE-CLAIM-018)

Three proof assistant candidates emerge as viable options:

1. **Lean 4**: Modern proof assistant with strong Rust interoperability
2. **Coq**: Established proof assistant with extensive IFC literature
3. **Rocq**: Modern fork of Coq with active development and ecosystem improvements

## Decision

**FrankenEngine adopts Lean 4** as the primary proof assistant, with pinned compiler version `v4.7.0` for reproducible verification.

## Evaluation Matrix

| Criterion | Lean 4 | Coq 8.19 | Rocq 8.20 | Weight | Winner |
|-----------|---------|-----------|-----------|---------|---------|
| Rust Interop | Excellent (lean4-tcc, leanrs) | Poor (requires OCaml FFI) | Poor (OCaml-based) | High | **Lean 4** |
| IFC Literature | Growing | Extensive (decades) | Inherits Coq | Medium | Coq |
| Active Development | Very Active | Active | Very Active | Medium | Tie |
| Learning Curve | Moderate | Steep | Steep | Medium | **Lean 4** |
| Performance | Fast compilation | Slower | Improved from Coq | Low | **Lean 4** |
| Community Size | Growing rapidly | Large, established | Small but active | Low | Coq |
| Verification Ecosystem | Modern, expanding | Mature | Emerging | Medium | Coq |

## Rationale

### Lean 4 Advantages
- **Rust Interoperability**: `lean4-tcc` and `leanrs` enable direct verification of Rust code properties
- **Modern Design**: Type classes, dependent types, and metaprogramming reduce proof verbosity  
- **Performance**: Faster compilation and checking than Coq/Rocq for large proof developments
- **Active Development**: Rapid feature development and ecosystem growth
- **Learning Curve**: More approachable syntax for engineers familiar with functional programming

### Coq/Rocq Advantages
- **IFC Literature**: Decades of published IFC formalizations available as reference
- **Maturity**: Battle-tested on large verification projects
- **Ecosystem**: Extensive libraries (CompCert, VST, etc.) for low-level verification
- **Rocq Improvements**: Better package management, modern tooling

### FrankenEngine-Specific Factors

1. **Rust-Centric Codebase**: Direct Rust interop via lean4-tcc reduces translation overhead
2. **Engineering Team**: Functional programming background makes Lean 4 more accessible
3. **Performance Requirements**: Faster proof checking enables CI integration
4. **Modern Verification**: FrankenEngine's novel security model benefits from Lean 4's expressiveness

## Implementation Plan

### Toolchain Setup
- **Pinned Version**: Lean 4.7.0 for reproducible verification
- **rch Worker Installation**: Add Lean toolchain to rch worker class
- **CI Integration**: Automated proof checking in verification pipeline
- **Reproducibility Lock**: `repro.lock` pins exact Lean version + dependencies

### Development Workflow  
- **Proof Development**: `proofs/lean4/` directory structure
- **Rust Integration**: Use lean4-tcc for direct Rust property verification
- **IFC Proofs**: Start with label propagation non-interference (ADR-0006)
- **Reference Materials**: Port relevant Coq IFC proofs to Lean 4 as needed

### Migration Strategy
- **Gradual Adoption**: Start with critical security properties
- **Coq Reference**: Maintain Coq versions of key proofs for cross-validation
- **Team Training**: Lean 4 workshops for formal methods team
- **External Review**: Lean 4 proof artifacts reviewed by external formal methods experts

## Verification Scope

### Phase 1: Core Security Properties
- Label propagation non-interference (IFC)
- Capability confinement invariants
- Decision evaluation correctness

### Phase 2: System Properties  
- Deterministic replay correctness
- Policy evaluation monotonicity
- Containment mechanism soundness

### Phase 3: Full Verification
- Proof-carrying compilation
- End-to-end security guarantees
- Performance property proofs

## Toolchain Configuration

```toml
# repro.lock excerpt
[lean4]
version = "4.7.0"
checksum = "sha256:a1b2c3d4..."
dependencies = [
  "lean4-tcc@1.2.0",
  "leanrs@0.3.1",
  "std4@4.7.0"
]
```

## Risk Mitigation

### Technical Risks
- **Lean 4 Immaturity**: Maintain Coq reference proofs for critical properties
- **Rust Interop Bugs**: Extensive testing of lean4-tcc integration
- **Proof Complexity**: Start with simple properties, build expertise gradually

### Organizational Risks  
- **Knowledge Gap**: External Lean 4 consulting for complex proofs
- **Maintenance Burden**: Automated proof checking prevents proof rot
- **Verification Timeline**: Phased approach allows progress validation

## Success Metrics

1. **IFC Non-interference**: Formal proof within 6 months
2. **CI Integration**: Proof checking in <10 minutes
3. **Team Adoption**: ≥3 engineers proficient in Lean 4 proof development
4. **External Validation**: Independent review confirms proof correctness

## Consequences

### Positive
- Direct Rust property verification via lean4-tcc
- Modern proof assistant with growing ecosystem
- Faster proof development and checking
- Strong typing enables complex security property specification

### Negative
- Smaller community compared to Coq
- Fewer existing IFC formalizations to reference
- Risk of Lean 4 ecosystem changes affecting verification

### Dependencies
- rch worker Lean 4 installation
- lean4-tcc stable release for Rust integration
- Formal methods team Lean 4 training
- External review capacity for proof validation

## References

- Lean 4 Documentation: https://leanprover.github.io/lean4/doc/
- lean4-tcc (Rust integration): https://github.com/leanprover/lean4-tcc
- IFC in Coq references: Appel et al. (VST), Pierce et al. (Software Foundations)
- ADR-0006: IFC formal proof strategy (label propagation)
- FE-CLAIM-017: Proof-carrying compilation contract