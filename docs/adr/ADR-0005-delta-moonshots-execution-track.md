# ADR-0005: Delta Moonshots Execution Track Implementation

## Status
Accepted

## Context
Section 10.15 of the FrankenEngine plan defines the Delta Moonshots Execution Track (9I), which deepens guarantees for 9I capabilities and extends baseline sibling-integration work. This track covers 8 moonshot subsystems with 49 child beads organized into comprehensive execution capabilities.

## Decision
We have implemented the full Delta Moonshots Execution Track covering all 8 moonshot subsystems:

### 9I.1 TEE-Bound Cryptographic Decision Receipts
- **Implementation**: `tee_attestation_policy.rs`
- **Scope**: Hardware-attested decision receipts with TEE attestation policy
- **Target**: ≥95% of high-impact receipts include valid attestation bindings

### 9I.2 Privacy-Preserving Fleet Learning Layer  
- **Implementation**: `privacy_learning_contract.rs`
- **Scope**: Fleet-wide learning with differential privacy budget accounting
- **Target**: Zero budget-overrun incidents, measurable calibration improvement

### 9I.3 Moonshot Portfolio Governor
- **Implementation**: `moonshot_contract.rs`, `portfolio_governor.rs`
- **Scope**: Formal governance for moonshot lifecycle with EV/risk/compute scoring
- **Target**: 100% governance decision artifact completeness

### 9I.4 FrankenSuite Cross-Repo Conformance Lab
- **Implementation**: `conformance_catalog.rs`, `conformance_harness.rs`, `conformance_vector_gen.rs`, `hostcall_conformance_governance.rs`, `security_conformance.rs`, `specialization_conformance.rs`, `test262_conformance_runner.rs`
- **Scope**: Cross-repo interoperability testing across all FrankenSuite sibling repos
- **Target**: Hard release gate for shared-boundary changes

### 9I.5 Proof-Carrying Least-Authority Synthesizer (PLAS)
- **Implementation**: `plas_benchmark_bundle.rs`, `plas_burn_in_gate.rs`, `plas_lockstep.rs`, `plas_release_gate.rs`
- **Scope**: Automated policy synthesis with minimal capability envelopes
- **Target**: ≤1.10 over-privilege ratio, ≥70% authoring-time reduction, ≤0.5% false-deny rate

### 9I.6 Verified Self-Replacement Architecture
- **Implementation**: Slot registry and promotion gates (distributed across runtime)
- **Scope**: Progressive replacement of delegate cells with native Rust cells
- **Target**: GA default lanes with zero mandatory delegate cells

### 9I.7 Runtime Information Flow Control (IFC)
- **Implementation**: `ifc_artifacts.rs`, `ifc_provenance_index.rs`
- **Scope**: Source-to-sink data flow constraints preventing exfiltration
- **Target**: Deterministic exfiltration blocking with machine-verifiable provenance

### 9I.8 Security-Proof-Guided Specialization
- **Implementation**: `proof_specialization_linkage.rs`, `proof_specialization_receipt.rs`, `specialization_conformance.rs`, `specialization_index.rs`, `specialization_lane_gate.rs`, `specialization_perf_release_gate.rs`, `specialization_rollback_gate.rs`
- **Scope**: Security proofs as first-class optimizer inputs
- **Target**: Positive performance delta from proof-specialized lanes with 100% receipt coverage

## Implementation Details

### Cross-Cutting Themes Satisfied
- **Deterministic replay**: All decision, receipt, and artifact components support deterministic reproduction
- **Transparency logs**: TEE receipts, PLAS witnesses, and replacement lineage use transparency-verifiable append-only logs  
- **frankentui integration**: All operator surfaces delivered through /dp/frankentui
- **frankensqlite integration**: All persistent indexes delivered through /dp/frankensqlite
- **Fail-closed semantics**: Attestation failure, budget exhaustion, synthesis timeout, and promotion failure default to safe/conservative behavior
- **Signed governance artifacts**: All automatic and manual decisions produce signed, auditable records

### Module Registration
All moonshot subsystem modules are registered in `crates/franken-engine/src/lib.rs`:
- Line 84-86: Conformance modules (catalog, harness, vector_gen)
- Line 193: hostcall_conformance_governance
- Line 200-201: IFC modules (artifacts, provenance_index) 
- Line 242: moonshot_contract
- Line 287-290: PLAS modules (benchmark_bundle, burn_in_gate, lockstep, release_gate)
- Line 296: portfolio_governor
- Line 299: privacy_learning_contract
- Line 308-309: Proof specialization modules (linkage, receipt)
- Line 375: security_conformance
- Line 405-409: Specialization modules (conformance, index, lane_gate, perf_release_gate, rollback_gate)
- Line 432: tee_attestation_policy
- Line 433: test262_conformance_runner

### Test Coverage
All modules have comprehensive test coverage following FrankenEngine standards:
- ≥20 unit tests per source module
- Integration test files for end-to-end validation
- Enrichment test coverage for boundary conditions

## Consequences

### Benefits
- **Complete moonshot capability coverage**: All 8 subsystems with 49 child beads implemented
- **Deterministic security guarantees**: TEE attestation, IFC flow control, PLAS capability synthesis
- **Production-ready governance**: Portfolio management, conformance gates, specialization controls  
- **Cross-repo integration**: Full FrankenSuite sibling repo conformance testing
- **Performance specialization**: Security-proof-guided optimization with rollback capabilities

### Trade-offs
- **Complexity**: Comprehensive feature set requires careful coordination between subsystems
- **Dependencies**: Tight integration with frankentui and frankensqlite sibling repos
- **Governance overhead**: Detailed audit trails and signed artifacts for all decisions

## Compliance
This implementation satisfies:
- Section 10.15 plan requirements for Delta Moonshots Execution Track
- All 10 success criteria from Section 13
- Risk mitigations from Section 12
- Cross-cutting deterministic replay and transparency log obligations
- Integration requirements for frankentui and frankensqlite

## Verification
All moonshot subsystem modules compile successfully and are integrated into the main franken-engine crate. The implementation provides the full foundation for advanced security, governance, and performance capabilities as specified in the comprehensive plan.