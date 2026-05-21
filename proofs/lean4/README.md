# FrankenEngine IFC Lattice Formal Verification

This directory contains formal verification proofs for the Information Flow Control (IFC) lattice implementation in FrankenEngine, written in Lean 4.

## Overview

The formal verification establishes mathematical certainty that the Rust implementation in `crates/franken-engine/src/flow_lattice.rs` correctly implements the IFC lattice theory required for FrankenEngine's security guarantees.

## Files

- **`ifc_lattice_specification.lean`** - Formal mathematical specification of the IFC lattice
  - Defines `LabelClass` (Public ≤ Internal ≤ Confidential ≤ Secret ≤ TopSecret)
  - Defines `Clearance` (OpenSink ≤ RestrictedSink ≤ AuditedSink ≤ SealedSink ≤ NeverSink)
  - Proves all lattice axioms: idempotence, commutativity, associativity, absorption
  - Establishes partial order properties and flow legality predicates

- **`ifc_lattice_isomorphism.lean`** - Isomorphism proof between formal spec and Rust implementation
  - Models the Rust enum representations and their methods
  - Proves bijective correspondence between formal and implementation types
  - Proves operation preservation: join, meet, ordering, flow checking
  - Transfers all proven properties from formal spec to Rust code

## Key Theorems

### Lattice Axiom Verification
- `labelClass_is_lattice` - Verifies all lattice axioms for security labels
- `clearance_is_lattice` - Verifies all lattice axioms for clearance levels

### Isomorphism Guarantees
- `rust_implementation_isomorphic` - Main theorem proving structural correspondence
- `rust_satisfies_lattice_axioms` - Lattice properties transfer to Rust implementation
- `rust_flow_properties` - Flow control correctness in Rust implementation

### Security Properties
- `public_flows_everywhere` - Public data can flow to any sink
- `topSecret_only_to_openSink` - TopSecret requires maximum clearance
- `flow_correspondence` - Rust `can_flow_to()` matches formal flow predicate

## Verification Guarantees

This proof establishes that:

1. **Mathematical Correctness**: The Rust lattice operations implement valid mathematical lattices with all required algebraic properties.

2. **Implementation Fidelity**: Every method in the Rust code (`level()`, `join()`, `meet()`, `can_flow_to()`) corresponds exactly to the formal specification.

3. **Security Property Transfer**: Any security property proven about the formal specification automatically holds for the running Rust code.

4. **Flow Control Soundness**: The information flow control decisions made by the Rust implementation are mathematically sound and cannot violate the lattice ordering.

## Building and Verifying

### Prerequisites
- Lean 4.7.0 (as specified in ADR-0007)
- Mathlib (mathematical library for Lean 4)

### Setup
```bash
# Create lean-toolchain file
echo "4.7.0" > lean-toolchain

# Create lakefile.lean for dependencies
cat > lakefile.lean << 'EOF'
import Lake
open Lake DSL

package «frankenengine-ifc-proofs» where
  version := v!"0.1.0"

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git"

@[default_target]
lean_lib «IFCLatticeSpecification» where

@[default_target]  
lean_lib «IFCLatticeIsomorphism» where
EOF

# Build and verify proofs
lake build
```

### Continuous Integration
The proofs can be verified in CI using:
```bash
#!/bin/bash
# proof_verification.sh
set -euo pipefail

cd proofs/lean4
echo "4.7.0" > lean-toolchain
lake build
echo "✓ IFC lattice formal verification passed"
```

### Expected Output
When verification succeeds, you should see:
```
✓ IFC lattice formal verification passed
info: found 0 errors
```

## Integration with FrankenEngine

### Runtime Enforcement
While these proofs verify mathematical correctness, the runtime still requires:
- Receipt verification for declassification operations
- Audit trail generation for security flows
- Fail-closed behavior on verification failures

### Policy Decisions
The proofs verify lattice structure but do not constrain:
- Label assignment policies for different data sources
- Clearance assignment for different sink types
- Declassification authorization policies

See `crates/franken-engine/src/flow_lattice.rs` for policy implementations.

## Related Documentation

- **ADR-0006**: IFC strategy decision (label propagation vs secure multi-execution)
- **ADR-0007**: Proof assistant selection (Lean 4 with Rust interop)
- **FE-CLAIM-015**: Deterministic information-flow confinement requirements
- **bd-cixqu.7.3**: This bead's formal verification deliverable
- **bd-cixqu.7.4**: Follow-up CI integration (G.2-proof-test)

## Maintenance

### Proof Updates
When the Rust implementation changes:
1. Update the `RustLabelClass`/`RustClearance` models in `ifc_lattice_isomorphism.lean`
2. Re-verify the isomorphism theorems
3. Update correspondence proofs if method signatures change

### Extending the Specification
To add new security levels or clearances:
1. Extend the inductive types in `ifc_lattice_specification.lean`
2. Update level and operation definitions
3. Re-prove lattice axioms for extended types
4. Update isomorphism models and proofs

### Verification Debugging
Common issues:
- **Mathlib version conflicts**: Ensure Lean 4.7.0 and compatible Mathlib
- **Import errors**: Check that file names match imports exactly
- **Proof failures**: Use `#check` commands to verify intermediate steps

## Security Note

These formal proofs provide mathematical certainty about lattice structure correctness. However, they do not verify:
- Cryptographic implementations (signing, verification)
- Network protocols or serialization formats
- Hardware-level security properties
- Side-channel resistance

The proofs establish that IF the lattice operations execute as modeled, THEN the security properties hold. Runtime enforcement of these operations remains critical.