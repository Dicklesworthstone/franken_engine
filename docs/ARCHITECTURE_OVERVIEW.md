# FrankenEngine Architecture Overview

**Version**: 1.0  
**Date**: April 2026  
**Bead**: bd-axlvk.1

FrankenEngine is a de novo Rust-native JavaScript runtime with mathematically explicit security, shipped replay APIs, fail-closed replay coverage gates, and byte-identical fixed-input artifact proof for the `frankenctl` compile/run path. This document provides a high-level architectural overview for developers getting oriented in the Rust module graph. Generated module, gate, export, and binary counts are tracked in [ARCHITECTURE_INVENTORY.md](ARCHITECTURE_INVENTORY.md).

---

## Page 1: Core Runtime Pipeline

### Execution Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐
│   Source    │    │   Parser    │    │      AST Builder        │
│   Code      │───▶│  (parser.rs)│───▶│     (ast.rs)           │
│   (JS/TS)   │    │             │    │                         │
└─────────────┘    └─────────────┘    └─────────────────────────┘
                                                    │
                                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    Lowering Pipeline                                    │
│                   (lowering_pipeline.rs)                               │
├─────────────┬─────────────┬─────────────┬─────────────────────────────┤
│     IR0     │     IR1     │     IR2     │            IR3              │
│  (Raw AST)  │(Normalized) │(Simplified) │      (Executable)           │
├─────────────┼─────────────┼─────────────┼─────────────────────────────┤
│ • Syntax    │ • Scoping   │ • Control   │ • Stack Operations          │
│   Trees     │   Analysis  │   Flow      │ • Register Allocation       │
│ • Raw Forms │ • Symbol    │   Lowering  │ • Concrete Instructions     │
│             │   Tables    │ • SSA Form  │ • Ready for Execution       │
└─────────────┴─────────────┴─────────────┴─────────────────────────────┘
                                                    │
                                                    ▼
┌─────────────────────────────┐    ┌─────────────────────────────┐
│    Baseline Interpreter     │    │   Execution Orchestrator   │
│   (baseline_interpreter.rs) │───▶│ (execution_orchestrator.rs) │
├─────────────────────────────┤    ├─────────────────────────────┤
│ • Instruction Dispatch      │    │ • Execution Context         │
│ • Runtime Value Operations  │    │ • Security Epoch Tracking   │
│ • Garbage Collection        │    │ • Resource Management       │
│ • Exception Handling        │    │ • Evidence Collection       │
└─────────────────────────────┘    └─────────────────────────────┘
                                                    │
                                                    ▼
                            ┌─────────────────────────────┐
                            │      Evidence Ledger       │
                            │   (evidence_ledger.rs)     │
                            ├─────────────────────────────┤
                            │ • Execution Traces          │
                            │ • Decision Records          │
                            │ • Audit Trail               │
                            │ • Replay Artifacts          │
                            └─────────────────────────────┘
```

### Key Types at Each Level

- **Parser**: `ParseResult<Ast>`, `SyntaxError`, `TokenStream`
- **AST**: `Expression`, `Statement`, `Declaration`, `Program`  
- **IR0-IR3**: `Ir0Node`, `Ir1Instruction`, `Ir2Block`, `Ir3Instruction`
- **Interpreter**: `Value`, `Object`, `ExecutionContext`, `Frame`
- **Orchestrator**: `ExecutionResult`, `SecurityEpoch`, `ResourceBudget`
- **Evidence**: `TraceEntry`, `DecisionRecord`, `AuditEvent`

### Data Flow Characteristics

- **Deterministic**: All operations produce identical results given identical inputs
- **Auditable**: Every execution step generates evidence for replay and verification
- **Secure**: Security epochs prevent temporal confusion attacks
- **Resource-Bounded**: Explicit budgets prevent resource exhaustion

---

## Page 2: Governance Overlay

### Security & Governance Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Governance Layer                               │
└─────────────────────────────────────────────────────────────────────────┘
    │                           │                           │
    ▼                           ▼                           ▼
┌─────────────┐         ┌─────────────┐         ┌─────────────────┐
│ Gate System │         │ Capability  │         │ Security Epochs │
│             │         │ Framework   │         │                 │
├─────────────┤         ├─────────────┤         ├─────────────────┤
│ • *_gate.rs │         │ • Authority │         │ • Temporal      │
│   (53 gates)│         │   Domains   │         │   Isolation     │
│ • Evidence  │         │ • OCAP      │         │ • Replay        │
│   Gates     │         │   Membrane  │         │   Consistency   │
│ • Parity    │         │ • Resource  │         │ • Upgrade       │
│   Validation│         │   Limits    │         │   Safety        │
└─────────────┘         └─────────────┘         └─────────────────┘
    │                           │                           │
    └───────────────┬───────────────────────┬───────────────┘
                    │                       │
                    ▼                       ▼
            ┌─────────────────┐    ┌─────────────────────────┐
            │ Fleet           │    │ Evidence Collection     │
            │ Convergence     │    │ & Checkpoint Density    │
            ├─────────────────┤    ├─────────────────────────┤
            │ • Consensus     │    │ • Decision Trees        │
            │   Protocols     │    │ • Audit Trails          │
            │ • State         │    │ • Rollback Points       │
            │   Sync          │    │ • Verification Proofs   │
            │ • Version       │    │ • Replay Guarantees     │
            │   Coordination  │    │ • Deterministic Hashing │
            └─────────────────┘    └─────────────────────────┘
```

### Governance Components

#### Gate System
- **Purpose**: Evidence-backed validation at every execution boundary
- **Examples**: `parity_gate.rs`, `security_gate.rs`, `performance_gate.rs`
- **Function**: Prevents progression without verified evidence of correctness
- **Integration**: Embedded throughout pipeline at critical decision points
- **Inventory**: Current `*_gate.rs` count is generated in `docs/ARCHITECTURE_INVENTORY.md`

#### Capability Framework
- **Authority Domains**: Hierarchical permission boundaries
- **OCAP Membrane**: Object-capability security model enforcement
- **Resource Limits**: Prevent resource exhaustion and DoS attacks
- **Fine-grained Control**: Per-module, per-operation capability grants

#### Security Epochs
- **Temporal Isolation**: Prevents confusion attacks across time boundaries  
- **Replay Consistency**: Constrains epoch artifacts so deterministic replay can be proven against fixed traces
- **Upgrade Safety**: Safe transitions between security policy versions
- **Audit Integration**: Epoch boundaries create natural audit checkpoints

#### Fleet Convergence
- **Distributed Consensus**: Multiple runtime instances reach agreement
- **State Synchronization**: Consistent state across distributed deployments
- **Version Coordination**: Safe upgrades across fleet deployments
- **Fault Tolerance**: Graceful degradation and recovery mechanisms

#### Evidence & Checkpoint Density
- **Decision Trees**: Complete record of all runtime decisions
- **Audit Trails**: Cryptographically verifiable execution logs
- **Rollback Points**: Safe recovery points for error conditions
- **Verification Proofs**: Mathematical proofs of execution correctness
- **Replay Guarantees**: Verified allow/deny/escalate replay coverage plus bit-for-bit fixed-input `frankenctl` artifact proof

### Key Innovation: De Novo Security

Unlike traditional JavaScript runtimes that retrofit security, FrankenEngine builds security into every layer:

1. **Parser Level**: Syntax-aware security policies prevent malicious code patterns
2. **IR Level**: Type safety and control flow integrity at intermediate representation
3. **Execution Level**: Capability-mediated access to all runtime services
4. **Evidence Level**: Cryptographic proof of all security-relevant decisions

This architecture achieves **category-defining performance/security posture** beyond Node.js/Bun by eliminating the need for runtime security retrofits.

---

## Getting Started for Developers

### Orientation Workflow (Hours, not Days)

1. **Start with Core Pipeline** (`parser.rs` → `ast.rs` → `lowering_pipeline.rs`)
2. **Understand IR Levels** (trace a simple expression through IR0→IR1→IR2→IR3)
3. **Explore Baseline Interpreter** (`baseline_interpreter.rs` instruction dispatch)
4. **Study Evidence Generation** (`evidence_ledger.rs` audit trail creation)
5. **Examine Gate Examples** (pick 2-3 `*_gate.rs` modules for patterns)

### Key Architectural Principles

- **No Unsafe Code**: `#![forbid(unsafe_code)]` enforced repository-wide
- **Deterministic Execution**: Identical inputs → identical outputs, always
- **Evidence-First**: Every decision generates auditable evidence
- **Capability-Mediated**: All authority grants explicit and revocable  
- **Security by Design**: Security integrated, not retrofitted

### Module Organization

- **Core Runtime**: `parser.rs`, `ast.rs`, `lowering_pipeline.rs`, `baseline_interpreter.rs`
- **Governance**: `*_gate.rs`, `*_governance.rs`, `security_epoch.rs`
- **Evidence**: `evidence_ledger.rs`, `audit_trail.rs`, `replay_*.rs`
- **Infrastructure**: `execution_orchestrator.rs`, `resource_management.rs`
- **Generated Inventory**: `docs/ARCHITECTURE_INVENTORY.md` records the current source modules, `lib.rs` exports, gate modules, disabled exports, and release binaries.

This document provides the essential mental model for navigating FrankenEngine's architecture. For implementation details, start with the modules listed above and follow the data flow patterns described in the pipeline diagram.
