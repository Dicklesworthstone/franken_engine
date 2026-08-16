# FrankenEngine Architecture Overview

**Version**: 1.1
**Date**: August 2026
**Bead**: bd-axlvk.1

FrankenEngine is a research-grade, de novo Rust-native JavaScript runtime for
adversarial extension workloads. Its implemented center is a parser, four-stage
lowering pipeline, policy-routed baseline interpreter, capability/IFC checks,
deterministic replay records, and signed evidence surfaces. This document is an
orientation map, not a proof of universal JavaScript compatibility, security,
determinism, fleet deployment, or performance. Current claim boundaries live in
[CLAIM_TO_PROOF_MATRIX_V1.md](CLAIM_TO_PROOF_MATRIX_V1.md), and generated module,
gate, export, and binary counts live in
[ARCHITECTURE_INVENTORY.md](ARCHITECTURE_INVENTORY.md).

---

## Core Runtime Pipeline

### Execution Flow

```text
JavaScript/TypeScript source
          |
          v
parser.rs + ast.rs --------------> SyntaxTree / parse diagnostics
          |
          v
Ir0Module -> Ir1Module -> Ir2Module -> Ir3Module
          lowering_pipeline.rs::lower_ir0_to_ir3
          |
          v
execution_orchestrator.rs -> LaneRouter -> InterpreterCore
          |                              (baseline_interpreter.rs)
          v
ExecutionResult + NondeterminismTrace + evidence / IR4 witnesses
```

The orchestrator owns the prepare, guard, execute, containment, and evidence
phases. The arrow therefore runs from the orchestrator into the lane/interpreter,
not from the interpreter into the orchestrator. Direct `HybridRouter` evaluation
also parses and lowers before reaching the same baseline execution core.

The historical `QuickJS` and `V8` lane names are compatibility labels. Neither
lane embeds those engines: both construct a fresh `InterpreterCore` and differ
primarily in configuration, limits, and policy budgets. The core execution path
does not contain an executable JIT or AOT backend. AOT and tiering modules that
emit plans, guards, or provenance should not be read as machine-code execution.

### Key Types at Each Level

- **Parser/AST**: `Parser`, `ParserOptions`, `ParseError`, `SyntaxTree`,
  `Expression`, `Statement`, `Declaration`, `Program`.
- **IR contract**: `Ir0Module`, `Ir1Module`, `Ir2Module`, `Ir3Module`, and
  `Ir3Instruction` in `ir_contract.rs`.
- **Interpreter**: `InterpreterCore`, `Value`, `Object`, `ExecutionResult`,
  `InterpreterConfig`, and `LaneRouter` in `baseline_interpreter.rs`.
- **Orchestration**: `ExecutionOrchestrator`, lowering contexts, resource
  budgets, containment policy, and security-epoch bindings.
- **Replay/evidence**: `NondeterminismTrace`, `TraceEvent`, `EvidenceEntry`, and
  post-execution IR4/witness artifacts.

### Data Flow Characteristics

- Fixed-input CLI compile artifacts are byte-identical in the declared proof
  lane; run artifacts are identical modulo per-invocation signing authority.
  This is narrower than a universal identical-output guarantee.
- High-impact decisions in the declared replay inventory emit replay/evidence
  records. Not every interpreter instruction becomes an evidence entry.
- Security epochs, instruction budgets, memory budgets, capability checks, and
  containment hooks are explicit runtime mechanisms. Their existence does not
  prove immunity to every temporal or resource-exhaustion attack.
- The public evaluation lifecycle currently includes parsing, static semantics,
  IR lowering, routing, and fresh interpreter setup per evaluation. Benchmark
  results must say whether they measure that mixed lifecycle or prepared
  execution alone.

---

## Security, Replay, and Governance Overlay

### Governance Components

#### Gate System

The repository contains runtime gates, offline evidence validators, CI/operator
scripts, and policy gates. They do not form one universal boundary around every
execution. Examples include `claim_publication_gate.rs`,
`composable_gate_framework.rs`, `remote_capability_gate.rs`, and
`containment_latency_metric_gate.rs`. The generated inventory is authoritative
for the current `*_gate.rs` count. A gate's presence proves only the scope its
producer and verification command actually execute.

#### Capability and IFC Framework

Capability profiles and host-effect checks mediate selected import/hostcall
edges. The interpreter also carries finite information-flow labels and signed
declassification receipts. The shipped selected-edge enforcement is observed;
the end-to-end TypeScript-to-IR rejection contract over every ambient construct
remains targeted. Host objects, proxies, streams, URLs, binary objects, and
cluster state have specialized semantics and label carriers, so generic object
fast paths must exclude them unless equivalence is proved.

#### Security Epochs and Replay

Security epochs bind policy/evidence state to monotonic versioned boundaries.
`deterministic_replay.rs` records sequence-numbered events for declared
nondeterministic and security-relevant operations. Replay coverage is observed
for a declared high-severity inventory, not every possible engine action.
Debugger/reusable cores retain traces after execution; fresh one-shot lane cores
have a different lifecycle and must preserve the same public result artifacts.

#### Fleet Convergence

Fleet/quarantine modules include an N-node harness, SLO schema, fault profiles,
and re-admission primitives. The published CI gate validates contract shape and
source references but does not execute the harness or preserve live percentile
measurements. `FE-CLAIM-005` is therefore TARGETED; this document does not claim
a deployed consensus fleet or measured production convergence.

#### Evidence and Formal Boundaries

`evidence_ledger.rs` supplies signed/chained `EvidenceEntry` records, while
replay and IR4/witness surfaces bind selected execution outcomes. The finite
security algebras, executable invariant tests, Lean sources, Z3-backed checks,
and bounded validators are real components. They are not an end-to-end theorem
that the parser, lowering pipeline, interpreter, host integrations, and every
optimization are correct. The formal claims remain bounded by
`FE-CLAIM-016`–`FE-CLAIM-021`.

### Extension Host Boundary

`crates/franken-extension-host` is a separate library for signed Ed25519
extension manifests, capability declarations, policy decisions, and ordered
journal/defense surfaces. It depends on engine-facing contracts without turning
the core execution path into a V8/QuickJS binding. Product compatibility belongs
in `franken_node`; dependency direction remains `franken_node -> franken_engine`.

## Performance Reality

The native baseline interpreter is the only production execution tier reached
by the named runtime lanes. Current routing configuration does not turn either
lane into a separate optimized engine, and the lane-router profiling API does
not yet supply useful profile data. Historical Node/Bun evidence is a
non-normative mixed-lifecycle failure baseline; current isolated studies still
show FrankenEngine far behind those runtimes despite material hot-path wins.

Optimization work should therefore distinguish:

1. parser/static-semantics/lowering/setup cost;
2. interpreter dispatch and value/object cost;
3. mandatory capability, IFC, replay, and evidence cost;
4. host integration and containment cost; and
5. comparator lifecycle, version, warmup, and JIT state.

A policy or provenance record from a quickening, AOT, superblock, or native-tier
module is not executable output. Promotion requires a linked backend, an
executed path, semantic parity, countermetrics, and reproducible measurement.

---

## Getting Started for Developers

### Orientation Workflow

1. Start with `execution_orchestrator.rs` to see prepare/guard/execute/evidence
   ownership.
2. Trace one program through `parser.rs`, `ast.rs`, `ir_contract.rs`, and
   `lowering_pipeline.rs::lower_ir0_to_ir3`.
3. Follow the resulting `Ir3Instruction` through `LaneRouter` and
   `InterpreterCore` in `baseline_interpreter.rs`.
4. Inspect `deterministic_replay.rs`, `evidence_ledger.rs`, and
   `security_epoch.rs` for the replay/evidence boundary.
5. Read the exact gate producer, verifier, and preserved artifact before relying
   on any `*_gate.rs` claim.

### Key Architectural Principles

- Production crate source forbids unsafe code. Selected integration and
  adversarial tests use `unsafe`; the prohibition is not repository-wide.
- Determinism, replay, and evidence claims are scoped to their declared inputs,
  inventories, and signing-authority caveats.
- Optimizations must preserve JavaScript behavior and capability/IFC/replay
  artifacts; a fast path that skips specialized host-object semantics is invalid.
- Explicit typed refusal is preferable to fabricated compatibility or evidence,
  but refusal alone does not count as implemented language capability.

### Module Organization

- **Core runtime**: `parser.rs`, `ast.rs`, `ir_contract.rs`,
  `lowering_pipeline.rs`, `baseline_interpreter.rs`.
- **Orchestration/policy**: `execution_orchestrator.rs`, `security_epoch.rs`,
  capability, host-effect, containment, and resource-budget modules.
- **Evidence/replay**: `evidence_ledger.rs`, `deterministic_replay.rs`, IR4 and
  witness modules.
- **Governance**: concrete `*_gate.rs` producers/verifiers plus operator scripts;
  consult each gate's contract rather than inferring a universal guarantee.
- **Generated Inventory**: `docs/ARCHITECTURE_INVENTORY.md` records the current source modules, `lib.rs` exports, gate modules, disabled exports, and release binaries.

For implementation details, follow the live call graph and bind conclusions to
the exact revision. For product truth, use the claim matrix and execution truth
ledger rather than architecture prose alone.
