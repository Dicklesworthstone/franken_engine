# FrankenEngine Impossible-by-Default Demos

## Setup

```bash
cargo build --workspace --release
```

## Impossible-by-Default Capabilities

The following table maps FrankenEngine's 13 impossible-by-default capabilities from PLAN section 3.2 to actual demo directories:

| # | Capability | Demo Directory | Verify Command | Status |
|---|------------|----------------|----------------|--------|
| 1 | Receipts | `02_signed_decision_receipt` | `cargo run --example 02_signed_decision_receipt` | PASSING |
| 2 | Replay | `05_replay_demo` | `cargo run --example 05_replay_demo` | IN_FLIGHT |
| 3 | Checkpoints | `20_signed_checkpoints` | `cargo run --example 20_signed_checkpoints` | PASSING |
| 4 | Quarantine | `07_quarantine_mesh` | `cargo run --example 07_quarantine_mesh` | PASSING |
| 5 | Proof-carrying | `15_proof_carrying` | `cargo run --example 15_proof_carrying` | IN_FLIGHT |
| 6 | Capability | `06_capability_typed` | `cargo run --example 06_capability_typed` | PASSING |
| 7 | Budget | `13_resource_budget_demo` | `cargo run --example 13_resource_budget_demo` | PASSING |
| 8 | Gate | `14_revocation_first_gate` | `cargo run --example 14_revocation_first_gate` | IN_FLIGHT |
| 9 | Quarantine+ | `07_quarantine_mesh` | `cargo run --example 07_quarantine_mesh` | PASSING |
| 10 | RedBlue | `19_redblue` | `cargo run --example 19_redblue` | IN_FLIGHT |
| 11 | Lineage | `16_self_replacement_lineage` | `cargo run --example 16_self_replacement_lineage` | PASSING |
| 12 | IFC | `17_information_flow_confinement` | `cargo run --example 17_information_flow_confinement` | PASSING |
| 13 | Spec | `18_spec` | `cargo run --example 18_spec` | IN_FLIGHT |

### Additional Examples

- `01_hello_world` - General FrankenEngine introduction
- `03_doctor_input` - Doctor diagnostic tooling
- `04_bench_vs_node` - Performance benchmarking
- `11_cli_workflow_smoke` - CLI workflow demonstration

## Usage

Each demo directory contains a complete example with source code and documentation. Run the verify command to see the capability in action.