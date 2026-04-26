# FrankenEngine Impossible-by-Default Demos

## How To Use This Index

These examples are directory-based demos and shell verifiers. The workspace does
not ship Cargo `--example` targets, so commands like
`cargo run --example 05_replay_demo` will fail in this checkout.

Run the listed `verify.sh` or `demo.sh` command from the repository root.

## Impossible-by-Default Capabilities

The following table maps FrankenEngine's 13 impossible-by-default capabilities
from PLAN section 3.2 to the shipped example directories in this repository.

| # | Capability | Demo Directory | Command |
|---|------------|----------------|---------|
| 1 | Receipts | `02_signed_decision_receipt` | `./examples/02_signed_decision_receipt/verify.sh` |
| 2 | Replay | `05_replay_demo` | `./examples/05_replay_demo/verify.sh` |
| 3 | Checkpoints | `20_signed_checkpoints` | `./examples/20_signed_checkpoints/verify.sh` |
| 4 | Quarantine | `07_quarantine_mesh` | `./examples/07_quarantine_mesh/demo.sh` |
| 5 | Proof-carrying adaptive optimization | `15_proof_carrying_optimization` | `./examples/15_proof_carrying_optimization/verify.sh` |
| 6 | Capability-typed execution | `06_capability_typed` | `./examples/06_capability_typed/verify.sh` |
| 7 | Deterministic resource exhaustion semantics | `13_resource_budget_demo` | `./examples/13_resource_budget_demo/verify.sh` |
| 8 | Revocation-first execution gates | `14_revocation_first_gate` | `./examples/14_revocation_first_gate/verify.sh` |
| 9 | Distributed anti-entropy trust reconciliation | `-` | No dedicated example directory is currently shipped. |
| 10 | Red/Blue coevolution | `19_red_blue_coevolution` | `./examples/19_red_blue_coevolution/verify.sh` |
| 11 | Self-replacement lineage | `16_self_replacement_lineage` | `./examples/16_self_replacement_lineage/verify.sh` |
| 12 | Information-flow confinement | `17_information_flow_confinement` | `./examples/17_information_flow_confinement/verify.sh` |
| 13 | Security-proof-guided specialization | `18_proof_guided_specialization` | `./examples/18_proof_guided_specialization/verify.sh` |

## Additional Examples

- `01_hello_world` - General FrankenEngine introduction
- `03_doctor_input` - Doctor diagnostic tooling
- `04_bench_vs_node` - Performance benchmarking
- `08_proof_carrying_optimization` - Alternate certified rewrite demo for capability #5
- `11_cli_workflow_smoke` - CLI workflow demonstration
- `12_frankenctl_react_demo` - Fail-closed React compile contract demo

Each example directory contains its own README plus the command listed above.
