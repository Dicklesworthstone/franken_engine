# Binary Audit and Classification

This document audits all 42 binary entry points and classifies them by function for consolidation into frankenctl subcommands.

## Current Binary Count: 42

### Gate Runners (Validation/Quality Gates) - 8 binaries
1. `franken_zero_placeholder_gate.rs` - Zero placeholder validation gate
2. `franken_signature_drift_gate.rs` - Signature drift validation gate  
3. `franken_adversarial_campaign_gate.rs` - Adversarial campaign validation
4. `franken_ambient_mock_guard.rs` - Mock guard validation
5. `franken_ifc_conformance_runner.rs` - IFC conformance validation
6. `franken_security_conformance_runner.rs` - Security conformance validation
7. `rgc_artifact_validator.rs` - RGC artifact validation
8. `franken_zero_placeholder_scan.rs` - Zero placeholder scanning

### Report Generators (Analysis/Reporting) - 12 binaries
1. `franken_parser_oracle_report.rs` - Parser oracle reports
2. `franken_parser_phase0_report.rs` - Parser phase0 reports  
3. `franken_lowering_gap_inventory.rs` - Lowering gap analysis
4. `franken_parser_gap_inventory.rs` - Parser gap analysis
5. `franken_control_plane_benchmark_split_report.rs` - Control plane benchmark reports
6. `franken_control_plane_mock_inventory.rs` - Control plane mock inventory
7. `franken_control_plane_policy_diagnostics.rs` - Control plane policy diagnostics
8. `franken_engine_product_blocker_ledger.rs` - Product blocker ledger
9. `franken_metadata_substrate_evidence.rs` - Metadata substrate evidence
10. `franken_npm_compatibility_matrix.rs` - NPM compatibility matrix
11. `franken_observability_publication_bundle.rs` - Observability publication bundle  
12. `franken_rgc_planning_track.rs` - RGC planning track reports

### Testing/Verification Tools - 10 binaries
1. `franken_test262_runner.rs` - Test262 conformance runner
2. `franken_lockstep_runner.rs` - Lockstep testing runner
3. `franken_parser_multi_engine_harness.rs` - Multi-engine parser testing
4. `franken_s3fifo_baseline_comparator.rs` - S3FIFO baseline comparison
5. `frx_lockstep_oracle.rs` - FRX lockstep oracle
6. `franken_seqlock_candidate_inventory.rs` - Seqlock candidate testing
7. `franken_seqlock_reader_writer_contract.rs` - Seqlock reader/writer testing
8. `franken_seqlock_rollout_guard.rs` - Seqlock rollout validation
9. `franken_shipped_path_parity.rs` - Shipped path parity testing
10. `franken-verify.rs` - General verification tool

### Synthesis/Generation Tools - 6 binaries  
1. `franken_kernel_synthesis_contract.rs` - Kernel synthesis contract
2. `franken_shape_lattice_bundle.rs` - Shape lattice bundle generation
3. `franken_law_mining.rs` - Law mining synthesis
4. `franken_evidence_ledger_stitching.rs` - Evidence ledger stitching
5. `franken_persistent_cache_contract.rs` - Persistent cache contract
6. `franken_cold_start_compilation_lane.rs` - Cold start compilation

### Orchestration/Execution Tools - 4 binaries
1. `franken_orchestrator_context_refactor.rs` - Orchestrator context management
2. `franken_react_package_cohort.rs` - React package cohort management
3. `franken_asupersync_contract_matrix.rs` - Asupersync contract matrix
4. `franken_tail_latency_control_plane.rs` - Tail latency control plane

### Core Runtime - 2 binaries
1. `frankenctl.rs` - Main CLI entry point (keep as primary binary)
2. `runtime_diagnostics.rs` - Runtime diagnostics

## Consolidation Strategy

### Target Structure:
```
frankenctl                           # Main binary (existing)
├── gates                           # Gate/validation subcommands
│   ├── zero-placeholder
│   ├── signature-drift  
│   ├── adversarial-campaign
│   ├── ambient-mock-guard
│   ├── ifc-conformance
│   ├── security-conformance
│   ├── artifact-validator
│   └── placeholder-scan
├── reports                         # Report generation subcommands
│   ├── parser-oracle
│   ├── parser-phase0
│   ├── lowering-gap
│   ├── parser-gap
│   ├── control-plane-benchmark
│   ├── control-plane-mock
│   ├── control-plane-policy
│   ├── engine-blocker-ledger
│   ├── metadata-evidence
│   ├── npm-compatibility
│   ├── observability-bundle
│   └── rgc-planning
├── test                           # Testing/verification subcommands
│   ├── test262
│   ├── lockstep
│   ├── multi-engine-parser
│   ├── s3fifo-baseline
│   ├── frx-oracle
│   ├── seqlock-candidate
│   ├── seqlock-reader-writer
│   ├── seqlock-rollout
│   ├── shipped-path-parity
│   └── verify-general
├── synth                          # Synthesis/generation subcommands
│   ├── kernel-contract
│   ├── shape-lattice
│   ├── law-mining
│   ├── evidence-stitching
│   ├── cache-contract
│   └── cold-start
├── orchestrate                    # Orchestration subcommands
│   ├── context-refactor
│   ├── react-cohort
│   ├── asupersync-matrix
│   └── tail-latency
└── runtime                        # Runtime diagnostic subcommands
    └── diagnostics
```

### Implementation Plan:
1. Extend frankenctl.rs CommandSpec enum with new subcommand groups
2. Add argument parsing for each subcommand group
3. Migrate functionality from standalone binaries to frankenctl subcommands
4. Remove standalone binary files
5. Update build configuration to only build frankenctl