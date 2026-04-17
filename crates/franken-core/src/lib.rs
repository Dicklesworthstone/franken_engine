#![forbid(unsafe_code)]

//! Core runtime modules for the FrankenEngine JavaScript runtime.
//!
//! This crate contains the fundamental modules that form the core execution
//! pipeline: parsing, lowering, interpretation, and evidence collection.

extern crate self as frankenengine_core;

// Core module declarations
pub mod ast;
pub mod baseline_interpreter;
pub mod bayesian_posterior;
pub mod capability;
pub mod checkpoint;
pub mod containment_executor;
pub mod cx_threading;
pub mod deterministic_serde;
pub mod engine_object_id;
pub mod entropy_evidence_compressor;
pub mod evidence_ledger;
pub mod execution_cell;
pub mod execution_orchestrator;
pub mod expected_loss_selector;
pub mod fleet_convergence;
pub mod fleet_immune_protocol;
pub mod flow_lattice;
pub mod guardplane_adapter;
pub mod hash_tiers;
pub mod hindsight_boundary_capture;
pub mod ifc_artifacts;
pub mod ir_contract;
pub mod lowering_pipeline;
pub mod optimal_stopping;
pub mod parser;
pub mod parser_gap_inventory;
pub mod region_lifecycle;
pub mod regret_bounded_router;
pub mod runtime_config;
pub mod saga_orchestrator;
pub mod security_epoch;
pub mod signature_preimage;
pub mod spectral_fleet_convergence;
pub mod tropical_semiring;
pub mod trust_economics;
pub mod ts_normalization;