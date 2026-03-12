//! Integration tests for `frankenengine_engine::succinct_witness_compiler`.
//!
//! Exercises the succinct witness compiler and merklized evidence packing
//! from the public crate boundary: SufficiencyDimension, WitnessSchema,
//! SufficiencyCertificate, EvidenceChunk, MerkleTree, InclusionProof,
//! ProvenanceAttachment, WitnessCompiler, CompilationResult, PackVerifier,
//! generate_report, canonical_witness_schemas.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::proof_obligations::ObligationCategory;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::succinct_witness_compiler::{
    ChunkManifestEntry, CompilationError, CompilationResult, DEFAULT_MAX_CHUNK_BYTES,
    EvidenceChunk, InclusionProof, MIN_SUFFICIENCY_SCORE, MerkleTree, PackReportEntry,
    PackVerificationResult, PackVerifier, ProofStep, ProvenanceAttachment, ReconstructionHint,
    ReconstructionKind, SCHEMA_VERSION, SufficiencyCertificate, SufficiencyConstraint,
    SufficiencyDimension, SufficiencyResult, SufficiencyViolation, WitnessCompiler, WitnessPack,
    WitnessPackReport, WitnessSchema, canonical_witness_schemas, generate_report, hash_pair,
};

// ── Helpers ─────────────────────────────────────────────────────────────

fn sample_provenance() -> ProvenanceAttachment {
    ProvenanceAttachment {
        toolchain_hash: "abc123".to_string(),
        git_hash: "def456".to_string(),
        environment_hash: "ghi789".to_string(),
        collection_epoch: SecurityEpoch::from_raw(5),
        packed_at: "2026-02-26T00:00:00Z".to_string(),
        legal_summary: Some("MIT licensed".to_string()),
    }
}

fn sample_schema(epoch: SecurityEpoch) -> WitnessSchema {
    let mut families = BTreeSet::new();
    families.insert("decision".to_string());
    let mut required = BTreeSet::new();
    required.insert("trace_id".to_string());
    let mut obligations = BTreeSet::new();
    obligations.insert("Correctness".to_string());
    let mut schema = WitnessSchema {
        schema_id: String::new(),
        name: "Test Schema".to_string(),
        payload_families: families,
        constraints: vec![SufficiencyConstraint {
            dimension: SufficiencyDimension::ReplayCompleteness,
            min_score_millionths: 800_000,
            rationale: "test constraint".to_string(),
        }],
        required_fields: required,
        obligation_categories: obligations,
        epoch,
    };
    schema.schema_id = schema.compute_id();
    schema
}

fn compile_simple() -> CompilationResult {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1, 2, 3, 4])
        .add_chunk("decision", vec![5, 6, 7, 8])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .expect("compile")
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn constants_are_valid() {
    assert!(!SCHEMA_VERSION.is_empty());
    const { assert!(DEFAULT_MAX_CHUNK_BYTES > 0) };
    const { assert!(MIN_SUFFICIENCY_SCORE > 0) };
}

// ── SufficiencyDimension ────────────────────────────────────────────────

#[test]
fn sufficiency_dimension_all_has_five() {
    assert_eq!(SufficiencyDimension::ALL.len(), 5);
}

#[test]
fn sufficiency_dimension_display() {
    assert_eq!(
        SufficiencyDimension::ReplayCompleteness.to_string(),
        "replay_completeness"
    );
    assert_eq!(
        SufficiencyDimension::VerificationCoverage.to_string(),
        "verification_coverage"
    );
    assert_eq!(
        SufficiencyDimension::LegalRetention.to_string(),
        "legal_retention"
    );
    assert_eq!(
        SufficiencyDimension::CausalOrdering.to_string(),
        "causal_ordering"
    );
    assert_eq!(
        SufficiencyDimension::ProvenanceBinding.to_string(),
        "provenance_binding"
    );
}

#[test]
fn sufficiency_dimension_serde_roundtrip() {
    for dim in SufficiencyDimension::ALL {
        let json = serde_json::to_string(&dim).unwrap();
        let back: SufficiencyDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(back, dim);
    }
}

// ── WitnessSchema ──────────────────────────────────────────────────────

#[test]
fn witness_schema_compute_id_deterministic() {
    let s1 = sample_schema(SecurityEpoch::from_raw(5));
    let s2 = sample_schema(SecurityEpoch::from_raw(5));
    assert_eq!(s1.schema_id, s2.schema_id);
    assert!(s1.schema_id.starts_with("ws-"));
}

#[test]
fn witness_schema_serde_roundtrip() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let json = serde_json::to_string(&schema).unwrap();
    let back: WitnessSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(back, schema);
}

#[test]
fn witness_schema_validate_sufficiency_passes() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 900_000i64);
    let cert = SufficiencyCertificate {
        certificate_id: "cert-1".to_string(),
        witness_pack_id: "wp-1".to_string(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 900_000,
        all_satisfied: true,
        epoch: SecurityEpoch::from_raw(5),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(result.satisfied);
    assert!(result.violations.is_empty());
}

#[test]
fn witness_schema_validate_sufficiency_fails_below_threshold() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 500_000i64);
    let cert = SufficiencyCertificate {
        certificate_id: "cert-1".to_string(),
        witness_pack_id: "wp-1".to_string(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 500_000,
        all_satisfied: false,
        epoch: SecurityEpoch::from_raw(5),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(!result.satisfied);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(
        result.violations[0].dimension,
        SufficiencyDimension::ReplayCompleteness
    );
}

// ── EvidenceChunk ──────────────────────────────────────────────────────

#[test]
fn evidence_chunk_new_computes_hash() {
    let chunk = EvidenceChunk::new(0, "decision", vec![1, 2, 3]);
    assert!(!chunk.content_hash.is_empty());
    assert_eq!(chunk.size_bytes, 3);
    assert_eq!(chunk.payload_family, "decision");
    assert_eq!(chunk.index, 0);
}

#[test]
fn evidence_chunk_deterministic_hash() {
    let c1 = EvidenceChunk::new(0, "test", vec![1, 2, 3]);
    let c2 = EvidenceChunk::new(0, "test", vec![1, 2, 3]);
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.leaf_hash(), c2.leaf_hash());
}

#[test]
fn evidence_chunk_different_payloads_differ() {
    let c1 = EvidenceChunk::new(0, "test", vec![1, 2, 3]);
    let c2 = EvidenceChunk::new(0, "test", vec![4, 5, 6]);
    assert_ne!(c1.content_hash, c2.content_hash);
    assert_ne!(c1.leaf_hash(), c2.leaf_hash());
}

#[test]
fn evidence_chunk_serde_roundtrip() {
    let chunk = EvidenceChunk::new(0, "decision", vec![1, 2, 3]);
    let json = serde_json::to_string(&chunk).unwrap();
    let back: EvidenceChunk = serde_json::from_str(&json).unwrap();
    assert_eq!(back, chunk);
}

// ── MerkleTree ──────────────────────────────────────────────────────────

#[test]
fn merkle_tree_empty() {
    let tree = MerkleTree::build(&[]);
    assert_eq!(tree.leaf_count, 0);
    assert_eq!(tree.root_hash, [0u8; 32]);
}

#[test]
fn merkle_tree_single_leaf() {
    let leaf = [42u8; 32];
    let tree = MerkleTree::build(&[leaf]);
    assert_eq!(tree.leaf_count, 1);
    assert_eq!(tree.root_hash, leaf);
}

#[test]
fn merkle_tree_two_leaves() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let tree = MerkleTree::build(&[a, b]);
    assert_eq!(tree.leaf_count, 2);
    assert_eq!(tree.root_hash, hash_pair(&a, &b));
}

#[test]
fn merkle_tree_deterministic() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let t1 = MerkleTree::build(&leaves);
    let t2 = MerkleTree::build(&leaves);
    assert_eq!(t1.root_hash, t2.root_hash);
}

#[test]
fn merkle_tree_serde_roundtrip() {
    let leaves: Vec<[u8; 32]> = (0..3).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    let json = serde_json::to_string(&tree).unwrap();
    let back: MerkleTree = serde_json::from_str(&json).unwrap();
    assert_eq!(back, tree);
}

// ── InclusionProof ──────────────────────────────────────────────────────

#[test]
fn inclusion_proof_verifies_for_valid_tree() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    for i in 0..4 {
        let proof = tree.inclusion_proof(i).expect("proof exists");
        assert!(proof.verify());
        assert!(proof.verify_against(&tree.root_hash));
    }
}

#[test]
fn inclusion_proof_fails_for_wrong_root() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    let proof = tree.inclusion_proof(0).unwrap();
    let wrong_root = [0xFF; 32];
    assert!(!proof.verify_against(&wrong_root));
}

#[test]
fn inclusion_proof_out_of_bounds_returns_none() {
    let tree = MerkleTree::build(&[[0u8; 32]]);
    assert!(tree.inclusion_proof(1).is_none());
}

#[test]
fn inclusion_proof_serde_roundtrip() {
    let leaves: Vec<[u8; 32]> = (0..2).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    let proof = tree.inclusion_proof(0).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let back: InclusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back, proof);
}

// ── ProvenanceAttachment ────────────────────────────────────────────────

#[test]
fn provenance_content_hash_deterministic() {
    let p1 = sample_provenance();
    let p2 = sample_provenance();
    assert_eq!(p1.content_hash(), p2.content_hash());
}

#[test]
fn provenance_content_hash_changes_with_different_input() {
    let mut p = sample_provenance();
    let hash1 = p.content_hash();
    p.git_hash = "changed".to_string();
    assert_ne!(p.content_hash(), hash1);
}

#[test]
fn provenance_serde_roundtrip() {
    let p = sample_provenance();
    let json = serde_json::to_string(&p).unwrap();
    let back: ProvenanceAttachment = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

// ── ReconstructionKind ──────────────────────────────────────────────────

#[test]
fn reconstruction_kind_display() {
    assert_eq!(ReconstructionKind::Inline.to_string(), "inline");
    assert_eq!(
        ReconstructionKind::ContentAddressed.to_string(),
        "content_addressed"
    );
    assert_eq!(
        ReconstructionKind::DeterministicReplay.to_string(),
        "deterministic_replay"
    );
    assert_eq!(ReconstructionKind::Hybrid.to_string(), "hybrid");
}

#[test]
fn reconstruction_kind_serde_roundtrip() {
    for kind in [
        ReconstructionKind::Inline,
        ReconstructionKind::ContentAddressed,
        ReconstructionKind::DeterministicReplay,
        ReconstructionKind::Hybrid,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ReconstructionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }
}

// ── WitnessCompiler ────────────────────────────────────────────────────

#[test]
fn compiler_no_evidence_returns_error() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5));
    assert_eq!(result.unwrap_err(), CompilationError::NoEvidence);
}

#[test]
fn compiler_missing_provenance_returns_error() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1, 2, 3])
        .compile(SecurityEpoch::from_raw(5));
    assert_eq!(result.unwrap_err(), CompilationError::MissingProvenance);
}

#[test]
fn compiler_chunk_too_large_returns_error() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let large_payload = vec![0u8; 100];
    let result = WitnessCompiler::new(schema)
        .max_chunk_bytes(50)
        .add_chunk("decision", large_payload)
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5));
    match result.unwrap_err() {
        CompilationError::ChunkTooLarge { index, size, max } => {
            assert_eq!(index, 0);
            assert_eq!(size, 100);
            assert_eq!(max, 50);
        }
        other => panic!("expected ChunkTooLarge, got {other:?}"),
    }
}

#[test]
fn compiler_simple_compilation_succeeds() {
    let result = compile_simple();
    assert_eq!(result.pack.chunk_count, 2);
    assert_eq!(result.chunks.len(), 2);
    assert_eq!(result.inclusion_proofs.len(), 2);
    assert!(!result.pack.merkle_root.is_empty());
    assert!(result.pack.pack_id.starts_with("wp-"));
}

#[test]
fn compiler_with_reconstruction_hints() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1, 2, 3])
        .with_reconstruction(ReconstructionKind::Inline)
        .add_chunk("replay", vec![4, 5, 6])
        .with_content_addressed_reconstruction("hash-abc")
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    assert_eq!(result.pack.reconstruction_hints.len(), 2);
    assert_eq!(
        result.pack.reconstruction_hints[0].kind,
        ReconstructionKind::Inline
    );
    assert_eq!(
        result.pack.reconstruction_hints[1].kind,
        ReconstructionKind::ContentAddressed
    );
    assert_eq!(
        result.pack.reconstruction_hints[1].artifact_hash.as_deref(),
        Some("hash-abc")
    );
}

// ── CompilationResult ──────────────────────────────────────────────────

#[test]
fn compilation_result_verify_all_proofs() {
    let result = compile_simple();
    assert!(result.verify_all_proofs());
}

#[test]
fn compilation_result_proof_for_chunk() {
    let result = compile_simple();
    assert!(result.proof_for_chunk(0).is_some());
    assert!(result.proof_for_chunk(1).is_some());
    assert!(result.proof_for_chunk(2).is_none());
}

#[test]
fn compilation_result_certify_sufficiency() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = compile_simple();
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 900_000i64);
    let cert = result.certify_sufficiency(&schema, scores);
    assert!(cert.all_satisfied);
    assert!(cert.certificate_id.starts_with("sc-"));
    assert_eq!(cert.witness_pack_id, result.pack.pack_id);
    assert_eq!(cert.overall_score_millionths, 900_000);
}

#[test]
fn compilation_result_certify_sufficiency_fails_when_below() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = compile_simple();
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 500_000i64);
    let cert = result.certify_sufficiency(&schema, scores);
    assert!(!cert.all_satisfied);
}

#[test]
fn compilation_result_serde_roundtrip() {
    let result = compile_simple();
    let json = serde_json::to_string(&result).unwrap();
    let back: CompilationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pack.pack_id, result.pack.pack_id);
    assert_eq!(back.pack.merkle_root, result.pack.merkle_root);
    assert_eq!(back.chunks.len(), result.chunks.len());
}

// ── PackVerifier ────────────────────────────────────────────────────────

#[test]
fn pack_verifier_valid_result() {
    let result = compile_simple();
    let v = PackVerifier::verify_result(&result);
    assert!(v.valid);
    assert!(v.issues.is_empty());
}

#[test]
fn pack_verifier_verify_inclusion_with_hex_root() {
    let result = compile_simple();
    let proof = result.proof_for_chunk(0).unwrap();
    assert!(PackVerifier::verify_inclusion(
        proof,
        &result.pack.merkle_root
    ));
}

#[test]
fn pack_verifier_verify_inclusion_bad_root() {
    let result = compile_simple();
    let proof = result.proof_for_chunk(0).unwrap();
    assert!(!PackVerifier::verify_inclusion(proof, "not-a-hex"));
}

// ── CompilationError ────────────────────────────────────────────────────

#[test]
fn compilation_error_display() {
    assert!(
        CompilationError::NoEvidence
            .to_string()
            .contains("no evidence")
    );
    assert!(
        CompilationError::MissingProvenance
            .to_string()
            .contains("provenance")
    );
    let err = CompilationError::ChunkTooLarge {
        index: 3,
        size: 8000,
        max: 4096,
    };
    let msg = err.to_string();
    assert!(msg.contains("3"));
    assert!(msg.contains("8000"));
    assert!(msg.contains("4096"));
}

#[test]
fn compilation_error_serde_roundtrip() {
    for err in [
        CompilationError::NoEvidence,
        CompilationError::MissingProvenance,
        CompilationError::ChunkTooLarge {
            index: 0,
            size: 100,
            max: 50,
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: CompilationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }
}

// ── generate_report ─────────────────────────────────────────────────────

#[test]
fn generate_report_single_pack() {
    let result = compile_simple();
    let report = generate_report(&[&result]);
    assert!(report.all_valid);
    assert_eq!(report.pack_ids.len(), 1);
    assert_eq!(report.total_chunks, 2);
    assert!(report.total_bytes > 0);
    assert!(!report.report_id.is_empty());
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_multiple_packs() {
    let r1 = compile_simple();
    let r2 = compile_simple();
    let report = generate_report(&[&r1, &r2]);
    assert!(report.all_valid);
    assert_eq!(report.pack_ids.len(), 2);
    assert_eq!(report.total_chunks, 4);
}

#[test]
fn generate_report_deterministic() {
    let r = compile_simple();
    let rep1 = generate_report(&[&r]);
    let rep2 = generate_report(&[&r]);
    assert_eq!(rep1.content_hash, rep2.content_hash);
    assert_eq!(rep1.report_id, rep2.report_id);
}

// ── canonical_witness_schemas ───────────────────────────────────────────

#[test]
fn canonical_schemas_produces_five() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    assert_eq!(schemas.len(), 5);
    for schema in &schemas {
        assert!(schema.schema_id.starts_with("ws-"));
        assert!(!schema.name.is_empty());
        assert!(!schema.constraints.is_empty());
    }
}

#[test]
fn canonical_schemas_have_unique_ids() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    let ids: BTreeSet<_> = schemas.iter().map(|s| &s.schema_id).collect();
    assert_eq!(ids.len(), 5);
}

// ── Full lifecycle ──────────────────────────────────────────────────────

#[test]
fn full_lifecycle_compile_verify_certify_report() {
    let epoch = SecurityEpoch::from_raw(5);
    let schema = sample_schema(epoch);

    // Compile.
    let result = WitnessCompiler::new(schema.clone())
        .add_chunk("decision", b"evidence-1".to_vec())
        .add_chunk("decision", b"evidence-2".to_vec())
        .add_chunk("decision", b"evidence-3".to_vec())
        .provenance(sample_provenance())
        .compile(epoch)
        .unwrap();

    // Verify.
    assert!(result.verify_all_proofs());
    let v = PackVerifier::verify_result(&result);
    assert!(v.valid);

    // Certify sufficiency.
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 900_000i64);
    let cert = result.certify_sufficiency(&schema, scores);
    assert!(cert.all_satisfied);
    let sufficiency_result = schema.validate_sufficiency(&cert);
    assert!(sufficiency_result.satisfied);

    // Report.
    let report = generate_report(&[&result]);
    assert!(report.all_valid);
    assert_eq!(report.total_chunks, 3);
}

#[test]
fn full_lifecycle_deterministic() {
    let epoch = SecurityEpoch::from_raw(5);
    let schema = sample_schema(epoch);

    let build = || {
        WitnessCompiler::new(schema.clone())
            .add_chunk("decision", b"payload".to_vec())
            .provenance(sample_provenance())
            .compile(epoch)
            .unwrap()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.pack.pack_id, r2.pack.pack_id);
    assert_eq!(r1.pack.merkle_root, r2.pack.merkle_root);
    assert_eq!(r1.tree.root_hash, r2.tree.root_hash);
}

// ── Enrichment: PearlTower 2026-03-12 ───────────────────────────────

// ── SufficiencyConstraint integration ────────────────────────────────

#[test]
fn sufficiency_constraint_serde_roundtrip_integration() {
    for dim in SufficiencyDimension::ALL {
        let sc = SufficiencyConstraint {
            dimension: dim,
            min_score_millionths: 750_000,
            rationale: format!("constraint for {dim}"),
        };
        let json = serde_json::to_string(&sc).unwrap();
        let back: SufficiencyConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(sc, back);
    }
}

#[test]
fn sufficiency_constraint_clone_independence() {
    let c1 = SufficiencyConstraint {
        dimension: SufficiencyDimension::LegalRetention,
        min_score_millionths: 800_000,
        rationale: "original".to_string(),
    };
    let mut c2 = c1.clone();
    c2.rationale = "mutated".to_string();
    assert_eq!(c1.rationale, "original");
    assert_ne!(c1.rationale, c2.rationale);
}

#[test]
fn sufficiency_constraint_zero_min_score() {
    let sc = SufficiencyConstraint {
        dimension: SufficiencyDimension::ReplayCompleteness,
        min_score_millionths: 0,
        rationale: "accepts anything".to_string(),
    };
    let json = serde_json::to_string(&sc).unwrap();
    let back: SufficiencyConstraint = serde_json::from_str(&json).unwrap();
    assert_eq!(back.min_score_millionths, 0);
}

// ── SufficiencyResult integration ────────────────────────────────────

#[test]
fn sufficiency_result_serde_roundtrip_satisfied() {
    let sr = SufficiencyResult {
        satisfied: true,
        min_score_millionths: 900_000,
        violations: vec![],
    };
    let json = serde_json::to_string(&sr).unwrap();
    let back: SufficiencyResult = serde_json::from_str(&json).unwrap();
    assert_eq!(sr, back);
}

#[test]
fn sufficiency_result_serde_roundtrip_unsatisfied_multi_violations() {
    let sr = SufficiencyResult {
        satisfied: false,
        min_score_millionths: 100_000,
        violations: vec![
            SufficiencyViolation {
                dimension: SufficiencyDimension::ReplayCompleteness,
                required_millionths: 800_000,
                actual_millionths: 100_000,
            },
            SufficiencyViolation {
                dimension: SufficiencyDimension::CausalOrdering,
                required_millionths: 900_000,
                actual_millionths: 200_000,
            },
        ],
    };
    let json = serde_json::to_string(&sr).unwrap();
    let back: SufficiencyResult = serde_json::from_str(&json).unwrap();
    assert_eq!(sr, back);
    assert_eq!(back.violations.len(), 2);
}

// ── SufficiencyViolation integration ─────────────────────────────────

#[test]
fn sufficiency_violation_serde_all_dimensions() {
    for dim in SufficiencyDimension::ALL {
        let sv = SufficiencyViolation {
            dimension: dim,
            required_millionths: 850_000,
            actual_millionths: 300_000,
        };
        let json = serde_json::to_string(&sv).unwrap();
        let back: SufficiencyViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(sv, back);
    }
}

#[test]
fn sufficiency_violation_zero_actual() {
    let sv = SufficiencyViolation {
        dimension: SufficiencyDimension::ProvenanceBinding,
        required_millionths: 850_000,
        actual_millionths: 0,
    };
    let json = serde_json::to_string(&sv).unwrap();
    let back: SufficiencyViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(back.actual_millionths, 0);
}

// ── SufficiencyCertificate integration ───────────────────────────────

#[test]
fn sufficiency_certificate_compute_id_deterministic() {
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 900_000i64);
    scores.insert("verification_coverage".to_string(), 800_000i64);
    let cert = SufficiencyCertificate {
        certificate_id: String::new(),
        witness_pack_id: "wp-test".to_string(),
        schema_id: "ws-test".to_string(),
        dimension_scores: scores,
        overall_score_millionths: 800_000,
        all_satisfied: true,
        epoch: SecurityEpoch::from_raw(5),
    };
    let id1 = cert.compute_id();
    let id2 = cert.compute_id();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("sc-"));
}

#[test]
fn sufficiency_certificate_compute_id_changes_with_witness_pack_id() {
    let make = |wp_id: &str| {
        let mut scores = BTreeMap::new();
        scores.insert("replay_completeness".to_string(), 900_000i64);
        SufficiencyCertificate {
            certificate_id: String::new(),
            witness_pack_id: wp_id.to_string(),
            schema_id: "ws-test".to_string(),
            dimension_scores: scores,
            overall_score_millionths: 900_000,
            all_satisfied: true,
            epoch: SecurityEpoch::from_raw(5),
        }
    };
    assert_ne!(make("wp-aaa").compute_id(), make("wp-bbb").compute_id());
}

#[test]
fn sufficiency_certificate_serde_roundtrip_integration() {
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 950_000i64);
    scores.insert("causal_ordering".to_string(), 880_000i64);
    scores.insert("legal_retention".to_string(), 760_000i64);
    let cert = SufficiencyCertificate {
        certificate_id: "sc-abc".to_string(),
        witness_pack_id: "wp-xyz".to_string(),
        schema_id: "ws-test".to_string(),
        dimension_scores: scores,
        overall_score_millionths: 760_000,
        all_satisfied: false,
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let back: SufficiencyCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ── ProofStep integration ────────────────────────────────────────────

#[test]
fn proof_step_serde_roundtrip_left() {
    let step = ProofStep {
        hash: [0x11; 32],
        is_right: false,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: ProofStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
    assert!(!back.is_right);
}

#[test]
fn proof_step_serde_roundtrip_right() {
    let step = ProofStep {
        hash: [0xFE; 32],
        is_right: true,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: ProofStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, back);
    assert!(back.is_right);
}

// ── ReconstructionHint integration ───────────────────────────────────

#[test]
fn reconstruction_hint_serde_no_optional_fields() {
    let hint = ReconstructionHint {
        chunk_index: 0,
        kind: ReconstructionKind::Inline,
        artifact_hash: None,
        replay_session_id: None,
    };
    let json = serde_json::to_string(&hint).unwrap();
    let back: ReconstructionHint = serde_json::from_str(&json).unwrap();
    assert_eq!(hint, back);
    assert!(back.artifact_hash.is_none());
    assert!(back.replay_session_id.is_none());
}

#[test]
fn reconstruction_hint_serde_all_fields_populated() {
    let hint = ReconstructionHint {
        chunk_index: 42,
        kind: ReconstructionKind::Hybrid,
        artifact_hash: Some("cafebabe".to_string()),
        replay_session_id: Some("session-99".to_string()),
    };
    let json = serde_json::to_string(&hint).unwrap();
    let back: ReconstructionHint = serde_json::from_str(&json).unwrap();
    assert_eq!(hint, back);
}

#[test]
fn reconstruction_hint_serde_each_kind() {
    for kind in [
        ReconstructionKind::Inline,
        ReconstructionKind::ContentAddressed,
        ReconstructionKind::DeterministicReplay,
        ReconstructionKind::Hybrid,
    ] {
        let hint = ReconstructionHint {
            chunk_index: 0,
            kind,
            artifact_hash: None,
            replay_session_id: None,
        };
        let json = serde_json::to_string(&hint).unwrap();
        let back: ReconstructionHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, kind);
    }
}

// ── ChunkManifestEntry integration ───────────────────────────────────

#[test]
fn chunk_manifest_entry_serde_roundtrip_integration() {
    let entry = ChunkManifestEntry {
        index: 5,
        content_hash: "deadbeefdeadbeef".to_string(),
        payload_family: "replay".to_string(),
        size_bytes: 1024,
        leaf_hash: "cafebabecafebabe".to_string(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: ChunkManifestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn chunk_manifest_entry_from_compilation_matches_chunk() {
    let result = compile_simple();
    for (entry, chunk) in result.pack.chunk_manifest.iter().zip(result.chunks.iter()) {
        assert_eq!(entry.index, chunk.index);
        assert_eq!(entry.content_hash, chunk.content_hash);
        assert_eq!(entry.payload_family, chunk.payload_family);
        assert_eq!(entry.size_bytes, chunk.size_bytes);
        assert_eq!(entry.leaf_hash, hex::encode(chunk.leaf_hash()));
    }
}

// ── WitnessPack integration ─────────────────────────────────────────

#[test]
fn witness_pack_compute_id_deterministic() {
    let result = compile_simple();
    let id1 = result.pack.compute_id();
    let id2 = result.pack.compute_id();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("wp-"));
}

#[test]
fn witness_pack_serde_roundtrip_integration() {
    let result = compile_simple();
    let json = serde_json::to_string(&result.pack).unwrap();
    let back: WitnessPack = serde_json::from_str(&json).unwrap();
    assert_eq!(result.pack, back);
}

#[test]
fn witness_pack_families_returns_deduped_sorted() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("zebra", vec![1])
        .add_chunk("alpha", vec![2])
        .add_chunk("zebra", vec![3])
        .add_chunk("middle", vec![4])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    let fams = result.pack.families();
    assert_eq!(fams, vec!["alpha", "middle", "zebra"]);
}

#[test]
fn witness_pack_covers_obligation_positive_and_negative() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1, 2, 3])
        .obligation_category(ObligationCategory::Safety)
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    assert!(result.pack.covers_obligation(&ObligationCategory::Safety));
    assert!(!result.pack.covers_obligation(&ObligationCategory::Liveness));
}

#[test]
fn witness_pack_compute_id_changes_with_epoch() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let r1 = WitnessCompiler::new(schema.clone())
        .add_chunk("decision", vec![1, 2, 3])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    let r2 = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1, 2, 3])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(99))
        .unwrap();
    assert_ne!(r1.pack.pack_id, r2.pack.pack_id);
}

// ── WitnessPackReport integration ────────────────────────────────────

#[test]
fn witness_pack_report_serde_roundtrip() {
    let result = compile_simple();
    let report = generate_report(&[&result]);
    let json = serde_json::to_string(&report).unwrap();
    let back: WitnessPackReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn witness_pack_report_compute_hash_deterministic() {
    let result = compile_simple();
    let report = generate_report(&[&result]);
    let h1 = report.compute_hash();
    let h2 = report.compute_hash();
    assert_eq!(h1, h2);
}

#[test]
fn witness_pack_report_report_id_starts_with_wpr() {
    let result = compile_simple();
    let report = generate_report(&[&result]);
    assert!(report.report_id.starts_with("wpr-"));
    assert_eq!(report.report_id.len(), 4 + 32); // "wpr-" + 32 hex chars
}

// ── PackReportEntry integration ──────────────────────────────────────

#[test]
fn pack_report_entry_serde_no_sufficiency() {
    let entry = PackReportEntry {
        pack_id: "wp-test".to_string(),
        chunk_count: 2,
        total_bytes: 256,
        payload_families: vec!["decision".to_string()],
        valid: true,
        issues: vec![],
        sufficiency_score: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PackReportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert!(back.sufficiency_score.is_none());
}

#[test]
fn pack_report_entry_serde_with_issues() {
    let entry = PackReportEntry {
        pack_id: "wp-bad".to_string(),
        chunk_count: 1,
        total_bytes: 100,
        payload_families: vec!["security".to_string()],
        valid: false,
        issues: vec![
            "merkle root mismatch".to_string(),
            "chunk count mismatch".to_string(),
        ],
        sufficiency_score: Some(400_000),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PackReportEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
    assert_eq!(back.issues.len(), 2);
}

// ── PackVerificationResult integration ───────────────────────────────

#[test]
fn pack_verification_result_serde_valid() {
    let pvr = PackVerificationResult {
        valid: true,
        issues: vec![],
    };
    let json = serde_json::to_string(&pvr).unwrap();
    let back: PackVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pvr, back);
}

#[test]
fn pack_verification_result_serde_invalid_with_issues() {
    let pvr = PackVerificationResult {
        valid: false,
        issues: vec!["pack_id is not deterministic".to_string()],
    };
    let json = serde_json::to_string(&pvr).unwrap();
    let back: PackVerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pvr, back);
    assert!(!back.valid);
}

// ── EvidenceChunk edge cases ─────────────────────────────────────────

#[test]
fn evidence_chunk_large_index() {
    let chunk = EvidenceChunk::new(999_999, "decision", vec![0xFF; 16]);
    assert_eq!(chunk.index, 999_999);
    assert_eq!(chunk.size_bytes, 16);
}

#[test]
fn evidence_chunk_same_content_hash_regardless_of_index() {
    let c0 = EvidenceChunk::new(0, "test", vec![1, 2, 3]);
    let c1 = EvidenceChunk::new(1, "test", vec![1, 2, 3]);
    // content_hash is based on payload only, not index
    assert_eq!(c0.content_hash, c1.content_hash);
    // but leaf_hash includes index
    assert_ne!(c0.leaf_hash(), c1.leaf_hash());
}

#[test]
fn evidence_chunk_different_family_same_payload() {
    let c1 = EvidenceChunk::new(0, "alpha", vec![1, 2, 3]);
    let c2 = EvidenceChunk::new(0, "beta", vec![1, 2, 3]);
    // content_hash is payload-based, same payload => same hash
    assert_eq!(c1.content_hash, c2.content_hash);
    // leaf_hash is index+content_hash-based, same index+hash => same leaf hash
    assert_eq!(c1.leaf_hash(), c2.leaf_hash());
    // but family differs
    assert_ne!(c1.payload_family, c2.payload_family);
}

#[test]
fn evidence_chunk_single_byte_payload() {
    let chunk = EvidenceChunk::new(0, "tiny", vec![42]);
    assert_eq!(chunk.size_bytes, 1);
    let json = serde_json::to_string(&chunk).unwrap();
    let back: EvidenceChunk = serde_json::from_str(&json).unwrap();
    assert_eq!(chunk, back);
}

// ── MerkleTree edge cases ────────────────────────────────────────────

#[test]
fn merkle_tree_five_leaves_all_proofs_verify() {
    let leaves: Vec<[u8; 32]> = (0..5).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    assert_eq!(tree.leaf_count, 5);
    for i in 0..5 {
        let proof = tree.inclusion_proof(i).unwrap();
        assert!(proof.verify(), "proof for leaf {i} failed");
    }
}

#[test]
fn merkle_tree_seven_leaves_all_proofs_verify() {
    let leaves: Vec<[u8; 32]> = (0..7).map(|i| [(i * 3) as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    assert_eq!(tree.leaf_count, 7);
    for i in 0..7 {
        assert!(
            tree.inclusion_proof(i).unwrap().verify(),
            "proof for leaf {i} failed"
        );
    }
}

#[test]
fn merkle_tree_levels_count() {
    // Single leaf: 1 level
    let tree = MerkleTree::build(&[[0u8; 32]]);
    assert_eq!(tree.levels.len(), 1);

    // Two leaves: 2 levels (leaves + root)
    let tree = MerkleTree::build(&[[0u8; 32], [1u8; 32]]);
    assert_eq!(tree.levels.len(), 2);

    // Four leaves: 3 levels
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    assert_eq!(tree.levels.len(), 3);
}

#[test]
fn merkle_tree_empty_has_one_empty_level() {
    let tree = MerkleTree::build(&[]);
    assert_eq!(tree.levels.len(), 1);
    assert!(tree.levels[0].is_empty());
}

#[test]
fn merkle_tree_root_changes_with_leaf_order() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let t1 = MerkleTree::build(&[a, b]);
    let t2 = MerkleTree::build(&[b, a]);
    assert_ne!(t1.root_hash, t2.root_hash);
}

// ── InclusionProof edge cases ────────────────────────────────────────

#[test]
fn inclusion_proof_empty_tree_no_proof() {
    let tree = MerkleTree::build(&[]);
    assert!(tree.inclusion_proof(0).is_none());
}

#[test]
fn inclusion_proof_single_leaf_no_siblings() {
    let tree = MerkleTree::build(&[[42u8; 32]]);
    let proof = tree.inclusion_proof(0).unwrap();
    assert!(proof.siblings.is_empty());
    assert!(proof.verify());
}

#[test]
fn inclusion_proof_verify_against_matching_root_eight_leaves() {
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    for i in 0..8 {
        let proof = tree.inclusion_proof(i).unwrap();
        assert!(proof.verify_against(&tree.root_hash));
    }
}

#[test]
fn inclusion_proof_tampered_leaf_fails() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    let mut proof = tree.inclusion_proof(0).unwrap();
    proof.leaf_hash = [0xFF; 32]; // tamper
    assert!(!proof.verify());
}

#[test]
fn inclusion_proof_tampered_sibling_fails() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let tree = MerkleTree::build(&leaves);
    let mut proof = tree.inclusion_proof(0).unwrap();
    if !proof.siblings.is_empty() {
        proof.siblings[0].hash = [0xFF; 32]; // tamper
    }
    assert!(!proof.verify());
}

// ── hash_pair edge cases ─────────────────────────────────────────────

#[test]
fn hash_pair_identical_inputs() {
    let a = [0x42; 32];
    let result = hash_pair(&a, &a);
    assert_eq!(result, hash_pair(&a, &a));
    assert_ne!(result, a);
}

#[test]
fn hash_pair_zero_inputs() {
    let zero = [0u8; 32];
    let result = hash_pair(&zero, &zero);
    assert_ne!(result, zero);
}

// ── ProvenanceAttachment edge cases ──────────────────────────────────

#[test]
fn provenance_content_hash_sensitive_to_toolchain() {
    let mut p = sample_provenance();
    let h1 = p.content_hash();
    p.toolchain_hash = "changed-toolchain".to_string();
    assert_ne!(h1, p.content_hash());
}

#[test]
fn provenance_content_hash_sensitive_to_environment() {
    let mut p = sample_provenance();
    let h1 = p.content_hash();
    p.environment_hash = "changed-env".to_string();
    assert_ne!(h1, p.content_hash());
}

#[test]
fn provenance_content_hash_sensitive_to_epoch() {
    let mut p = sample_provenance();
    let h1 = p.content_hash();
    p.collection_epoch = SecurityEpoch::from_raw(999);
    assert_ne!(h1, p.content_hash());
}

#[test]
fn provenance_content_hash_sensitive_to_packed_at() {
    let mut p = sample_provenance();
    let h1 = p.content_hash();
    p.packed_at = "2099-01-01T00:00:00Z".to_string();
    assert_ne!(h1, p.content_hash());
}

#[test]
fn provenance_serde_roundtrip_no_legal_summary() {
    let mut p = sample_provenance();
    p.legal_summary = None;
    let json = serde_json::to_string(&p).unwrap();
    let back: ProvenanceAttachment = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert!(back.legal_summary.is_none());
}

// ── WitnessSchema edge cases ─────────────────────────────────────────

#[test]
fn witness_schema_compute_id_sensitive_to_constraints() {
    let s1 = sample_schema(SecurityEpoch::from_raw(5));
    let mut s2 = sample_schema(SecurityEpoch::from_raw(5));
    s2.constraints.push(SufficiencyConstraint {
        dimension: SufficiencyDimension::CausalOrdering,
        min_score_millionths: 900_000,
        rationale: "extra".to_string(),
    });
    s2.schema_id = s2.compute_id();
    assert_ne!(s1.schema_id, s2.schema_id);
}

#[test]
fn witness_schema_compute_id_sensitive_to_required_fields() {
    let s1 = sample_schema(SecurityEpoch::from_raw(5));
    let mut s2 = sample_schema(SecurityEpoch::from_raw(5));
    s2.required_fields.insert("extra_field".to_string());
    s2.schema_id = s2.compute_id();
    assert_ne!(s1.schema_id, s2.schema_id);
}

#[test]
fn witness_schema_validate_sufficiency_all_dimensions_at_threshold() {
    let mut families = BTreeSet::new();
    families.insert("decision".to_string());
    let mut schema = WitnessSchema {
        schema_id: String::new(),
        name: "multi-constraint".to_string(),
        payload_families: families,
        constraints: SufficiencyDimension::ALL
            .iter()
            .map(|dim| SufficiencyConstraint {
                dimension: *dim,
                min_score_millionths: 800_000,
                rationale: format!("{dim} must meet threshold"),
            })
            .collect(),
        required_fields: BTreeSet::new(),
        obligation_categories: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(5),
    };
    schema.schema_id = schema.compute_id();

    let mut scores = BTreeMap::new();
    for dim in SufficiencyDimension::ALL {
        scores.insert(dim.to_string(), 800_000i64);
    }
    let cert = SufficiencyCertificate {
        certificate_id: String::new(),
        witness_pack_id: "wp-1".to_string(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 800_000,
        all_satisfied: true,
        epoch: SecurityEpoch::from_raw(5),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(result.satisfied);
    assert!(result.violations.is_empty());
}

#[test]
fn witness_schema_validate_sufficiency_one_under_all_over() {
    let mut families = BTreeSet::new();
    families.insert("decision".to_string());
    let mut schema = WitnessSchema {
        schema_id: String::new(),
        name: "multi".to_string(),
        payload_families: families,
        constraints: vec![
            SufficiencyConstraint {
                dimension: SufficiencyDimension::ReplayCompleteness,
                min_score_millionths: 800_000,
                rationale: "r".to_string(),
            },
            SufficiencyConstraint {
                dimension: SufficiencyDimension::LegalRetention,
                min_score_millionths: 750_000,
                rationale: "l".to_string(),
            },
        ],
        required_fields: BTreeSet::new(),
        obligation_categories: BTreeSet::new(),
        epoch: SecurityEpoch::from_raw(5),
    };
    schema.schema_id = schema.compute_id();

    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".to_string(), 900_000i64);
    scores.insert("legal_retention".to_string(), 749_999i64);
    let cert = SufficiencyCertificate {
        certificate_id: String::new(),
        witness_pack_id: "wp-1".to_string(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 749_999,
        all_satisfied: false,
        epoch: SecurityEpoch::from_raw(5),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(!result.satisfied);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(
        result.violations[0].dimension,
        SufficiencyDimension::LegalRetention
    );
}

// ── WitnessCompiler edge cases ───────────────────────────────────────

#[test]
fn compiler_add_chunk_increments_index() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("a", vec![1])
        .add_chunk("b", vec![2])
        .add_chunk("c", vec![3])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    for (i, chunk) in result.chunks.iter().enumerate() {
        assert_eq!(chunk.index, i);
    }
}

#[test]
fn compiler_max_chunk_bytes_default_limit() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![0u8; DEFAULT_MAX_CHUNK_BYTES])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5));
    assert!(result.is_ok());
}

#[test]
fn compiler_max_chunk_bytes_default_exceeded() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![0u8; DEFAULT_MAX_CHUNK_BYTES + 1])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5));
    assert!(matches!(
        result,
        Err(CompilationError::ChunkTooLarge { .. })
    ));
}

#[test]
fn compiler_with_reconstruction_targets_last_chunk() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("a", vec![1])
        .add_chunk("b", vec![2])
        .with_reconstruction(ReconstructionKind::DeterministicReplay)
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    assert_eq!(result.pack.reconstruction_hints.len(), 1);
    assert_eq!(result.pack.reconstruction_hints[0].chunk_index, 1);
}

#[test]
fn compiler_multiple_obligation_categories() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("decision", vec![1])
        .obligation_category(ObligationCategory::Safety)
        .obligation_category(ObligationCategory::BehavioralPreservation)
        .obligation_category(ObligationCategory::Liveness)
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    assert!(result.pack.covers_obligation(&ObligationCategory::Safety));
    assert!(
        result
            .pack
            .covers_obligation(&ObligationCategory::BehavioralPreservation)
    );
    assert!(result.pack.covers_obligation(&ObligationCategory::Liveness));
}

// ── CompilationResult edge cases ─────────────────────────────────────

#[test]
fn compilation_result_certify_sufficiency_empty_scores() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = compile_simple();
    let scores = BTreeMap::new();
    let cert = result.certify_sufficiency(&schema, scores);
    assert_eq!(cert.overall_score_millionths, 0);
    assert!(!cert.all_satisfied);
}

#[test]
fn compilation_result_pack_total_bytes_matches_sum() {
    let result = compile_simple();
    let sum: usize = result.chunks.iter().map(|c| c.size_bytes).sum();
    assert_eq!(result.pack.total_bytes, sum);
}

#[test]
fn compilation_result_merkle_root_matches_tree() {
    let result = compile_simple();
    assert_eq!(result.pack.merkle_root, hex::encode(result.tree.root_hash));
}

#[test]
fn compilation_result_schema_id_matches() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema.clone())
        .add_chunk("decision", vec![1, 2, 3])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    assert_eq!(result.pack.schema_id, schema.schema_id);
}

// ── PackVerifier edge cases ──────────────────────────────────────────

#[test]
fn pack_verifier_verify_inclusion_empty_string() {
    let result = compile_simple();
    let proof = result.proof_for_chunk(0).unwrap();
    assert!(!PackVerifier::verify_inclusion(proof, ""));
}

#[test]
fn pack_verifier_verify_inclusion_valid_hex_wrong_length() {
    let result = compile_simple();
    let proof = result.proof_for_chunk(0).unwrap();
    assert!(!PackVerifier::verify_inclusion(
        proof,
        &hex::encode([0u8; 31])
    ));
    assert!(!PackVerifier::verify_inclusion(
        proof,
        &hex::encode([0u8; 33])
    ));
}

// ── generate_report edge cases ───────────────────────────────────────

#[test]
fn generate_report_empty_results() {
    let report = generate_report(&[]);
    assert!(report.all_valid);
    assert_eq!(report.total_chunks, 0);
    assert_eq!(report.total_bytes, 0);
    assert!(report.pack_ids.is_empty());
    assert!(report.pack_results.is_empty());
    assert!(report.report_id.starts_with("wpr-"));
}

#[test]
fn generate_report_schema_version_matches_constant() {
    let result = compile_simple();
    let report = generate_report(&[&result]);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
}

#[test]
fn generate_report_pack_entry_has_correct_families() {
    let schema = sample_schema(SecurityEpoch::from_raw(5));
    let result = WitnessCompiler::new(schema)
        .add_chunk("zebra", vec![1])
        .add_chunk("alpha", vec![2])
        .provenance(sample_provenance())
        .compile(SecurityEpoch::from_raw(5))
        .unwrap();
    let report = generate_report(&[&result]);
    assert_eq!(
        report.pack_results[0].payload_families,
        vec!["alpha", "zebra"]
    );
}

// ── canonical_witness_schemas edge cases ─────────────────────────────

#[test]
fn canonical_schemas_names_match_expected() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    let names: Vec<&str> = schemas.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"Decision Witness Schema"));
    assert!(names.contains(&"Replay Witness Schema"));
    assert!(names.contains(&"Optimization Witness Schema"));
    assert!(names.contains(&"Security Witness Schema"));
    assert!(names.contains(&"Legal Provenance Witness Schema"));
}

#[test]
fn canonical_schemas_all_have_five_constraints() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    for s in &schemas {
        assert_eq!(s.constraints.len(), 5);
    }
}

#[test]
fn canonical_schemas_all_cover_all_dimensions() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    for s in &schemas {
        let dims: BTreeSet<SufficiencyDimension> =
            s.constraints.iter().map(|c| c.dimension).collect();
        assert_eq!(dims.len(), 5);
        for dim in SufficiencyDimension::ALL {
            assert!(dims.contains(&dim), "schema {} missing {dim}", s.name);
        }
    }
}

#[test]
fn canonical_schemas_epoch_matches_input() {
    let epoch = SecurityEpoch::from_raw(42);
    let schemas = canonical_witness_schemas(epoch);
    for s in &schemas {
        assert_eq!(s.epoch, epoch);
    }
}

#[test]
fn canonical_schemas_ids_stable_across_epochs() {
    let s1 = canonical_witness_schemas(SecurityEpoch::from_raw(1));
    let s2 = canonical_witness_schemas(SecurityEpoch::from_raw(2));
    for (a, b) in s1.iter().zip(s2.iter()) {
        assert_eq!(a.schema_id, b.schema_id);
    }
}

#[test]
fn canonical_schemas_required_fields_include_standard_set() {
    let schemas = canonical_witness_schemas(SecurityEpoch::from_raw(5));
    for s in &schemas {
        assert!(s.required_fields.contains("epoch"));
        assert!(s.required_fields.contains("merkle_root"));
        assert!(s.required_fields.contains("provenance"));
    }
}

// ── SufficiencyDimension additional ──────────────────────────────────

#[test]
fn sufficiency_dimension_copy_semantics() {
    let d1 = SufficiencyDimension::ReplayCompleteness;
    let d2 = d1;
    assert_eq!(d1, d2);
}

#[test]
fn sufficiency_dimension_debug_not_empty() {
    for dim in SufficiencyDimension::ALL {
        assert!(!format!("{dim:?}").is_empty());
    }
}

// ── ReconstructionKind additional ────────────────────────────────────

#[test]
fn reconstruction_kind_copy_semantics() {
    let k1 = ReconstructionKind::Hybrid;
    let k2 = k1;
    assert_eq!(k1, k2);
}

#[test]
fn reconstruction_kind_debug_not_empty() {
    for kind in [
        ReconstructionKind::Inline,
        ReconstructionKind::ContentAddressed,
        ReconstructionKind::DeterministicReplay,
        ReconstructionKind::Hybrid,
    ] {
        assert!(!format!("{kind:?}").is_empty());
    }
}

// ── CompilationError additional ──────────────────────────────────────

#[test]
fn compilation_error_debug_not_empty() {
    for err in [
        CompilationError::NoEvidence,
        CompilationError::MissingProvenance,
        CompilationError::ChunkTooLarge {
            index: 0,
            size: 100,
            max: 50,
        },
    ] {
        assert!(!format!("{err:?}").is_empty());
    }
}

#[test]
fn compilation_error_chunk_too_large_display_format() {
    let err = CompilationError::ChunkTooLarge {
        index: 7,
        size: 10_000,
        max: 4096,
    };
    let msg = err.to_string();
    assert!(msg.contains("7"));
    assert!(msg.contains("10000"));
    assert!(msg.contains("4096"));
}

// ── Constants additional ─────────────────────────────────────────────

#[test]
fn schema_version_is_well_formed() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("witness"));
    assert!(SCHEMA_VERSION.ends_with(".v1"));
}

#[test]
fn default_max_chunk_bytes_is_power_of_two() {
    assert!(DEFAULT_MAX_CHUNK_BYTES.is_power_of_two());
}

#[test]
fn min_sufficiency_score_is_fixed_point() {
    assert_eq!(MIN_SUFFICIENCY_SCORE, 800_000);
    assert!(MIN_SUFFICIENCY_SCORE > 0);
    assert!(MIN_SUFFICIENCY_SCORE < 1_000_000);
}
