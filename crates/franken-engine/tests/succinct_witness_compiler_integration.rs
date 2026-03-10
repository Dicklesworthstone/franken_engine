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

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::succinct_witness_compiler::{
    CompilationError, CompilationResult, DEFAULT_MAX_CHUNK_BYTES, EvidenceChunk, InclusionProof,
    MIN_SUFFICIENCY_SCORE, MerkleTree, PackVerifier, ProvenanceAttachment, ReconstructionKind,
    SCHEMA_VERSION, SufficiencyCertificate, SufficiencyConstraint, SufficiencyDimension,
    WitnessCompiler, WitnessSchema, canonical_witness_schemas, generate_report, hash_pair,
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
