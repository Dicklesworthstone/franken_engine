//! Enrichment integration tests for `succinct_witness_compiler`.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::succinct_witness_compiler::{
    CompilationError, EvidenceChunk, MerkleTree, PackVerifier, ProvenanceAttachment,
    ReconstructionKind, SCHEMA_VERSION, SufficiencyCertificate, SufficiencyConstraint,
    SufficiencyDimension, WitnessCompiler, WitnessPack, WitnessSchema, canonical_witness_schemas,
    generate_report, hash_pair,
};

fn ep(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn test_provenance() -> ProvenanceAttachment {
    ProvenanceAttachment {
        toolchain_hash: "abc123".into(),
        git_hash: "def456".into(),
        environment_hash: "ghi789".into(),
        collection_epoch: ep(42),
        packed_at: "2026-03-19T00:00:00Z".into(),
        legal_summary: None,
    }
}

fn test_schema() -> WitnessSchema {
    let mut schema = WitnessSchema {
        schema_id: String::new(),
        name: "test-schema".into(),
        payload_families: {
            let mut s = BTreeSet::new();
            s.insert("decision".into());
            s
        },
        constraints: vec![
            SufficiencyConstraint {
                dimension: SufficiencyDimension::ReplayCompleteness,
                min_score_millionths: 800_000,
                rationale: "test".into(),
            },
            SufficiencyConstraint {
                dimension: SufficiencyDimension::VerificationCoverage,
                min_score_millionths: 700_000,
                rationale: "test".into(),
            },
        ],
        required_fields: {
            let mut s = BTreeSet::new();
            s.insert("epoch".into());
            s
        },
        obligation_categories: BTreeSet::new(),
        epoch: ep(42),
    };
    schema.schema_id = schema.compute_id();
    schema
}

#[test]
fn enrichment_schema_version_constant() {
    assert_eq!(SCHEMA_VERSION, "franken-engine.succinct-witness.v1");
}

#[test]
fn enrichment_sufficiency_dimension_all_five() {
    assert_eq!(SufficiencyDimension::ALL.len(), 5);
}

#[test]
fn enrichment_sufficiency_dimension_display_unique() {
    let displays: BTreeSet<String> = SufficiencyDimension::ALL
        .iter()
        .map(|d| d.to_string())
        .collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_sufficiency_dimension_serde() {
    for dim in &SufficiencyDimension::ALL {
        let json = serde_json::to_string(dim).unwrap();
        let back: SufficiencyDimension = serde_json::from_str(&json).unwrap();
        assert_eq!(*dim, back);
    }
}

#[test]
fn enrichment_schema_id_deterministic() {
    let s1 = test_schema();
    let s2 = test_schema();
    assert_eq!(s1.schema_id, s2.schema_id);
    assert!(s1.schema_id.starts_with("ws-"));
}

#[test]
fn enrichment_schema_validate_sufficiency_pass() {
    let schema = test_schema();
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".into(), 900_000i64);
    scores.insert("verification_coverage".into(), 800_000);
    let cert = SufficiencyCertificate {
        certificate_id: String::new(),
        witness_pack_id: "wp-test".into(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 800_000,
        all_satisfied: true,
        epoch: ep(42),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(result.satisfied);
}

#[test]
fn enrichment_schema_validate_sufficiency_fail() {
    let schema = test_schema();
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".into(), 500_000i64);
    scores.insert("verification_coverage".into(), 800_000);
    let cert = SufficiencyCertificate {
        certificate_id: String::new(),
        witness_pack_id: "wp-test".into(),
        schema_id: schema.schema_id.clone(),
        dimension_scores: scores,
        overall_score_millionths: 500_000,
        all_satisfied: false,
        epoch: ep(42),
    };
    let result = schema.validate_sufficiency(&cert);
    assert!(!result.satisfied);
    assert_eq!(result.violations.len(), 1);
}

#[test]
fn enrichment_evidence_chunk_new() {
    let chunk = EvidenceChunk::new(0, "decision", b"hello".to_vec());
    assert_eq!(chunk.index, 0);
    assert_eq!(chunk.size_bytes, 5);
    assert!(!chunk.content_hash.is_empty());
}

#[test]
fn enrichment_evidence_chunk_leaf_hash_deterministic() {
    let c1 = EvidenceChunk::new(0, "x", b"data".to_vec());
    let c2 = EvidenceChunk::new(0, "x", b"data".to_vec());
    assert_eq!(c1.leaf_hash(), c2.leaf_hash());
}

#[test]
fn enrichment_merkle_tree_empty() {
    let tree = MerkleTree::build(&[]);
    assert_eq!(tree.leaf_count, 0);
    assert_eq!(tree.root_hash, [0u8; 32]);
}

#[test]
fn enrichment_merkle_tree_single() {
    let leaf = EvidenceChunk::new(0, "a", b"x".to_vec()).leaf_hash();
    let tree = MerkleTree::build(&[leaf]);
    assert_eq!(tree.root_hash, leaf);
}

#[test]
fn enrichment_merkle_tree_two_leaves() {
    let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
    let l2 = EvidenceChunk::new(1, "b", b"two".to_vec()).leaf_hash();
    let tree = MerkleTree::build(&[l1, l2]);
    assert_eq!(tree.root_hash, hash_pair(&l1, &l2));
}

#[test]
fn enrichment_inclusion_proof_verifies() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| EvidenceChunk::new(i, "x", format!("d{i}").into_bytes()).leaf_hash())
        .collect();
    let tree = MerkleTree::build(&leaves);
    for i in 0..4 {
        assert!(tree.inclusion_proof(i).unwrap().verify());
    }
}

#[test]
fn enrichment_inclusion_proof_wrong_root_fails() {
    let l1 = EvidenceChunk::new(0, "a", b"one".to_vec()).leaf_hash();
    let tree = MerkleTree::build(&[l1]);
    assert!(!tree.inclusion_proof(0).unwrap().verify_against(&[0xFF; 32]));
}

#[test]
fn enrichment_hash_pair_not_commutative() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    assert_ne!(hash_pair(&a, &b), hash_pair(&b, &a));
}

#[test]
fn enrichment_provenance_hash_deterministic() {
    assert_eq!(
        test_provenance().content_hash(),
        test_provenance().content_hash()
    );
}

#[test]
fn enrichment_reconstruction_kind_serde() {
    for kind in [
        ReconstructionKind::Inline,
        ReconstructionKind::ContentAddressed,
        ReconstructionKind::DeterministicReplay,
        ReconstructionKind::Hybrid,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: ReconstructionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn enrichment_compiler_single_chunk() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"evidence data".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    assert_eq!(result.pack.chunk_count, 1);
    assert!(result.pack.pack_id.starts_with("wp-"));
    assert!(result.verify_all_proofs());
}

#[test]
fn enrichment_compiler_no_evidence_fails() {
    let err = WitnessCompiler::new(test_schema())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap_err();
    assert_eq!(err, CompilationError::NoEvidence);
}

#[test]
fn enrichment_compiler_missing_provenance_fails() {
    let err = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"data".to_vec())
        .compile(ep(42))
        .unwrap_err();
    assert_eq!(err, CompilationError::MissingProvenance);
}

#[test]
fn enrichment_compiler_chunk_too_large_fails() {
    let err = WitnessCompiler::new(test_schema())
        .max_chunk_bytes(50)
        .add_chunk("decision", vec![0u8; 100])
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap_err();
    assert!(matches!(err, CompilationError::ChunkTooLarge { .. }));
}

#[test]
fn enrichment_compilation_error_display_all() {
    let errors = [
        CompilationError::NoEvidence,
        CompilationError::MissingProvenance,
        CompilationError::ChunkTooLarge {
            index: 0,
            size: 9999,
            max: 4096,
        },
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_verifier_valid_result() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"hello".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    let v = PackVerifier::verify_result(&result);
    assert!(v.valid);
    assert!(v.issues.is_empty());
}

#[test]
fn enrichment_report_single_pack() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"evidence".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    let report = generate_report(&[&result]);
    assert!(report.all_valid);
    assert_eq!(report.total_chunks, 1);
}

#[test]
fn enrichment_canonical_schemas_five() {
    let schemas = canonical_witness_schemas(ep(42));
    assert_eq!(schemas.len(), 5);
    for s in &schemas {
        assert!(s.schema_id.starts_with("ws-"));
    }
}

#[test]
fn enrichment_certify_sufficiency() {
    let schema = test_schema();
    let result = WitnessCompiler::new(schema.clone())
        .add_chunk("decision", b"data".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    let mut scores = BTreeMap::new();
    scores.insert("replay_completeness".into(), 950_000i64);
    scores.insert("verification_coverage".into(), 800_000);
    let cert = result.certify_sufficiency(&schema, scores);
    assert!(cert.all_satisfied);
    assert_eq!(cert.overall_score_millionths, 800_000);
}

#[test]
fn enrichment_compiler_pack_id_deterministic() {
    let build = || {
        WitnessCompiler::new(test_schema())
            .add_chunk("decision", b"same data".to_vec())
            .provenance(test_provenance())
            .compile(ep(42))
            .unwrap()
    };
    assert_eq!(build().pack.pack_id, build().pack.pack_id);
}

#[test]
fn enrichment_compiler_payload_families_collected() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"d".to_vec())
        .add_chunk("replay", b"r".to_vec())
        .add_chunk("decision", b"d2".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    assert_eq!(result.pack.families(), vec!["decision", "replay"]);
}

#[test]
fn enrichment_provenance_serde_roundtrip() {
    let prov = test_provenance();
    let json = serde_json::to_string(&prov).unwrap();
    let back: ProvenanceAttachment = serde_json::from_str(&json).unwrap();
    assert_eq!(prov, back);
}

#[test]
fn enrichment_report_hash_deterministic() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"data".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    assert_eq!(
        generate_report(&[&result]).content_hash,
        generate_report(&[&result]).content_hash
    );
}

#[test]
fn enrichment_schema_serde_roundtrip() {
    let schema = test_schema();
    let json = serde_json::to_string(&schema).unwrap();
    let back: WitnessSchema = serde_json::from_str(&json).unwrap();
    assert_eq!(schema, back);
}

#[test]
fn enrichment_witness_pack_serde_roundtrip() {
    let result = WitnessCompiler::new(test_schema())
        .add_chunk("decision", b"data".to_vec())
        .provenance(test_provenance())
        .compile(ep(42))
        .unwrap();
    let json = serde_json::to_string(&result.pack).unwrap();
    let back: WitnessPack = serde_json::from_str(&json).unwrap();
    assert_eq!(result.pack, back);
}

#[test]
fn enrichment_merkle_tree_four_leaves() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| EvidenceChunk::new(i, "x", format!("data{i}").into_bytes()).leaf_hash())
        .collect();
    let tree = MerkleTree::build(&leaves);
    assert_eq!(
        tree.root_hash,
        hash_pair(
            &hash_pair(&leaves[0], &leaves[1]),
            &hash_pair(&leaves[2], &leaves[3])
        )
    );
}

#[test]
fn enrichment_evidence_chunk_different_payload_different_hash() {
    let c1 = EvidenceChunk::new(0, "x", b"alpha".to_vec());
    let c2 = EvidenceChunk::new(0, "x", b"beta".to_vec());
    assert_ne!(c1.leaf_hash(), c2.leaf_hash());
}
