#![forbid(unsafe_code)]

//! Enrichment integration tests for the `proof_backed_compression` module.
//!
//! Covers Display uniqueness, serde roundtrips, pipeline behavior, edge cases,
//! deterministic hash behavior, dedup semantics, refusal logic, and summary
//! report correctness.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_backed_compression::*;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_canonical_basis::ArtifactFamily;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn make_descriptor(
    id: &str,
    domain: ArtifactDomain,
    family: ArtifactFamily,
    size: u64,
    canonical: Option<&[u8]>,
) -> ArtifactDescriptor {
    ArtifactDescriptor {
        artifact_id: id.to_string(),
        domain,
        family,
        size_bytes: size,
        content_hash: ContentHash::compute(format!("content-{id}").as_bytes()),
        canonical_id: canonical.map(ContentHash::compute),
        artifact_epoch: epoch(10),
    }
}

// ---------------------------------------------------------------------------
// ArtifactDomain — Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_domain_display_uniqueness() {
    let mut displays = BTreeSet::new();
    for d in ArtifactDomain::ALL {
        displays.insert(d.to_string());
    }
    assert_eq!(displays.len(), ArtifactDomain::ALL.len());
}

#[test]
fn enrichment_artifact_domain_display_values() {
    assert_eq!(ArtifactDomain::Cache.to_string(), "cache");
    assert_eq!(ArtifactDomain::Aot.to_string(), "aot");
    assert_eq!(ArtifactDomain::Evidence.to_string(), "evidence");
}

#[test]
fn enrichment_artifact_domain_all_covers_three_variants() {
    assert_eq!(ArtifactDomain::ALL.len(), 3);
    assert!(ArtifactDomain::ALL.contains(&ArtifactDomain::Cache));
    assert!(ArtifactDomain::ALL.contains(&ArtifactDomain::Aot));
    assert!(ArtifactDomain::ALL.contains(&ArtifactDomain::Evidence));
}

#[test]
fn enrichment_artifact_domain_serde_roundtrip_all() {
    for d in ArtifactDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let back: ArtifactDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(*d, back);
    }
}

#[test]
fn enrichment_artifact_domain_ordering() {
    // Derive Ord should give a consistent ordering
    let mut domains = vec![
        ArtifactDomain::Evidence,
        ArtifactDomain::Cache,
        ArtifactDomain::Aot,
    ];
    domains.sort();
    let sorted_displays: Vec<_> = domains.iter().map(|d| d.to_string()).collect();
    // Sorted by discriminant order: Cache, Aot, Evidence
    assert_eq!(sorted_displays[0], "cache");
}

#[test]
fn enrichment_artifact_domain_clone_eq() {
    let d = ArtifactDomain::Aot;
    let d2 = d;
    assert_eq!(d, d2);
}

// ---------------------------------------------------------------------------
// CompressionStrategy — Display uniqueness & expected_ratio
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compression_strategy_display_uniqueness() {
    let mut displays = BTreeSet::new();
    for s in CompressionStrategy::ALL {
        displays.insert(s.to_string());
    }
    assert_eq!(displays.len(), CompressionStrategy::ALL.len());
}

#[test]
fn enrichment_compression_strategy_display_values() {
    assert_eq!(CompressionStrategy::Dedup.to_string(), "dedup");
    assert_eq!(
        CompressionStrategy::DictionaryCompression.to_string(),
        "dictionary_compression"
    );
    assert_eq!(
        CompressionStrategy::DeltaEncoding.to_string(),
        "delta_encoding"
    );
    assert_eq!(CompressionStrategy::Identity.to_string(), "identity");
}

#[test]
fn enrichment_compression_strategy_all_covers_four_variants() {
    assert_eq!(CompressionStrategy::ALL.len(), 4);
    assert!(CompressionStrategy::ALL.contains(&CompressionStrategy::Dedup));
    assert!(CompressionStrategy::ALL.contains(&CompressionStrategy::DictionaryCompression));
    assert!(CompressionStrategy::ALL.contains(&CompressionStrategy::DeltaEncoding));
    assert!(CompressionStrategy::ALL.contains(&CompressionStrategy::Identity));
}

#[test]
fn enrichment_compression_strategy_serde_roundtrip_all() {
    for s in CompressionStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let back: CompressionStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, back);
    }
}

#[test]
fn enrichment_compression_strategy_identity_ratio_is_million() {
    assert_eq!(
        CompressionStrategy::Identity.expected_ratio_millionths(),
        1_000_000
    );
}

#[test]
fn enrichment_compression_strategy_dedup_ratio() {
    assert_eq!(
        CompressionStrategy::Dedup.expected_ratio_millionths(),
        100_000
    );
}

#[test]
fn enrichment_compression_strategy_dictionary_ratio() {
    assert_eq!(
        CompressionStrategy::DictionaryCompression.expected_ratio_millionths(),
        350_000
    );
}

#[test]
fn enrichment_compression_strategy_delta_ratio() {
    assert_eq!(
        CompressionStrategy::DeltaEncoding.expected_ratio_millionths(),
        200_000
    );
}

#[test]
fn enrichment_compression_strategy_all_ratios_below_million() {
    for s in CompressionStrategy::ALL {
        assert!(s.expected_ratio_millionths() <= 1_000_000);
    }
}

#[test]
fn enrichment_compression_strategy_dedup_best_ratio() {
    let mut min = CompressionStrategy::Identity;
    for s in CompressionStrategy::ALL {
        if s.expected_ratio_millionths() < min.expected_ratio_millionths() {
            min = *s;
        }
    }
    assert_eq!(min, CompressionStrategy::Dedup);
}

#[test]
fn enrichment_compression_strategy_ordering_deterministic() {
    let mut strats = vec![
        CompressionStrategy::Identity,
        CompressionStrategy::Dedup,
        CompressionStrategy::DeltaEncoding,
        CompressionStrategy::DictionaryCompression,
    ];
    let strats2 = strats.clone();
    strats.sort();
    let mut strats3 = strats2;
    strats3.sort();
    assert_eq!(strats, strats3);
}

// ---------------------------------------------------------------------------
// CompressionRefusalReason — Display uniqueness & serde
// ---------------------------------------------------------------------------

fn all_refusal_variants() -> Vec<CompressionRefusalReason> {
    vec![
        CompressionRefusalReason::TooSmall {
            size_bytes: 10,
            min_bytes: 64,
        },
        CompressionRefusalReason::NoCanonicalIdentity,
        CompressionRefusalReason::ReplayContractViolation {
            detail: "replay test".to_string(),
        },
        CompressionRefusalReason::EpochMismatch {
            artifact_epoch: 5,
            reference_epoch: 10,
        },
        CompressionRefusalReason::SuspiciousRatio {
            ratio_millionths: 500,
        },
        CompressionRefusalReason::DomainStrategyMismatch {
            domain: ArtifactDomain::Cache,
            strategy: CompressionStrategy::Identity,
        },
        CompressionRefusalReason::UnsupportedFamily {
            family: ArtifactFamily::ShapeChain,
        },
    ]
}

#[test]
fn enrichment_refusal_reason_display_uniqueness() {
    let reasons = all_refusal_variants();
    let mut displays = BTreeSet::new();
    for r in &reasons {
        displays.insert(r.to_string());
    }
    assert_eq!(displays.len(), reasons.len());
}

#[test]
fn enrichment_refusal_reason_serde_roundtrip_all_variants() {
    for r in all_refusal_variants() {
        let json = serde_json::to_string(&r).unwrap();
        let back: CompressionRefusalReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }
}

#[test]
fn enrichment_refusal_too_small_display_contains_sizes() {
    let r = CompressionRefusalReason::TooSmall {
        size_bytes: 32,
        min_bytes: 64,
    };
    let s = r.to_string();
    assert!(s.contains("32"));
    assert!(s.contains("64"));
}

#[test]
fn enrichment_refusal_epoch_mismatch_display() {
    let r = CompressionRefusalReason::EpochMismatch {
        artifact_epoch: 3,
        reference_epoch: 7,
    };
    let s = r.to_string();
    assert!(s.contains("3"));
    assert!(s.contains("7"));
    assert!(s.contains("mismatch"));
}

#[test]
fn enrichment_refusal_replay_contract_display() {
    let r = CompressionRefusalReason::ReplayContractViolation {
        detail: "snapshot integrity".to_string(),
    };
    let s = r.to_string();
    assert!(s.contains("snapshot integrity"));
    assert!(s.contains("replay"));
}

#[test]
fn enrichment_refusal_suspicious_ratio_display() {
    let r = CompressionRefusalReason::SuspiciousRatio {
        ratio_millionths: 999,
    };
    let s = r.to_string();
    assert!(s.contains("999"));
    assert!(s.contains("suspicious"));
}

#[test]
fn enrichment_refusal_domain_strategy_mismatch_display() {
    let r = CompressionRefusalReason::DomainStrategyMismatch {
        domain: ArtifactDomain::Evidence,
        strategy: CompressionStrategy::DeltaEncoding,
    };
    let s = r.to_string();
    assert!(s.contains("evidence"));
    assert!(s.contains("delta_encoding"));
}

#[test]
fn enrichment_refusal_unsupported_family_display() {
    let r = CompressionRefusalReason::UnsupportedFamily {
        family: ArtifactFamily::RewritePack,
    };
    let s = r.to_string();
    assert!(s.contains("unsupported"));
}

#[test]
fn enrichment_refusal_no_canonical_identity_display() {
    let r = CompressionRefusalReason::NoCanonicalIdentity;
    assert!(r.to_string().contains("canonical"));
}

// ---------------------------------------------------------------------------
// CompressionError — Display uniqueness & serde
// ---------------------------------------------------------------------------

fn all_error_variants() -> Vec<CompressionError> {
    vec![
        CompressionError::ArtifactNotFound {
            artifact_id: "art-404".to_string(),
        },
        CompressionError::RestorationFailed {
            artifact_id: "art-bad".to_string(),
            expected_hash: "aaa".to_string(),
            actual_hash: "bbb".to_string(),
        },
        CompressionError::StrategyNotApplicable {
            strategy: CompressionStrategy::Dedup,
            reason: "no canonical id".to_string(),
        },
        CompressionError::InvalidConfig {
            detail: "missing field".to_string(),
        },
    ]
}

#[test]
fn enrichment_compression_error_display_uniqueness() {
    let errors = all_error_variants();
    let mut displays = BTreeSet::new();
    for e in &errors {
        displays.insert(e.to_string());
    }
    assert_eq!(displays.len(), errors.len());
}

#[test]
fn enrichment_compression_error_serde_roundtrip_all_variants() {
    for e in all_error_variants() {
        let json = serde_json::to_string(&e).unwrap();
        let back: CompressionError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn enrichment_compression_error_artifact_not_found_display() {
    let e = CompressionError::ArtifactNotFound {
        artifact_id: "xyz-123".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("xyz-123"));
    assert!(s.contains("not found"));
}

#[test]
fn enrichment_compression_error_restoration_failed_display() {
    let e = CompressionError::RestorationFailed {
        artifact_id: "art-rf".to_string(),
        expected_hash: "expected_h".to_string(),
        actual_hash: "actual_h".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("art-rf"));
    assert!(s.contains("expected_h"));
    assert!(s.contains("actual_h"));
    assert!(s.contains("restoration"));
}

#[test]
fn enrichment_compression_error_strategy_not_applicable_display() {
    let e = CompressionError::StrategyNotApplicable {
        strategy: CompressionStrategy::DictionaryCompression,
        reason: "too sparse".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("dictionary_compression"));
    assert!(s.contains("too sparse"));
}

#[test]
fn enrichment_compression_error_invalid_config_display() {
    let e = CompressionError::InvalidConfig {
        detail: "threshold out of range".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("threshold out of range"));
    assert!(s.contains("invalid config"));
}

// ---------------------------------------------------------------------------
// ArtifactDescriptor — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_artifact_descriptor_serde_roundtrip() {
    let d = make_descriptor(
        "art-serde-1",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        4096,
        Some(b"canonical-seed"),
    );
    let json = serde_json::to_string(&d).unwrap();
    let back: ArtifactDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_artifact_descriptor_serde_no_canonical() {
    let d = make_descriptor(
        "art-no-canon",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        2048,
        None,
    );
    let json = serde_json::to_string(&d).unwrap();
    let back: ArtifactDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
    assert!(back.canonical_id.is_none());
}

#[test]
fn enrichment_artifact_descriptor_different_domains_different_hashes() {
    let d1 = make_descriptor(
        "same-id",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        1000,
        None,
    );
    let d2 = make_descriptor(
        "same-id",
        ArtifactDomain::Aot,
        ArtifactFamily::CacheEntry,
        1000,
        None,
    );
    // Same content hash because it only depends on id
    assert_eq!(d1.content_hash, d2.content_hash);
    // But domain differs
    assert_ne!(d1.domain, d2.domain);
}

// ---------------------------------------------------------------------------
// CompressionResult — bytes_saved, serde, hash behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compression_result_bytes_saved_basic() {
    let r = CompressionResult {
        artifact_id: "bs-1".to_string(),
        strategy: CompressionStrategy::DictionaryCompression,
        original_size_bytes: 10_000,
        compressed_size_bytes: 3_500,
        ratio_millionths: 350_000,
        compressed_hash: ContentHash::compute(b"c"),
        dedup_representative_id: None,
        result_hash: ContentHash::compute(b"placeholder"),
    };
    assert_eq!(r.bytes_saved(), 6_500);
}

#[test]
fn enrichment_compression_result_bytes_saved_identity() {
    let r = CompressionResult {
        artifact_id: "bs-id".to_string(),
        strategy: CompressionStrategy::Identity,
        original_size_bytes: 5_000,
        compressed_size_bytes: 5_000,
        ratio_millionths: 1_000_000,
        compressed_hash: ContentHash::compute(b"identity"),
        dedup_representative_id: None,
        result_hash: ContentHash::compute(b"placeholder"),
    };
    assert_eq!(r.bytes_saved(), 0);
}

#[test]
fn enrichment_compression_result_bytes_saved_saturating() {
    // If compressed > original (shouldn't happen normally), saturating_sub returns 0
    let r = CompressionResult {
        artifact_id: "bs-sat".to_string(),
        strategy: CompressionStrategy::Identity,
        original_size_bytes: 100,
        compressed_size_bytes: 200,
        ratio_millionths: 2_000_000,
        compressed_hash: ContentHash::compute(b"over"),
        dedup_representative_id: None,
        result_hash: ContentHash::compute(b"placeholder"),
    };
    assert_eq!(r.bytes_saved(), 0);
}

#[test]
fn enrichment_compression_result_bytes_saved_zero_original() {
    let r = CompressionResult {
        artifact_id: "bs-zero".to_string(),
        strategy: CompressionStrategy::Identity,
        original_size_bytes: 0,
        compressed_size_bytes: 0,
        ratio_millionths: 1_000_000,
        compressed_hash: ContentHash::compute(b"zero"),
        dedup_representative_id: None,
        result_hash: ContentHash::compute(b"placeholder"),
    };
    assert_eq!(r.bytes_saved(), 0);
}

#[test]
fn enrichment_compression_result_serde_roundtrip_with_dedup() {
    let r = CompressionResult {
        artifact_id: "dedup-rt".to_string(),
        strategy: CompressionStrategy::Dedup,
        original_size_bytes: 8000,
        compressed_size_bytes: 0,
        ratio_millionths: 0,
        compressed_hash: ContentHash::compute(b"dedup-compressed"),
        dedup_representative_id: Some("representative-001".to_string()),
        result_hash: ContentHash::compute(b"dedup-result"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CompressionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_compression_result_serde_roundtrip_without_dedup() {
    let r = CompressionResult {
        artifact_id: "no-dedup-rt".to_string(),
        strategy: CompressionStrategy::DeltaEncoding,
        original_size_bytes: 5000,
        compressed_size_bytes: 1000,
        ratio_millionths: 200_000,
        compressed_hash: ContentHash::compute(b"delta-c"),
        dedup_representative_id: None,
        result_hash: ContentHash::compute(b"delta-r"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CompressionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// CompressionReceipt — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compression_receipt_serde_with_canonical() {
    let r = CompressionReceipt {
        receipt_id: "rcpt-canon".to_string(),
        artifact_id: "art-canon".to_string(),
        original_hash: ContentHash::compute(b"orig-canon"),
        compressed_hash: ContentHash::compute(b"comp-canon"),
        canonical_id: Some(ContentHash::compute(b"canonical-id")),
        strategy: CompressionStrategy::Dedup,
        domain: ArtifactDomain::Cache,
        restoration_verified: true,
        receipt_epoch: epoch(42),
        receipt_hash: ContentHash::compute(b"rcpt-hash"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CompressionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_compression_receipt_serde_without_canonical() {
    let r = CompressionReceipt {
        receipt_id: "rcpt-nocan".to_string(),
        artifact_id: "art-nocan".to_string(),
        original_hash: ContentHash::compute(b"orig-nocan"),
        compressed_hash: ContentHash::compute(b"comp-nocan"),
        canonical_id: None,
        strategy: CompressionStrategy::DictionaryCompression,
        domain: ArtifactDomain::Evidence,
        restoration_verified: false,
        receipt_epoch: epoch(7),
        receipt_hash: ContentHash::compute(b"rcpt-hash2"),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CompressionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DedupEntry — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_dedup_entry_serde_roundtrip() {
    let entry = DedupEntry {
        artifact_id: "dup-art".to_string(),
        representative_id: "rep-art".to_string(),
        canonical_id: ContentHash::compute(b"canonical-dup"),
        domain: ArtifactDomain::Aot,
        size_saved_bytes: 9999,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: DedupEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_dedup_entry_clone_eq() {
    let entry = DedupEntry {
        artifact_id: "dup-clone".to_string(),
        representative_id: "rep-clone".to_string(),
        canonical_id: ContentHash::compute(b"canonical-clone"),
        domain: ArtifactDomain::Cache,
        size_saved_bytes: 500,
    };
    let cloned = entry.clone();
    assert_eq!(entry, cloned);
}

// ---------------------------------------------------------------------------
// StrategyBreakdown — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_strategy_breakdown_serde_roundtrip() {
    let sb = StrategyBreakdown {
        strategy: CompressionStrategy::DeltaEncoding,
        artifact_count: 12,
        original_bytes: 120_000,
        compressed_bytes: 24_000,
    };
    let json = serde_json::to_string(&sb).unwrap();
    let back: StrategyBreakdown = serde_json::from_str(&json).unwrap();
    assert_eq!(sb, back);
}

// ---------------------------------------------------------------------------
// CompressionSummary — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_compression_summary_serde_roundtrip() {
    let summary = CompressionSummary {
        total_artifacts: 10,
        total_original_bytes: 100_000,
        total_compressed_bytes: 40_000,
        total_saved_bytes: 60_000,
        overall_ratio_millionths: 400_000,
        dedup_count: 3,
        dedup_saved_bytes: 30_000,
        refusal_count: 1,
        by_strategy: vec![
            StrategyBreakdown {
                strategy: CompressionStrategy::DictionaryCompression,
                artifact_count: 5,
                original_bytes: 50_000,
                compressed_bytes: 17_500,
            },
            StrategyBreakdown {
                strategy: CompressionStrategy::DeltaEncoding,
                artifact_count: 5,
                original_bytes: 50_000,
                compressed_bytes: 10_000,
            },
        ],
        by_domain: vec![
            (ArtifactDomain::Cache, 6),
            (ArtifactDomain::Aot, 4),
        ],
        pipeline_epoch: epoch(100),
        summary_hash: ContentHash::compute(b"summary-hash"),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: CompressionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// CompressionPipeline — construction & basic invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_new_schema_version() {
    let p = CompressionPipeline::new(epoch(1));
    assert_eq!(p.schema_version, COMPRESSION_SCHEMA_VERSION);
}

#[test]
fn enrichment_pipeline_new_bead_id() {
    let p = CompressionPipeline::new(epoch(1));
    assert_eq!(p.bead_id, COMPRESSION_BEAD_ID);
}

#[test]
fn enrichment_pipeline_new_empty_collections() {
    let p = CompressionPipeline::new(epoch(1));
    assert!(p.results.is_empty());
    assert!(p.receipts.is_empty());
    assert!(p.dedup_index.is_empty());
    assert!(p.dedup_entries.is_empty());
    assert!(p.refusals.is_empty());
}

#[test]
fn enrichment_pipeline_new_epoch_preserved() {
    let p = CompressionPipeline::new(epoch(42));
    assert_eq!(p.pipeline_epoch, epoch(42));
}

#[test]
fn enrichment_pipeline_new_has_nonzero_hash() {
    let p = CompressionPipeline::new(epoch(1));
    // Pipeline hash is computed from schema/bead/epoch, should not be all zeros
    let zero_hash = ContentHash::compute(b"compression_pipeline");
    // After recompute_hash in new(), the hash should differ from the placeholder
    assert_ne!(p.pipeline_hash, zero_hash);
}

#[test]
fn enrichment_pipeline_serde_roundtrip_empty() {
    let p = CompressionPipeline::new(epoch(5));
    let json = serde_json::to_string(&p).unwrap();
    let back: CompressionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn enrichment_pipeline_serde_roundtrip_with_artifacts() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "serde-art",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        2000,
        None,
    );
    p.process_artifact(&d);
    let json = serde_json::to_string(&p).unwrap();
    let back: CompressionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// CompressionPipeline — process_artifact behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_process_cache_uses_dictionary() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "cache-dict",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("cache-dict").unwrap();
    assert_eq!(r.strategy, CompressionStrategy::DictionaryCompression);
}

#[test]
fn enrichment_pipeline_process_aot_uses_delta() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "aot-delta",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("aot-delta").unwrap();
    assert_eq!(r.strategy, CompressionStrategy::DeltaEncoding);
}

#[test]
fn enrichment_pipeline_process_evidence_uses_dictionary() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "ev-dict",
        ArtifactDomain::Evidence,
        ArtifactFamily::EvidenceRecord,
        5_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("ev-dict").unwrap();
    assert_eq!(r.strategy, CompressionStrategy::DictionaryCompression);
}

#[test]
fn enrichment_pipeline_process_creates_receipt() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "rcpt-test",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        1000,
        None,
    );
    p.process_artifact(&d);
    let receipt = p.receipt_for("rcpt-test").unwrap();
    assert_eq!(receipt.artifact_id, "rcpt-test");
    assert_eq!(receipt.domain, ArtifactDomain::Cache);
    assert!(receipt.restoration_verified);
    assert_eq!(receipt.receipt_epoch, epoch(10));
}

#[test]
fn enrichment_pipeline_compressed_size_less_than_original_for_dict() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "size-check",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("size-check").unwrap();
    assert!(r.compressed_size_bytes < r.original_size_bytes);
    assert!(r.bytes_saved() > 0);
}

#[test]
fn enrichment_pipeline_compressed_size_less_than_original_for_delta() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "delta-check",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("delta-check").unwrap();
    assert!(r.compressed_size_bytes < r.original_size_bytes);
}

// ---------------------------------------------------------------------------
// CompressionPipeline — refusal behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_refuses_too_small_artifact() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "tiny",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10,
        None,
    );
    p.process_artifact(&d);
    assert!(p.results.is_empty());
    assert_eq!(p.refusals.len(), 1);
    assert_eq!(p.refusals[0].0, "tiny");
}

#[test]
fn enrichment_pipeline_refuses_zero_size_artifact() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "zero-size",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        0,
        None,
    );
    p.process_artifact(&d);
    assert!(p.results.is_empty());
    assert_eq!(p.refusals.len(), 1);
}

#[test]
fn enrichment_pipeline_refuses_63_byte_artifact() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "edge-63",
        ArtifactDomain::Evidence,
        ArtifactFamily::EvidenceRecord,
        63,
        None,
    );
    p.process_artifact(&d);
    assert!(p.results.is_empty());
    assert_eq!(p.refusals.len(), 1);
}

#[test]
fn enrichment_pipeline_accepts_64_byte_artifact() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "edge-64",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        64,
        None,
    );
    p.process_artifact(&d);
    assert_eq!(p.results.len(), 1);
    assert!(p.refusals.is_empty());
}

#[test]
fn enrichment_pipeline_accepts_65_byte_artifact() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "edge-65",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        65,
        None,
    );
    p.process_artifact(&d);
    assert_eq!(p.results.len(), 1);
    assert!(p.refusals.is_empty());
}

// ---------------------------------------------------------------------------
// CompressionPipeline — dedup behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_dedup_first_is_representative() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"shared-canon-first";
    let d1 = make_descriptor(
        "first",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        2000,
        Some(canonical),
    );
    p.process_artifact(&d1);
    let r = p.result_for("first").unwrap();
    assert_eq!(r.strategy, CompressionStrategy::Dedup);
    assert!(r.dedup_representative_id.is_none());
    assert_eq!(r.compressed_size_bytes, 2000);
}

#[test]
fn enrichment_pipeline_dedup_second_references_first() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"shared-canon-second";
    let d1 = make_descriptor(
        "rep",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        2000,
        Some(canonical),
    );
    let d2 = make_descriptor(
        "dup",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        2000,
        Some(canonical),
    );
    p.process_artifact(&d1);
    p.process_artifact(&d2);
    let r2 = p.result_for("dup").unwrap();
    assert_eq!(r2.compressed_size_bytes, 0);
    assert_eq!(
        r2.dedup_representative_id.as_deref(),
        Some("rep")
    );
}

#[test]
fn enrichment_pipeline_dedup_creates_dedup_entry() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"shared-canon-entry";
    let d1 = make_descriptor(
        "rep-e",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        3000,
        Some(canonical),
    );
    let d2 = make_descriptor(
        "dup-e",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        3000,
        Some(canonical),
    );
    p.process_artifact(&d1);
    p.process_artifact(&d2);
    assert_eq!(p.dedup_entries.len(), 1);
    let entry = &p.dedup_entries[0];
    assert_eq!(entry.artifact_id, "dup-e");
    assert_eq!(entry.representative_id, "rep-e");
    assert_eq!(entry.size_saved_bytes, 3000);
}

#[test]
fn enrichment_pipeline_dedup_multiple_duplicates() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"multi-dup-canon";
    for i in 0..6 {
        let d = make_descriptor(
            &format!("md-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            1500,
            Some(canonical),
        );
        p.process_artifact(&d);
    }
    // First is representative, 5 duplicates
    assert_eq!(p.dedup_entries.len(), 5);
    let r0 = p.result_for("md-0").unwrap();
    assert!(r0.dedup_representative_id.is_none());
    for i in 1..6 {
        let r = p.result_for(&format!("md-{i}")).unwrap();
        assert_eq!(r.compressed_size_bytes, 0);
        assert!(r.dedup_representative_id.is_some());
    }
}

#[test]
fn enrichment_pipeline_dedup_different_canonicals_no_dedup() {
    let mut p = CompressionPipeline::new(epoch(10));
    for i in 0..4 {
        let canonical = format!("unique-canon-{i}");
        let d = make_descriptor(
            &format!("uniq-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            2000,
            Some(canonical.as_bytes()),
        );
        p.process_artifact(&d);
    }
    assert!(p.dedup_entries.is_empty());
}

#[test]
fn enrichment_pipeline_dedup_entries_for_canonical() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical_bytes = b"filter-canon";
    let canonical_hash = ContentHash::compute(canonical_bytes);
    for i in 0..3 {
        let d = make_descriptor(
            &format!("fc-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            1000,
            Some(canonical_bytes),
        );
        p.process_artifact(&d);
    }
    let entries = p.dedup_entries_for_canonical(&canonical_hash);
    assert_eq!(entries.len(), 2); // 2 dedup entries (not counting representative)
}

// ---------------------------------------------------------------------------
// CompressionPipeline — batch processing
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_batch_sorts_results_by_artifact_id() {
    let mut p = CompressionPipeline::new(epoch(10));
    let descriptors: Vec<_> = ["zebra", "alpha", "middle"]
        .iter()
        .map(|id| {
            make_descriptor(
                id,
                ArtifactDomain::Cache,
                ArtifactFamily::CacheEntry,
                500,
                None,
            )
        })
        .collect();
    p.process_batch(&descriptors);
    let ids: Vec<&str> = p.results.iter().map(|r| r.artifact_id.as_str()).collect();
    let mut sorted_ids = ids.clone();
    sorted_ids.sort();
    assert_eq!(ids, sorted_ids);
}

#[test]
fn enrichment_pipeline_batch_sorts_receipts_by_receipt_id() {
    let mut p = CompressionPipeline::new(epoch(10));
    let descriptors: Vec<_> = ["z-art", "a-art", "m-art"]
        .iter()
        .map(|id| {
            make_descriptor(
                id,
                ArtifactDomain::Aot,
                ArtifactFamily::BytecodeArtifact,
                800,
                None,
            )
        })
        .collect();
    p.process_batch(&descriptors);
    let receipt_ids: Vec<&str> = p.receipts.iter().map(|r| r.receipt_id.as_str()).collect();
    let mut sorted = receipt_ids.clone();
    sorted.sort();
    assert_eq!(receipt_ids, sorted);
}

#[test]
fn enrichment_pipeline_batch_empty_descriptors() {
    let mut p = CompressionPipeline::new(epoch(10));
    p.process_batch(&[]);
    assert!(p.results.is_empty());
    assert!(p.receipts.is_empty());
}

#[test]
fn enrichment_pipeline_batch_mixed_domains() {
    let mut p = CompressionPipeline::new(epoch(10));
    let descriptors = vec![
        make_descriptor("m-cache", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 1000, None),
        make_descriptor("m-aot", ArtifactDomain::Aot, ArtifactFamily::BytecodeArtifact, 1000, None),
        make_descriptor("m-ev", ArtifactDomain::Evidence, ArtifactFamily::EvidenceRecord, 1000, None),
    ];
    p.process_batch(&descriptors);
    assert_eq!(p.results.len(), 3);
    // Verify each got the expected strategy
    assert_eq!(
        p.result_for("m-cache").unwrap().strategy,
        CompressionStrategy::DictionaryCompression
    );
    assert_eq!(
        p.result_for("m-aot").unwrap().strategy,
        CompressionStrategy::DeltaEncoding
    );
    assert_eq!(
        p.result_for("m-ev").unwrap().strategy,
        CompressionStrategy::DictionaryCompression
    );
}

// ---------------------------------------------------------------------------
// CompressionPipeline — hash determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_hash_deterministic_same_artifacts() {
    let build = || {
        let mut p = CompressionPipeline::new(epoch(10));
        let d = make_descriptor(
            "det-1",
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            2000,
            None,
        );
        p.process_artifact(&d);
        p.pipeline_hash
    };
    let h1 = build();
    let h2 = build();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_pipeline_hash_changes_on_artifact_addition() {
    let mut p = CompressionPipeline::new(epoch(10));
    let h_empty = p.pipeline_hash;
    let d = make_descriptor(
        "hash-change",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        1000,
        None,
    );
    p.process_artifact(&d);
    assert_ne!(h_empty, p.pipeline_hash);
}

#[test]
fn enrichment_pipeline_hash_changes_on_refusal() {
    let mut p = CompressionPipeline::new(epoch(10));
    let h_empty = p.pipeline_hash;
    let d = make_descriptor(
        "tiny-hash",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10,
        None,
    );
    p.process_artifact(&d);
    assert_ne!(h_empty, p.pipeline_hash);
}

#[test]
fn enrichment_pipeline_different_epochs_different_hashes() {
    let p1 = CompressionPipeline::new(epoch(1));
    let p2 = CompressionPipeline::new(epoch(2));
    assert_ne!(p1.pipeline_hash, p2.pipeline_hash);
}

// ---------------------------------------------------------------------------
// CompressionPipeline — result_for / receipt_for lookups
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_result_for_nonexistent_returns_none() {
    let p = CompressionPipeline::new(epoch(10));
    assert!(p.result_for("nonexistent").is_none());
}

#[test]
fn enrichment_pipeline_receipt_for_nonexistent_returns_none() {
    let p = CompressionPipeline::new(epoch(10));
    assert!(p.receipt_for("nonexistent").is_none());
}

#[test]
fn enrichment_pipeline_result_for_existing() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "lookup-art",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        500,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("lookup-art");
    assert!(r.is_some());
    assert_eq!(r.unwrap().artifact_id, "lookup-art");
}

#[test]
fn enrichment_pipeline_receipt_for_existing() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "rcpt-lookup",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        500,
        None,
    );
    p.process_artifact(&d);
    let r = p.receipt_for("rcpt-lookup");
    assert!(r.is_some());
    assert_eq!(r.unwrap().artifact_id, "rcpt-lookup");
}

// ---------------------------------------------------------------------------
// CompressionPipeline — summary_report behavior
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_summary_empty() {
    let p = CompressionPipeline::new(epoch(10));
    let s = p.summary_report();
    assert_eq!(s.total_artifacts, 0);
    assert_eq!(s.total_original_bytes, 0);
    assert_eq!(s.total_compressed_bytes, 0);
    assert_eq!(s.total_saved_bytes, 0);
    assert_eq!(s.dedup_count, 0);
    assert_eq!(s.dedup_saved_bytes, 0);
    assert_eq!(s.refusal_count, 0);
    assert!(s.by_strategy.is_empty());
    assert!(s.by_domain.is_empty());
    assert_eq!(s.pipeline_epoch, epoch(10));
}

#[test]
fn enrichment_pipeline_summary_total_saved_bytes_correct() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "sum-save",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let s = p.summary_report();
    assert_eq!(s.total_original_bytes, 10_000);
    assert_eq!(
        s.total_saved_bytes,
        s.total_original_bytes - s.total_compressed_bytes
    );
}

#[test]
fn enrichment_pipeline_summary_ratio_below_million_for_compressed() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "ratio-check",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        10_000,
        None,
    );
    p.process_artifact(&d);
    let s = p.summary_report();
    assert!(s.overall_ratio_millionths < 1_000_000);
}

#[test]
fn enrichment_pipeline_summary_by_strategy_breakdown() {
    let mut p = CompressionPipeline::new(epoch(10));
    // Add cache (dictionary) and aot (delta) artifacts
    p.process_artifact(&make_descriptor(
        "strat-c1", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 2000, None,
    ));
    p.process_artifact(&make_descriptor(
        "strat-c2", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 3000, None,
    ));
    p.process_artifact(&make_descriptor(
        "strat-a1", ArtifactDomain::Aot, ArtifactFamily::BytecodeArtifact, 4000, None,
    ));
    let s = p.summary_report();
    // Should have 2 strategies in breakdown
    assert_eq!(s.by_strategy.len(), 2);
    let dict_bd = s.by_strategy.iter().find(|b| b.strategy == CompressionStrategy::DictionaryCompression);
    assert!(dict_bd.is_some());
    assert_eq!(dict_bd.unwrap().artifact_count, 2);
    let delta_bd = s.by_strategy.iter().find(|b| b.strategy == CompressionStrategy::DeltaEncoding);
    assert!(delta_bd.is_some());
    assert_eq!(delta_bd.unwrap().artifact_count, 1);
}

#[test]
fn enrichment_pipeline_summary_by_domain_counts() {
    let mut p = CompressionPipeline::new(epoch(10));
    p.process_artifact(&make_descriptor(
        "dom-c", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 500, None,
    ));
    p.process_artifact(&make_descriptor(
        "dom-a", ArtifactDomain::Aot, ArtifactFamily::BytecodeArtifact, 500, None,
    ));
    p.process_artifact(&make_descriptor(
        "dom-e", ArtifactDomain::Evidence, ArtifactFamily::EvidenceRecord, 500, None,
    ));
    let s = p.summary_report();
    assert_eq!(s.by_domain.len(), 3);
}

#[test]
fn enrichment_pipeline_summary_dedup_count_and_savings() {
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"summary-dedup-canon";
    for i in 0..5 {
        p.process_artifact(&make_descriptor(
            &format!("sd-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            2000,
            Some(canonical),
        ));
    }
    let s = p.summary_report();
    assert_eq!(s.dedup_count, 4);
    assert_eq!(s.dedup_saved_bytes, 4 * 2000);
}

#[test]
fn enrichment_pipeline_summary_refusal_count() {
    let mut p = CompressionPipeline::new(epoch(10));
    // Add a few too-small artifacts and a few valid ones
    p.process_artifact(&make_descriptor(
        "small-1", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 10, None,
    ));
    p.process_artifact(&make_descriptor(
        "small-2", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 30, None,
    ));
    p.process_artifact(&make_descriptor(
        "valid-1", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 1000, None,
    ));
    let s = p.summary_report();
    assert_eq!(s.refusal_count, 2);
    assert_eq!(s.total_artifacts, 1);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_schema_version_prefix() {
    assert!(COMPRESSION_SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(COMPRESSION_SCHEMA_VERSION.contains("proof-backed-compression"));
}

#[test]
fn enrichment_constants_bead_id_format() {
    assert!(COMPRESSION_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_constants_component_name() {
    assert_eq!(COMPONENT, "proof_backed_compression");
}

// ---------------------------------------------------------------------------
// CompressionPipeline — serde roundtrip with complex state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_serde_roundtrip_with_refusals_and_dedup() {
    let mut p = CompressionPipeline::new(epoch(15));
    // Add a refused artifact
    p.process_artifact(&make_descriptor(
        "refused-1", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 5, None,
    ));
    // Add dedup artifacts
    let canonical = b"complex-canon";
    p.process_artifact(&make_descriptor(
        "dup-a", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 3000, Some(canonical),
    ));
    p.process_artifact(&make_descriptor(
        "dup-b", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 3000, Some(canonical),
    ));
    // Add non-dedup artifact
    p.process_artifact(&make_descriptor(
        "plain", ArtifactDomain::Aot, ArtifactFamily::BytecodeArtifact, 5000, None,
    ));

    let json = serde_json::to_string(&p).unwrap();
    let back: CompressionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert_eq!(back.refusals.len(), 1);
    assert_eq!(back.dedup_entries.len(), 1);
    assert_eq!(back.results.len(), 3);
}

// ---------------------------------------------------------------------------
// Edge cases — large artifacts, artifact families
// ---------------------------------------------------------------------------

#[test]
fn enrichment_pipeline_large_artifact_compressed() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "large",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        100_000_000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("large").unwrap();
    assert!(r.compressed_size_bytes < r.original_size_bytes);
    // For dictionary compression at 35%: ~35_000_000
    assert_eq!(r.compressed_size_bytes, 35_000_000);
}

#[test]
fn enrichment_pipeline_all_artifact_families_accepted_at_min_size() {
    let mut p = CompressionPipeline::new(epoch(10));
    let families = [
        ArtifactFamily::Ir1Fragment,
        ArtifactFamily::Ir3Fragment,
        ArtifactFamily::BytecodeArtifact,
        ArtifactFamily::RewritePack,
        ArtifactFamily::EvidenceRecord,
        ArtifactFamily::ModuleSnapshot,
        ArtifactFamily::ShapeChain,
        ArtifactFamily::TypeFeedbackProfile,
        ArtifactFamily::ResourceCertificate,
        ArtifactFamily::CacheEntry,
    ];
    for (i, family) in families.iter().enumerate() {
        let d = make_descriptor(
            &format!("fam-{i}"),
            ArtifactDomain::Cache,
            *family,
            64, // exactly at minimum
            None,
        );
        p.process_artifact(&d);
    }
    assert_eq!(p.results.len(), families.len());
    assert!(p.refusals.is_empty());
}

#[test]
fn enrichment_pipeline_dedup_across_different_domains() {
    // Dedup uses canonical_id, which can be same across domains
    let mut p = CompressionPipeline::new(epoch(10));
    let canonical = b"cross-domain-canon";
    p.process_artifact(&make_descriptor(
        "cd-cache", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 1000, Some(canonical),
    ));
    p.process_artifact(&make_descriptor(
        "cd-aot", ArtifactDomain::Aot, ArtifactFamily::BytecodeArtifact, 1000, Some(canonical),
    ));
    // Second should be deduped because canonical_id matches
    assert_eq!(p.dedup_entries.len(), 1);
    let r2 = p.result_for("cd-aot").unwrap();
    assert_eq!(r2.compressed_size_bytes, 0);
}

#[test]
fn enrichment_pipeline_receipt_id_format() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "rcpt-fmt",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        500,
        None,
    );
    p.process_artifact(&d);
    let receipt = p.receipt_for("rcpt-fmt").unwrap();
    assert_eq!(receipt.receipt_id, "receipt-rcpt-fmt");
}

#[test]
fn enrichment_pipeline_receipt_original_hash_matches_descriptor() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "hash-match",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        800,
        None,
    );
    let expected_hash = d.content_hash;
    p.process_artifact(&d);
    let receipt = p.receipt_for("hash-match").unwrap();
    assert_eq!(receipt.original_hash, expected_hash);
}

#[test]
fn enrichment_pipeline_summary_hash_deterministic() {
    let build = || {
        let mut p = CompressionPipeline::new(epoch(10));
        p.process_artifact(&make_descriptor(
            "sh-det", ArtifactDomain::Cache, ArtifactFamily::CacheEntry, 1000, None,
        ));
        p.summary_report().summary_hash
    };
    let h1 = build();
    let h2 = build();
    assert_eq!(h1, h2);
}

#[test]
fn enrichment_pipeline_summary_epoch_propagated() {
    let p = CompressionPipeline::new(epoch(77));
    let s = p.summary_report();
    assert_eq!(s.pipeline_epoch, epoch(77));
}

#[test]
fn enrichment_pipeline_canonical_with_dedup_uses_dedup_strategy() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "canon-strat",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        2000,
        Some(b"has-canonical"),
    );
    p.process_artifact(&d);
    let r = p.result_for("canon-strat").unwrap();
    // Even first canonical artifact uses Dedup strategy (registers as representative)
    assert_eq!(r.strategy, CompressionStrategy::Dedup);
}

#[test]
fn enrichment_pipeline_no_canonical_aot_uses_delta() {
    let mut p = CompressionPipeline::new(epoch(10));
    let d = make_descriptor(
        "no-canon-aot",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        5000,
        None,
    );
    p.process_artifact(&d);
    let r = p.result_for("no-canon-aot").unwrap();
    assert_eq!(r.strategy, CompressionStrategy::DeltaEncoding);
}
