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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::proof_backed_compression::{
    ArtifactDescriptor, ArtifactDomain, CompressionError, CompressionPipeline,
    CompressionRefusalReason, CompressionStrategy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::semantic_canonical_basis::ArtifactFamily;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn desc(
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

// ===========================================================================
// ArtifactDomain integration tests
// ===========================================================================

#[test]
fn domain_all_unique() {
    let mut seen = BTreeSet::new();
    for d in ArtifactDomain::ALL {
        assert!(seen.insert(d.to_string()), "duplicate domain: {d}");
    }
}

#[test]
fn domain_display_matches_serde() {
    for d in ArtifactDomain::ALL {
        let json = serde_json::to_string(d).unwrap();
        let display = d.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

// ===========================================================================
// CompressionStrategy integration tests
// ===========================================================================

#[test]
fn strategy_all_unique() {
    let mut seen = BTreeSet::new();
    for s in CompressionStrategy::ALL {
        assert!(seen.insert(s.to_string()), "duplicate strategy: {s}");
    }
}

#[test]
fn strategy_display_matches_serde() {
    for s in CompressionStrategy::ALL {
        let json = serde_json::to_string(s).unwrap();
        let display = s.to_string();
        assert_eq!(json, format!("\"{display}\""));
    }
}

#[test]
fn strategy_ratios_ordered() {
    // Dedup should be the most aggressive
    assert!(
        CompressionStrategy::Dedup.expected_ratio_millionths()
            < CompressionStrategy::DeltaEncoding.expected_ratio_millionths()
    );
    assert!(
        CompressionStrategy::DeltaEncoding.expected_ratio_millionths()
            < CompressionStrategy::DictionaryCompression.expected_ratio_millionths()
    );
    assert!(
        CompressionStrategy::DictionaryCompression.expected_ratio_millionths()
            < CompressionStrategy::Identity.expected_ratio_millionths()
    );
}

// ===========================================================================
// CompressionRefusalReason integration tests
// ===========================================================================

#[test]
fn refusal_all_variants_serde() {
    let reasons = vec![
        CompressionRefusalReason::TooSmall {
            size_bytes: 5,
            min_bytes: 64,
        },
        CompressionRefusalReason::NoCanonicalIdentity,
        CompressionRefusalReason::ReplayContractViolation {
            detail: "test".to_string(),
        },
        CompressionRefusalReason::EpochMismatch {
            artifact_epoch: 1,
            reference_epoch: 2,
        },
        CompressionRefusalReason::SuspiciousRatio {
            ratio_millionths: 500,
        },
        CompressionRefusalReason::DomainStrategyMismatch {
            domain: ArtifactDomain::Aot,
            strategy: CompressionStrategy::Dedup,
        },
        CompressionRefusalReason::UnsupportedFamily {
            family: ArtifactFamily::ShapeChain,
        },
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: CompressionRefusalReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn refusal_display_unique() {
    let reasons = vec![
        CompressionRefusalReason::TooSmall {
            size_bytes: 5,
            min_bytes: 64,
        },
        CompressionRefusalReason::NoCanonicalIdentity,
        CompressionRefusalReason::ReplayContractViolation {
            detail: "x".to_string(),
        },
    ];
    let displays: Vec<_> = reasons.iter().map(|r| r.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(displays.len(), unique.len());
}

// ===========================================================================
// CompressionPipeline integration tests
// ===========================================================================

#[test]
fn pipeline_process_all_domains() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    for (i, domain) in ArtifactDomain::ALL.iter().enumerate() {
        let d = desc(
            &format!("dom-{i}"),
            *domain,
            ArtifactFamily::CacheEntry,
            1000,
            None,
        );
        pipeline.process_artifact(&d);
    }
    assert_eq!(pipeline.results.len(), 3);
}

#[test]
fn pipeline_cache_uses_dictionary() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let d = desc(
        "cache-test",
        ArtifactDomain::Cache,
        ArtifactFamily::CacheEntry,
        5000,
        None,
    );
    pipeline.process_artifact(&d);
    let result = pipeline.result_for("cache-test").unwrap();
    assert_eq!(result.strategy, CompressionStrategy::DictionaryCompression);
}

#[test]
fn pipeline_aot_uses_delta() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let d = desc(
        "aot-test",
        ArtifactDomain::Aot,
        ArtifactFamily::BytecodeArtifact,
        5000,
        None,
    );
    pipeline.process_artifact(&d);
    let result = pipeline.result_for("aot-test").unwrap();
    assert_eq!(result.strategy, CompressionStrategy::DeltaEncoding);
}

#[test]
fn pipeline_evidence_uses_dictionary() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let d = desc(
        "ev-test",
        ArtifactDomain::Evidence,
        ArtifactFamily::EvidenceRecord,
        5000,
        None,
    );
    pipeline.process_artifact(&d);
    let result = pipeline.result_for("ev-test").unwrap();
    assert_eq!(result.strategy, CompressionStrategy::DictionaryCompression);
}

#[test]
fn pipeline_dedup_saves_space() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let canonical = b"shared-canonical";
    for i in 0..10 {
        let d = desc(
            &format!("dup-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            5000,
            Some(canonical),
        );
        pipeline.process_artifact(&d);
    }
    let summary = pipeline.summary_report();
    assert_eq!(summary.dedup_count, 9); // 9 duplicates
    assert_eq!(summary.dedup_saved_bytes, 9 * 5000);
}

#[test]
fn pipeline_mixed_canonical_and_not() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    // Some with canonical ID, some without
    for i in 0..6 {
        let canonical = if i < 3 { Some(b"can-a" as &[u8]) } else { None };
        let d = desc(
            &format!("mix-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            2000,
            canonical,
        );
        pipeline.process_artifact(&d);
    }
    assert_eq!(pipeline.results.len(), 6);
    // First 3 should use dedup strategy, last 3 dictionary
    let r0 = pipeline.result_for("mix-0").unwrap();
    assert_eq!(r0.strategy, CompressionStrategy::Dedup);
    let r4 = pipeline.result_for("mix-4").unwrap();
    assert_eq!(r4.strategy, CompressionStrategy::DictionaryCompression);
}

#[test]
fn pipeline_refusal_small_artifacts() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    for i in 0..5 {
        let d = desc(
            &format!("small-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            10, // too small
            None,
        );
        pipeline.process_artifact(&d);
    }
    assert_eq!(pipeline.refusals.len(), 5);
    assert!(pipeline.results.is_empty());
}

#[test]
fn pipeline_receipt_for_every_result() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    for i in 0..8 {
        let d = desc(
            &format!("rcpt-{i}"),
            ArtifactDomain::ALL[i % 3],
            ArtifactFamily::CacheEntry,
            1000 + i as u64 * 200,
            None,
        );
        pipeline.process_artifact(&d);
    }
    for result in &pipeline.results {
        let receipt = pipeline.receipt_for(&result.artifact_id);
        assert!(
            receipt.is_some(),
            "missing receipt for {}",
            result.artifact_id
        );
        let receipt = receipt.unwrap();
        assert!(receipt.restoration_verified);
    }
}

#[test]
fn pipeline_summary_ratio_less_than_one() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    for i in 0..10 {
        let d = desc(
            &format!("ratio-{i}"),
            ArtifactDomain::Cache,
            ArtifactFamily::CacheEntry,
            5000,
            None,
        );
        pipeline.process_artifact(&d);
    }
    let summary = pipeline.summary_report();
    assert!(summary.overall_ratio_millionths < 1_000_000);
}

#[test]
fn pipeline_deterministic_same_inputs() {
    let descriptors: Vec<_> = (0..5)
        .map(|i| {
            desc(
                &format!("det-{i}"),
                ArtifactDomain::Cache,
                ArtifactFamily::CacheEntry,
                2000,
                Some(format!("can-{}", i % 2).as_bytes()),
            )
        })
        .collect();

    let mut p1 = CompressionPipeline::new(epoch(10));
    let mut p2 = CompressionPipeline::new(epoch(10));

    p1.process_batch(&descriptors);
    p2.process_batch(&descriptors);

    assert_eq!(p1.pipeline_hash, p2.pipeline_hash);
}

#[test]
fn pipeline_serde_full_roundtrip() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let canonical = b"serde-can";
    for i in 0..5 {
        let d = desc(
            &format!("serde-{i}"),
            ArtifactDomain::ALL[i % 3],
            ArtifactFamily::CacheEntry,
            3000,
            if i < 3 { Some(canonical) } else { None },
        );
        pipeline.process_artifact(&d);
    }
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: CompressionPipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(pipeline.pipeline_hash, back.pipeline_hash);
}

// ===========================================================================
// CompressionError integration tests
// ===========================================================================

#[test]
fn error_variants_unique_display() {
    let errors = vec![
        CompressionError::ArtifactNotFound {
            artifact_id: "a".to_string(),
        },
        CompressionError::RestorationFailed {
            artifact_id: "b".to_string(),
            expected_hash: "x".to_string(),
            actual_hash: "y".to_string(),
        },
        CompressionError::StrategyNotApplicable {
            strategy: CompressionStrategy::Dedup,
            reason: "no canonical".to_string(),
        },
        CompressionError::InvalidConfig {
            detail: "bad".to_string(),
        },
    ];
    let displays: Vec<_> = errors.iter().map(|e| e.to_string()).collect();
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(displays.len(), unique.len());
}

#[test]
fn error_serde_all_variants() {
    for err in [
        CompressionError::ArtifactNotFound {
            artifact_id: "x".to_string(),
        },
        CompressionError::RestorationFailed {
            artifact_id: "y".to_string(),
            expected_hash: "a".to_string(),
            actual_hash: "b".to_string(),
        },
        CompressionError::StrategyNotApplicable {
            strategy: CompressionStrategy::DeltaEncoding,
            reason: "test".to_string(),
        },
        CompressionError::InvalidConfig {
            detail: "z".to_string(),
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: CompressionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// Cross-domain integration tests
// ===========================================================================

#[test]
fn large_batch_mixed_domains_and_families() {
    let mut pipeline = CompressionPipeline::new(epoch(42));
    let families = [
        ArtifactFamily::CacheEntry,
        ArtifactFamily::BytecodeArtifact,
        ArtifactFamily::EvidenceRecord,
        ArtifactFamily::RewritePack,
        ArtifactFamily::ModuleSnapshot,
    ];

    for i in 0..20 {
        let domain = ArtifactDomain::ALL[i % 3];
        let family = families[i % 5];
        let canonical = if i % 4 == 0 {
            Some(format!("can-group-{}", i % 3).as_bytes().to_vec())
        } else {
            None
        };
        let d = ArtifactDescriptor {
            artifact_id: format!("batch-{i}"),
            domain,
            family,
            size_bytes: 500 + (i as u64) * 300,
            content_hash: ContentHash::compute(format!("content-{i}").as_bytes()),
            canonical_id: canonical.as_deref().map(ContentHash::compute),
            artifact_epoch: epoch(42),
        };
        pipeline.process_artifact(&d);
    }

    let summary = pipeline.summary_report();
    let processed = summary.total_artifacts + pipeline.refusals.len();
    assert_eq!(processed, 20);
    assert!(summary.total_saved_bytes > 0 || summary.overall_ratio_millionths <= 1_000_000);
}

#[test]
fn dedup_across_domains() {
    let mut pipeline = CompressionPipeline::new(epoch(10));
    let canonical = b"cross-domain-canonical";
    // Same canonical ID but different domains
    for (i, domain) in ArtifactDomain::ALL.iter().enumerate() {
        let d = desc(
            &format!("xdom-{i}"),
            *domain,
            ArtifactFamily::CacheEntry,
            3000,
            Some(canonical),
        );
        pipeline.process_artifact(&d);
    }
    // All three should use dedup; first is representative, other two deduped
    assert_eq!(pipeline.dedup_entries.len(), 2);
}
