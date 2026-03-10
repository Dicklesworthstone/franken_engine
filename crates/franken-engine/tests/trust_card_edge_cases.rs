//! Integration-level edge-case tests for `trust_card`.
//!
//! Complements the inline unit tests by exercising boundary conditions,
//! serde roundtrips for all public types, ordering guarantees, Display
//! format structure, TrustCardDiff semantics, UpdatePipeline edge cases,
//! TrustCardCache staleness, and cross-type interactions.

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

use frankenengine_engine::reputation::{
    EvidenceNode, EvidenceSource, EvidenceType, ExtensionNode, IncidentNode, IncidentSeverity,
    ProvenanceRecord, PublisherNode, ReputationGraph, ResolutionStatus, TrustLevel,
    TrustTransition,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::trust_card::{
    CardFormat, EvidenceSummary, GeneratorConfig, ProvenanceSummary, Recommendation,
    RecommendedAction, RiskDriver, RiskTrend, TrustCard, TrustCardCache, TrustCardDiff,
    TrustCardError, TrustCardGenerator, TrustHistoryEntry, UpdateNotification, UpdatePipeline,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_extension(id: &str, publisher: &str) -> ExtensionNode {
    ExtensionNode {
        extension_id: id.to_string(),
        package_name: format!("pkg-{id}"),
        version: "1.0.0".to_string(),
        publisher_id: publisher.to_string(),
        manifest_hash: [0u8; 32],
        first_seen_ns: 1_000_000_000,
        current_trust_level: TrustLevel::Unknown,
        dependencies: BTreeSet::new(),
    }
}

fn test_publisher(id: &str) -> PublisherNode {
    PublisherNode {
        publisher_id: id.to_string(),
        identity_attestation: [1u8; 32],
        published_count: 1,
        trust_score: 500_000,
        first_published_ns: 1_000_000_000,
    }
}

fn test_evidence(id: &str, etype: EvidenceType) -> EvidenceNode {
    EvidenceNode {
        evidence_id: id.to_string(),
        evidence_type: etype,
        source: EvidenceSource::BayesianSentinel,
        timestamp_ns: 2_000_000_000,
        content_hash: [2u8; 32],
        linked_decision_ids: vec!["dec-1".to_string()],
        epoch: SecurityEpoch::from_raw(1),
    }
}

fn test_graph_with_extension() -> ReputationGraph {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph
}

fn test_graph_with_provenance() -> ReputationGraph {
    let mut graph = test_graph_with_extension();
    graph
        .set_provenance(ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: true,
            attestation_source: Some("sigstore".into()),
            dependency_depth: 0,
            has_provenance_gap: false,
            gap_descriptions: vec![],
        })
        .unwrap();
    graph
}

fn make_trust_transition(
    id: &str,
    ext_id: &str,
    old: TrustLevel,
    new: TrustLevel,
    ts: u64,
) -> TrustTransition {
    TrustTransition {
        transition_id: id.to_string(),
        extension_id: ext_id.to_string(),
        old_level: old,
        new_level: new,
        triggering_evidence_ids: vec![],
        policy_version: 1,
        operator_override: false,
        operator_justification: None,
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(1),
    }
}

// ===========================================================================
// RiskTrend
// ===========================================================================

#[test]
fn risk_trend_ordering() {
    assert!(RiskTrend::Improving < RiskTrend::Stable);
    assert!(RiskTrend::Stable < RiskTrend::Degrading);
}

#[test]
fn risk_trend_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(RiskTrend::Improving);
    set.insert(RiskTrend::Stable);
    set.insert(RiskTrend::Degrading);
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// RecommendedAction
// ===========================================================================

#[test]
fn recommended_action_ordering() {
    assert!(RecommendedAction::Monitor < RecommendedAction::Review);
    assert!(RecommendedAction::Review < RecommendedAction::Restrict);
    assert!(RecommendedAction::Restrict < RecommendedAction::Remove);
}

#[test]
fn recommended_action_hash_distinct() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(RecommendedAction::Monitor);
    set.insert(RecommendedAction::Review);
    set.insert(RecommendedAction::Restrict);
    set.insert(RecommendedAction::Remove);
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// CardFormat
// ===========================================================================

#[test]
fn card_format_ordering() {
    assert!(CardFormat::Json < CardFormat::Text);
    assert!(CardFormat::Text < CardFormat::Compact);
}

#[test]
fn card_format_serde_all() {
    for fmt in [CardFormat::Json, CardFormat::Text, CardFormat::Compact] {
        let json = serde_json::to_string(&fmt).unwrap();
        let restored: CardFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(fmt, restored);
    }
}

// ===========================================================================
// RiskDriver
// ===========================================================================

#[test]
fn risk_driver_serde_roundtrip() {
    let driver = RiskDriver {
        description: "high dependency risk".to_string(),
        contribution: 25,
    };
    let json = serde_json::to_string(&driver).unwrap();
    let restored: RiskDriver = serde_json::from_str(&json).unwrap();
    assert_eq!(driver, restored);
}

// ===========================================================================
// EvidenceSummary
// ===========================================================================

#[test]
fn evidence_summary_serde_roundtrip() {
    let summary = EvidenceSummary {
        positive_count: 5,
        negative_count: 2,
        neutral_count: 10,
        most_recent_ns: Some(9_000_000_000),
        most_recent_description: Some("behavioral observation".to_string()),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: EvidenceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn evidence_summary_empty_serde() {
    let summary = EvidenceSummary {
        positive_count: 0,
        negative_count: 0,
        neutral_count: 0,
        most_recent_ns: None,
        most_recent_description: None,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: EvidenceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// ===========================================================================
// ProvenanceSummary
// ===========================================================================

#[test]
fn provenance_summary_serde_roundtrip() {
    let prov = ProvenanceSummary {
        publisher_verified: true,
        build_attested: false,
        dependency_risk: 300_000,
        has_provenance_gap: true,
    };
    let json = serde_json::to_string(&prov).unwrap();
    let restored: ProvenanceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(prov, restored);
}

// ===========================================================================
// TrustHistoryEntry
// ===========================================================================

#[test]
fn trust_history_entry_serde_roundtrip() {
    let entry = TrustHistoryEntry {
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Provisional,
        reason: "evidence: ev-1".to_string(),
        timestamp_ns: 5_000_000_000,
        operator_override: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: TrustHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn trust_history_entry_from_operator_override_without_justification() {
    let tt = TrustTransition {
        transition_id: "tt-1".into(),
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Compromised,
        new_level: TrustLevel::Provisional,
        triggering_evidence_ids: vec![],
        policy_version: 1,
        operator_override: true,
        operator_justification: None,
        timestamp_ns: 5_000_000_000,
        epoch: SecurityEpoch::from_raw(1),
    };
    let entry = TrustHistoryEntry::from(&tt);
    assert!(entry.operator_override);
    assert_eq!(entry.reason, "operator override");
}

#[test]
fn trust_history_entry_from_evidence_transition() {
    let tt = TrustTransition {
        transition_id: "tt-2".into(),
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Established,
        triggering_evidence_ids: vec!["ev-a".into(), "ev-b".into()],
        policy_version: 1,
        operator_override: false,
        operator_justification: None,
        timestamp_ns: 6_000_000_000,
        epoch: SecurityEpoch::from_raw(1),
    };
    let entry = TrustHistoryEntry::from(&tt);
    assert!(!entry.operator_override);
    assert!(entry.reason.contains("ev-a"));
    assert!(entry.reason.contains("ev-b"));
}

// ===========================================================================
// Recommendation
// ===========================================================================

#[test]
fn recommendation_serde_roundtrip() {
    let rec = Recommendation {
        action: RecommendedAction::Restrict,
        confidence: 750_000,
        rationale: "suspicious behavior with high risk".to_string(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let restored: Recommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
}

// ===========================================================================
// TrustCardError
// ===========================================================================

#[test]
fn trust_card_error_std_error_trait() {
    let err = TrustCardError::ExtensionNotFound {
        extension_id: "ext-1".into(),
    };
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.source().is_none());
    assert!(std_err.to_string().contains("ext-1"));
}

#[test]
fn trust_card_error_serde_all_variants() {
    let errors = [
        TrustCardError::ExtensionNotFound {
            extension_id: "ext-1".into(),
        },
        TrustCardError::GenerationFailed {
            extension_id: "ext-2".into(),
            reason: "test reason".into(),
        },
        TrustCardError::GraphError {
            message: "graph issue".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: TrustCardError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

#[test]
fn trust_card_error_display_generation_failed() {
    let err = TrustCardError::GenerationFailed {
        extension_id: "ext-42".into(),
        reason: "missing data".into(),
    };
    let s = err.to_string();
    assert!(s.contains("ext-42"));
    assert!(s.contains("missing data"));
}

// ===========================================================================
// GeneratorConfig
// ===========================================================================

#[test]
fn generator_config_custom_values() {
    let config = GeneratorConfig {
        max_history_entries: 5,
        max_risk_drivers: 2,
        trend_window_ns: 3_600_000_000_000, // 1 hour
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: GeneratorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
    assert_eq!(restored.max_history_entries, 5);
}

#[test]
fn generator_config_default_values() {
    let config = GeneratorConfig::default();
    assert_eq!(config.max_history_entries, 10);
    assert_eq!(config.max_risk_drivers, 3);
    assert_eq!(config.trend_window_ns, 86_400_000_000_000);
}

// ===========================================================================
// TrustCardGenerator
// ===========================================================================

#[test]
fn generator_default_trait() {
    let generator = TrustCardGenerator::default();
    let graph = test_graph_with_extension();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert_eq!(card.extension_id, "ext-1");
}

#[test]
fn generator_extension_not_found_error() {
    let graph = ReputationGraph::new();
    let generator = TrustCardGenerator::new();
    let result = generator.generate(&graph, "nonexistent", SecurityEpoch::from_raw(1), 1000);
    assert!(matches!(
        result,
        Err(TrustCardError::ExtensionNotFound { .. })
    ));
}

#[test]
fn generator_card_fields_populated() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(42), 10_000_000_000)
        .unwrap();

    assert_eq!(card.extension_id, "ext-1");
    assert_eq!(card.package_name, "pkg-ext-1");
    assert_eq!(card.version, "1.0.0");
    assert_eq!(card.current_trust_level, TrustLevel::Unknown);
    assert_eq!(card.epoch, SecurityEpoch::from_raw(42));
    assert_eq!(card.generated_at_ns, 10_000_000_000);
    assert_eq!(card.publisher_trust_score, Some(500_000));
}

#[test]
fn generator_format_json_is_valid_json() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let json_str = TrustCardGenerator::format_card(&card, CardFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_object());
    assert_eq!(parsed["extension_id"], "ext-1");
}

#[test]
fn generator_format_compact_single_line() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let compact = TrustCardGenerator::format_card(&card, CardFormat::Compact);
    assert!(!compact.contains('\n'));
    assert!(compact.contains("pkg-ext-1"));
    assert!(compact.contains("1.0.0"));
}

#[test]
fn generator_format_text_multiline() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let text = TrustCardGenerator::format_card(&card, CardFormat::Text);
    assert!(text.contains('\n'));
    assert!(text.contains("ext-1"));
    assert!(text.contains("risk:"));
    assert!(text.contains("evidence:"));
    assert!(text.contains("provenance:"));
    assert!(text.contains("recommendation:"));
}

// ===========================================================================
// TrustCard Display
// ===========================================================================

#[test]
fn trust_card_display_contains_key_sections() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let display = card.to_string();
    assert!(display.contains("ext-1"));
    assert!(display.contains("pkg-ext-1"));
    assert!(display.contains("risk:"));
    assert!(display.contains("evidence:"));
    assert!(display.contains("provenance:"));
    assert!(display.contains("recommendation:"));
    assert!(display.contains("rationale:"));
}

// ===========================================================================
// TrustCard serde
// ===========================================================================

#[test]
fn trust_card_serde_roundtrip() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let json = serde_json::to_string(&card).unwrap();
    let restored: TrustCard = serde_json::from_str(&json).unwrap();
    assert_eq!(card, restored);
}

#[test]
fn trust_card_serde_with_evidence_and_history() {
    let mut graph = test_graph_with_extension();
    graph
        .add_evidence("ext-1", test_evidence("ev-1", EvidenceType::IncidentRecord))
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-1".into()],
            1,
            SecurityEpoch::from_raw(1),
            9_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let json = serde_json::to_string(&card).unwrap();
    let restored: TrustCard = serde_json::from_str(&json).unwrap();
    assert_eq!(card, restored);
    assert!(restored.evidence.negative_count > 0);
    assert!(!restored.history.is_empty());
}

// ===========================================================================
// TrustCardDiff
// ===========================================================================

#[test]
fn diff_serde_roundtrip() {
    let diff = TrustCardDiff {
        extension_id: "ext-1".into(),
        old_trust_level: TrustLevel::Established,
        new_trust_level: TrustLevel::Suspicious,
        risk_score_delta: 30,
        old_recommendation: RecommendedAction::Monitor,
        new_recommendation: RecommendedAction::Restrict,
        change_summary: "trust degraded; risk increased".into(),
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: TrustCardDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

#[test]
fn diff_risk_score_delta_negative() {
    let mut graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();

    let card_high_risk = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    // Improve trust level and add provenance.
    graph
        .set_provenance(ProvenanceRecord {
            extension_id: "ext-1".into(),
            publisher_verified: true,
            build_attested: true,
            attestation_source: Some("sigstore".into()),
            dependency_depth: 0,
            has_provenance_gap: false,
            gap_descriptions: vec![],
        })
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Trusted,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            11_000_000_000,
        )
        .unwrap();

    let card_low_risk = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card_high_risk, &card_low_risk);
    assert!(
        diff.risk_score_delta < 0,
        "improving trust should decrease risk delta, got {}",
        diff.risk_score_delta
    );
}

#[test]
fn diff_change_summary_includes_recommendation_change() {
    let mut graph = test_graph_with_provenance();
    let generator = TrustCardGenerator::new();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Trusted,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            5_000_000_000,
        )
        .unwrap();
    let card_before = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Revoked,
            vec!["ev-bad".into()],
            2,
            SecurityEpoch::from_raw(1),
            11_000_000_000,
        )
        .unwrap();
    let card_after = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card_before, &card_after);
    assert!(diff.change_summary.contains("recommendation:"));
    assert!(diff.change_summary.contains("trust:"));
}

// ===========================================================================
// UpdateNotification
// ===========================================================================

#[test]
fn notification_display_contains_all_fields() {
    let notif = UpdateNotification {
        extension_id: "ext-42".into(),
        old_level: TrustLevel::Trusted,
        new_level: TrustLevel::Compromised,
        triggering_evidence_summary: "malware detected".into(),
        timestamp_ns: 9_000_000_000,
    };
    let s = notif.to_string();
    assert!(s.contains("ext-42"));
    assert!(s.contains("trusted"));
    assert!(s.contains("compromised"));
    assert!(s.contains("malware detected"));
}

#[test]
fn notification_serde_roundtrip() {
    let notif = UpdateNotification {
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Revoked,
        triggering_evidence_summary: "policy violation".into(),
        timestamp_ns: 5_000_000_000,
    };
    let json = serde_json::to_string(&notif).unwrap();
    let restored: UpdateNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(notif, restored);
}

// ===========================================================================
// UpdatePipeline
// ===========================================================================

#[test]
fn pipeline_default() {
    let pipeline = UpdatePipeline::default();
    assert_eq!(pipeline.pending_count(), 0);
    assert_eq!(pipeline.subscription_count(), 0);
}

#[test]
fn pipeline_empty_subscriptions_pass_all() {
    let mut pipeline = UpdatePipeline::new();
    // No subscriptions means all extensions pass through.
    let tt = make_trust_transition(
        "tt-1",
        "ext-any",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        5000,
    );
    pipeline.on_trust_transition(&tt);
    assert_eq!(pipeline.pending_count(), 1);
}

#[test]
fn pipeline_subscribe_and_unsubscribe() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");
    pipeline.subscribe("ext-2");
    assert_eq!(pipeline.subscription_count(), 2);

    pipeline.unsubscribe("ext-1");
    assert_eq!(pipeline.subscription_count(), 1);

    pipeline.unsubscribe("ext-2");
    assert_eq!(pipeline.subscription_count(), 0);
}

#[test]
fn pipeline_filters_unsubscribed_extensions() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");

    let tt_ext2 = make_trust_transition(
        "tt-1",
        "ext-2",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        5000,
    );
    pipeline.on_trust_transition(&tt_ext2);
    assert_eq!(pipeline.pending_count(), 0, "ext-2 should be filtered");

    let tt_ext1 = make_trust_transition(
        "tt-2",
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        6000,
    );
    pipeline.on_trust_transition(&tt_ext1);
    assert_eq!(pipeline.pending_count(), 1, "ext-1 should pass");
}

#[test]
fn pipeline_drain_clears_notifications() {
    let mut pipeline = UpdatePipeline::new();
    let tt = make_trust_transition(
        "tt-1",
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        5000,
    );
    pipeline.on_trust_transition(&tt);
    assert_eq!(pipeline.pending_count(), 1);

    let drained = pipeline.drain_notifications();
    assert_eq!(drained.len(), 1);
    assert_eq!(pipeline.pending_count(), 0);
}

#[test]
fn pipeline_multiple_notifications() {
    let mut pipeline = UpdatePipeline::new();
    for i in 0..5 {
        let tt = make_trust_transition(
            &format!("tt-{i}"),
            "ext-1",
            TrustLevel::Unknown,
            TrustLevel::Provisional,
            1000 + i,
        );
        pipeline.on_trust_transition(&tt);
    }
    assert_eq!(pipeline.pending_count(), 5);
}

#[test]
fn pipeline_operator_override_evidence_summary() {
    let mut pipeline = UpdatePipeline::new();
    let tt = TrustTransition {
        transition_id: "tt-1".into(),
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Compromised,
        new_level: TrustLevel::Provisional,
        triggering_evidence_ids: vec![],
        policy_version: 1,
        operator_override: true,
        operator_justification: Some("resolved".into()),
        timestamp_ns: 5_000_000_000,
        epoch: SecurityEpoch::from_raw(1),
    };
    pipeline.on_trust_transition(&tt);
    let notifications = pipeline.drain_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(
        notifications[0].triggering_evidence_summary,
        "no linked evidence"
    );
}

// ===========================================================================
// TrustCardCache
// ===========================================================================

#[test]
fn cache_default() {
    let cache = TrustCardCache::default();
    assert_eq!(cache.cached_count(), 0);
}

#[test]
fn cache_miss_then_hit() {
    let mut cache = TrustCardCache::new();
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    assert!(cache.get("ext-1", &graph, now).is_none());

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();
    assert_eq!(cache.cached_count(), 1);
    assert!(cache.get("ext-1", &graph, now + 1000).is_some());
}

#[test]
fn cache_invalidate_specific() {
    let mut cache = TrustCardCache::new();
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, 10_000_000_000)
        .unwrap();
    assert_eq!(cache.cached_count(), 1);

    cache.invalidate("ext-1");
    assert_eq!(cache.cached_count(), 0);
}

#[test]
fn cache_invalidate_all() {
    let mut cache = TrustCardCache::new();
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    graph
        .register_extension(test_extension("ext-1", "pub-1"))
        .unwrap();
    graph
        .register_extension(test_extension("ext-2", "pub-1"))
        .unwrap();

    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();
    cache
        .get_or_generate(&generator, &graph, "ext-2", epoch, now)
        .unwrap();
    assert_eq!(cache.cached_count(), 2);

    cache.invalidate_all();
    assert_eq!(cache.cached_count(), 0);
}

#[test]
fn cache_staleness_threshold() {
    let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000); // 1 second
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    // Within staleness window.
    assert!(cache.get("ext-1", &graph, now + 500_000_000).is_some());

    // After staleness window.
    assert!(cache.get("ext-1", &graph, now + 2_000_000_000).is_none());
}

#[test]
fn cache_invalidated_on_graph_transition() {
    let mut cache = TrustCardCache::new();
    let mut graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    // Transition changes graph version.
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec![],
            1,
            epoch,
            now + 1000,
        )
        .unwrap();

    assert!(
        cache.get("ext-1", &graph, now + 2000).is_none(),
        "cache should miss after graph transition"
    );
}

// ===========================================================================
// Card generation edge cases
// ===========================================================================

#[test]
fn card_risk_score_capped_at_100() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    let mut ext = test_extension("ext-1", "pub-1");
    ext.current_trust_level = TrustLevel::Revoked;
    graph.register_extension(ext).unwrap();

    for i in 0..20 {
        graph
            .add_evidence(
                "ext-1",
                test_evidence(&format!("ev-{i}"), EvidenceType::IncidentRecord),
            )
            .unwrap();
    }

    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_risk_drivers: 10,
        ..Default::default()
    });
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert!(card.risk_score <= 100);
}

#[test]
fn card_with_incident() {
    let mut graph = test_graph_with_extension();
    graph.add_incident(IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::Critical,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["isolate".into()],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 5_000_000_000,
    });

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert_eq!(card.incident_count, 1);
}

#[test]
fn card_determinism() {
    let build_graph = || {
        let mut g = ReputationGraph::new();
        g.register_publisher(test_publisher("pub-1"));
        g.register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        g.add_evidence(
            "ext-1",
            test_evidence("ev-1", EvidenceType::BehavioralObservation),
        )
        .unwrap();
        g
    };

    let generator = TrustCardGenerator::new();
    let card1 = generator
        .generate(
            &build_graph(),
            "ext-1",
            SecurityEpoch::from_raw(1),
            10_000_000_000,
        )
        .unwrap();
    let card2 = generator
        .generate(
            &build_graph(),
            "ext-1",
            SecurityEpoch::from_raw(1),
            10_000_000_000,
        )
        .unwrap();

    let json1 = serde_json::to_string(&card1).unwrap();
    let json2 = serde_json::to_string(&card2).unwrap();
    assert_eq!(
        json1, json2,
        "identical inputs must produce identical cards"
    );
}

#[test]
fn card_revoked_recommends_remove() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Revoked,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            5_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert_eq!(card.recommendation.action, RecommendedAction::Remove);
    assert!(card.recommendation.confidence >= 900_000);
}

#[test]
fn card_trusted_with_negatives_recommends_review() {
    let mut graph = test_graph_with_provenance();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Trusted,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            5_000_000_000,
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-bad", EvidenceType::IncidentRecord),
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert_eq!(card.recommendation.action, RecommendedAction::Review);
}

// ===========================================================================
// TrustCardGenerator serde
// ===========================================================================

#[test]
fn generator_serde_roundtrip() {
    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_history_entries: 5,
        max_risk_drivers: 2,
        trend_window_ns: 3_600_000_000_000,
    });
    let json = serde_json::to_string(&generator).unwrap();
    let restored: TrustCardGenerator = serde_json::from_str(&json).unwrap();
    // Generate from both to verify equivalence.
    let graph = test_graph_with_extension();
    let card1 = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    let card2 = restored
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert_eq!(card1, card2);
}
