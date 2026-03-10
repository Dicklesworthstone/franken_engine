#![forbid(unsafe_code)]
//! Integration tests for the `trust_card` module.
//!
//! Covers: RiskTrend, RiskDriver, EvidenceSummary, ProvenanceSummary,
//! TrustHistoryEntry, RecommendedAction, Recommendation, TrustCard,
//! TrustCardDiff, UpdateNotification, TrustCardError, CardFormat,
//! GeneratorConfig, TrustCardGenerator, TrustCardCache, UpdatePipeline.

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
// Test helpers
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

fn test_extension_with_deps(id: &str, publisher: &str, deps: &[&str]) -> ExtensionNode {
    let mut ext = test_extension(id, publisher);
    ext.dependencies = deps.iter().map(|d| d.to_string()).collect();
    ext
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

fn test_evidence_at(id: &str, etype: EvidenceType, ts: u64) -> EvidenceNode {
    EvidenceNode {
        evidence_id: id.to_string(),
        evidence_type: etype,
        source: EvidenceSource::BayesianSentinel,
        timestamp_ns: ts,
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

fn make_transition(
    ext_id: &str,
    old: TrustLevel,
    new: TrustLevel,
    evidence: Vec<String>,
    is_override: bool,
    justification: Option<String>,
    ts: u64,
) -> TrustTransition {
    TrustTransition {
        transition_id: format!("tt-{ts}"),
        extension_id: ext_id.to_string(),
        old_level: old,
        new_level: new,
        triggering_evidence_ids: evidence,
        policy_version: 1,
        operator_override: is_override,
        operator_justification: justification,
        timestamp_ns: ts,
        epoch: SecurityEpoch::from_raw(1),
    }
}

// =========================================================================
// Section 1: Display impls
// =========================================================================

#[test]
fn risk_trend_display_all_variants() {
    assert_eq!(RiskTrend::Improving.to_string(), "improving");
    assert_eq!(RiskTrend::Stable.to_string(), "stable");
    assert_eq!(RiskTrend::Degrading.to_string(), "degrading");
}

#[test]
fn recommended_action_display_all_variants() {
    assert_eq!(RecommendedAction::Monitor.to_string(), "monitor");
    assert_eq!(RecommendedAction::Review.to_string(), "review");
    assert_eq!(RecommendedAction::Restrict.to_string(), "restrict");
    assert_eq!(RecommendedAction::Remove.to_string(), "remove");
}

#[test]
fn trust_card_error_display_extension_not_found() {
    let err = TrustCardError::ExtensionNotFound {
        extension_id: "ext-missing".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("extension not found"));
    assert!(msg.contains("ext-missing"));
}

#[test]
fn trust_card_error_display_generation_failed() {
    let err = TrustCardError::GenerationFailed {
        extension_id: "ext-fail".into(),
        reason: "bad provenance data".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("card generation failed"));
    assert!(msg.contains("ext-fail"));
    assert!(msg.contains("bad provenance data"));
}

#[test]
fn trust_card_error_display_graph_error() {
    let err = TrustCardError::GraphError {
        message: "internal inconsistency".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("graph error"));
    assert!(msg.contains("internal inconsistency"));
}

#[test]
fn trust_card_display_contains_key_fields() {
    let card = TrustCard {
        extension_id: "ext-display".into(),
        package_name: "my-pkg".into(),
        version: "2.1.0".into(),
        current_trust_level: TrustLevel::Suspicious,
        trust_level_since_ns: 5_000,
        publisher_trust_score: Some(750_000),
        risk_score: 45,
        risk_trend: RiskTrend::Degrading,
        risk_drivers: vec![RiskDriver {
            description: "suspicious behavior".into(),
            contribution: 25,
        }],
        evidence: EvidenceSummary {
            positive_count: 3,
            negative_count: 2,
            neutral_count: 1,
            most_recent_ns: Some(9_000),
            most_recent_description: Some("recent event".into()),
        },
        provenance: ProvenanceSummary {
            publisher_verified: false,
            build_attested: true,
            dependency_risk: 100_000,
            has_provenance_gap: true,
        },
        history: vec![],
        incident_count: 1,
        recommendation: Recommendation {
            action: RecommendedAction::Restrict,
            confidence: 750_000,
            rationale: "high risk".into(),
        },
        epoch: SecurityEpoch::from_raw(2),
        generated_at_ns: 10_000,
    };

    let text = card.to_string();
    assert!(text.contains("ext-display"), "must contain extension_id");
    assert!(text.contains("my-pkg"), "must contain package_name");
    assert!(text.contains("2.1.0"), "must contain version");
    assert!(text.contains("suspicious"), "must contain trust level");
    assert!(text.contains("45/100"), "must contain risk score");
    assert!(text.contains("degrading"), "must contain risk trend");
    assert!(
        text.contains("+25"),
        "must contain risk driver contribution"
    );
    assert!(text.contains("+3"), "must contain positive evidence count");
    assert!(text.contains("-2"), "must contain negative evidence count");
    assert!(
        text.contains("restrict"),
        "must contain recommendation action"
    );
    assert!(text.contains("high risk"), "must contain rationale");
}

#[test]
fn update_notification_display() {
    let notif = UpdateNotification {
        extension_id: "ext-notif".into(),
        old_level: TrustLevel::Established,
        new_level: TrustLevel::Compromised,
        triggering_evidence_summary: "ev-incident-42".into(),
        timestamp_ns: 99_000,
    };
    let msg = notif.to_string();
    assert!(msg.contains("ext-notif"));
    assert!(msg.contains("established"));
    assert!(msg.contains("compromised"));
    assert!(msg.contains("ev-incident-42"));
}

// =========================================================================
// Section 2: Construction / Defaults
// =========================================================================

#[test]
fn generator_config_default_values() {
    let cfg = GeneratorConfig::default();
    assert_eq!(cfg.max_history_entries, 10);
    assert_eq!(cfg.max_risk_drivers, 3);
    assert_eq!(cfg.trend_window_ns, 86_400_000_000_000);
}

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
fn trust_card_cache_default_trait() {
    let cache = TrustCardCache::default();
    assert_eq!(cache.cached_count(), 0);
}

#[test]
fn update_pipeline_default_trait() {
    let pipeline = UpdatePipeline::default();
    assert_eq!(pipeline.pending_count(), 0);
    assert_eq!(pipeline.subscription_count(), 0);
}

#[test]
fn trust_card_cache_custom_staleness() {
    let cache = TrustCardCache::with_max_staleness_ns(60_000_000_000);
    assert_eq!(cache.cached_count(), 0);
}

// =========================================================================
// Section 3: Card generation — basic scenarios
// =========================================================================

#[test]
fn generate_card_for_unknown_extension() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.extension_id, "ext-1");
    assert_eq!(card.package_name, "pkg-ext-1");
    assert_eq!(card.version, "1.0.0");
    assert_eq!(card.current_trust_level, TrustLevel::Unknown);
    assert_eq!(card.publisher_trust_score, Some(500_000));
    assert!(
        card.risk_score > 0,
        "unknown extension should have some risk"
    );
    assert_eq!(card.epoch, SecurityEpoch::from_raw(1));
    assert_eq!(card.generated_at_ns, 10_000_000_000);
}

#[test]
fn generate_card_for_trusted_extension_with_full_provenance() {
    let mut graph = test_graph_with_provenance();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Trusted,
            vec!["ev-good".into()],
            1,
            SecurityEpoch::from_raw(1),
            5_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.current_trust_level, TrustLevel::Trusted);
    assert_eq!(card.risk_score, 0);
    assert_eq!(card.recommendation.action, RecommendedAction::Monitor);
    assert!(card.provenance.publisher_verified);
    assert!(card.provenance.build_attested);
    assert!(!card.provenance.has_provenance_gap);
}

#[test]
fn generate_card_missing_extension_returns_error() {
    let graph = ReputationGraph::new();
    let generator = TrustCardGenerator::new();
    let result = generator.generate(&graph, "nonexistent", SecurityEpoch::from_raw(1), 0);
    assert!(matches!(
        result,
        Err(TrustCardError::ExtensionNotFound { .. })
    ));
}

#[test]
fn generate_card_with_custom_config() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_history_entries: 5,
        max_risk_drivers: 2,
        trend_window_ns: 1_000_000_000,
    });
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert!(card.risk_drivers.len() <= 2);
}

#[test]
fn generate_cards_for_multiple_extensions() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    for i in 0..5 {
        graph
            .register_extension(test_extension(&format!("ext-{i}"), "pub-1"))
            .unwrap();
    }

    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let cards: Vec<TrustCard> = (0..5)
        .map(|i| {
            generator
                .generate(&graph, &format!("ext-{i}"), epoch, 10_000_000_000)
                .unwrap()
        })
        .collect();

    assert_eq!(cards.len(), 5);
    for (i, card) in cards.iter().enumerate() {
        assert_eq!(card.extension_id, format!("ext-{i}"));
    }
}

// =========================================================================
// Section 4: Risk drivers
// =========================================================================

#[test]
fn risk_drivers_include_unverified_publisher() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let descriptions: Vec<&str> = card
        .risk_drivers
        .iter()
        .map(|d| d.description.as_str())
        .collect();
    assert!(
        descriptions
            .iter()
            .any(|d| d.contains("unverified publisher")),
        "expected unverified publisher driver, got: {descriptions:?}"
    );
}

#[test]
fn risk_drivers_sorted_descending_by_contribution() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    for pair in card.risk_drivers.windows(2) {
        assert!(
            pair[0].contribution >= pair[1].contribution,
            "not sorted descending: {} vs {}",
            pair[0].contribution,
            pair[1].contribution
        );
    }
}

#[test]
fn risk_drivers_capped_at_max() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_risk_drivers: 2,
        ..Default::default()
    });
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert!(card.risk_drivers.len() <= 2);
}

#[test]
fn risk_score_capped_at_100() {
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

    assert!(
        card.risk_score <= 100,
        "risk score must cap at 100, got {}",
        card.risk_score
    );
}

#[test]
fn risk_drivers_include_negative_evidence() {
    let mut graph = test_graph_with_extension();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-bad", EvidenceType::IncidentRecord),
        )
        .unwrap();

    // Use higher max_risk_drivers so negative evidence isn't truncated.
    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_risk_drivers: 10,
        ..Default::default()
    });
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let has_neg = card
        .risk_drivers
        .iter()
        .any(|d| d.description.contains("negative evidence"));
    assert!(
        has_neg,
        "expected negative evidence driver in: {:?}",
        card.risk_drivers
    );
}

#[test]
fn risk_drivers_include_trust_level_for_degraded() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
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

    let has_trust_driver = card
        .risk_drivers
        .iter()
        .any(|d| d.description.contains("trust level"));
    assert!(
        has_trust_driver,
        "expected trust level driver for suspicious"
    );
}

// =========================================================================
// Section 5: Evidence summary
// =========================================================================

#[test]
fn evidence_summary_counts_by_type() {
    let mut graph = test_graph_with_extension();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-1", EvidenceType::ProvenanceAttestation),
        )
        .unwrap();
    graph
        .add_evidence("ext-1", test_evidence("ev-2", EvidenceType::IncidentRecord))
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-3", EvidenceType::BehavioralObservation),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-4", EvidenceType::OperatorAssessment),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-5", EvidenceType::ThreatIntelligence),
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.evidence.positive_count, 2); // Provenance + OperatorAssessment
    assert_eq!(card.evidence.negative_count, 2); // IncidentRecord + ThreatIntelligence
    assert_eq!(card.evidence.neutral_count, 1); // BehavioralObservation
    assert!(card.evidence.most_recent_ns.is_some());
    assert!(card.evidence.most_recent_description.is_some());
}

#[test]
fn evidence_summary_empty_when_no_evidence() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.evidence.positive_count, 0);
    assert_eq!(card.evidence.negative_count, 0);
    assert_eq!(card.evidence.neutral_count, 0);
    assert!(card.evidence.most_recent_ns.is_none());
    assert!(card.evidence.most_recent_description.is_none());
}

#[test]
fn evidence_summary_most_recent_tracks_timestamp() {
    let mut graph = test_graph_with_extension();
    graph
        .add_evidence(
            "ext-1",
            test_evidence_at("ev-old", EvidenceType::BehavioralObservation, 1_000),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence_at("ev-new", EvidenceType::IncidentRecord, 9_000),
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.evidence.most_recent_ns, Some(9_000));
}

// =========================================================================
// Section 6: Risk trend
// =========================================================================

#[test]
fn risk_trend_stable_no_transitions() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.risk_trend, RiskTrend::Stable);
}

#[test]
fn risk_trend_degrading_on_demotion() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-bad".into()],
            1,
            SecurityEpoch::from_raw(1),
            9_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.risk_trend, RiskTrend::Degrading);
}

#[test]
fn risk_trend_improving_on_upgrade() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Established,
            vec!["ev-good".into()],
            1,
            SecurityEpoch::from_raw(1),
            9_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.risk_trend, RiskTrend::Improving);
}

#[test]
fn risk_trend_stable_when_transitions_outside_window() {
    let mut graph = test_graph_with_extension();
    // Transition happened long ago, outside the 24h window.
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-old".into()],
            1,
            SecurityEpoch::from_raw(1),
            1_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    // now_ns is 24h + margin past the transition
    let card = generator
        .generate(
            &graph,
            "ext-1",
            SecurityEpoch::from_raw(1),
            86_400_000_000_000 + 1_000_000_000,
        )
        .unwrap();

    assert_eq!(card.risk_trend, RiskTrend::Stable);
}

// =========================================================================
// Section 7: Recommendations
// =========================================================================

#[test]
fn recommendation_remove_for_revoked() {
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
fn recommendation_remove_for_compromised() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Compromised,
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
    assert!(card.recommendation.confidence >= 850_000);
}

#[test]
fn recommendation_review_or_restrict_for_suspicious() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
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

    assert!(
        card.recommendation.action == RecommendedAction::Review
            || card.recommendation.action == RecommendedAction::Restrict
    );
}

#[test]
fn recommendation_review_for_unknown_without_provenance() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.recommendation.action, RecommendedAction::Review);
}

#[test]
fn recommendation_monitor_for_trusted_no_negatives() {
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

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.recommendation.action, RecommendedAction::Monitor);
    assert!(card.recommendation.confidence >= 800_000);
}

#[test]
fn recommendation_review_for_trusted_with_negative_evidence() {
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

// =========================================================================
// Section 8: Trust history
// =========================================================================

#[test]
fn history_entries_most_recent_first() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            2_000_000_000,
        )
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Established,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            3_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.history.len(), 2);
    assert_eq!(card.history[0].new_level, TrustLevel::Established);
    assert_eq!(card.history[1].new_level, TrustLevel::Provisional);
}

#[test]
fn history_capped_at_max_entries() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            2_000,
        )
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Established,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            3_000,
        )
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            4_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_history_entries: 2,
        ..Default::default()
    });
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.history.len(), 2);
}

#[test]
fn history_entry_from_transition_contains_evidence_ids() {
    let tt = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec!["ev-1".into(), "ev-2".into()],
        false,
        None,
        5_000,
    );
    let entry = TrustHistoryEntry::from(&tt);
    assert_eq!(entry.old_level, TrustLevel::Unknown);
    assert_eq!(entry.new_level, TrustLevel::Provisional);
    assert!(!entry.operator_override);
    assert!(entry.reason.contains("ev-1"));
    assert!(entry.reason.contains("ev-2"));
}

#[test]
fn history_entry_from_operator_override_uses_justification() {
    let tt = make_transition(
        "ext-1",
        TrustLevel::Compromised,
        TrustLevel::Provisional,
        vec![],
        true,
        Some("incident fully resolved".into()),
        6_000,
    );
    let entry = TrustHistoryEntry::from(&tt);
    assert!(entry.operator_override);
    assert_eq!(entry.reason, "incident fully resolved");
}

#[test]
fn history_entry_from_operator_override_without_justification() {
    let tt = make_transition(
        "ext-1",
        TrustLevel::Suspicious,
        TrustLevel::Unknown,
        vec![],
        true,
        None,
        7_000,
    );
    let entry = TrustHistoryEntry::from(&tt);
    assert!(entry.operator_override);
    assert_eq!(entry.reason, "operator override");
}

// =========================================================================
// Section 9: Provenance summary
// =========================================================================

#[test]
fn provenance_defaults_when_no_record() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert!(!card.provenance.publisher_verified);
    assert!(!card.provenance.build_attested);
    assert!(card.provenance.has_provenance_gap);
}

#[test]
fn provenance_reflects_record_when_set() {
    let graph = test_graph_with_provenance();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert!(card.provenance.publisher_verified);
    assert!(card.provenance.build_attested);
    assert!(!card.provenance.has_provenance_gap);
}

// =========================================================================
// Section 10: Incident count
// =========================================================================

#[test]
fn card_incident_count_zero_with_no_incidents() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.incident_count, 0);
}

#[test]
fn card_incident_count_reflects_incidents() {
    let mut graph = test_graph_with_extension();
    graph.add_incident(IncidentNode {
        incident_id: "inc-1".into(),
        severity: IncidentSeverity::High,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["quarantine".into()],
        resolution_status: ResolutionStatus::Active,
        timestamp_ns: 5_000_000_000,
    });
    graph.add_incident(IncidentNode {
        incident_id: "inc-2".into(),
        severity: IncidentSeverity::Critical,
        affected_extensions: ["ext-1".into()].into_iter().collect(),
        containment_actions: vec!["isolate".into()],
        resolution_status: ResolutionStatus::Contained,
        timestamp_ns: 6_000_000_000,
    });

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.incident_count, 2);
}

// =========================================================================
// Section 11: Dependency risk
// =========================================================================

#[test]
fn card_includes_dependency_risk_from_unknown_dep() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    let dep = test_extension("dep-1", "pub-1");
    graph.register_extension(dep).unwrap();
    let ext = test_extension_with_deps("ext-1", "pub-1", &["dep-1"]);
    graph.register_extension(ext).unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert!(card.provenance.dependency_risk > 0);
}

// =========================================================================
// Section 12: Card formatting
// =========================================================================

#[test]
fn format_json_produces_valid_json() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let json_str = TrustCardGenerator::format_card(&card, CardFormat::Json);
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_object());
}

#[test]
fn format_text_contains_extension_info() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let text = TrustCardGenerator::format_card(&card, CardFormat::Text);
    assert!(text.contains("ext-1"));
    assert!(text.contains("pkg-ext-1"));
    assert!(text.contains("1.0.0"));
}

#[test]
fn format_compact_is_single_line() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let compact = TrustCardGenerator::format_card(&card, CardFormat::Compact);
    assert!(
        !compact.contains('\n'),
        "compact format must be single line"
    );
    assert!(compact.contains("pkg-ext-1"));
    assert!(compact.contains("/100"));
}

// =========================================================================
// Section 13: TrustCardDiff
// =========================================================================

#[test]
fn diff_detects_trust_level_change() {
    let mut graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card_before = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-bad".into()],
            1,
            SecurityEpoch::from_raw(1),
            11_000_000_000,
        )
        .unwrap();
    let card_after = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card_before, &card_after);
    assert_eq!(diff.extension_id, "ext-1");
    assert_eq!(diff.old_trust_level, TrustLevel::Unknown);
    assert_eq!(diff.new_trust_level, TrustLevel::Suspicious);
    assert!(diff.change_summary.contains("trust:"));
}

#[test]
fn diff_detects_risk_score_change() {
    let mut graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card_before = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            11_000_000_000,
        )
        .unwrap();
    let card_after = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card_before, &card_after);
    assert_ne!(diff.risk_score_delta, 0);
    assert!(diff.change_summary.contains("risk:"));
}

#[test]
fn diff_no_changes_reports_no_significant() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card, &card);
    assert_eq!(diff.risk_score_delta, 0);
    assert!(diff.change_summary.contains("no significant changes"));
}

#[test]
fn diff_detects_recommendation_change() {
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

    let generator = TrustCardGenerator::new();
    let card_trusted = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Revoked,
            vec![],
            1,
            SecurityEpoch::from_raw(1),
            11_000_000_000,
        )
        .unwrap();
    let card_revoked = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 12_000_000_000)
        .unwrap();

    let diff = TrustCardDiff::compute(&card_trusted, &card_revoked);
    assert_eq!(diff.old_recommendation, RecommendedAction::Monitor);
    assert_eq!(diff.new_recommendation, RecommendedAction::Remove);
    assert!(diff.change_summary.contains("recommendation:"));
}

// =========================================================================
// Section 14: UpdateNotification
// =========================================================================

#[test]
fn notification_fields_populated() {
    let notif = UpdateNotification {
        extension_id: "ext-42".into(),
        old_level: TrustLevel::Provisional,
        new_level: TrustLevel::Compromised,
        triggering_evidence_summary: "ev-x, ev-y".into(),
        timestamp_ns: 12_000,
    };

    assert_eq!(notif.extension_id, "ext-42");
    assert_eq!(notif.old_level, TrustLevel::Provisional);
    assert_eq!(notif.new_level, TrustLevel::Compromised);
    assert_eq!(notif.triggering_evidence_summary, "ev-x, ev-y");
    assert_eq!(notif.timestamp_ns, 12_000);
}

// =========================================================================
// Section 15: UpdatePipeline
// =========================================================================

#[test]
fn pipeline_emits_notification_on_transition() {
    let mut pipeline = UpdatePipeline::new();
    let tt = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        vec!["ev-1".into()],
        false,
        None,
        5_000,
    );

    pipeline.on_trust_transition(&tt);
    assert_eq!(pipeline.pending_count(), 1);

    let notifications = pipeline.drain_notifications();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].extension_id, "ext-1");
    assert_eq!(notifications[0].old_level, TrustLevel::Unknown);
    assert_eq!(notifications[0].new_level, TrustLevel::Suspicious);
    assert_eq!(pipeline.pending_count(), 0);
}

#[test]
fn pipeline_subscription_filter_excludes_unsubscribed() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-2");

    let tt1 = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        vec![],
        false,
        None,
        5_000,
    );
    pipeline.on_trust_transition(&tt1);
    assert_eq!(
        pipeline.pending_count(),
        0,
        "ext-1 not subscribed, should be filtered"
    );

    let tt2 = make_transition(
        "ext-2",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec![],
        false,
        None,
        6_000,
    );
    pipeline.on_trust_transition(&tt2);
    assert_eq!(pipeline.pending_count(), 1);
}

#[test]
fn pipeline_empty_subscriptions_means_all() {
    let mut pipeline = UpdatePipeline::new();
    // No subscriptions = monitor all.
    let tt = make_transition(
        "ext-any",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec![],
        false,
        None,
        5_000,
    );
    pipeline.on_trust_transition(&tt);
    assert_eq!(pipeline.pending_count(), 1);
}

#[test]
fn pipeline_subscribe_and_unsubscribe() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");
    assert_eq!(pipeline.subscription_count(), 1);
    pipeline.subscribe("ext-2");
    assert_eq!(pipeline.subscription_count(), 2);
    pipeline.unsubscribe("ext-1");
    assert_eq!(pipeline.subscription_count(), 1);
    pipeline.unsubscribe("ext-2");
    assert_eq!(pipeline.subscription_count(), 0);
}

#[test]
fn pipeline_notification_includes_no_linked_evidence_summary() {
    let mut pipeline = UpdatePipeline::new();
    let tt = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec![],
        false,
        None,
        5_000,
    );
    pipeline.on_trust_transition(&tt);
    let notifications = pipeline.drain_notifications();
    assert_eq!(
        notifications[0].triggering_evidence_summary,
        "no linked evidence"
    );
}

#[test]
fn pipeline_drain_clears_pending() {
    let mut pipeline = UpdatePipeline::new();
    for i in 0..3 {
        let tt = make_transition(
            &format!("ext-{i}"),
            TrustLevel::Unknown,
            TrustLevel::Suspicious,
            vec![],
            false,
            None,
            (i + 1) as u64 * 1000,
        );
        pipeline.on_trust_transition(&tt);
    }

    assert_eq!(pipeline.pending_count(), 3);
    let drained = pipeline.drain_notifications();
    assert_eq!(drained.len(), 3);
    assert_eq!(pipeline.pending_count(), 0);
}

// =========================================================================
// Section 16: TrustCardCache
// =========================================================================

#[test]
fn cache_miss_on_empty() {
    let cache = TrustCardCache::new();
    let graph = test_graph_with_extension();
    assert!(cache.get("ext-1", &graph, 10_000_000_000).is_none());
}

#[test]
fn cache_hit_after_generation() {
    let mut cache = TrustCardCache::new();
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();
    assert_eq!(cache.cached_count(), 1);

    let card = cache.get("ext-1", &graph, now + 1_000);
    assert!(card.is_some());
}

#[test]
fn cache_invalidated_on_graph_change() {
    let mut cache = TrustCardCache::new();
    let mut graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec![],
            1,
            epoch,
            now + 1_000,
        )
        .unwrap();

    assert!(
        cache.get("ext-1", &graph, now + 2_000).is_none(),
        "cache must invalidate after graph change"
    );
}

#[test]
fn cache_invalidated_on_staleness() {
    let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000);
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    assert!(
        cache.get("ext-1", &graph, now + 2_000_000_000).is_none(),
        "cache must invalidate after staleness period"
    );
}

#[test]
fn cache_invalidate_specific_extension() {
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
fn cache_regenerates_on_stale_get_or_generate() {
    let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000);
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    let card1 = cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap()
        .clone();

    // After staleness period, get_or_generate should regenerate.
    let card2 = cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now + 2_000_000_000)
        .unwrap();

    assert_eq!(card1.extension_id, card2.extension_id);
    assert_ne!(card1.generated_at_ns, card2.generated_at_ns);
}

// =========================================================================
// Section 17: Serde roundtrips
// =========================================================================

#[test]
fn risk_trend_serde_roundtrip() {
    for trend in [
        RiskTrend::Improving,
        RiskTrend::Stable,
        RiskTrend::Degrading,
    ] {
        let json = serde_json::to_string(&trend).unwrap();
        let restored: RiskTrend = serde_json::from_str(&json).unwrap();
        assert_eq!(trend, restored);
    }
}

#[test]
fn recommended_action_serde_roundtrip() {
    for action in [
        RecommendedAction::Monitor,
        RecommendedAction::Review,
        RecommendedAction::Restrict,
        RecommendedAction::Remove,
    ] {
        let json = serde_json::to_string(&action).unwrap();
        let restored: RecommendedAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, restored);
    }
}

#[test]
fn card_format_serde_roundtrip() {
    for fmt in [CardFormat::Json, CardFormat::Text, CardFormat::Compact] {
        let json = serde_json::to_string(&fmt).unwrap();
        let restored: CardFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(fmt, restored);
    }
}

#[test]
fn trust_card_error_serde_roundtrip() {
    let errors = vec![
        TrustCardError::ExtensionNotFound {
            extension_id: "ext-1".into(),
        },
        TrustCardError::GenerationFailed {
            extension_id: "ext-2".into(),
            reason: "test reason".into(),
        },
        TrustCardError::GraphError {
            message: "graph msg".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: TrustCardError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

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
fn trust_card_diff_serde_roundtrip() {
    let diff = TrustCardDiff {
        extension_id: "ext-1".into(),
        old_trust_level: TrustLevel::Established,
        new_trust_level: TrustLevel::Suspicious,
        risk_score_delta: 25,
        old_recommendation: RecommendedAction::Monitor,
        new_recommendation: RecommendedAction::Review,
        change_summary: "trust degraded".into(),
    };
    let json = serde_json::to_string(&diff).unwrap();
    let restored: TrustCardDiff = serde_json::from_str(&json).unwrap();
    assert_eq!(diff, restored);
}

#[test]
fn update_notification_serde_roundtrip() {
    let notif = UpdateNotification {
        extension_id: "ext-1".into(),
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Provisional,
        triggering_evidence_summary: "ev-1".into(),
        timestamp_ns: 5_000_000_000,
    };
    let json = serde_json::to_string(&notif).unwrap();
    let restored: UpdateNotification = serde_json::from_str(&json).unwrap();
    assert_eq!(notif, restored);
}

#[test]
fn generator_config_serde_roundtrip() {
    let config = GeneratorConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: GeneratorConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn risk_driver_serde_roundtrip() {
    let driver = RiskDriver {
        description: "unverified publisher".into(),
        contribution: 20,
    };
    let json = serde_json::to_string(&driver).unwrap();
    let restored: RiskDriver = serde_json::from_str(&json).unwrap();
    assert_eq!(driver, restored);
}

#[test]
fn evidence_summary_serde_roundtrip() {
    let summary = EvidenceSummary {
        positive_count: 5,
        negative_count: 2,
        neutral_count: 3,
        most_recent_ns: Some(9_000),
        most_recent_description: Some("latest event".into()),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: EvidenceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

#[test]
fn provenance_summary_serde_roundtrip() {
    let prov = ProvenanceSummary {
        publisher_verified: true,
        build_attested: false,
        dependency_risk: 250_000,
        has_provenance_gap: true,
    };
    let json = serde_json::to_string(&prov).unwrap();
    let restored: ProvenanceSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(prov, restored);
}

#[test]
fn recommendation_serde_roundtrip() {
    let rec = Recommendation {
        action: RecommendedAction::Restrict,
        confidence: 750_000,
        rationale: "suspicious behavior detected".into(),
    };
    let json = serde_json::to_string(&rec).unwrap();
    let restored: Recommendation = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, restored);
}

#[test]
fn trust_history_entry_serde_roundtrip() {
    let entry = TrustHistoryEntry {
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Provisional,
        reason: "evidence: ev-1, ev-2".into(),
        timestamp_ns: 5_000,
        operator_override: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let restored: TrustHistoryEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// =========================================================================
// Section 18: Deterministic replay
// =========================================================================

#[test]
fn card_generation_deterministic_replay() {
    let build = || {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        graph
            .register_extension(test_extension("ext-1", "pub-1"))
            .unwrap();
        graph
            .add_evidence(
                "ext-1",
                test_evidence("ev-1", EvidenceType::BehavioralObservation),
            )
            .unwrap();
        graph
            .transition_trust(
                "ext-1",
                TrustLevel::Provisional,
                vec!["ev-1".into()],
                1,
                SecurityEpoch::from_raw(1),
                5_000,
            )
            .unwrap();
        graph
    };

    let generator = TrustCardGenerator::new();
    let card1 = generator
        .generate(
            &build(),
            "ext-1",
            SecurityEpoch::from_raw(1),
            10_000_000_000,
        )
        .unwrap();
    let card2 = generator
        .generate(
            &build(),
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
fn diff_deterministic_replay() {
    let card_a = TrustCard {
        extension_id: "ext-d".into(),
        package_name: "pkg".into(),
        version: "1.0.0".into(),
        current_trust_level: TrustLevel::Unknown,
        trust_level_since_ns: 1_000,
        publisher_trust_score: None,
        risk_score: 30,
        risk_trend: RiskTrend::Stable,
        risk_drivers: vec![],
        evidence: EvidenceSummary {
            positive_count: 0,
            negative_count: 0,
            neutral_count: 0,
            most_recent_ns: None,
            most_recent_description: None,
        },
        provenance: ProvenanceSummary {
            publisher_verified: false,
            build_attested: false,
            dependency_risk: 0,
            has_provenance_gap: true,
        },
        history: vec![],
        incident_count: 0,
        recommendation: Recommendation {
            action: RecommendedAction::Review,
            confidence: 600_000,
            rationale: "review needed".into(),
        },
        epoch: SecurityEpoch::from_raw(1),
        generated_at_ns: 10_000,
    };

    let card_b = TrustCard {
        risk_score: 60,
        current_trust_level: TrustLevel::Suspicious,
        recommendation: Recommendation {
            action: RecommendedAction::Restrict,
            confidence: 750_000,
            rationale: "restricted".into(),
        },
        ..card_a.clone()
    };

    let diff1 = TrustCardDiff::compute(&card_a, &card_b);
    let diff2 = TrustCardDiff::compute(&card_a, &card_b);
    assert_eq!(
        serde_json::to_string(&diff1).unwrap(),
        serde_json::to_string(&diff2).unwrap()
    );
}

// =========================================================================
// Section 19: Error conditions and edge cases
// =========================================================================

#[test]
fn trust_card_error_is_error_trait() {
    let err = TrustCardError::ExtensionNotFound {
        extension_id: "ext-1".into(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn from_reputation_graph_error_conversion() {
    use frankenengine_engine::reputation::ReputationGraphError;
    let graph_err = ReputationGraphError::ExtensionNotFound {
        extension_id: "ext-missing".into(),
    };
    let card_err: TrustCardError = graph_err.into();
    assert!(matches!(card_err, TrustCardError::GraphError { .. }));
    assert!(card_err.to_string().contains("ext-missing"));
}

#[test]
fn risk_trend_ordering() {
    assert!(RiskTrend::Improving < RiskTrend::Stable);
    assert!(RiskTrend::Stable < RiskTrend::Degrading);
}

#[test]
fn recommended_action_ordering() {
    assert!(RecommendedAction::Monitor < RecommendedAction::Review);
    assert!(RecommendedAction::Review < RecommendedAction::Restrict);
    assert!(RecommendedAction::Restrict < RecommendedAction::Remove);
}

#[test]
fn multiple_evidence_types_classified_correctly() {
    let mut graph = test_graph_with_extension();
    // Positive types
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-p1", EvidenceType::ProvenanceAttestation),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-p2", EvidenceType::OperatorAssessment),
        )
        .unwrap();
    // Negative types
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-n1", EvidenceType::IncidentRecord),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-n2", EvidenceType::ThreatIntelligence),
        )
        .unwrap();
    // Neutral types
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-u1", EvidenceType::BehavioralObservation),
        )
        .unwrap();
    graph
        .add_evidence(
            "ext-1",
            test_evidence("ev-u2", EvidenceType::AdversarialCampaignResult),
        )
        .unwrap();
    graph
        .add_evidence("ext-1", test_evidence("ev-u3", EvidenceType::FleetEvidence))
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.evidence.positive_count, 2);
    assert_eq!(card.evidence.negative_count, 2);
    assert_eq!(card.evidence.neutral_count, 3);
}

#[test]
fn card_with_all_trust_levels() {
    let levels = [
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        TrustLevel::Established,
        TrustLevel::Trusted,
        TrustLevel::Suspicious,
        TrustLevel::Compromised,
        TrustLevel::Revoked,
    ];

    for level in &levels {
        let mut graph = ReputationGraph::new();
        graph.register_publisher(test_publisher("pub-1"));
        let mut ext = test_extension("ext-1", "pub-1");
        ext.current_trust_level = *level;
        graph.register_extension(ext).unwrap();

        let generator = TrustCardGenerator::new();
        let card = generator
            .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
            .unwrap();

        assert_eq!(card.current_trust_level, *level);
    }
}
