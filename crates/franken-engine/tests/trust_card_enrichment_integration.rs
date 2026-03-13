#![forbid(unsafe_code)]
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
    EvidenceNode, EvidenceSource, EvidenceType, ExtensionNode, ProvenanceRecord, PublisherNode,
    ReputationGraph, ReputationGraphError, TrustLevel, TrustTransition,
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
// A. BTreeSet dedup and ordering for enum types
// =========================================================================

#[test]
fn enrichment_risk_trend_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(RiskTrend::Improving);
    set.insert(RiskTrend::Stable);
    set.insert(RiskTrend::Degrading);
    set.insert(RiskTrend::Improving); // dup
    set.insert(RiskTrend::Stable); // dup
    assert_eq!(set.len(), 3);
    let vals: Vec<_> = set.into_iter().collect();
    assert_eq!(vals[0], RiskTrend::Improving);
    assert_eq!(vals[2], RiskTrend::Degrading);
}

#[test]
fn enrichment_recommended_action_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(RecommendedAction::Remove);
    set.insert(RecommendedAction::Monitor);
    set.insert(RecommendedAction::Restrict);
    set.insert(RecommendedAction::Review);
    set.insert(RecommendedAction::Monitor); // dup
    assert_eq!(set.len(), 4);
    let vals: Vec<_> = set.into_iter().collect();
    assert_eq!(vals[0], RecommendedAction::Monitor);
    assert_eq!(vals[3], RecommendedAction::Remove);
}

#[test]
fn enrichment_card_format_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(CardFormat::Compact);
    set.insert(CardFormat::Json);
    set.insert(CardFormat::Text);
    set.insert(CardFormat::Json); // dup
    assert_eq!(set.len(), 3);
    let vals: Vec<_> = set.into_iter().collect();
    assert_eq!(vals[0], CardFormat::Json);
    assert_eq!(vals[2], CardFormat::Compact);
}

// =========================================================================
// B. Hash consistency via collections
// =========================================================================

#[test]
fn enrichment_risk_trend_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    RiskTrend::Degrading.hash(&mut h1);
    RiskTrend::Degrading.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());
}

#[test]
fn enrichment_recommended_action_hash_differs() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    RecommendedAction::Monitor.hash(&mut h1);
    RecommendedAction::Remove.hash(&mut h2);
    assert_ne!(h1.finish(), h2.finish());
}

// =========================================================================
// C. Display distinctness for all enum variants
// =========================================================================

#[test]
fn enrichment_risk_trend_display_distinct() {
    let displays: BTreeSet<String> = [
        RiskTrend::Improving,
        RiskTrend::Stable,
        RiskTrend::Degrading,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_recommended_action_display_distinct() {
    let displays: BTreeSet<String> = [
        RecommendedAction::Monitor,
        RecommendedAction::Review,
        RecommendedAction::Restrict,
        RecommendedAction::Remove,
    ]
    .iter()
    .map(|v| v.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// D. Clone independence
// =========================================================================

#[test]
fn enrichment_trust_card_clone_independence() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    let mut cloned = card.clone();
    cloned.risk_score = 99;
    assert_ne!(card.risk_score, cloned.risk_score);
    assert_eq!(card.extension_id, cloned.extension_id);
}

#[test]
fn enrichment_trust_card_diff_clone_independence() {
    let diff = TrustCardDiff::compute(
        &make_card(TrustLevel::Unknown, 30),
        &make_card(TrustLevel::Suspicious, 60),
    );
    let mut cloned = diff.clone();
    cloned.risk_score_delta = 0;
    assert_ne!(diff.risk_score_delta, cloned.risk_score_delta);
}

fn make_card(level: TrustLevel, risk: u32) -> TrustCard {
    TrustCard {
        extension_id: "ext-c".into(),
        package_name: "pkg-c".into(),
        version: "1.0.0".into(),
        current_trust_level: level,
        trust_level_since_ns: 1_000,
        publisher_trust_score: None,
        risk_score: risk,
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
    }
}

// =========================================================================
// E. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", RiskTrend::Improving).is_empty());
    assert!(!format!("{:?}", RecommendedAction::Restrict).is_empty());
    assert!(!format!("{:?}", CardFormat::Text).is_empty());
    assert!(
        !format!(
            "{:?}",
            TrustCardError::ExtensionNotFound {
                extension_id: "x".into()
            }
        )
        .is_empty()
    );
    assert!(
        !format!(
            "{:?}",
            RiskDriver {
                description: "d".into(),
                contribution: 5
            }
        )
        .is_empty()
    );
    assert!(!format!("{:?}", GeneratorConfig::default()).is_empty());
    assert!(!format!("{:?}", TrustCardGenerator::new()).is_empty());
    assert!(!format!("{:?}", TrustCardCache::new()).is_empty());
    assert!(!format!("{:?}", UpdatePipeline::new()).is_empty());
}

// =========================================================================
// F. TrustCardCache serde roundtrip
// =========================================================================

#[test]
fn enrichment_trust_card_cache_serde_roundtrip() {
    let cache = TrustCardCache::new();
    let json = serde_json::to_string(&cache).unwrap();
    let back: TrustCardCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cached_count(), 0);
}

#[test]
fn enrichment_trust_card_cache_with_entries_serde() {
    let mut cache = TrustCardCache::new();
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, 10_000_000_000)
        .unwrap();
    let json = serde_json::to_string(&cache).unwrap();
    let back: TrustCardCache = serde_json::from_str(&json).unwrap();
    assert_eq!(back.cached_count(), 1);
}

// =========================================================================
// G. UpdatePipeline serde roundtrip
// =========================================================================

#[test]
fn enrichment_update_pipeline_serde_roundtrip() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-a");
    pipeline.subscribe("ext-b");
    let tt = make_transition(
        "ext-a",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        vec!["ev-1".into()],
        false,
        None,
        5_000,
    );
    pipeline.on_trust_transition(&tt);
    let json = serde_json::to_string(&pipeline).unwrap();
    let back: UpdatePipeline = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pending_count(), 1);
    assert_eq!(back.subscription_count(), 2);
}

// =========================================================================
// H. TrustCardGenerator serde roundtrip
// =========================================================================

#[test]
fn enrichment_trust_card_generator_serde_roundtrip() {
    let generator = TrustCardGenerator::with_config(GeneratorConfig {
        max_history_entries: 5,
        max_risk_drivers: 2,
        trend_window_ns: 3_600_000_000_000,
    });
    let json = serde_json::to_string(&generator).unwrap();
    let back: TrustCardGenerator = serde_json::from_str(&json).unwrap();
    // Verify it still works by generating a card.
    let graph = test_graph_with_extension();
    let card = back
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();
    assert!(card.risk_drivers.len() <= 2);
}

// =========================================================================
// I. Suspicious with high risk → Restrict vs low → Review
// =========================================================================

#[test]
fn enrichment_suspicious_high_risk_restrict() {
    // Suspicious + many negative evidence = high risk score → Restrict.
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
    // Add many negative evidence items to push risk score high.
    for i in 0..5 {
        graph
            .add_evidence(
                "ext-1",
                test_evidence(&format!("ev-neg-{i}"), EvidenceType::IncidentRecord),
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

    // With Suspicious + high risk score >= 60, recommendation should be Restrict.
    if card.risk_score >= 60 {
        assert_eq!(card.recommendation.action, RecommendedAction::Restrict);
    } else {
        assert_eq!(card.recommendation.action, RecommendedAction::Review);
    }
}

// =========================================================================
// J. Provisional with good provenance → Monitor
// =========================================================================

#[test]
fn enrichment_provisional_with_provenance_monitor() {
    let mut graph = test_graph_with_provenance();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
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

    // Provisional + verified publisher + no gap = Monitor.
    assert_eq!(card.recommendation.action, RecommendedAction::Monitor);
    assert!(card.recommendation.confidence >= 500_000);
}

// =========================================================================
// K. Risk score capping with many drivers
// =========================================================================

#[test]
fn enrichment_risk_score_sum_capped_at_100() {
    let mut graph = ReputationGraph::new();
    graph.register_publisher(test_publisher("pub-1"));
    let mut ext = test_extension("ext-1", "pub-1");
    ext.current_trust_level = TrustLevel::Revoked;
    graph.register_extension(ext).unwrap();
    // Many negative evidence items.
    for i in 0..10 {
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
    // Revoked + unverified + unattested + gap + negative evidence = should hit cap.
    assert_eq!(card.risk_score, 100);
}

// =========================================================================
// L. Risk trend balanced transitions → Stable
// =========================================================================

#[test]
fn enrichment_risk_trend_balanced_stable() {
    let mut graph = test_graph_with_extension();
    // Upgrade then downgrade within window → balanced = Stable.
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
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Suspicious,
            vec!["ev-bad".into()],
            1,
            SecurityEpoch::from_raw(1),
            9_500_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    // One improvement + one degradation = balanced = Stable.
    assert_eq!(card.risk_trend, RiskTrend::Stable);
}

// =========================================================================
// M. TrustCard Display with history and risk drivers
// =========================================================================

#[test]
fn enrichment_trust_card_display_with_drivers() {
    let card = TrustCard {
        risk_drivers: vec![
            RiskDriver {
                description: "unverified publisher identity".into(),
                contribution: 20,
            },
            RiskDriver {
                description: "provenance gap in supply chain".into(),
                contribution: 10,
            },
        ],
        ..make_card(TrustLevel::Unknown, 30)
    };

    let display = card.to_string();
    assert!(display.contains("+20"));
    assert!(display.contains("unverified publisher identity"));
    assert!(display.contains("+10"));
    assert!(display.contains("provenance gap"));
}

#[test]
fn enrichment_trust_card_display_with_history() {
    let mut graph = test_graph_with_extension();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Provisional,
            vec!["ev-1".into()],
            1,
            SecurityEpoch::from_raw(1),
            5_000_000_000,
        )
        .unwrap();
    graph
        .transition_trust(
            "ext-1",
            TrustLevel::Established,
            vec!["ev-2".into()],
            1,
            SecurityEpoch::from_raw(1),
            6_000_000_000,
        )
        .unwrap();

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.history.len(), 2);
    assert_eq!(card.history[0].new_level, TrustLevel::Established);
}

// =========================================================================
// N. UpdateNotification Display structure
// =========================================================================

#[test]
fn enrichment_notification_display_structure() {
    let notif = UpdateNotification {
        extension_id: "ext-99".into(),
        old_level: TrustLevel::Trusted,
        new_level: TrustLevel::Compromised,
        triggering_evidence_summary: "ev-x, ev-y".into(),
        timestamp_ns: 42_000,
    };
    let display = notif.to_string();
    assert!(display.contains("ext-99"));
    assert!(display.contains("trusted"));
    assert!(display.contains("compromised"));
    assert!(display.contains("ev-x, ev-y"));
}

// =========================================================================
// O. Diff with only risk change (same trust level)
// =========================================================================

#[test]
fn enrichment_diff_only_risk_change() {
    let card_a = make_card(TrustLevel::Unknown, 20);
    let card_b = TrustCard {
        risk_score: 40,
        ..card_a.clone()
    };
    let diff = TrustCardDiff::compute(&card_a, &card_b);
    assert_eq!(diff.risk_score_delta, 20);
    assert!(diff.change_summary.contains("risk:"));
    assert!(!diff.change_summary.contains("trust:"));
}

#[test]
fn enrichment_diff_negative_risk_delta() {
    let card_a = make_card(TrustLevel::Suspicious, 60);
    let card_b = TrustCard {
        risk_score: 30,
        ..card_a.clone()
    };
    let diff = TrustCardDiff::compute(&card_a, &card_b);
    assert_eq!(diff.risk_score_delta, -30);
}

// =========================================================================
// P. Cache staleness edge cases
// =========================================================================

#[test]
fn enrichment_cache_just_within_staleness() {
    let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000);
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    // Just within staleness boundary.
    let card = cache.get("ext-1", &graph, now + 999_999_999);
    assert!(card.is_some(), "should still be cached within staleness");
}

#[test]
fn enrichment_cache_exactly_at_staleness() {
    let mut cache = TrustCardCache::with_max_staleness_ns(1_000_000_000);
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let epoch = SecurityEpoch::from_raw(1);
    let now = 10_000_000_000u64;

    cache
        .get_or_generate(&generator, &graph, "ext-1", epoch, now)
        .unwrap();

    // Exactly at staleness boundary.
    let card = cache.get("ext-1", &graph, now + 1_000_000_000);
    assert!(card.is_some(), "boundary should be inclusive");
}

// =========================================================================
// Q. Pipeline with multiple subscriptions
// =========================================================================

#[test]
fn enrichment_pipeline_multi_subscribe_mixed() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");
    pipeline.subscribe("ext-3");

    let tt1 = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        vec![],
        false,
        None,
        1_000,
    );
    let tt2 = make_transition(
        "ext-2",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec![],
        false,
        None,
        2_000,
    );
    let tt3 = make_transition(
        "ext-3",
        TrustLevel::Unknown,
        TrustLevel::Established,
        vec![],
        false,
        None,
        3_000,
    );

    pipeline.on_trust_transition(&tt1);
    pipeline.on_trust_transition(&tt2);
    pipeline.on_trust_transition(&tt3);

    // ext-2 not subscribed, so only ext-1 and ext-3.
    assert_eq!(pipeline.pending_count(), 2);
    let notifications = pipeline.drain_notifications();
    assert_eq!(notifications[0].extension_id, "ext-1");
    assert_eq!(notifications[1].extension_id, "ext-3");
}

// =========================================================================
// R. Pipeline notification with evidence IDs joined
// =========================================================================

#[test]
fn enrichment_pipeline_notification_with_evidence_ids() {
    let mut pipeline = UpdatePipeline::new();
    let tt = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Suspicious,
        vec!["ev-a".into(), "ev-b".into(), "ev-c".into()],
        false,
        None,
        5_000,
    );
    pipeline.on_trust_transition(&tt);
    let notifications = pipeline.drain_notifications();
    assert_eq!(
        notifications[0].triggering_evidence_summary,
        "ev-a, ev-b, ev-c"
    );
}

// =========================================================================
// S. Evidence summary with only negative evidence
// =========================================================================

#[test]
fn enrichment_evidence_all_negative() {
    let mut graph = test_graph_with_extension();
    for i in 0..4 {
        graph
            .add_evidence(
                "ext-1",
                test_evidence(&format!("ev-n{i}"), EvidenceType::IncidentRecord),
            )
            .unwrap();
    }

    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    assert_eq!(card.evidence.positive_count, 0);
    assert_eq!(card.evidence.negative_count, 4);
    assert_eq!(card.evidence.neutral_count, 0);
}

// =========================================================================
// T. Compact format content
// =========================================================================

#[test]
fn enrichment_compact_format_pipe_separated() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let compact = TrustCardGenerator::format_card(&card, CardFormat::Compact);
    assert!(compact.contains(" | "));
    assert!(compact.contains("pkg-ext-1"));
    assert!(compact.contains("v1.0.0"));
    assert!(compact.contains("/100"));
    assert!(compact.contains("unknown"));
}

// =========================================================================
// U. From<ReputationGraphError> for TrustCardError
// =========================================================================

#[test]
fn enrichment_from_graph_error_preserves_message() {
    let graph_err = ReputationGraphError::ExtensionNotFound {
        extension_id: "ext-gone".into(),
    };
    let card_err: TrustCardError = graph_err.into();
    let msg = card_err.to_string();
    assert!(msg.contains("ext-gone"));
    assert!(matches!(card_err, TrustCardError::GraphError { .. }));
}

// =========================================================================
// V. TrustCardDiff Debug nonempty
// =========================================================================

#[test]
fn enrichment_trust_card_diff_debug_nonempty() {
    let diff = TrustCardDiff::compute(
        &make_card(TrustLevel::Unknown, 30),
        &make_card(TrustLevel::Unknown, 30),
    );
    let debug = format!("{diff:?}");
    assert!(!debug.is_empty());
    assert!(debug.contains("TrustCardDiff"));
}

// =========================================================================
// W. History entry reason with empty evidence list
// =========================================================================

#[test]
fn enrichment_history_entry_empty_evidence_list() {
    let tt = make_transition(
        "ext-1",
        TrustLevel::Unknown,
        TrustLevel::Provisional,
        vec![],
        false,
        None,
        5_000,
    );
    let entry = TrustHistoryEntry::from(&tt);
    assert_eq!(entry.reason, "evidence: ");
    assert!(!entry.operator_override);
}

// =========================================================================
// X. Cache multiple extensions, invalidate one
// =========================================================================

#[test]
fn enrichment_cache_invalidate_one_preserves_others() {
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

    cache.invalidate("ext-1");
    assert_eq!(cache.cached_count(), 1);
    assert!(cache.get("ext-1", &graph, now + 1).is_none());
    assert!(cache.get("ext-2", &graph, now + 1).is_some());
}

// =========================================================================
// Y. TrustHistoryEntry Clone independence
// =========================================================================

#[test]
fn enrichment_history_entry_clone_independence() {
    let entry = TrustHistoryEntry {
        old_level: TrustLevel::Unknown,
        new_level: TrustLevel::Provisional,
        reason: "evidence: ev-1".into(),
        timestamp_ns: 5_000,
        operator_override: false,
    };
    let mut cloned = entry.clone();
    cloned.reason = "mutated".into();
    assert_ne!(entry.reason, cloned.reason);
    assert_eq!(entry.old_level, cloned.old_level);
}

// =========================================================================
// Z. Recommendation Clone independence
// =========================================================================

#[test]
fn enrichment_recommendation_clone_independence() {
    let rec = Recommendation {
        action: RecommendedAction::Monitor,
        confidence: 800_000,
        rationale: "healthy extension".into(),
    };
    let mut cloned = rec.clone();
    cloned.confidence = 100_000;
    assert_ne!(rec.confidence, cloned.confidence);
    assert_eq!(rec.action, cloned.action);
}

// =========================================================================
// AA. Diff detects only recommendation change
// =========================================================================

#[test]
fn enrichment_diff_only_recommendation_change() {
    let card_a = make_card(TrustLevel::Unknown, 30);
    let card_b = TrustCard {
        recommendation: Recommendation {
            action: RecommendedAction::Restrict,
            confidence: 700_000,
            rationale: "restricted".into(),
        },
        ..card_a.clone()
    };
    let diff = TrustCardDiff::compute(&card_a, &card_b);
    assert!(diff.change_summary.contains("recommendation:"));
    assert!(!diff.change_summary.contains("trust:"));
    assert!(!diff.change_summary.contains("risk:"));
}

// =========================================================================
// AB. Diff with all three changes
// =========================================================================

#[test]
fn enrichment_diff_trust_risk_recommendation_all_change() {
    let card_a = make_card(TrustLevel::Unknown, 30);
    let card_b = TrustCard {
        current_trust_level: TrustLevel::Compromised,
        risk_score: 80,
        recommendation: Recommendation {
            action: RecommendedAction::Remove,
            confidence: 850_000,
            rationale: "compromised".into(),
        },
        ..card_a.clone()
    };
    let diff = TrustCardDiff::compute(&card_a, &card_b);
    assert!(diff.change_summary.contains("trust:"));
    assert!(diff.change_summary.contains("risk:"));
    assert!(diff.change_summary.contains("recommendation:"));
    assert_eq!(diff.risk_score_delta, 50);
}

// =========================================================================
// AC. Pipeline unsubscribe nonexistent is noop
// =========================================================================

#[test]
fn enrichment_pipeline_unsubscribe_nonexistent_noop() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");
    pipeline.unsubscribe("ext-999"); // not subscribed
    assert_eq!(pipeline.subscription_count(), 1);
}

// =========================================================================
// AD. Pipeline double subscribe dedup
// =========================================================================

#[test]
fn enrichment_pipeline_double_subscribe_dedup() {
    let mut pipeline = UpdatePipeline::new();
    pipeline.subscribe("ext-1");
    pipeline.subscribe("ext-1"); // duplicate
    assert_eq!(pipeline.subscription_count(), 1);
}

// =========================================================================
// AE. Card generated_at_ns equals now_ns
// =========================================================================

#[test]
fn enrichment_card_generated_at_ns_equals_now() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let now = 42_000_000_000u64;
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(3), now)
        .unwrap();
    assert_eq!(card.generated_at_ns, now);
    assert_eq!(card.epoch, SecurityEpoch::from_raw(3));
}

// =========================================================================
// AF. Negative evidence driver contribution capped at 30
// =========================================================================

#[test]
fn enrichment_negative_evidence_driver_capped() {
    let mut graph = test_graph_with_extension();
    // Add 10 negative evidence items → contribution = min(10*10, 30) = 30.
    for i in 0..10 {
        graph
            .add_evidence(
                "ext-1",
                test_evidence(&format!("ev-n{i}"), EvidenceType::IncidentRecord),
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

    let neg_driver = card
        .risk_drivers
        .iter()
        .find(|d| d.description.contains("negative evidence"));
    assert!(neg_driver.is_some());
    assert!(neg_driver.unwrap().contribution <= 30);
}

// =========================================================================
// AG. Text format includes multiple sections
// =========================================================================

#[test]
fn enrichment_text_format_includes_sections() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let text = TrustCardGenerator::format_card(&card, CardFormat::Text);
    assert!(text.contains("ext-1"));
    assert!(text.contains("risk:"));
    assert!(text.contains("evidence:"));
    assert!(text.contains("provenance:"));
    assert!(text.contains("recommendation:"));
    assert!(text.contains("rationale:"));
}

// =========================================================================
// AH. JSON format parses back as TrustCard
// =========================================================================

#[test]
fn enrichment_json_format_round_trips() {
    let graph = test_graph_with_extension();
    let generator = TrustCardGenerator::new();
    let card = generator
        .generate(&graph, "ext-1", SecurityEpoch::from_raw(1), 10_000_000_000)
        .unwrap();

    let json_str = TrustCardGenerator::format_card(&card, CardFormat::Json);
    let restored: TrustCard = serde_json::from_str(&json_str).unwrap();
    assert_eq!(card, restored);
}
