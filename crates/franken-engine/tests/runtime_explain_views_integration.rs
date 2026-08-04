//! Integration coverage for the derived explain views (E3.T4, `bd-fqlfw.3.4`).
//!
//! Drives the public `runtime_explain_views` API that backs
//! `frankenctl explain --emit-bundle` against a `RuntimeExplainBundle` built
//! through the public index builder, locking the public surface and the
//! end-to-end shape (narrative "why" story, per-decision source links,
//! deterministic repro.lock). Per-function unit tests live alongside the module.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_explain_bundle::{
    RuntimeArtifactKind, RuntimeArtifactRef, RuntimeExplainBundle, RuntimeExplainBundleBuilder,
    RuntimeExplainLink, RuntimeExplainRelation, RuntimeExplainRole, StableArtifactRef,
};
use frankenengine_engine::runtime_explain_views::{
    EXPLAIN_META_CHOSEN_ACTION, EXPLAIN_META_LANE, EXPLAIN_META_SOURCE_SPAN, EvidenceCategory,
    build_evidence_graph, build_explain_bundle,
};

/// A small index: source -> action (DerivedFrom), action -> containment
/// (ProducesContainment). The action carries the "why" metadata + a span.
fn quarantine_bundle() -> RuntimeExplainBundle {
    let source = RuntimeArtifactRef::new(
        "source",
        RuntimeArtifactKind::Other {
            schema_id: "franken-engine.frankenctl.run-source.v1".to_string(),
        },
        ContentHash::compute(b"fetch('http://evil')\n"),
        StableArtifactRef::new("source_file", "ext.js"),
    )
    .with_schema_id("franken-engine.frankenctl.run-source.v1");

    let action = RuntimeArtifactRef::new(
        "action-decision",
        RuntimeArtifactKind::ChosenAction,
        ContentHash::compute(b"quarantine"),
        StableArtifactRef::new("execution_orchestrator", "decision-9").with_revision("trace-9"),
    )
    .with_role(RuntimeExplainRole::ChosenAction)
    .with_metadata(EXPLAIN_META_CHOSEN_ACTION, "quarantine")
    .with_metadata(EXPLAIN_META_LANE, "adaptive")
    .with_metadata(EXPLAIN_META_SOURCE_SPAN, "L1:1");

    let containment = RuntimeArtifactRef::new(
        "containment-receipt",
        RuntimeArtifactKind::ContainmentReceipt,
        ContentHash::compute(b"receipt"),
        StableArtifactRef::new("containment_executor", "decision-9"),
    )
    .with_role(RuntimeExplainRole::ContainmentReceipt);

    RuntimeExplainBundleBuilder::new("trace-9")
        .with_source_revision("0.1.0")
        .with_metadata("command", "frankenctl run")
        .with_metadata("extension_id", "evil-ext")
        .with_metadata("parse_goal", "module")
        .add_artifact(source)
        .unwrap()
        .add_artifact(action)
        .unwrap()
        .add_artifact(containment)
        .unwrap()
        .add_link(RuntimeExplainLink::new(
            "source-to-action",
            "source",
            "action-decision",
            RuntimeExplainRelation::DerivedFrom,
        ))
        .add_link(RuntimeExplainLink::new(
            "action-to-containment",
            "action-decision",
            "containment-receipt",
            RuntimeExplainRelation::ProducesContainment,
        ))
        .build()
}

#[test]
fn emit_bundle_tells_quarantine_story_with_source_links() {
    let bundle = quarantine_bundle();
    let views = build_explain_bundle(&bundle);

    // explain.md narrates the quarantine "why" story.
    assert!(views.explain_md.contains("chose **quarantine**"));
    assert!(views.explain_md.contains("source_file:ext.js"));
    assert!(views.explain_md.contains("@ L1:1"));

    // evidence_graph categorizes nodes and links the containment receipt back to
    // the source (transitively through the action).
    let receipt = views
        .evidence_graph
        .nodes
        .iter()
        .find(|n| n.id == "containment-receipt")
        .expect("receipt node present");
    assert_eq!(receipt.category, EvidenceCategory::Receipt);
    assert_eq!(
        receipt.source_link.as_ref().map(|l| l.stable_ref.as_str()),
        Some("source_file:ext.js")
    );

    // replay/counterfactual views present with honest "absent" notes.
    assert_eq!(views.replay.modes, vec!["strict", "validate"]);
    assert!(views.replay.indexed_replay_artifacts.is_empty());
    assert!(
        views
            .counterfactuals
            .indexed_counterfactual_artifacts
            .is_empty()
    );

    // repro.lock covers every artifact and content-addresses the index.
    assert_eq!(views.repro_lock.artifacts.len(), bundle.artifacts.len());
    assert_eq!(
        views.repro_lock.bundle_content_hash,
        bundle.content_hash().to_string()
    );

    // commands.txt references the indexed source.
    assert!(views.commands_txt.contains("frankenctl run --input ext.js"));
}

#[test]
fn views_are_a_pure_function_of_the_index() {
    let bundle = quarantine_bundle();
    let first = build_explain_bundle(&bundle);
    let second = build_explain_bundle(&bundle);
    assert_eq!(first, second);

    // The evidence graph alone is also deterministic and serializes stably.
    let g1 = serde_json::to_string(&build_evidence_graph(&bundle)).unwrap();
    let g2 = serde_json::to_string(&build_evidence_graph(&bundle)).unwrap();
    assert_eq!(g1, g2);
}
