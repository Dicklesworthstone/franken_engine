use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_explain_bundle::{
    RuntimeArtifactCatalog, RuntimeArtifactKind, RuntimeArtifactRef, RuntimeExplainBundleBuilder,
    RuntimeExplainDiagnostic, RuntimeExplainLink, RuntimeExplainLinkEndpoint,
    RuntimeExplainRelation, RuntimeExplainRole, StableArtifactRef,
};

fn artifact(
    artifact_id: &str,
    kind: RuntimeArtifactKind,
    stable_key: &str,
    bytes: &[u8],
    roles: impl IntoIterator<Item = RuntimeExplainRole>,
) -> RuntimeArtifactRef {
    RuntimeArtifactRef::new(
        artifact_id,
        kind,
        ContentHash::compute(bytes),
        StableArtifactRef::new("test-store", stable_key).with_revision("run-7"),
    )
    .with_producer("runtime-explain-test")
    .with_logical_epoch(7)
    .with_roles(roles)
}

fn sample_bundle_artifacts() -> Vec<RuntimeArtifactRef> {
    vec![
        artifact(
            "parse",
            RuntimeArtifactKind::ParseEventIrHash,
            "parse-event",
            b"parse",
            [RuntimeExplainRole::ParseEventIrHash],
        ),
        artifact(
            "ir0",
            RuntimeArtifactKind::Ir0Module,
            "ir0",
            b"ir0",
            [RuntimeExplainRole::Ir0Hash],
        ),
        artifact(
            "ir1",
            RuntimeArtifactKind::Ir1Module,
            "ir1",
            b"ir1",
            [RuntimeExplainRole::Ir1Hash],
        ),
        artifact(
            "ir2",
            RuntimeArtifactKind::Ir2Module,
            "ir2",
            b"ir2",
            [RuntimeExplainRole::Ir2Hash],
        ),
        artifact(
            "ir3",
            RuntimeArtifactKind::Ir3ExecIr,
            "ir3",
            b"ir3",
            [RuntimeExplainRole::Ir3Hash],
        ),
        artifact(
            "cap-req",
            RuntimeArtifactKind::CapabilityRequest,
            "capability-request",
            b"capability-request",
            [RuntimeExplainRole::CapabilityRequest],
        ),
        artifact(
            "cap-grant",
            RuntimeArtifactKind::CapabilityGrant,
            "capability-grant",
            b"capability-grant",
            [RuntimeExplainRole::CapabilityGrant],
        ),
        artifact(
            "ifc",
            RuntimeArtifactKind::IfcDecision,
            "ifc-decision",
            b"ifc-decision",
            [RuntimeExplainRole::IfcDecision],
        ),
        artifact(
            "posterior",
            RuntimeArtifactKind::GuardplanePosterior,
            "posterior",
            b"posterior",
            [RuntimeExplainRole::GuardplanePosterior],
        ),
        artifact(
            "eprocess",
            RuntimeArtifactKind::EProcessState,
            "eprocess",
            b"eprocess",
            [RuntimeExplainRole::EProcessState],
        ),
        artifact(
            "expected-loss",
            RuntimeArtifactKind::ExpectedLoss,
            "expected-loss",
            b"expected-loss",
            [RuntimeExplainRole::ExpectedLoss],
        ),
        artifact(
            "chosen-action",
            RuntimeArtifactKind::ChosenAction,
            "chosen-action",
            b"chosen-action",
            [RuntimeExplainRole::ChosenAction],
        ),
        artifact(
            "containment",
            RuntimeArtifactKind::ContainmentReceipt,
            "containment",
            b"containment",
            [RuntimeExplainRole::ContainmentReceipt],
        ),
        artifact(
            "evidence",
            RuntimeArtifactKind::EvidenceEntry,
            "evidence",
            b"evidence",
            [RuntimeExplainRole::EvidenceEntry],
        ),
        artifact(
            "replay",
            RuntimeArtifactKind::ReplayStatus,
            "replay",
            b"replay",
            [RuntimeExplainRole::ReplayStatus],
        ),
        artifact(
            "counterfactual",
            RuntimeArtifactKind::CounterfactualStatus,
            "counterfactual",
            b"counterfactual",
            [RuntimeExplainRole::CounterfactualStatus],
        ),
    ]
}

#[test]
fn runtime_explain_bundle_resolves_existing_artifacts() {
    let artifacts = sample_bundle_artifacts();
    let catalog = RuntimeArtifactCatalog::from_artifacts(artifacts.clone());
    let mut builder = RuntimeExplainBundleBuilder::new("run-7").with_source_revision("rev-a");

    for role in [
        RuntimeExplainRole::ParseEventIrHash,
        RuntimeExplainRole::Ir0Hash,
        RuntimeExplainRole::Ir1Hash,
        RuntimeExplainRole::Ir2Hash,
        RuntimeExplainRole::Ir3Hash,
        RuntimeExplainRole::CapabilityRequest,
        RuntimeExplainRole::CapabilityGrant,
        RuntimeExplainRole::IfcDecision,
        RuntimeExplainRole::GuardplanePosterior,
        RuntimeExplainRole::EProcessState,
        RuntimeExplainRole::ExpectedLoss,
        RuntimeExplainRole::ChosenAction,
        RuntimeExplainRole::ContainmentReceipt,
        RuntimeExplainRole::EvidenceEntry,
        RuntimeExplainRole::ReplayStatus,
        RuntimeExplainRole::CounterfactualStatus,
    ] {
        builder = builder.require_role(role);
    }

    for artifact in artifacts {
        builder = builder.add_artifact(artifact).unwrap();
    }

    let bundle = builder
        .add_link(RuntimeExplainLink::new(
            "parse-to-ir0",
            "parse",
            "ir0",
            RuntimeExplainRelation::DerivedFrom,
        ))
        .add_link(RuntimeExplainLink::new(
            "posterior-to-action",
            "posterior",
            "chosen-action",
            RuntimeExplainRelation::SelectsAction,
        ))
        .add_link(RuntimeExplainLink::new(
            "action-to-containment",
            "chosen-action",
            "containment",
            RuntimeExplainRelation::ProducesContainment,
        ))
        .build();

    let report = bundle.validate(&catalog);

    assert!(report.is_valid(), "{:?}", report.diagnostics);
    assert_eq!(report.resolved_artifact_count, 16);
    assert_eq!(bundle.content_hash(), bundle.content_hash());
}

#[test]
fn runtime_explain_bundle_flags_missing_and_stale_links_without_inventing_artifacts() {
    let ir0 = artifact(
        "ir0",
        RuntimeArtifactKind::Ir0Module,
        "ir0",
        b"ir0",
        [RuntimeExplainRole::Ir0Hash],
    );
    let stale_ir0 = artifact(
        "ir0",
        RuntimeArtifactKind::Ir0Module,
        "ir0",
        b"changed-ir0",
        [RuntimeExplainRole::Ir0Hash],
    );

    let bundle = RuntimeExplainBundleBuilder::new("run-8")
        .require_role(RuntimeExplainRole::Ir0Hash)
        .require_role(RuntimeExplainRole::CounterfactualStatus)
        .add_artifact(ir0)
        .unwrap()
        .build();
    let catalog = RuntimeArtifactCatalog::from_artifacts([stale_ir0]);

    let report = bundle.validate(&catalog);

    assert!(!report.is_valid());
    assert_eq!(bundle.artifacts.len(), 1);
    assert!(!bundle.artifacts.contains_key("counterfactual"));
    assert!(report.diagnostics.iter().any(|diagnostic| matches!(
        diagnostic,
        RuntimeExplainDiagnostic::MissingRequiredRole {
            role: RuntimeExplainRole::CounterfactualStatus
        }
    )));
    assert!(report.diagnostics.iter().any(|diagnostic| matches!(
        diagnostic,
        RuntimeExplainDiagnostic::StaleArtifactHash { artifact_id, .. }
            if artifact_id == "ir0"
    )));
}

#[test]
fn runtime_explain_bundle_flags_unknown_link_endpoints() {
    let ir3 = artifact(
        "ir3",
        RuntimeArtifactKind::Ir3ExecIr,
        "ir3",
        b"ir3",
        [RuntimeExplainRole::Ir3Hash],
    );
    let catalog = RuntimeArtifactCatalog::from_artifacts([ir3.clone()]);
    let bundle = RuntimeExplainBundleBuilder::new("run-9")
        .require_role(RuntimeExplainRole::Ir3Hash)
        .add_artifact(ir3)
        .unwrap()
        .add_link(RuntimeExplainLink::new(
            "ir3-to-replay",
            "ir3",
            "missing-replay",
            RuntimeExplainRelation::ReplayChecks,
        ))
        .build();

    let report = bundle.validate(&catalog);

    assert!(!report.is_valid());
    assert!(report.diagnostics.iter().any(|diagnostic| matches!(
        diagnostic,
        RuntimeExplainDiagnostic::MissingLinkEndpoint {
            link_id,
            endpoint: RuntimeExplainLinkEndpoint::To,
            artifact_id,
        } if link_id == "ir3-to-replay" && artifact_id == "missing-replay"
    )));
}
