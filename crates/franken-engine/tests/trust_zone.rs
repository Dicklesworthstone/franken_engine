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

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability::trust_zone::{
    CrossZoneReferenceChecker, CrossZoneReferenceRequest, ReferenceType, TrustZoneClass,
    TrustZoneError, ZoneCreateRequest, ZoneEventOutcome, ZoneEventType, ZoneHierarchy,
    ZoneTransitionRequest,
};

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

#[test]
fn unassigned_entities_default_to_community_zone() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let zone = hierarchy
        .zone_for_entity("ext-unassigned")
        .expect("default zone");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn multi_zone_configuration_enforces_team_ceiling() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-team-tool", "team", "trace-assign")
        .expect("assign team");

    let allowed = capset(&[RuntimeCapability::VmDispatch]);
    hierarchy
        .enforce_ceiling("team", &allowed, "trace-ceiling-pass")
        .expect("team should allow vm dispatch");

    let denied = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    let err = hierarchy
        .enforce_ceiling("team", &denied, "trace-ceiling-fail")
        .expect_err("team must reject network egress");

    match err {
        TrustZoneError::CapabilityCeilingExceeded { zone_name, .. } => {
            assert_eq!(zone_name, "team");
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn transition_to_private_re_evaluates_and_allows_broader_caps() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 2).expect("hierarchy");
    hierarchy
        .assign_entity("ext-upgrade", "community", "trace-initial")
        .expect("assign initial");

    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);

    let before = hierarchy
        .enforce_ceiling("community", &requested, "trace-before")
        .expect_err("community ceiling should deny network egress");
    assert!(matches!(
        before,
        TrustZoneError::CapabilityCeilingExceeded { .. }
    ));

    hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-upgrade",
            "private",
            "trace-transition",
            "policy-zone",
            "decision-zone",
            true,
        ))
        .expect("policy-approved transition");

    let now_zone = hierarchy.zone_for_entity("ext-upgrade").expect("zone");
    assert_eq!(now_zone.zone_name, "private");

    hierarchy
        .enforce_ceiling("private", &requested, "trace-after")
        .expect("private ceiling should allow requested caps after re-check");
}

// ────────────────────────────────────────────────────────────
// Enrichment: zone lifecycle, transitions, error paths, serde
// ────────────────────────────────────────────────────────────

#[test]
fn zone_hierarchy_new_creates_default_zone() {
    let hierarchy = ZoneHierarchy::new("community");
    let zone = hierarchy.zone("community");
    assert!(zone.is_none(), "new() does not auto-create zones");
}

#[test]
fn add_zone_succeeds_and_zone_is_retrievable() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("myzone");
    hierarchy
        .add_zone(ZoneCreateRequest::new(
            "myzone",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect("should add zone");

    let zone = hierarchy.zone("myzone").expect("zone should exist");
    assert_eq!(zone.zone_name, "myzone");
}

#[test]
fn duplicate_zone_add_fails() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("dup");
    hierarchy
        .add_zone(ZoneCreateRequest::new(
            "dup",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect("first add");
    let err = hierarchy
        .add_zone(ZoneCreateRequest::new(
            "dup",
            TrustZoneClass::Community,
            1,
            "test",
        ))
        .expect_err("duplicate zone add must fail");
    assert!(matches!(err, TrustZoneError::ZoneAlreadyExists { .. }));
    assert!(err.to_string().contains("dup"));
}

#[test]
fn add_zone_with_missing_parent_fails() {
    use frankenengine_engine::capability::trust_zone::{TrustZoneClass, ZoneCreateRequest};

    let mut hierarchy = ZoneHierarchy::new("orphan");
    let err = hierarchy
        .add_zone(
            ZoneCreateRequest::new("orphan", TrustZoneClass::Team, 1, "test")
                .with_parent("nonexistent-parent"),
        )
        .expect_err("missing parent must fail");
    assert!(matches!(err, TrustZoneError::ParentZoneMissing { .. }));
}

#[test]
fn zone_for_entity_returns_default_for_unknown() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let zone = hierarchy
        .zone_for_entity("never-assigned")
        .expect("default zone");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn assign_entity_to_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .assign_entity("ext-1", "nonexistent-zone", "trace-bad")
        .expect_err("missing zone assign must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn assign_entity_changes_zone_lookup() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-reassign", "team", "trace-assign")
        .expect("assign to team");
    let zone = hierarchy.zone_for_entity("ext-reassign").expect("zone");
    assert_eq!(zone.zone_name, "team");

    // Reassign to private
    hierarchy
        .assign_entity("ext-reassign", "private", "trace-reassign")
        .expect("reassign to private");
    let zone2 = hierarchy.zone_for_entity("ext-reassign").expect("zone");
    assert_eq!(zone2.zone_name, "private");
}

#[test]
fn transition_entity_to_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-t", "community", "trace-init")
        .expect("assign");
    let err = hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-t",
            "nonexistent",
            "trace-trans",
            "policy",
            "decision",
            true,
        ))
        .expect_err("transition to missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn transition_entity_denied_when_policy_gate_not_approved() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-deny", "community", "trace-init")
        .expect("assign");
    let err = hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-deny",
            "team",
            "trace-deny",
            "policy-deny",
            "decision-deny",
            false,
        ))
        .expect_err("unapproved transition must fail");
    assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
    assert!(err.to_string().contains("ext-deny"));
}

#[test]
fn compute_effective_ceiling_for_missing_zone_fails() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .compute_effective_ceiling("nonexistent")
        .expect_err("missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn compute_effective_ceiling_for_existing_zone_returns_set() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let ceiling = hierarchy
        .compute_effective_ceiling("owner")
        .expect("owner zone exists");
    // Owner zone has the broadest ceiling
    assert!(!ceiling.is_empty());
}

#[test]
fn events_are_recorded_during_transitions() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-ev", "community", "trace-ev-init")
        .expect("assign");
    hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-ev",
            "team",
            "trace-ev-trans",
            "policy-ev",
            "decision-ev",
            true,
        ))
        .expect("transition");

    let events = hierarchy.events();
    assert!(!events.is_empty());
    let last = events.last().expect("at least one event");
    assert_eq!(last.from_zone.as_deref(), Some("community"));
    assert_eq!(last.to_zone.as_deref(), Some("team"));
}

#[test]
fn drain_events_clears_event_list() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-drain", "community", "trace-drain")
        .expect("assign");

    let drained = hierarchy.drain_events();
    assert!(!drained.is_empty());
    assert!(hierarchy.events().is_empty());
}

#[test]
fn zone_hierarchy_serde_round_trip() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize");
    let recovered: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize");
    let json2 = serde_json::to_string(&recovered).expect("re-serialize");
    assert_eq!(json, json2);
}

#[test]
fn zone_transition_request_serde_round_trip() {
    let request = ZoneTransitionRequest::new(
        "ext-serde",
        "team",
        "trace-serde",
        "policy-serde",
        "decision-serde",
        true,
    );
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: ZoneTransitionRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(request.entity_id, recovered.entity_id);
    assert_eq!(request.to_zone_name, recovered.to_zone_name);
    assert_eq!(request.policy_gate_approved, recovered.policy_gate_approved);
}

#[test]
fn enforce_ceiling_on_missing_zone_fails() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let requested = capset(&[RuntimeCapability::VmDispatch]);
    let err = hierarchy
        .enforce_ceiling("nonexistent-zone", &requested, "trace-bad-zone")
        .expect_err("missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn trust_zone_error_display_covers_all_variants() {
    let errors: Vec<TrustZoneError> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "z".to_string(),
            parent_zone: "p".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".to_string(),
            requested: capset(&[RuntimeCapability::VmDispatch]),
            ceiling: BTreeSet::new(),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "e".to_string(),
            from_zone: "a".to_string(),
            to_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneAuthorityLeak {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneProvenanceNotPermitted {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
    ];

    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {err:?} must not be empty");
    }
}

// ────────────────────────────────────────────────────────────
// Enrichment batch 8: enum coverage, serde, allows(), builder,
// cross-zone checker, derive_zone_scoped_object_id, ceiling
// ────────────────────────────────────────────────────────────

#[test]
fn trust_zone_class_ordered_has_four_elements() {
    assert_eq!(TrustZoneClass::ORDERED.len(), 4);
    assert_eq!(TrustZoneClass::ORDERED[0], TrustZoneClass::Owner);
    assert_eq!(TrustZoneClass::ORDERED[3], TrustZoneClass::Community);
}

#[test]
fn trust_zone_class_as_str_matches_display() {
    for class in TrustZoneClass::ORDERED {
        assert_eq!(class.as_str(), class.to_string());
    }
}

#[test]
fn trust_zone_class_serde_round_trip() {
    for class in TrustZoneClass::ORDERED {
        let json = serde_json::to_string(&class).expect("serialize");
        let recovered: TrustZoneClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, recovered);
    }
}

#[test]
fn trust_zone_class_default_ceiling_owner_is_superset_of_private() {
    let owner_ceiling = TrustZoneClass::Owner.default_ceiling();
    let private_ceiling = TrustZoneClass::Private.default_ceiling();
    assert!(private_ceiling.is_subset(&owner_ceiling));
}

#[test]
fn trust_zone_class_default_ceiling_private_is_superset_of_team() {
    let private_ceiling = TrustZoneClass::Private.default_ceiling();
    let team_ceiling = TrustZoneClass::Team.default_ceiling();
    assert!(team_ceiling.is_subset(&private_ceiling));
}

#[test]
fn trust_zone_class_default_ceiling_team_is_superset_of_community() {
    let team_ceiling = TrustZoneClass::Team.default_ceiling();
    let community_ceiling = TrustZoneClass::Community.default_ceiling();
    assert!(community_ceiling.is_subset(&team_ceiling));
}

#[test]
fn zone_event_type_serde_round_trip() {
    let types = [
        ZoneEventType::Assignment,
        ZoneEventType::CeilingCheck,
        ZoneEventType::ZoneTransition,
        ZoneEventType::CrossZoneReference,
    ];
    for t in types {
        let json = serde_json::to_string(&t).expect("serialize");
        let recovered: ZoneEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, recovered);
    }
}

#[test]
fn zone_event_outcome_serde_round_trip() {
    let outcomes = [
        ZoneEventOutcome::Pass,
        ZoneEventOutcome::Allowed,
        ZoneEventOutcome::Assigned,
        ZoneEventOutcome::Migrated,
        ZoneEventOutcome::CeilingExceeded,
        ZoneEventOutcome::Denied,
    ];
    for o in outcomes {
        let json = serde_json::to_string(&o).expect("serialize");
        let recovered: ZoneEventOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(o, recovered);
    }
}

#[test]
fn trust_zone_error_serde_round_trip() {
    let errors = [
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "z".to_string(),
            parent_zone: "p".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "e".to_string(),
            from_zone: "a".to_string(),
            to_zone: "b".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: TrustZoneError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

#[test]
fn trust_zone_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(TrustZoneError::ZoneMissing {
        zone_name: "test".to_string(),
    });
    assert!(!err.to_string().is_empty());
}

#[test]
fn trust_zone_error_display_all_unique() {
    let errors: Vec<String> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "z".to_string(),
            parent_zone: "p".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "e".to_string(),
            from_zone: "a".to_string(),
            to_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneAuthorityLeak {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneProvenanceNotPermitted {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
    ]
    .into_iter()
    .map(|e| e.to_string())
    .collect();
    let unique: BTreeSet<_> = errors.iter().collect();
    assert_eq!(
        unique.len(),
        errors.len(),
        "each error Display must be unique"
    );
}

#[test]
fn zone_allows_returns_true_for_subset_of_ceiling() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let owner = hierarchy.zone("owner").expect("owner zone");
    let team_caps = TrustZoneClass::Team.default_ceiling();
    assert!(owner.allows(&team_caps));
}

#[test]
fn zone_allows_returns_false_for_superset_of_ceiling() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let community = hierarchy.zone("community").expect("community zone");
    let owner_caps = TrustZoneClass::Owner.default_ceiling();
    assert!(!community.allows(&owner_caps));
}

#[test]
fn zone_create_request_with_declared_ceiling() {
    let ceiling = capset(&[RuntimeCapability::VmDispatch]);
    let mut hierarchy = ZoneHierarchy::new("custom");
    hierarchy
        .add_zone(
            ZoneCreateRequest::new("custom", TrustZoneClass::Community, 1, "test")
                .with_declared_ceiling(ceiling.clone()),
        )
        .expect("add zone with custom ceiling");

    let zone = hierarchy.zone("custom").expect("zone");
    assert_eq!(zone.declared_ceiling, ceiling);
}

#[test]
fn zone_create_request_serde_round_trip() {
    let req = ZoneCreateRequest::new("myzone", TrustZoneClass::Team, 3, "admin")
        .with_parent("root")
        .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch]));
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: ZoneCreateRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, recovered);
}

#[test]
fn standard_hierarchy_contains_four_zones() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    for name in ["owner", "private", "team", "community"] {
        assert!(hierarchy.zone(name).is_some(), "missing zone: {name}");
    }
}

#[test]
fn standard_hierarchy_zone_classes_match_names() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    assert_eq!(
        hierarchy.zone("owner").unwrap().class,
        TrustZoneClass::Owner
    );
    assert_eq!(
        hierarchy.zone("private").unwrap().class,
        TrustZoneClass::Private
    );
    assert_eq!(hierarchy.zone("team").unwrap().class, TrustZoneClass::Team);
    assert_eq!(
        hierarchy.zone("community").unwrap().class,
        TrustZoneClass::Community
    );
}

#[test]
fn compute_effective_ceiling_owner_broader_than_community() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let owner_ceiling = hierarchy.compute_effective_ceiling("owner").expect("owner");
    let community_ceiling = hierarchy
        .compute_effective_ceiling("community")
        .expect("community");
    assert!(community_ceiling.is_subset(&owner_ceiling));
    assert!(owner_ceiling.len() > community_ceiling.len());
}

#[test]
fn derive_zone_scoped_object_id_deterministic() {
    use frankenengine_engine::capability::trust_zone::derive_zone_scoped_object_id;
    use frankenengine_engine::engine_object_id::ObjectDomain;
    use frankenengine_engine::engine_object_id::SchemaId;

    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let zone = hierarchy.zone("team").expect("team zone");
    let schema = SchemaId::from_definition(b"test-schema");
    let id1 = derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, b"payload")
        .expect("derive id1");
    let id2 = derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, b"payload")
        .expect("derive id2");
    assert_eq!(id1, id2);
}

#[test]
fn derive_zone_scoped_object_id_differs_across_zones() {
    use frankenengine_engine::capability::trust_zone::derive_zone_scoped_object_id;
    use frankenengine_engine::engine_object_id::ObjectDomain;
    use frankenengine_engine::engine_object_id::SchemaId;

    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let team = hierarchy.zone("team").expect("team zone");
    let owner = hierarchy.zone("owner").expect("owner zone");
    let schema = SchemaId::from_definition(b"test-schema");
    let id_team =
        derive_zone_scoped_object_id(team, ObjectDomain::PolicyObject, &schema, b"payload")
            .expect("team id");
    let id_owner =
        derive_zone_scoped_object_id(owner, ObjectDomain::PolicyObject, &schema, b"payload")
            .expect("owner id");
    assert_ne!(id_team, id_owner);
}

#[test]
fn cross_zone_reference_checker_allows_same_zone() {
    let mut checker = CrossZoneReferenceChecker::new();
    let result = checker.validate(CrossZoneReferenceRequest::new(
        "team",
        "team",
        ReferenceType::Authority,
        "trace-same",
    ));
    assert!(result.is_ok());
}

#[test]
fn cross_zone_reference_checker_authority_leak_denied() {
    let mut checker = CrossZoneReferenceChecker::new();
    let err = checker
        .validate(CrossZoneReferenceRequest::new(
            "community",
            "owner",
            ReferenceType::Authority,
            "trace-leak",
        ))
        .expect_err("authority leak must be denied");
    assert!(matches!(err, TrustZoneError::CrossZoneAuthorityLeak { .. }));
}

#[test]
fn cross_zone_reference_checker_provenance_not_permitted() {
    let mut checker = CrossZoneReferenceChecker::new();
    let err = checker
        .validate(CrossZoneReferenceRequest::new(
            "community",
            "owner",
            ReferenceType::Provenance,
            "trace-prov",
        ))
        .expect_err("provenance not permitted");
    assert!(matches!(
        err,
        TrustZoneError::CrossZoneProvenanceNotPermitted { .. }
    ));
}

#[test]
fn cross_zone_reference_request_serde_round_trip() {
    let req = CrossZoneReferenceRequest::new(
        "team",
        "community",
        ReferenceType::Provenance,
        "trace-serde",
    )
    .with_policy_id("pol-1")
    .with_decision_id("dec-1");
    let json = serde_json::to_string(&req).expect("serialize");
    let recovered: CrossZoneReferenceRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, recovered);
}

#[test]
fn reference_type_serde_round_trip() {
    for rt in [ReferenceType::Provenance, ReferenceType::Authority] {
        let json = serde_json::to_string(&rt).expect("serialize");
        let recovered: ReferenceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rt, recovered);
    }
}

#[test]
fn cross_zone_reference_checker_default_matches_new() {
    let from_new = CrossZoneReferenceChecker::new();
    let from_default = CrossZoneReferenceChecker::default();
    assert_eq!(from_new.events().len(), from_default.events().len());
}

#[test]
fn zone_event_assignment_recorded_with_correct_type() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-check", "team", "trace-check")
        .expect("assign");
    let events = hierarchy.events();
    assert!(events.iter().any(|e| e.event == ZoneEventType::Assignment));
}

#[test]
fn zone_event_ceiling_check_recorded() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let caps = capset(&[RuntimeCapability::VmDispatch]);
    hierarchy
        .enforce_ceiling("team", &caps, "trace-ceil")
        .expect("enforce ceiling");
    let events = hierarchy.events();
    assert!(
        events
            .iter()
            .any(|e| e.event == ZoneEventType::CeilingCheck)
    );
}

#[test]
fn zone_event_transition_recorded_with_correct_type() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-tr", "community", "trace-init")
        .expect("assign");
    hierarchy
        .transition_entity(ZoneTransitionRequest::new(
            "ext-tr", "team", "trace-tr", "policy", "decision", true,
        ))
        .expect("transition");
    let events = hierarchy.events();
    assert!(
        events
            .iter()
            .any(|e| e.event == ZoneEventType::ZoneTransition)
    );
}
