#![forbid(unsafe_code)]
//! Integration tests for the `trust_zone` module.
//!
//! Exercises the full public API from outside the crate:
//! zone classes, hierarchy construction, capability ceilings,
//! entity assignment, zone transitions, policy gates, events,
//! scoped object IDs, and serde round-trips.

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

use frankenengine_engine::capability::{CapabilityProfile, RuntimeCapability};
use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId};
use frankenengine_engine::trust_zone::{
    TrustZone, TrustZoneClass, TrustZoneError, ZoneCreateRequest, ZoneEvent, ZoneEventOutcome,
    ZoneEventType, ZoneHierarchy, ZoneTransitionRequest, derive_zone_scoped_object_id,
};

// =========================================================================
// Helpers
// =========================================================================

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

fn standard_hierarchy() -> ZoneHierarchy {
    ZoneHierarchy::standard("test-maintainer", 1).expect("build standard hierarchy")
}

// =========================================================================
// Section 1 — TrustZoneClass
// =========================================================================

#[test]
fn trust_zone_class_display_all() {
    assert_eq!(TrustZoneClass::Owner.to_string(), "owner");
    assert_eq!(TrustZoneClass::Private.to_string(), "private");
    assert_eq!(TrustZoneClass::Team.to_string(), "team");
    assert_eq!(TrustZoneClass::Community.to_string(), "community");
}

#[test]
fn trust_zone_class_as_str() {
    assert_eq!(TrustZoneClass::Owner.as_str(), "owner");
    assert_eq!(TrustZoneClass::Private.as_str(), "private");
    assert_eq!(TrustZoneClass::Team.as_str(), "team");
    assert_eq!(TrustZoneClass::Community.as_str(), "community");
}

#[test]
fn trust_zone_class_ordered_constant() {
    assert_eq!(TrustZoneClass::ORDERED.len(), 4);
    assert_eq!(TrustZoneClass::ORDERED[0], TrustZoneClass::Owner);
    assert_eq!(TrustZoneClass::ORDERED[1], TrustZoneClass::Private);
    assert_eq!(TrustZoneClass::ORDERED[2], TrustZoneClass::Team);
    assert_eq!(TrustZoneClass::ORDERED[3], TrustZoneClass::Community);
}

#[test]
fn trust_zone_class_serde_round_trip() {
    for class in TrustZoneClass::ORDERED {
        let json = serde_json::to_string(&class).expect("serialize");
        let restored: TrustZoneClass = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(class, restored);
    }
}

#[test]
fn trust_zone_class_serde_uses_snake_case() {
    let json = serde_json::to_string(&TrustZoneClass::Community).expect("serialize");
    assert_eq!(json, "\"community\"");
}

// =========================================================================
// Section 2 — Default ceilings
// =========================================================================

#[test]
fn owner_default_ceiling_is_full() {
    let owner_ceiling = TrustZoneClass::Owner.default_ceiling();
    let full = CapabilityProfile::full().capabilities;
    assert_eq!(owner_ceiling, full);
}

#[test]
fn private_default_ceiling_is_subset_of_owner() {
    let owner_ceiling = TrustZoneClass::Owner.default_ceiling();
    let private_ceiling = TrustZoneClass::Private.default_ceiling();
    assert!(private_ceiling.is_subset(&owner_ceiling));
    // Private has more capabilities than Team
    assert!(private_ceiling.len() > TrustZoneClass::Team.default_ceiling().len());
}

#[test]
fn team_default_ceiling_is_subset_of_private() {
    let private_ceiling = TrustZoneClass::Private.default_ceiling();
    let team_ceiling = TrustZoneClass::Team.default_ceiling();
    assert!(team_ceiling.is_subset(&private_ceiling));
}

#[test]
fn community_default_ceiling_is_subset_of_team() {
    let team_ceiling = TrustZoneClass::Team.default_ceiling();
    let community_ceiling = TrustZoneClass::Community.default_ceiling();
    assert!(community_ceiling.is_subset(&team_ceiling));
}

#[test]
fn community_ceiling_has_no_network_or_fs() {
    let community_ceiling = TrustZoneClass::Community.default_ceiling();
    assert!(!community_ceiling.contains(&RuntimeCapability::NetworkEgress));
    assert!(!community_ceiling.contains(&RuntimeCapability::FsRead));
    assert!(!community_ceiling.contains(&RuntimeCapability::FsWrite));
}

#[test]
fn private_ceiling_has_network_egress() {
    let private_ceiling = TrustZoneClass::Private.default_ceiling();
    assert!(private_ceiling.contains(&RuntimeCapability::NetworkEgress));
}

#[test]
fn default_ceiling_monotonic_shrinking() {
    // Owner >= Private >= Team >= Community
    let ordered = TrustZoneClass::ORDERED;
    for i in 1..ordered.len() {
        let parent = ordered[i - 1].default_ceiling();
        let child = ordered[i].default_ceiling();
        assert!(
            child.is_subset(&parent),
            "{} ceiling should be subset of {} ceiling",
            ordered[i].as_str(),
            ordered[i - 1].as_str()
        );
    }
}

// =========================================================================
// Section 3 — ZoneCreateRequest
// =========================================================================

#[test]
fn zone_create_request_new_defaults() {
    let req = ZoneCreateRequest::new("my-zone", TrustZoneClass::Team, 5, "admin");
    assert_eq!(req.zone_name, "my-zone");
    assert_eq!(req.class, TrustZoneClass::Team);
    assert_eq!(req.policy_version, 5);
    assert_eq!(req.created_by, "admin");
    assert!(req.parent_zone_name.is_none());
    assert!(req.declared_ceiling.is_none());
}

#[test]
fn zone_create_request_with_parent() {
    let req = ZoneCreateRequest::new("child", TrustZoneClass::Private, 1, "admin")
        .with_parent("parent-zone");
    assert_eq!(req.parent_zone_name.as_deref(), Some("parent-zone"));
}

#[test]
fn zone_create_request_with_declared_ceiling() {
    let ceiling = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
    let req = ZoneCreateRequest::new("custom", TrustZoneClass::Community, 1, "admin")
        .with_declared_ceiling(ceiling.clone());
    assert_eq!(req.declared_ceiling, Some(ceiling));
}

#[test]
fn zone_create_request_serde_round_trip() {
    let req = ZoneCreateRequest::new("zone-a", TrustZoneClass::Owner, 3, "admin")
        .with_parent("root")
        .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch]));
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: ZoneCreateRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, restored);
}

// =========================================================================
// Section 4 — ZoneHierarchy construction
// =========================================================================

#[test]
fn zone_hierarchy_new_has_no_zones() {
    let h = ZoneHierarchy::new("default");
    assert!(h.zone("default").is_none());
    assert!(h.events().is_empty());
}

#[test]
fn standard_hierarchy_has_all_four_zones() {
    let h = standard_hierarchy();
    for class in TrustZoneClass::ORDERED {
        let zone_name = class.as_str();
        assert!(
            h.zone(zone_name).is_some(),
            "standard hierarchy missing zone '{zone_name}'"
        );
    }
}

#[test]
fn standard_hierarchy_default_zone_is_community() {
    let h = standard_hierarchy();
    let zone = h
        .zone_for_entity("unassigned-entity")
        .expect("default zone");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn standard_hierarchy_zone_ids_are_distinct() {
    let h = standard_hierarchy();
    let mut ids = BTreeSet::new();
    for class in TrustZoneClass::ORDERED {
        let zone = h.zone(class.as_str()).unwrap();
        assert!(
            ids.insert(zone.zone_id.clone()),
            "duplicate zone_id for {}",
            class.as_str()
        );
    }
}

#[test]
fn add_zone_returns_zone_id() {
    let mut h = ZoneHierarchy::new("test");
    let zone_id = h
        .add_zone(ZoneCreateRequest::new(
            "owner",
            TrustZoneClass::Owner,
            1,
            "admin",
        ))
        .expect("add_zone");
    let zone = h.zone("owner").unwrap();
    assert_eq!(zone.zone_id, zone_id);
}

#[test]
fn add_zone_rejects_duplicate_name() {
    let mut h = ZoneHierarchy::new("test");
    h.add_zone(ZoneCreateRequest::new(
        "owner",
        TrustZoneClass::Owner,
        1,
        "admin",
    ))
    .expect("first add");
    let err = h
        .add_zone(ZoneCreateRequest::new(
            "owner",
            TrustZoneClass::Owner,
            1,
            "admin",
        ))
        .expect_err("duplicate");
    assert!(matches!(err, TrustZoneError::ZoneAlreadyExists { .. }));
}

#[test]
fn add_zone_rejects_missing_parent() {
    let mut h = ZoneHierarchy::new("test");
    let err = h
        .add_zone(
            ZoneCreateRequest::new("child", TrustZoneClass::Team, 1, "admin")
                .with_parent("nonexistent"),
        )
        .expect_err("missing parent");
    assert!(matches!(err, TrustZoneError::ParentZoneMissing { .. }));
}

// =========================================================================
// Section 5 — Effective ceiling inheritance
// =========================================================================

#[test]
fn child_effective_ceiling_is_intersection_with_parent() {
    let mut h = ZoneHierarchy::new("test");
    h.add_zone(ZoneCreateRequest::new(
        "owner",
        TrustZoneClass::Owner,
        1,
        "admin",
    ))
    .expect("owner");

    // Declare capabilities including FsWrite, which is NOT in Private default
    // but IS in owner (full)
    h.add_zone(
        ZoneCreateRequest::new("priv", TrustZoneClass::Private, 1, "admin")
            .with_parent("owner")
            .with_declared_ceiling(capset(&[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::NetworkEgress,
            ])),
    )
    .expect("priv");

    h.add_zone(
        ZoneCreateRequest::new("team", TrustZoneClass::Team, 1, "admin")
            .with_parent("priv")
            .with_declared_ceiling(capset(&[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::FsWrite, // Not in parent effective
            ])),
    )
    .expect("team");

    let team = h.zone("team").unwrap();
    // Effective = intersection of declared {VmDispatch, FsWrite} and parent_effective {VmDispatch, NetworkEgress}
    assert_eq!(
        team.effective_ceiling,
        capset(&[RuntimeCapability::VmDispatch])
    );
}

#[test]
fn root_zone_effective_equals_declared() {
    let mut h = ZoneHierarchy::new("test");
    let ceiling = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
    h.add_zone(
        ZoneCreateRequest::new("root", TrustZoneClass::Owner, 1, "admin")
            .with_declared_ceiling(ceiling.clone()),
    )
    .expect("root");
    let zone = h.zone("root").unwrap();
    assert_eq!(zone.effective_ceiling, ceiling);
    assert!(zone.parent_zone.is_none());
}

#[test]
fn effective_ceiling_in_standard_hierarchy_is_monotonically_shrinking() {
    let h = standard_hierarchy();
    let owner = h.zone("owner").unwrap();
    let private = h.zone("private").unwrap();
    let team = h.zone("team").unwrap();
    let community = h.zone("community").unwrap();

    assert!(
        private
            .effective_ceiling
            .is_subset(&owner.effective_ceiling)
    );
    assert!(team.effective_ceiling.is_subset(&private.effective_ceiling));
    assert!(
        community
            .effective_ceiling
            .is_subset(&team.effective_ceiling)
    );
}

#[test]
fn compute_effective_ceiling_returns_stored_ceiling() {
    let h = standard_hierarchy();
    let ceiling = h.compute_effective_ceiling("community").expect("ceiling");
    let zone = h.zone("community").unwrap();
    assert_eq!(ceiling, zone.effective_ceiling);
}

#[test]
fn compute_effective_ceiling_missing_zone_returns_error() {
    let h = standard_hierarchy();
    let err = h
        .compute_effective_ceiling("nonexistent")
        .expect_err("missing zone");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

// =========================================================================
// Section 6 — TrustZone::allows
// =========================================================================

#[test]
fn zone_allows_subset_of_ceiling() {
    let h = standard_hierarchy();
    let owner = h.zone("owner").unwrap();
    let requested = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
    assert!(owner.allows(&requested));
}

#[test]
fn zone_denies_superset_of_ceiling() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress, // Not in community ceiling
    ]);
    assert!(!community.allows(&requested));
}

#[test]
fn zone_allows_empty_request() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    assert!(community.allows(&BTreeSet::new()));
}

#[test]
fn zone_allows_exact_ceiling() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    assert!(community.allows(&community.effective_ceiling));
}

// =========================================================================
// Section 7 — Entity assignment
// =========================================================================

#[test]
fn assign_entity_to_valid_zone() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "team", "trace-001")
        .expect("assign");
    let zone = h.zone_for_entity("ext-1").expect("zone");
    assert_eq!(zone.zone_name, "team");
}

#[test]
fn assign_entity_to_missing_zone_errors() {
    let mut h = standard_hierarchy();
    let err = h
        .assign_entity("ext-1", "nonexistent", "trace-001")
        .expect_err("missing zone");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn unassigned_entity_returns_default_zone() {
    let h = standard_hierarchy();
    let zone = h.zone_for_entity("unassigned").expect("default");
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn reassign_entity_overwrites_previous_assignment() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1").expect("first");
    h.assign_entity("ext-1", "team", "t-2").expect("second");
    let zone = h.zone_for_entity("ext-1").expect("zone");
    assert_eq!(zone.zone_name, "team");
}

#[test]
fn assign_entity_emits_assignment_event() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-alpha", "owner", "trace-42")
        .expect("assign");
    let events = h.events();
    assert!(!events.is_empty());
    let event = events.last().unwrap();
    assert_eq!(event.event, ZoneEventType::Assignment);
    assert_eq!(event.outcome, ZoneEventOutcome::Assigned);
    assert_eq!(event.entity_id.as_deref(), Some("ext-alpha"));
    assert_eq!(event.zone_name.as_deref(), Some("owner"));
    assert_eq!(event.trace_id, "trace-42");
}

// =========================================================================
// Section 8 — Enforce ceiling
// =========================================================================

#[test]
fn enforce_ceiling_passes_for_allowed_capabilities() {
    let mut h = standard_hierarchy();
    let requested = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
    h.enforce_ceiling("community", &requested, "t-1")
        .expect("should pass");
    let event = h.events().last().unwrap();
    assert_eq!(event.event, ZoneEventType::CeilingCheck);
    assert_eq!(event.outcome, ZoneEventOutcome::Pass);
}

#[test]
fn enforce_ceiling_rejects_capabilities_outside_ceiling() {
    let mut h = standard_hierarchy();
    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    let err = h
        .enforce_ceiling("community", &requested, "t-1")
        .expect_err("should reject");
    match err {
        TrustZoneError::CapabilityCeilingExceeded { zone_name, .. } => {
            assert_eq!(zone_name, "community");
        }
        other => panic!("expected CapabilityCeilingExceeded, got {other}"),
    }
    let event = h.events().last().unwrap();
    assert_eq!(event.event, ZoneEventType::CeilingCheck);
    assert_eq!(event.outcome, ZoneEventOutcome::CeilingExceeded);
    assert!(event.error_code.is_some());
}

#[test]
fn enforce_ceiling_missing_zone_errors() {
    let mut h = standard_hierarchy();
    let err = h
        .enforce_ceiling("nonexistent", &BTreeSet::new(), "t-1")
        .expect_err("missing");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn enforce_ceiling_empty_request_always_passes() {
    let mut h = standard_hierarchy();
    h.enforce_ceiling("community", &BTreeSet::new(), "t-1")
        .expect("empty request should always pass");
}

// =========================================================================
// Section 9 — Zone transitions
// =========================================================================

#[test]
fn transition_approved_updates_assignment() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-1",
        "team",
        "t-2",
        "policy-1",
        "decision-1",
        true,
    ))
    .expect("transition");
    let zone = h.zone_for_entity("ext-1").expect("zone");
    assert_eq!(zone.zone_name, "team");
}

#[test]
fn transition_approved_emits_migrated_event() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-1",
        "team",
        "t-2",
        "policy-1",
        "decision-1",
        true,
    ))
    .expect("transition");
    let event = h.events().last().unwrap();
    assert_eq!(event.event, ZoneEventType::ZoneTransition);
    assert_eq!(event.outcome, ZoneEventOutcome::Migrated);
    assert_eq!(event.entity_id.as_deref(), Some("ext-1"));
    assert_eq!(event.from_zone.as_deref(), Some("community"));
    assert_eq!(event.to_zone.as_deref(), Some("team"));
    assert_eq!(event.policy_id.as_deref(), Some("policy-1"));
    assert_eq!(event.decision_id.as_deref(), Some("decision-1"));
}

#[test]
fn transition_denied_by_policy_gate() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    let err = h
        .transition_entity(ZoneTransitionRequest::new(
            "ext-1",
            "team",
            "t-2",
            "policy-1",
            "decision-1",
            false,
        ))
        .expect_err("denied");
    match err {
        TrustZoneError::PolicyGateDenied {
            entity_id,
            from_zone,
            to_zone,
        } => {
            assert_eq!(entity_id, "ext-1");
            assert_eq!(from_zone, "community");
            assert_eq!(to_zone, "team");
        }
        other => panic!("expected PolicyGateDenied, got {other}"),
    }
    let event = h.events().last().unwrap();
    assert_eq!(event.event, ZoneEventType::ZoneTransition);
    assert_eq!(event.outcome, ZoneEventOutcome::Denied);
    assert!(event.error_code.is_some());
}

#[test]
fn transition_to_missing_zone_errors() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    let err = h
        .transition_entity(ZoneTransitionRequest::new(
            "ext-1",
            "nonexistent",
            "t-2",
            "p-1",
            "d-1",
            true,
        ))
        .expect_err("missing zone");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn transition_unassigned_entity_uses_default_zone_as_from() {
    let mut h = standard_hierarchy();
    // "ext-new" is not assigned, so it defaults to "community"
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-new", "team", "t-1", "p-1", "d-1", true,
    ))
    .expect("transition from default");
    let event = h.events().last().unwrap();
    assert_eq!(event.from_zone.as_deref(), Some("community"));
    assert_eq!(event.to_zone.as_deref(), Some("team"));
}

#[test]
fn transition_same_zone_is_allowed() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "team", "t-1").expect("assign");
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-1", "team", "t-2", "p-1", "d-1", true,
    ))
    .expect("same-zone transition");
    let zone = h.zone_for_entity("ext-1").expect("zone");
    assert_eq!(zone.zone_name, "team");
}

// =========================================================================
// Section 10 — ZoneTransitionRequest
// =========================================================================

#[test]
fn zone_transition_request_new() {
    let req = ZoneTransitionRequest::new("ent-1", "zone-b", "trace-1", "pol-1", "dec-1", true);
    assert_eq!(req.entity_id, "ent-1");
    assert_eq!(req.to_zone_name, "zone-b");
    assert_eq!(req.trace_id, "trace-1");
    assert_eq!(req.policy_id, "pol-1");
    assert_eq!(req.decision_id, "dec-1");
    assert!(req.policy_gate_approved);
}

#[test]
fn zone_transition_request_serde_round_trip() {
    let req = ZoneTransitionRequest::new("ent-1", "zone-b", "trace-1", "pol-1", "dec-1", false);
    let json = serde_json::to_string(&req).expect("serialize");
    let restored: ZoneTransitionRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(req, restored);
}

// =========================================================================
// Section 11 — Events
// =========================================================================

#[test]
fn events_accumulate_across_operations() {
    let mut h = standard_hierarchy();
    assert!(h.events().is_empty());

    h.assign_entity("ext-1", "community", "t-1").expect("a1");
    assert_eq!(h.events().len(), 1);

    h.assign_entity("ext-2", "team", "t-2").expect("a2");
    assert_eq!(h.events().len(), 2);

    let _ = h.enforce_ceiling("community", &BTreeSet::new(), "t-3");
    assert_eq!(h.events().len(), 3);
}

#[test]
fn drain_events_clears_and_returns() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    h.assign_entity("ext-2", "team", "t-2").expect("assign");
    assert_eq!(h.events().len(), 2);

    let drained = h.drain_events();
    assert_eq!(drained.len(), 2);
    assert!(h.events().is_empty());
}

#[test]
fn zone_event_serde_round_trip() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    let event = h.events().last().unwrap().clone();
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: ZoneEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn zone_event_types_serde_round_trip() {
    let types = [
        ZoneEventType::Assignment,
        ZoneEventType::CeilingCheck,
        ZoneEventType::ZoneTransition,
    ];
    for t in &types {
        let json = serde_json::to_string(t).expect("serialize");
        let restored: ZoneEventType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*t, restored);
    }
}

#[test]
fn zone_event_outcomes_serde_round_trip() {
    let outcomes = [
        ZoneEventOutcome::Pass,
        ZoneEventOutcome::Assigned,
        ZoneEventOutcome::Migrated,
        ZoneEventOutcome::CeilingExceeded,
        ZoneEventOutcome::Denied,
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).expect("serialize");
        let restored: ZoneEventOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*o, restored);
    }
}

// =========================================================================
// Section 12 — Error Display
// =========================================================================

#[test]
fn error_display_zone_already_exists() {
    let err = TrustZoneError::ZoneAlreadyExists {
        zone_name: "owner".into(),
    };
    assert_eq!(err.to_string(), "zone already exists: owner");
}

#[test]
fn error_display_parent_zone_missing() {
    let err = TrustZoneError::ParentZoneMissing {
        zone_name: "child".into(),
        parent_zone: "parent".into(),
    };
    assert!(err.to_string().contains("child"));
    assert!(err.to_string().contains("parent"));
}

#[test]
fn error_display_zone_missing() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "nonexistent".into(),
    };
    assert_eq!(err.to_string(), "unknown zone: nonexistent");
}

#[test]
fn error_display_ceiling_exceeds_parent() {
    let err = TrustZoneError::CeilingExceedsParent {
        zone_name: "child".into(),
        exceeded: capset(&[RuntimeCapability::NetworkEgress]),
    };
    assert!(err.to_string().contains("child"));
    assert!(err.to_string().contains("not permitted by parent"));
}

#[test]
fn error_display_capability_ceiling_exceeded() {
    let err = TrustZoneError::CapabilityCeilingExceeded {
        zone_name: "community".into(),
        requested: capset(&[RuntimeCapability::NetworkEgress]),
        ceiling: capset(&[RuntimeCapability::VmDispatch]),
    };
    assert!(err.to_string().contains("community"));
    assert!(err.to_string().contains("ceiling exceeded"));
}

#[test]
fn error_display_policy_gate_denied() {
    let err = TrustZoneError::PolicyGateDenied {
        entity_id: "ext-1".into(),
        from_zone: "community".into(),
        to_zone: "team".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("ext-1"));
    assert!(msg.contains("community"));
    assert!(msg.contains("team"));
}

#[test]
fn trust_zone_error_is_std_error() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "test".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// Section 13 — Error serde
// =========================================================================

#[test]
fn trust_zone_error_serde_round_trip_all_variants() {
    let errors: Vec<TrustZoneError> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".into(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "c".into(),
            parent_zone: "p".into(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "x".into(),
        },
        TrustZoneError::CeilingExceedsParent {
            zone_name: "y".into(),
            exceeded: capset(&[RuntimeCapability::FsWrite]),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".into(),
            requested: capset(&[RuntimeCapability::NetworkEgress]),
            ceiling: capset(&[RuntimeCapability::VmDispatch]),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "ent".into(),
            from_zone: "a".into(),
            to_zone: "b".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: TrustZoneError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// Section 14 — Zone-scoped object IDs
// =========================================================================

#[test]
fn zone_scoped_object_id_differs_across_zones() {
    let h = standard_hierarchy();
    let team = h.zone("team").unwrap();
    let community = h.zone("community").unwrap();
    let schema = SchemaId::from_definition(b"test-schema-v1");
    let canonical = b"same-object";

    let team_id =
        derive_zone_scoped_object_id(team, ObjectDomain::EvidenceRecord, &schema, canonical)
            .expect("team id");
    let community_id =
        derive_zone_scoped_object_id(community, ObjectDomain::EvidenceRecord, &schema, canonical)
            .expect("community id");
    assert_ne!(team_id, community_id);
}

#[test]
fn zone_scoped_object_id_deterministic() {
    let h = standard_hierarchy();
    let zone = h.zone("owner").unwrap();
    let schema = SchemaId::from_definition(b"test-schema-v1");
    let canonical = b"object-data";

    let id1 = derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, canonical)
        .expect("id1");
    let id2 = derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, canonical)
        .expect("id2");
    assert_eq!(id1, id2);
}

#[test]
fn zone_scoped_object_id_differs_by_domain() {
    let h = standard_hierarchy();
    let zone = h.zone("owner").unwrap();
    let schema = SchemaId::from_definition(b"test-schema-v1");
    let canonical = b"same-payload";

    let id_evidence =
        derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema, canonical)
            .expect("evidence id");
    let id_policy =
        derive_zone_scoped_object_id(zone, ObjectDomain::PolicyObject, &schema, canonical)
            .expect("policy id");
    assert_ne!(id_evidence, id_policy);
}

#[test]
fn zone_scoped_object_id_differs_by_schema() {
    let h = standard_hierarchy();
    let zone = h.zone("team").unwrap();
    let schema_a = SchemaId::from_definition(b"schema-a");
    let schema_b = SchemaId::from_definition(b"schema-b");
    let canonical = b"same-payload";

    let id_a =
        derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema_a, canonical)
            .expect("id_a");
    let id_b =
        derive_zone_scoped_object_id(zone, ObjectDomain::EvidenceRecord, &schema_b, canonical)
            .expect("id_b");
    assert_ne!(id_a, id_b);
}

// =========================================================================
// Section 15 — Serde round-trips for TrustZone and ZoneHierarchy
// =========================================================================

#[test]
fn trust_zone_serde_round_trip() {
    let h = standard_hierarchy();
    let zone = h.zone("team").unwrap();
    let json = serde_json::to_string(zone).expect("serialize");
    let restored: TrustZone = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*zone, restored);
}

#[test]
fn zone_hierarchy_serde_round_trip() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "t-1")
        .expect("assign");
    let json = serde_json::to_string(&h).expect("serialize");
    let restored: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(h, restored);
}

// =========================================================================
// Section 16 — Deterministic replay
// =========================================================================

#[test]
fn deterministic_hierarchy_serialization() {
    let h1 = ZoneHierarchy::standard("maintainer", 5).expect("h1");
    let h2 = ZoneHierarchy::standard("maintainer", 5).expect("h2");
    let json1 = serde_json::to_string(&h1).expect("s1");
    let json2 = serde_json::to_string(&h2).expect("s2");
    assert_eq!(json1, json2);
}

#[test]
fn deterministic_zone_id_generation() {
    let h1 = ZoneHierarchy::standard("admin", 3).expect("h1");
    let h2 = ZoneHierarchy::standard("admin", 3).expect("h2");
    for class in TrustZoneClass::ORDERED {
        let name = class.as_str();
        assert_eq!(
            h1.zone(name).unwrap().zone_id,
            h2.zone(name).unwrap().zone_id,
            "zone_id mismatch for {name}"
        );
    }
}

#[test]
fn different_policy_version_produces_different_zone_ids() {
    let h1 = ZoneHierarchy::standard("admin", 1).expect("h1");
    let h2 = ZoneHierarchy::standard("admin", 2).expect("h2");
    let id1 = &h1.zone("owner").unwrap().zone_id;
    let id2 = &h2.zone("owner").unwrap().zone_id;
    assert_ne!(id1, id2);
}

// =========================================================================
// Section 17 — Complex workflows
// =========================================================================

#[test]
fn full_lifecycle_assign_enforce_transition_drain() {
    let mut h = standard_hierarchy();

    // 1. Assign entity to community zone
    h.assign_entity("ext-lifecycle", "community", "trace-lc-1")
        .expect("assign to community");

    // 2. Enforce ceiling passes for allowed capability
    let community_caps = capset(&[RuntimeCapability::VmDispatch]);
    h.enforce_ceiling("community", &community_caps, "trace-lc-2")
        .expect("ceiling check");

    // 3. Transition to team (approved)
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-lifecycle",
        "team",
        "trace-lc-3",
        "policy-main",
        "decision-main",
        true,
    ))
    .expect("transition to team");

    // 4. Verify entity is now in team
    let zone = h.zone_for_entity("ext-lifecycle").expect("zone");
    assert_eq!(zone.zone_name, "team");

    // 5. Enforce ceiling passes for team-level capability
    let team_caps = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::EvidenceEmit,
    ]);
    h.enforce_ceiling("team", &team_caps, "trace-lc-4")
        .expect("team ceiling check");

    // 6. Drain events and verify
    let events = h.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].event, ZoneEventType::Assignment);
    assert_eq!(events[1].event, ZoneEventType::CeilingCheck);
    assert_eq!(events[2].event, ZoneEventType::ZoneTransition);
    assert_eq!(events[3].event, ZoneEventType::CeilingCheck);

    // 7. Events buffer is now empty
    assert!(h.events().is_empty());
}

#[test]
fn multiple_entities_different_zones() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-a", "owner", "t-1").expect("assign a");
    h.assign_entity("ext-b", "team", "t-2").expect("assign b");
    h.assign_entity("ext-c", "community", "t-3")
        .expect("assign c");

    assert_eq!(h.zone_for_entity("ext-a").unwrap().zone_name, "owner");
    assert_eq!(h.zone_for_entity("ext-b").unwrap().zone_name, "team");
    assert_eq!(h.zone_for_entity("ext-c").unwrap().zone_name, "community");
}

#[test]
fn custom_hierarchy_with_restricted_ceilings() {
    let mut h = ZoneHierarchy::new("restricted");

    // Root with only VmDispatch and GcInvoke
    h.add_zone(
        ZoneCreateRequest::new("root", TrustZoneClass::Owner, 1, "admin").with_declared_ceiling(
            capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]),
        ),
    )
    .expect("root");

    // Child inherits intersection: only VmDispatch
    h.add_zone(
        ZoneCreateRequest::new("restricted", TrustZoneClass::Community, 1, "admin")
            .with_parent("root")
            .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch])),
    )
    .expect("restricted");

    let zone = h.zone("restricted").unwrap();
    assert_eq!(
        zone.effective_ceiling,
        capset(&[RuntimeCapability::VmDispatch])
    );
}

// =========================================================================
// Section 18 — Edge cases
// =========================================================================

#[test]
fn zone_for_entity_errors_if_default_zone_not_registered() {
    let h = ZoneHierarchy::new("nonexistent-default");
    let err = h
        .zone_for_entity("any-entity")
        .expect_err("missing default");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
}

#[test]
fn zone_name_empty_string_is_allowed() {
    let mut h = ZoneHierarchy::new("");
    h.add_zone(ZoneCreateRequest::new(
        "",
        TrustZoneClass::Owner,
        1,
        "admin",
    ))
    .expect("empty name zone");
    assert!(h.zone("").is_some());
}

#[test]
fn zone_created_by_preserved() {
    let h = standard_hierarchy();
    let zone = h.zone("owner").unwrap();
    assert_eq!(zone.created_by, "test-maintainer");
}

#[test]
fn zone_policy_version_preserved() {
    let h = standard_hierarchy();
    let zone = h.zone("owner").unwrap();
    assert_eq!(zone.policy_version, 1);
}

#[test]
fn zone_class_preserved() {
    let h = standard_hierarchy();
    assert_eq!(h.zone("owner").unwrap().class, TrustZoneClass::Owner);
    assert_eq!(h.zone("private").unwrap().class, TrustZoneClass::Private);
    assert_eq!(h.zone("team").unwrap().class, TrustZoneClass::Team);
    assert_eq!(
        h.zone("community").unwrap().class,
        TrustZoneClass::Community
    );
}

#[test]
fn zone_parent_zone_chain() {
    let h = standard_hierarchy();
    assert!(h.zone("owner").unwrap().parent_zone.is_none());
    assert!(h.zone("private").unwrap().parent_zone.is_some());
    assert!(h.zone("team").unwrap().parent_zone.is_some());
    assert!(h.zone("community").unwrap().parent_zone.is_some());

    // private's parent is owner
    let private = h.zone("private").unwrap();
    let owner = h.zone("owner").unwrap();
    assert_eq!(private.parent_zone.as_ref().unwrap(), &owner.zone_id);

    // team's parent is private
    let team = h.zone("team").unwrap();
    assert_eq!(team.parent_zone.as_ref().unwrap(), &private.zone_id);

    // community's parent is team
    let community = h.zone("community").unwrap();
    assert_eq!(community.parent_zone.as_ref().unwrap(), &team.zone_id);
}
