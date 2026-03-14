#![forbid(unsafe_code)]

//! Enrichment integration tests for trust_zone module.

use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::trust_zone::{
    TrustZoneClass, TrustZoneError, ZoneCreateRequest, ZoneEventOutcome, ZoneEventType,
    ZoneHierarchy, ZoneTransitionRequest,
};

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

fn standard_hierarchy() -> ZoneHierarchy {
    ZoneHierarchy::standard("test-maintainer", 1).expect("build standard hierarchy")
}

// ── TrustZoneClass ──────────────────────────────────────────────────────

#[test]
fn enrichment_trust_zone_class_copy_semantics() {
    let a = TrustZoneClass::Owner;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_trust_zone_class_btreeset_dedup() {
    let mut set = BTreeSet::new();
    for v in TrustZoneClass::ORDERED {
        assert!(set.insert(v));
    }
    assert_eq!(set.len(), 4);
    for v in TrustZoneClass::ORDERED {
        assert!(!set.insert(v));
    }
}

#[test]
fn enrichment_trust_zone_class_debug_all_unique() {
    let debugs: BTreeSet<String> = TrustZoneClass::ORDERED
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_trust_zone_class_display_all_unique() {
    let displays: BTreeSet<String> = TrustZoneClass::ORDERED
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_trust_zone_class_as_str_matches_display() {
    for v in TrustZoneClass::ORDERED {
        assert_eq!(v.as_str(), v.to_string());
    }
}

#[test]
fn enrichment_trust_zone_class_ceiling_shrinks_monotonically() {
    let owner = TrustZoneClass::Owner.default_ceiling();
    let private = TrustZoneClass::Private.default_ceiling();
    let team = TrustZoneClass::Team.default_ceiling();
    let community = TrustZoneClass::Community.default_ceiling();
    assert!(owner.len() >= private.len());
    assert!(private.len() >= team.len());
    assert!(team.len() >= community.len());
    assert!(private.is_subset(&owner));
    assert!(team.is_subset(&private));
    assert!(community.is_subset(&team));
}

// ── ZoneEventType ───────────────────────────────────────────────────────

#[test]
fn enrichment_zone_event_type_copy_semantics() {
    let a = ZoneEventType::Assignment;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_zone_event_type_debug_all_unique() {
    let all = [
        ZoneEventType::Assignment,
        ZoneEventType::CeilingCheck,
        ZoneEventType::ZoneTransition,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 3);
}

#[test]
fn enrichment_zone_event_type_serde_roundtrip() {
    let all = [
        ZoneEventType::Assignment,
        ZoneEventType::CeilingCheck,
        ZoneEventType::ZoneTransition,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: ZoneEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ── ZoneEventOutcome ────────────────────────────────────────────────────

#[test]
fn enrichment_zone_event_outcome_copy_semantics() {
    let a = ZoneEventOutcome::Pass;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_zone_event_outcome_debug_all_unique() {
    let all = [
        ZoneEventOutcome::Pass,
        ZoneEventOutcome::Assigned,
        ZoneEventOutcome::Migrated,
        ZoneEventOutcome::CeilingExceeded,
        ZoneEventOutcome::Denied,
    ];
    let debugs: BTreeSet<String> = all.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_zone_event_outcome_serde_roundtrip() {
    let all = [
        ZoneEventOutcome::Pass,
        ZoneEventOutcome::Assigned,
        ZoneEventOutcome::Migrated,
        ZoneEventOutcome::CeilingExceeded,
        ZoneEventOutcome::Denied,
    ];
    for v in &all {
        let json = serde_json::to_string(v).unwrap();
        let back: ZoneEventOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ── ZoneCreateRequest ───────────────────────────────────────────────────

#[test]
fn enrichment_zone_create_request_clone_independence() {
    let a = ZoneCreateRequest::new("test", TrustZoneClass::Team, 1, "admin");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_zone_create_request_json_field_names() {
    let req = ZoneCreateRequest::new("test", TrustZoneClass::Team, 1, "admin");
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "zone_name",
        "class",
        "parent_zone_name",
        "declared_ceiling",
        "policy_version",
        "created_by",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_zone_create_request_debug_nonempty() {
    let req = ZoneCreateRequest::new("test", TrustZoneClass::Team, 1, "admin");
    let d = format!("{req:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ZoneCreateRequest"));
}

#[test]
fn enrichment_zone_create_request_with_parent_chaining() {
    let req = ZoneCreateRequest::new("child", TrustZoneClass::Community, 1, "admin")
        .with_parent("parent_zone");
    assert_eq!(req.parent_zone_name.as_deref(), Some("parent_zone"));
}

#[test]
fn enrichment_zone_create_request_with_declared_ceiling() {
    let ceiling = capset(&[RuntimeCapability::VmDispatch, RuntimeCapability::GcInvoke]);
    let req = ZoneCreateRequest::new("custom", TrustZoneClass::Team, 1, "admin")
        .with_declared_ceiling(ceiling.clone());
    assert_eq!(req.declared_ceiling, Some(ceiling));
}

#[test]
fn enrichment_zone_create_request_serde_roundtrip() {
    let req = ZoneCreateRequest::new("test", TrustZoneClass::Private, 2, "admin")
        .with_parent("owner")
        .with_declared_ceiling(capset(&[RuntimeCapability::VmDispatch]));
    let json = serde_json::to_string(&req).unwrap();
    let back: ZoneCreateRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(req, back);
}

// ── ZoneTransitionRequest ───────────────────────────────────────────────

#[test]
fn enrichment_zone_transition_request_clone_independence() {
    let a = ZoneTransitionRequest::new(
        "entity-1",
        "team",
        "trace-1",
        "policy-1",
        "decision-1",
        true,
    );
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_zone_transition_request_json_field_names() {
    let req = ZoneTransitionRequest::new("e", "z", "t", "p", "d", true);
    let v: serde_json::Value = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "entity_id",
        "to_zone_name",
        "trace_id",
        "policy_id",
        "decision_id",
        "policy_gate_approved",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 6);
}

#[test]
fn enrichment_zone_transition_request_debug_nonempty() {
    let req = ZoneTransitionRequest::new("e", "z", "t", "p", "d", false);
    let d = format!("{req:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ZoneTransitionRequest"));
}

// ── TrustZoneError ──────────────────────────────────────────────────────

#[test]
fn enrichment_trust_zone_error_display_zone_already_exists() {
    let err = TrustZoneError::ZoneAlreadyExists {
        zone_name: "test".into(),
    };
    let s = err.to_string();
    assert!(s.contains("already exists"));
    assert!(s.contains("test"));
}

#[test]
fn enrichment_trust_zone_error_display_parent_missing() {
    let err = TrustZoneError::ParentZoneMissing {
        zone_name: "child".into(),
        parent_zone: "missing_parent".into(),
    };
    let s = err.to_string();
    assert!(s.contains("missing parent"));
    assert!(s.contains("child"));
}

#[test]
fn enrichment_trust_zone_error_display_zone_missing() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "nonexistent".into(),
    };
    let s = err.to_string();
    assert!(s.contains("nonexistent"));
}

#[test]
fn enrichment_trust_zone_error_display_ceiling_exceeded() {
    let err = TrustZoneError::CapabilityCeilingExceeded {
        zone_name: "community".into(),
        requested: capset(&[RuntimeCapability::NetworkEgress]),
        ceiling: capset(&[RuntimeCapability::VmDispatch]),
    };
    let s = err.to_string();
    assert!(s.contains("ceiling exceeded"));
    assert!(s.contains("community"));
}

#[test]
fn enrichment_trust_zone_error_display_policy_gate_denied() {
    let err = TrustZoneError::PolicyGateDenied {
        entity_id: "ext-1".into(),
        from_zone: "community".into(),
        to_zone: "team".into(),
    };
    let s = err.to_string();
    assert!(s.contains("policy gate denied"));
    assert!(s.contains("ext-1"));
}

#[test]
fn enrichment_trust_zone_error_clone_independence() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "test".into(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_trust_zone_error_debug_all_variants_unique() {
    let errors = [
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".into(),
        },
        TrustZoneError::ParentZoneMissing {
            zone_name: "z".into(),
            parent_zone: "p".into(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".into(),
        },
        TrustZoneError::CeilingExceedsParent {
            zone_name: "z".into(),
            exceeded: BTreeSet::new(),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".into(),
            requested: BTreeSet::new(),
            ceiling: BTreeSet::new(),
        },
        TrustZoneError::PolicyGateDenied {
            entity_id: "e".into(),
            from_zone: "f".into(),
            to_zone: "t".into(),
        },
    ];
    let debugs: BTreeSet<String> = errors.iter().map(|e| format!("{e:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_trust_zone_error_is_std_error() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "test".into(),
    };
    let _: &dyn std::error::Error = &err;
}

// ── TrustZone (via hierarchy) ───────────────────────────────────────────

#[test]
fn enrichment_trust_zone_clone_independence() {
    let h = standard_hierarchy();
    let zone = h.zone("owner").unwrap();
    let cloned = zone.clone();
    assert_eq!(*zone, cloned);
}

#[test]
fn enrichment_trust_zone_debug_nonempty() {
    let h = standard_hierarchy();
    let zone = h.zone("team").unwrap();
    let d = format!("{zone:?}");
    assert!(!d.is_empty());
    assert!(d.contains("TrustZone"));
}

#[test]
fn enrichment_trust_zone_allows_subset() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    let allowed = capset(&[RuntimeCapability::VmDispatch]);
    assert!(community.allows(&allowed));
}

#[test]
fn enrichment_trust_zone_denies_superset() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    let denied = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    assert!(!community.allows(&denied));
}

#[test]
fn enrichment_trust_zone_allows_empty_set() {
    let h = standard_hierarchy();
    let community = h.zone("community").unwrap();
    assert!(community.allows(&BTreeSet::new()));
}

// ── ZoneHierarchy ───────────────────────────────────────────────────────

#[test]
fn enrichment_zone_hierarchy_clone_independence() {
    let a = standard_hierarchy();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_zone_hierarchy_debug_nonempty() {
    let h = standard_hierarchy();
    let d = format!("{h:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ZoneHierarchy"));
}

#[test]
fn enrichment_zone_hierarchy_zone_missing_returns_none() {
    let h = standard_hierarchy();
    assert!(h.zone("nonexistent").is_none());
}

#[test]
fn enrichment_zone_hierarchy_add_duplicate_zone_errors() {
    let mut h = standard_hierarchy();
    let result = h.add_zone(ZoneCreateRequest::new(
        "owner",
        TrustZoneClass::Owner,
        1,
        "admin",
    ));
    assert!(matches!(
        result,
        Err(TrustZoneError::ZoneAlreadyExists { .. })
    ));
}

#[test]
fn enrichment_zone_hierarchy_assign_to_missing_zone_errors() {
    let mut h = standard_hierarchy();
    let result = h.assign_entity("entity-1", "nonexistent", "trace-1");
    assert!(matches!(result, Err(TrustZoneError::ZoneMissing { .. })));
}

#[test]
fn enrichment_zone_hierarchy_entity_defaults_to_community() {
    let h = standard_hierarchy();
    let zone = h.zone_for_entity("never-assigned").unwrap();
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn enrichment_zone_hierarchy_assign_and_lookup() {
    let mut h = standard_hierarchy();
    h.assign_entity("entity-x", "team", "trace-1").unwrap();
    let zone = h.zone_for_entity("entity-x").unwrap();
    assert_eq!(zone.zone_name, "team");
}

#[test]
fn enrichment_zone_hierarchy_enforce_ceiling_pass() {
    let mut h = standard_hierarchy();
    let allowed = capset(&[RuntimeCapability::VmDispatch]);
    h.enforce_ceiling("community", &allowed, "trace-1").unwrap();
    let last_event = h.events().last().unwrap();
    assert_eq!(last_event.event, ZoneEventType::CeilingCheck);
    assert_eq!(last_event.outcome, ZoneEventOutcome::Pass);
}

#[test]
fn enrichment_zone_hierarchy_enforce_ceiling_on_missing_zone() {
    let mut h = standard_hierarchy();
    let caps = capset(&[RuntimeCapability::VmDispatch]);
    let result = h.enforce_ceiling("nonexistent", &caps, "trace-1");
    assert!(matches!(result, Err(TrustZoneError::ZoneMissing { .. })));
}

#[test]
fn enrichment_zone_hierarchy_transition_approved() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "community", "trace-1").unwrap();
    h.transition_entity(ZoneTransitionRequest::new(
        "ext-1", "team", "trace-2", "pol-1", "dec-1", true,
    ))
    .unwrap();
    let zone = h.zone_for_entity("ext-1").unwrap();
    assert_eq!(zone.zone_name, "team");
    let last = h.events().last().unwrap();
    assert_eq!(last.outcome, ZoneEventOutcome::Migrated);
}

#[test]
fn enrichment_zone_hierarchy_transition_denied() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-2", "community", "trace-1").unwrap();
    let err = h
        .transition_entity(ZoneTransitionRequest::new(
            "ext-2", "team", "trace-2", "pol-1", "dec-1", false,
        ))
        .unwrap_err();
    assert!(matches!(err, TrustZoneError::PolicyGateDenied { .. }));
    // Entity stays in community
    let zone = h.zone_for_entity("ext-2").unwrap();
    assert_eq!(zone.zone_name, "community");
}

#[test]
fn enrichment_zone_hierarchy_transition_to_missing_zone_errors() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-3", "community", "trace-1").unwrap();
    let result = h.transition_entity(ZoneTransitionRequest::new(
        "ext-3",
        "nonexistent",
        "trace-2",
        "pol-1",
        "dec-1",
        true,
    ));
    assert!(matches!(result, Err(TrustZoneError::ZoneMissing { .. })));
}

#[test]
fn enrichment_zone_hierarchy_compute_effective_ceiling_all_zones() {
    let h = standard_hierarchy();
    for class in TrustZoneClass::ORDERED {
        let ceiling = h.compute_effective_ceiling(class.as_str()).unwrap();
        let zone = h.zone(class.as_str()).unwrap();
        assert_eq!(ceiling, zone.effective_ceiling);
    }
}

#[test]
fn enrichment_zone_hierarchy_compute_effective_ceiling_missing() {
    let h = standard_hierarchy();
    let result = h.compute_effective_ceiling("nonexistent");
    assert!(matches!(result, Err(TrustZoneError::ZoneMissing { .. })));
}

#[test]
fn enrichment_zone_hierarchy_drain_events() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "owner", "trace-1").unwrap();
    assert!(!h.events().is_empty());
    let drained = h.drain_events();
    assert!(!drained.is_empty());
    assert!(h.events().is_empty());
}

// ── ZoneEvent ───────────────────────────────────────────────────────────

#[test]
fn enrichment_zone_event_clone_independence() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "owner", "trace-1").unwrap();
    let event = h.events().last().unwrap();
    let cloned = event.clone();
    assert_eq!(*event, cloned);
}

#[test]
fn enrichment_zone_event_json_field_names() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "owner", "trace-1").unwrap();
    let event = h.events().last().unwrap();
    let v: serde_json::Value = serde_json::to_value(event).unwrap();
    let obj = v.as_object().unwrap();
    for key in &[
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
        "entity_id",
        "zone_name",
        "from_zone",
        "to_zone",
    ] {
        assert!(obj.contains_key(*key), "missing field {key}");
    }
    assert_eq!(obj.len(), 11);
}

#[test]
fn enrichment_zone_event_debug_nonempty() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "owner", "trace-1").unwrap();
    let event = h.events().last().unwrap();
    let d = format!("{event:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ZoneEvent"));
}

// ── Custom hierarchy with ceiling intersection ──────────────────────────

#[test]
fn enrichment_custom_ceiling_intersection() {
    let mut h = ZoneHierarchy::new("narrow");
    h.add_zone(ZoneCreateRequest::new(
        "root",
        TrustZoneClass::Owner,
        1,
        "admin",
    ))
    .unwrap();
    h.add_zone(
        ZoneCreateRequest::new("narrow", TrustZoneClass::Team, 1, "admin")
            .with_parent("root")
            .with_declared_ceiling(capset(&[
                RuntimeCapability::VmDispatch,
                RuntimeCapability::GcInvoke,
                RuntimeCapability::FsRead,
            ])),
    )
    .unwrap();
    let narrow = h.zone("narrow").unwrap();
    // Intersection with Owner (full) and declared => declared
    assert!(
        narrow
            .effective_ceiling
            .contains(&RuntimeCapability::VmDispatch)
    );
    assert!(
        narrow
            .effective_ceiling
            .contains(&RuntimeCapability::GcInvoke)
    );
    assert!(
        narrow
            .effective_ceiling
            .contains(&RuntimeCapability::FsRead)
    );
    assert!(
        !narrow
            .effective_ceiling
            .contains(&RuntimeCapability::NetworkEgress)
    );
}

// ── Five-run determinism ────────────────────────────────────────────────

#[test]
fn enrichment_five_run_determinism_standard_hierarchy() {
    let hierarchies: Vec<_> = (0..5)
        .map(|_| {
            let h = standard_hierarchy();
            serde_json::to_string(&h).unwrap()
        })
        .collect();
    for h in &hierarchies[1..] {
        assert_eq!(hierarchies[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_zone_ids() {
    let ids: Vec<_> = (0..5)
        .map(|_| {
            let h = standard_hierarchy();
            h.zone("team").unwrap().zone_id.clone()
        })
        .collect();
    for id in &ids[1..] {
        assert_eq!(ids[0], *id);
    }
}

// ── Serde roundtrip for hierarchy ───────────────────────────────────────

#[test]
fn enrichment_zone_hierarchy_serde_roundtrip() {
    let h = standard_hierarchy();
    let json = serde_json::to_string(&h).unwrap();
    let back: ZoneHierarchy = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}

#[test]
fn enrichment_zone_hierarchy_serde_with_events() {
    let mut h = standard_hierarchy();
    h.assign_entity("ext-1", "owner", "trace-1").unwrap();
    h.enforce_ceiling(
        "owner",
        &capset(&[RuntimeCapability::VmDispatch]),
        "trace-2",
    )
    .unwrap();
    let json = serde_json::to_string(&h).unwrap();
    let back: ZoneHierarchy = serde_json::from_str(&json).unwrap();
    assert_eq!(h, back);
}
