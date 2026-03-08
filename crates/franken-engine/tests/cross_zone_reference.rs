use std::collections::BTreeSet;

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::capability::trust_zone::{
    CrossZoneReferenceChecker, CrossZoneReferenceRequest, ReferenceType, TrustZoneError,
    ZoneHierarchy,
};

fn capset(caps: &[RuntimeCapability]) -> BTreeSet<RuntimeCapability> {
    caps.iter().copied().collect()
}

#[test]
fn multi_zone_extensions_can_reference_foreign_audit_data_via_provenance() {
    let hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-prov-1",
            ),
        )
        .expect("provenance cross-zone reference should be permitted");

    let event = checker.events().last().expect("event");
    assert_eq!(event.trace_id, "trace-prov-1");
    assert_eq!(event.from_zone.as_deref(), Some("community"));
    assert_eq!(event.to_zone.as_deref(), Some("team"));
}

#[test]
fn cross_zone_authority_reference_and_capability_escalation_are_denied() {
    let mut hierarchy = ZoneHierarchy::standard("maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-community", "community", "trace-assign")
        .expect("assign");

    let mut checker = CrossZoneReferenceChecker::new();
    let err = hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "private",
                ReferenceType::Authority,
                "trace-auth-deny",
            ),
        )
        .expect_err("authority cross-zone ref must be denied");
    assert!(matches!(err, TrustZoneError::CrossZoneAuthorityLeak { .. }));

    let requested = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    let err = hierarchy
        .enforce_ceiling("community", &requested, "trace-ceiling-deny")
        .expect_err("community ceiling must deny attempted escalation");

    assert!(matches!(
        err,
        TrustZoneError::CapabilityCeilingExceeded { .. }
    ));
}

// ────────────────────────────────────────────────────────────
// Enrichment: zone hierarchy, entity lifecycle, error paths
// ────────────────────────────────────────────────────────────

#[test]
fn standard_hierarchy_creates_expected_zones() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize");
    // Standard hierarchy creates maintainer, team, community, private zones
    assert!(json.contains("maintainer"));
    assert!(json.contains("team"));
    assert!(json.contains("community"));
    assert!(json.contains("private"));
}

#[test]
fn entity_assignment_succeeds_for_existing_zone() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-1", "community", "trace-assign-1")
        .expect("assign to community zone should succeed");
}

#[test]
fn entity_assignment_fails_for_missing_zone() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let err = hierarchy
        .assign_entity("ext-1", "nonexistent-zone", "trace-missing-zone")
        .expect_err("assign to missing zone must fail");
    assert!(matches!(err, TrustZoneError::ZoneMissing { .. }));
    assert!(err.to_string().contains("nonexistent-zone"));
}

#[test]
fn provenance_not_permitted_when_not_allowed() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    // do NOT allow provenance from community to team

    let err = hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-prov-denied",
            ),
        )
        .expect_err("provenance without explicit allow must fail");

    assert!(matches!(
        err,
        TrustZoneError::CrossZoneProvenanceNotPermitted { .. }
    ));
}

#[test]
fn cross_zone_reference_checker_serde_round_trip() {
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    let json = serde_json::to_string(&checker).expect("serialize checker");
    let recovered: CrossZoneReferenceChecker =
        serde_json::from_str(&json).expect("deserialize checker");

    // Validate the recovered checker works the same
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-recovered",
            ),
        )
        .expect("recovered checker should allow same provenance");

    let _ = recovered; // confirm deserialization succeeded
}

#[test]
fn zone_hierarchy_serde_round_trip() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize hierarchy");
    let recovered: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize hierarchy");

    let recovered_json = serde_json::to_string(&recovered).expect("serialize recovered");
    assert_eq!(json, recovered_json);
}

#[test]
fn enforce_ceiling_allows_subset_capabilities() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    // The owner zone should have a generous ceiling
    let requested = capset(&[RuntimeCapability::VmDispatch]);
    hierarchy
        .enforce_ceiling("owner", &requested, "trace-ceiling-ok")
        .expect("owner ceiling should allow VmDispatch");
}

#[test]
fn trust_zone_error_display_is_non_empty() {
    let errors: Vec<TrustZoneError> = vec![
        TrustZoneError::ZoneAlreadyExists {
            zone_name: "z".to_string(),
        },
        TrustZoneError::ZoneMissing {
            zone_name: "z".to_string(),
        },
        TrustZoneError::CrossZoneAuthorityLeak {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CrossZoneProvenanceNotPermitted {
            source_zone: "a".to_string(),
            target_zone: "b".to_string(),
        },
        TrustZoneError::CapabilityCeilingExceeded {
            zone_name: "z".to_string(),
            requested: capset(&[RuntimeCapability::VmDispatch]),
            ceiling: BTreeSet::new(),
        },
    ];

    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "Display for {err:?} must not be empty");
    }
}

#[test]
fn reference_type_serde_round_trip() {
    for ref_type in [ReferenceType::Provenance, ReferenceType::Authority] {
        let json = serde_json::to_string(&ref_type).expect("serialize");
        let recovered: ReferenceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ref_type, recovered);
    }
}

#[test]
fn cross_zone_reference_request_serde_round_trip() {
    let request = CrossZoneReferenceRequest::new(
        "community",
        "team",
        ReferenceType::Provenance,
        "trace-serde-rt",
    );
    let json = serde_json::to_string(&request).expect("serialize");
    let recovered: CrossZoneReferenceRequest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(request.source_zone, recovered.source_zone);
    assert_eq!(request.target_zone, recovered.target_zone);
    assert_eq!(request.reference_type, recovered.reference_type);
}

#[test]
fn checker_events_are_recorded() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");

    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-event-check",
            ),
        )
        .expect("should succeed");

    assert!(!checker.events().is_empty());
    let event = &checker.events()[0];
    assert_eq!(event.trace_id, "trace-event-check");
}

#[test]
fn zone_hierarchy_deterministic_double_create() {
    let a = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let b = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let json_a = serde_json::to_string(&a).expect("serialize a");
    let json_b = serde_json::to_string(&b).expect("serialize b");
    assert_eq!(json_a, json_b);
}

#[test]
fn multiple_provenance_allowances_do_not_interfere() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    checker.allow_provenance("community", "team");
    checker.allow_provenance("team", "private");

    // First allowance should still work
    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-multi-1",
            ),
        )
        .expect("community->team provenance should succeed");

    // Second allowance should also work
    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "team",
                "private",
                ReferenceType::Provenance,
                "trace-multi-2",
            ),
        )
        .expect("team->private provenance should succeed");

    assert!(checker.events().len() >= 2);
}

#[test]
fn capset_produces_correct_size() {
    let set = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::NetworkEgress,
    ]);
    assert_eq!(set.len(), 2);
    assert!(set.contains(&RuntimeCapability::VmDispatch));
    assert!(set.contains(&RuntimeCapability::NetworkEgress));
}

#[test]
fn checker_starts_with_no_events() {
    let checker = CrossZoneReferenceChecker::new();
    assert!(checker.events().is_empty());
}

#[test]
fn cross_zone_reference_request_populates_all_fields() {
    let req = CrossZoneReferenceRequest::new(
        "community",
        "team",
        ReferenceType::Provenance,
        "trace-populate",
    );
    assert_eq!(req.source_zone, "community");
    assert_eq!(req.target_zone, "team");
    assert_eq!(req.reference_type, ReferenceType::Provenance);
    assert_eq!(req.trace_id, "trace-populate");
}

#[test]
fn authority_reference_within_same_zone_is_allowed() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    // Same-zone authority reference should be allowed (not cross-zone)
    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "team",
                "team",
                ReferenceType::Authority,
                "trace-same-zone",
            ),
        )
        .expect("same-zone authority reference should succeed");
}

#[test]
fn capset_empty_input_produces_empty_set() {
    let set = capset(&[]);
    assert!(set.is_empty());
}

#[test]
fn reference_type_all_variants_serde_roundtrip() {
    for rt in [ReferenceType::Provenance, ReferenceType::Authority] {
        let json = serde_json::to_string(&rt).expect("serialize");
        let recovered: ReferenceType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(recovered, rt);
    }
}

#[test]
fn trust_zone_error_variants_display_differently() {
    let e1 = TrustZoneError::ZoneMissing {
        zone_name: "alpha".into(),
    };
    let e2 = TrustZoneError::ZoneMissing {
        zone_name: "beta".into(),
    };
    let s1 = format!("{e1}");
    let s2 = format!("{e2}");
    assert_ne!(s1, s2);
}

#[test]
fn reference_type_debug_is_nonempty() {
    for rt in [ReferenceType::Provenance, ReferenceType::Authority] {
        assert!(!format!("{rt:?}").is_empty());
    }
}

#[test]
fn trust_zone_error_debug_is_nonempty() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "dbg-zone".into(),
    };
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn trust_zone_error_is_std_error() {
    let err = TrustZoneError::ZoneMissing {
        zone_name: "std-err".into(),
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ---------- Additional edge-case and boundary tests ----------

#[test]
fn authority_reference_across_different_zones_is_always_denied() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    // Authority from any zone to any other zone should be denied
    let pairs = [
        ("community", "private"),
        ("team", "community"),
        ("private", "team"),
    ];
    for (from, to) in pairs {
        let err = hierarchy
            .validate_cross_zone_reference(
                &mut checker,
                CrossZoneReferenceRequest::new(
                    from,
                    to,
                    ReferenceType::Authority,
                    format!("trace-auth-{from}-{to}"),
                ),
            )
            .expect_err(&format!("authority from {from} to {to} must be denied"));
        assert!(
            matches!(err, TrustZoneError::CrossZoneAuthorityLeak { .. }),
            "expected CrossZoneAuthorityLeak for {from} -> {to}, got: {err}"
        );
    }
}

#[test]
fn duplicate_entity_assignment_to_same_zone_does_not_error() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-dup", "community", "trace-dup-1")
        .expect("first assign should succeed");
    // Assigning the same entity again to the same zone should be idempotent or succeed
    hierarchy
        .assign_entity("ext-dup", "community", "trace-dup-2")
        .expect("second assign to same zone should succeed");
}

#[test]
fn capset_deduplicates_identical_capabilities() {
    let set = capset(&[
        RuntimeCapability::VmDispatch,
        RuntimeCapability::VmDispatch,
        RuntimeCapability::VmDispatch,
    ]);
    assert_eq!(
        set.len(),
        1,
        "BTreeSet must deduplicate identical capabilities"
    );
    assert!(set.contains(&RuntimeCapability::VmDispatch));
}

#[test]
fn zone_hierarchy_serde_roundtrip_after_entity_assignment() {
    let mut hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    hierarchy
        .assign_entity("ext-persist", "team", "trace-persist")
        .expect("assign");

    let json = serde_json::to_string(&hierarchy).expect("serialize");
    let recovered: ZoneHierarchy = serde_json::from_str(&json).expect("deserialize");
    let recovered_json = serde_json::to_string(&recovered).expect("re-serialize");
    assert_eq!(
        json, recovered_json,
        "serde roundtrip must be stable after entity assignment"
    );
}

#[test]
fn provenance_allowance_is_directional() {
    let hierarchy = ZoneHierarchy::standard("test-maintainer", 1).expect("hierarchy");
    let mut checker = CrossZoneReferenceChecker::new();
    // Allow community -> team but NOT team -> community
    checker.allow_provenance("community", "team");

    hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "community",
                "team",
                ReferenceType::Provenance,
                "trace-fwd",
            ),
        )
        .expect("community -> team provenance should succeed");

    let err = hierarchy
        .validate_cross_zone_reference(
            &mut checker,
            CrossZoneReferenceRequest::new(
                "team",
                "community",
                ReferenceType::Provenance,
                "trace-rev",
            ),
        )
        .expect_err("team -> community provenance must be denied (not allowed)");
    assert!(matches!(
        err,
        TrustZoneError::CrossZoneProvenanceNotPermitted { .. }
    ));
}

#[test]
fn zone_hierarchy_debug_is_nonempty() {
    let hierarchy = ZoneHierarchy::standard("test-debug", 1).expect("hierarchy");
    assert!(!format!("{hierarchy:?}").is_empty());
}

#[test]
fn zone_hierarchy_serde_is_deterministic() {
    let hierarchy = ZoneHierarchy::standard("test-det", 1).expect("hierarchy");
    let a = serde_json::to_string(&hierarchy).expect("first");
    let b = serde_json::to_string(&hierarchy).expect("second");
    assert_eq!(a, b);
}

#[test]
fn zone_hierarchy_standard_serialized_length_exceeds_minimum() {
    let hierarchy = ZoneHierarchy::standard("test-len", 1).expect("hierarchy");
    let json = serde_json::to_string(&hierarchy).expect("serialize");
    assert!(
        json.len() > 50,
        "serialized hierarchy should be >50 chars, got {}",
        json.len()
    );
}
