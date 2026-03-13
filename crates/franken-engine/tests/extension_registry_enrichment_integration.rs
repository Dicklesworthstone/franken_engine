#![forbid(unsafe_code)]
//! Enrichment integration tests for `extension_registry`.
//!
//! Adds exact Display messages, Debug distinctness, JSON field-name stability,
//! serde exact enum values, PackageQuery defaults, and additional edge-case
//! coverage beyond the existing 40 integration tests.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::extension_registry::{
    ArtifactEntry, BuildDescriptor, CapabilityDeclaration, EventOutcome, ExtensionRegistry,
    PackageKey, PackageQuery, PackageVersion, PublisherIdentity, RegistryError, RegistryEvent,
    RegistryEventType, VerificationResult,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::signature_preimage::SigningKey;

// ===========================================================================
// Test helpers
// ===========================================================================

fn sk() -> SigningKey {
    SigningKey::from_bytes([77u8; 32])
}

fn pub_id() -> frankenengine_engine::engine_object_id::EngineObjectId {
    frankenengine_engine::engine_object_id::derive_id(
        frankenengine_engine::engine_object_id::ObjectDomain::SignedManifest,
        "extension-registry",
        &frankenengine_engine::engine_object_id::SchemaId::from_definition(
            b"ExtensionPublisher.v1",
        ),
        &sk().verification_key().0,
    )
    .unwrap()
}

fn ts() -> DeterministicTimestamp {
    DeterministicTimestamp(1_000_000_000)
}

// ===========================================================================
// 1) RegistryEventType — exact Display
// ===========================================================================

#[test]
fn registry_event_type_display_exact() {
    assert_eq!(
        RegistryEventType::PublisherRegistered.to_string(),
        "publisher_registered"
    );
    assert_eq!(
        RegistryEventType::PublisherRevoked.to_string(),
        "publisher_revoked"
    );
    assert_eq!(RegistryEventType::ScopeClaimed.to_string(), "scope_claimed");
    assert_eq!(
        RegistryEventType::PackagePublished.to_string(),
        "package_published"
    );
    assert_eq!(
        RegistryEventType::PackageQueried.to_string(),
        "package_queried"
    );
    assert_eq!(
        RegistryEventType::PackageVerified.to_string(),
        "package_verified"
    );
    assert_eq!(
        RegistryEventType::PackageRevoked.to_string(),
        "package_revoked"
    );
    assert_eq!(
        RegistryEventType::VerificationFailed.to_string(),
        "verification_failed"
    );
    assert_eq!(
        RegistryEventType::RevocationPropagated.to_string(),
        "revocation_propagated"
    );
}

// ===========================================================================
// 2) EventOutcome — exact Display
// ===========================================================================

#[test]
fn event_outcome_display_exact() {
    assert_eq!(EventOutcome::Success.to_string(), "success");
    assert_eq!(EventOutcome::Denied.to_string(), "denied");
    assert_eq!(EventOutcome::Error.to_string(), "error");
}

// ===========================================================================
// 3) PackageVersion — exact Display
// ===========================================================================

#[test]
fn package_version_display_exact() {
    assert_eq!(PackageVersion::new(1, 2, 3).to_string(), "1.2.3");
    assert_eq!(PackageVersion::new(0, 0, 0).to_string(), "0.0.0");
    assert_eq!(
        PackageVersion::new(100, 200, 300).to_string(),
        "100.200.300"
    );
}

// ===========================================================================
// 4) PackageKey — exact Display
// ===========================================================================

#[test]
fn package_key_display_exact() {
    let key = PackageKey {
        scope: "myorg".to_string(),
        name: "weather-ext".to_string(),
        version: PackageVersion::new(2, 1, 0),
    };
    assert_eq!(key.to_string(), "@myorg/weather-ext@2.1.0");
}

// ===========================================================================
// 5) RegistryError — exact Display messages
// ===========================================================================

#[test]
fn error_display_exact_publisher_not_found() {
    let id = pub_id();
    let e = RegistryError::PublisherNotFound {
        publisher_id: id.clone(),
    };
    assert_eq!(e.to_string(), format!("publisher not found: {id}"));
}

#[test]
fn error_display_exact_publisher_revoked() {
    let id = pub_id();
    let e = RegistryError::PublisherRevoked {
        publisher_id: id.clone(),
    };
    assert_eq!(e.to_string(), format!("publisher revoked: {id}"));
}

#[test]
fn error_display_exact_package_already_exists() {
    let e = RegistryError::PackageAlreadyExists {
        scope: "org".to_string(),
        name: "ext".to_string(),
        version: PackageVersion::new(1, 0, 0),
    };
    assert_eq!(e.to_string(), "package already exists: @org/ext@1.0.0");
}

#[test]
fn error_display_exact_package_not_found() {
    let e = RegistryError::PackageNotFound {
        scope: "org".to_string(),
        name: "ext".to_string(),
        version: PackageVersion::new(1, 0, 0),
    };
    assert_eq!(e.to_string(), "package not found: @org/ext@1.0.0");
}

#[test]
fn error_display_exact_package_revoked() {
    let id = pub_id();
    let e = RegistryError::PackageRevoked {
        package_id: id.clone(),
    };
    assert_eq!(e.to_string(), format!("package revoked: {id}"));
}

#[test]
fn error_display_exact_signature_invalid() {
    let e = RegistryError::SignatureInvalid {
        reason: "bad key".to_string(),
    };
    assert_eq!(e.to_string(), "signature invalid: bad key");
}

#[test]
fn error_display_exact_scope_not_owned() {
    let id = pub_id();
    let e = RegistryError::ScopeNotOwned {
        scope: "myorg".to_string(),
        publisher_id: id.clone(),
    };
    assert_eq!(e.to_string(), format!("scope @myorg not owned by {id}"));
}

#[test]
fn error_display_exact_too_many_capabilities() {
    let e = RegistryError::TooManyCapabilities {
        count: 300,
        max: 256,
    };
    assert_eq!(e.to_string(), "too many capabilities: 300 > 256");
}

#[test]
fn error_display_exact_too_many_artifacts() {
    let e = RegistryError::TooManyArtifacts {
        count: 2000,
        max: 1024,
    };
    assert_eq!(e.to_string(), "too many artifacts: 2000 > 1024");
}

#[test]
fn error_display_exact_invalid_scope() {
    let e = RegistryError::InvalidScope {
        scope: "bad scope!".to_string(),
        reason: "special chars".to_string(),
    };
    assert_eq!(e.to_string(), "invalid scope @bad scope!: special chars");
}

#[test]
fn error_display_exact_invalid_name() {
    let e = RegistryError::InvalidName {
        name: "bad name!".to_string(),
        reason: "special chars".to_string(),
    };
    assert_eq!(e.to_string(), "invalid name bad name!: special chars");
}

#[test]
fn error_display_exact_revocation_target_unknown() {
    let id = pub_id();
    let e = RegistryError::RevocationTargetUnknown {
        target_id: id.clone(),
    };
    assert_eq!(e.to_string(), format!("revocation target unknown: {id}"));
}

#[test]
fn error_display_exact_build_descriptor_incomplete() {
    let e = RegistryError::BuildDescriptorIncomplete {
        missing_field: "toolchain_version".to_string(),
    };
    assert_eq!(
        e.to_string(),
        "build descriptor incomplete: missing toolchain_version"
    );
}

// ===========================================================================
// 6) Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_registry_event_type() {
    let variants = [
        RegistryEventType::PublisherRegistered,
        RegistryEventType::PublisherRevoked,
        RegistryEventType::ScopeClaimed,
        RegistryEventType::PackagePublished,
        RegistryEventType::PackageQueried,
        RegistryEventType::PackageVerified,
        RegistryEventType::PackageRevoked,
        RegistryEventType::VerificationFailed,
        RegistryEventType::RevocationPropagated,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

#[test]
fn debug_distinct_event_outcome() {
    let variants = [
        EventOutcome::Success,
        EventOutcome::Denied,
        EventOutcome::Error,
    ];
    let debugs: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), variants.len());
}

// ===========================================================================
// 7) serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_registry_event_type() {
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PublisherRegistered).unwrap(),
        "\"PublisherRegistered\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PublisherRevoked).unwrap(),
        "\"PublisherRevoked\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::ScopeClaimed).unwrap(),
        "\"ScopeClaimed\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PackagePublished).unwrap(),
        "\"PackagePublished\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PackageQueried).unwrap(),
        "\"PackageQueried\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PackageVerified).unwrap(),
        "\"PackageVerified\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::PackageRevoked).unwrap(),
        "\"PackageRevoked\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::VerificationFailed).unwrap(),
        "\"VerificationFailed\""
    );
    assert_eq!(
        serde_json::to_string(&RegistryEventType::RevocationPropagated).unwrap(),
        "\"RevocationPropagated\""
    );
}

#[test]
fn serde_exact_event_outcome() {
    assert_eq!(
        serde_json::to_string(&EventOutcome::Success).unwrap(),
        "\"Success\""
    );
    assert_eq!(
        serde_json::to_string(&EventOutcome::Denied).unwrap(),
        "\"Denied\""
    );
    assert_eq!(
        serde_json::to_string(&EventOutcome::Error).unwrap(),
        "\"Error\""
    );
}

// ===========================================================================
// 8) JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_package_version() {
    let v = PackageVersion::new(1, 2, 3);
    let json = serde_json::to_string(&v).unwrap();
    assert!(json.contains("\"major\""));
    assert!(json.contains("\"minor\""));
    assert!(json.contains("\"patch\""));
}

#[test]
fn json_fields_publisher_identity() {
    let pi = PublisherIdentity {
        id: pub_id(),
        display_name: "test-pub".to_string(),
        verification_key: sk().verification_key(),
        owned_scopes: vec!["myorg".to_string()].into_iter().collect(),
        registered_at: ts(),
        revoked: false,
        revoked_at: None,
        revocation_reason: None,
    };
    let json = serde_json::to_string(&pi).unwrap();
    assert!(json.contains("\"id\""));
    assert!(json.contains("\"display_name\""));
    assert!(json.contains("\"verification_key\""));
    assert!(json.contains("\"owned_scopes\""));
    assert!(json.contains("\"registered_at\""));
    assert!(json.contains("\"revoked\""));
    assert!(json.contains("\"revoked_at\""));
    assert!(json.contains("\"revocation_reason\""));
}

#[test]
fn json_fields_build_descriptor() {
    let bd = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "1.0.0".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec!["-O2".to_string()],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    let json = serde_json::to_string(&bd).unwrap();
    assert!(json.contains("\"toolchain_hash\""));
    assert!(json.contains("\"toolchain_version\""));
    assert!(json.contains("\"source_hash\""));
    assert!(json.contains("\"build_flags\""));
    assert!(json.contains("\"dependency_hashes\""));
    assert!(json.contains("\"reproducible\""));
}

#[test]
fn json_fields_artifact_entry() {
    let ae = ArtifactEntry {
        path: "main.wasm".to_string(),
        content_hash: ContentHash::compute(b"wasm"),
        size_bytes: 1024,
        mime_type: Some("application/wasm".to_string()),
    };
    let json = serde_json::to_string(&ae).unwrap();
    assert!(json.contains("\"path\""));
    assert!(json.contains("\"content_hash\""));
    assert!(json.contains("\"size_bytes\""));
    assert!(json.contains("\"mime_type\""));
}

#[test]
fn json_fields_capability_declaration() {
    let cd = CapabilityDeclaration {
        name: "fs:read".to_string(),
        justification: "needs file access".to_string(),
        optional: false,
    };
    let json = serde_json::to_string(&cd).unwrap();
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"justification\""));
    assert!(json.contains("\"optional\""));
}

#[test]
fn json_fields_package_key() {
    let pk = PackageKey {
        scope: "org".to_string(),
        name: "ext".to_string(),
        version: PackageVersion::new(1, 0, 0),
    };
    let json = serde_json::to_string(&pk).unwrap();
    assert!(json.contains("\"scope\""));
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"version\""));
}

#[test]
fn json_fields_package_query() {
    let pq = PackageQuery::default();
    let json = serde_json::to_string(&pq).unwrap();
    assert!(json.contains("\"scope\""));
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"publisher_id\""));
    assert!(json.contains("\"include_revoked\""));
    assert!(json.contains("\"limit\""));
}

#[test]
fn json_fields_registry_event() {
    let re = RegistryEvent {
        event_type: RegistryEventType::PackagePublished,
        component: "test".to_string(),
        outcome: EventOutcome::Success,
        publisher_id: None,
        package_id: None,
        scope: Some("org".to_string()),
        name: Some("ext".to_string()),
        version: Some(PackageVersion::new(1, 0, 0)),
        error_code: None,
        timestamp: ts(),
    };
    let json = serde_json::to_string(&re).unwrap();
    assert!(json.contains("\"event_type\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"publisher_id\""));
    assert!(json.contains("\"package_id\""));
    assert!(json.contains("\"scope\""));
    assert!(json.contains("\"name\""));
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"error_code\""));
    assert!(json.contains("\"timestamp\""));
}

// ===========================================================================
// 9) PackageQuery default exact values
// ===========================================================================

#[test]
fn package_query_default_exact() {
    let pq = PackageQuery::default();
    assert!(pq.scope.is_none());
    assert!(pq.name.is_none());
    assert!(pq.publisher_id.is_none());
    assert!(!pq.include_revoked);
    assert_eq!(pq.limit, 100);
}

// ===========================================================================
// 10) PackageVersion ordering
// ===========================================================================

#[test]
fn package_version_ordering_major_then_minor_then_patch() {
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(2, 0, 0);
    let v1_1 = PackageVersion::new(1, 1, 0);
    let v1_0_1 = PackageVersion::new(1, 0, 1);
    assert!(v1 < v2);
    assert!(v1 < v1_1);
    assert!(v1 < v1_0_1);
    assert!(v1_0_1 < v1_1);
}

// ===========================================================================
// 11) BuildDescriptor validation
// ===========================================================================

#[test]
fn build_descriptor_validate_empty_toolchain_version() {
    let bd = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: String::new(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec![],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    let err = bd.validate().unwrap_err();
    assert!(matches!(
        err,
        RegistryError::BuildDescriptorIncomplete { .. }
    ));
}

#[test]
fn build_descriptor_validate_valid_passes() {
    let bd = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "rustc-1.80".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec!["-O2".to_string()],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    bd.validate().expect("should pass validation");
}

// ===========================================================================
// 12) BuildDescriptor content hash determinism
// ===========================================================================

#[test]
fn build_descriptor_content_hash_deterministic() {
    let mk = || BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "1.0.0".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec!["-O2".to_string()],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    assert_eq!(mk().content_hash(), mk().content_hash());
}

#[test]
fn build_descriptor_content_hash_differs_for_different_flags() {
    let bd1 = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "1.0.0".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec!["-O2".to_string()],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    let bd2 = BuildDescriptor {
        build_flags: vec!["-O3".to_string()],
        ..bd1.clone()
    };
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

// ===========================================================================
// 13) Serde roundtrips
// ===========================================================================

#[test]
fn serde_roundtrip_package_version() {
    let v = PackageVersion::new(1, 2, 3);
    let json = serde_json::to_string(&v).unwrap();
    let back: PackageVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn serde_roundtrip_artifact_entry() {
    let ae = ArtifactEntry {
        path: "main.wasm".to_string(),
        content_hash: ContentHash::compute(b"wasm"),
        size_bytes: 2048,
        mime_type: None,
    };
    let json = serde_json::to_string(&ae).unwrap();
    let back: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(ae, back);
}

#[test]
fn serde_roundtrip_capability_declaration() {
    let cd = CapabilityDeclaration {
        name: "net:outbound".to_string(),
        justification: "API calls".to_string(),
        optional: true,
    };
    let json = serde_json::to_string(&cd).unwrap();
    let back: CapabilityDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(cd, back);
}

#[test]
fn serde_roundtrip_package_key() {
    let pk = PackageKey {
        scope: "org".to_string(),
        name: "ext".to_string(),
        version: PackageVersion::new(3, 2, 1),
    };
    let json = serde_json::to_string(&pk).unwrap();
    let back: PackageKey = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, back);
}

#[test]
fn serde_roundtrip_package_query() {
    let pq = PackageQuery {
        scope: Some("org".to_string()),
        name: None,
        publisher_id: None,
        include_revoked: true,
        limit: 50,
    };
    let json = serde_json::to_string(&pq).unwrap();
    let back: PackageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(pq, back);
}

// ===========================================================================
// 14) RegistryError Display messages are unique
// ===========================================================================

#[test]
fn registry_error_display_unique() {
    let id = pub_id();
    let msgs: Vec<String> = vec![
        RegistryError::PublisherNotFound {
            publisher_id: id.clone(),
        }
        .to_string(),
        RegistryError::PublisherRevoked {
            publisher_id: id.clone(),
        }
        .to_string(),
        RegistryError::PackageAlreadyExists {
            scope: "s".to_string(),
            name: "n".to_string(),
            version: PackageVersion::new(1, 0, 0),
        }
        .to_string(),
        RegistryError::PackageNotFound {
            scope: "s".to_string(),
            name: "n".to_string(),
            version: PackageVersion::new(1, 0, 0),
        }
        .to_string(),
        RegistryError::PackageRevoked {
            package_id: id.clone(),
        }
        .to_string(),
        RegistryError::SignatureInvalid {
            reason: "bad".to_string(),
        }
        .to_string(),
        RegistryError::ScopeNotOwned {
            scope: "s".to_string(),
            publisher_id: id.clone(),
        }
        .to_string(),
        RegistryError::TooManyCapabilities {
            count: 300,
            max: 256,
        }
        .to_string(),
        RegistryError::TooManyArtifacts {
            count: 2000,
            max: 1024,
        }
        .to_string(),
        RegistryError::InvalidScope {
            scope: "x".to_string(),
            reason: "r".to_string(),
        }
        .to_string(),
        RegistryError::InvalidName {
            name: "n".to_string(),
            reason: "r".to_string(),
        }
        .to_string(),
        RegistryError::RevocationTargetUnknown {
            target_id: id.clone(),
        }
        .to_string(),
        RegistryError::BuildDescriptorIncomplete {
            missing_field: "f".to_string(),
        }
        .to_string(),
    ];
    let set: BTreeSet<&str> = msgs.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), msgs.len());
}

// ===========================================================================
// 15) RegistryError — is std::error::Error
// ===========================================================================

#[test]
fn registry_error_display_nonempty() {
    let e = RegistryError::PackageNotFound {
        scope: "s".to_string(),
        name: "n".to_string(),
        version: PackageVersion::new(0, 0, 1),
    };
    assert!(!e.to_string().is_empty());
}

// ===========================================================================
// 16) Serde roundtrips — additional types
// ===========================================================================

#[test]
fn serde_roundtrip_registry_event_type_all() {
    let types = [
        RegistryEventType::PublisherRegistered,
        RegistryEventType::PublisherRevoked,
        RegistryEventType::ScopeClaimed,
        RegistryEventType::PackagePublished,
        RegistryEventType::PackageQueried,
        RegistryEventType::PackageVerified,
        RegistryEventType::PackageRevoked,
        RegistryEventType::VerificationFailed,
        RegistryEventType::RevocationPropagated,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let back: RegistryEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, back);
    }
}

#[test]
fn serde_roundtrip_event_outcome_all() {
    for o in [
        EventOutcome::Success,
        EventOutcome::Denied,
        EventOutcome::Error,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let back: EventOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }
}

#[test]
fn serde_roundtrip_registry_error_all_variants() {
    let errors: Vec<RegistryError> = vec![
        RegistryError::PublisherNotFound {
            publisher_id: pub_id(),
        },
        RegistryError::PublisherRevoked {
            publisher_id: pub_id(),
        },
        RegistryError::PackageAlreadyExists {
            scope: "s".to_string(),
            name: "n".to_string(),
            version: PackageVersion::new(1, 0, 0),
        },
        RegistryError::PackageNotFound {
            scope: "s".to_string(),
            name: "n".to_string(),
            version: PackageVersion::new(1, 0, 0),
        },
        RegistryError::PackageRevoked {
            package_id: pub_id(),
        },
        RegistryError::SignatureInvalid {
            reason: "bad sig".to_string(),
        },
        RegistryError::ContentHashMismatch {
            artifact_name: "main.wasm".to_string(),
            expected: ContentHash::compute(b"expected"),
            actual: ContentHash::compute(b"actual"),
        },
        RegistryError::ScopeNotOwned {
            scope: "s".to_string(),
            publisher_id: pub_id(),
        },
        RegistryError::TooManyCapabilities {
            count: 500,
            max: 256,
        },
        RegistryError::TooManyArtifacts {
            count: 2000,
            max: 1024,
        },
        RegistryError::InvalidScope {
            scope: "".to_string(),
            reason: "empty".to_string(),
        },
        RegistryError::InvalidName {
            name: "".to_string(),
            reason: "empty".to_string(),
        },
        RegistryError::RevocationTargetUnknown {
            target_id: pub_id(),
        },
        RegistryError::BuildDescriptorIncomplete {
            missing_field: "toolchain_version".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: RegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn serde_roundtrip_build_descriptor() {
    let bd = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "1.82.0-nightly".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec!["--release".to_string()],
        dependency_hashes: BTreeMap::new(),
        reproducible: true,
    };
    let json = serde_json::to_string(&bd).unwrap();
    let back: BuildDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(bd, back);
}

#[test]
fn serde_roundtrip_publisher_identity() {
    let pi = PublisherIdentity {
        id: pub_id(),
        display_name: "test publisher".to_string(),
        verification_key: sk().verification_key(),
        owned_scopes: vec!["test-scope".to_string()].into_iter().collect(),
        registered_at: ts(),
        revoked: false,
        revoked_at: None,
        revocation_reason: None,
    };
    let json = serde_json::to_string(&pi).unwrap();
    let back: PublisherIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(pi, back);
}

// ===========================================================================
// 17) ExtensionRegistry — construction and initial state
// ===========================================================================

#[test]
fn registry_new_initial_state() {
    let registry = ExtensionRegistry::new(ts());
    assert_eq!(registry.package_count(), 0);
    assert_eq!(registry.publisher_count(), 0);
    assert_eq!(registry.audit_event_count(), 0);
    assert!(registry.events().is_empty());
}

// ===========================================================================
// 18) ExtensionRegistry — publisher lifecycle
// ===========================================================================

#[test]
fn registry_register_publisher() {
    let mut registry = ExtensionRegistry::new(ts());
    let vk = sk().verification_key();
    let publisher_id = registry.register_publisher("Test Publisher", vk).unwrap();
    assert_eq!(registry.publisher_count(), 1);
    assert!(registry.is_publisher_active(&publisher_id));
    let pub_info = registry.get_publisher(&publisher_id).unwrap();
    assert_eq!(pub_info.display_name, "Test Publisher");
    assert!(!pub_info.revoked);
}

#[test]
fn registry_revoke_publisher() {
    let mut registry = ExtensionRegistry::new(ts());
    let vk = sk().verification_key();
    let publisher_id = registry.register_publisher("Test Publisher", vk).unwrap();
    assert!(registry.is_publisher_active(&publisher_id));
    let pid_copy = publisher_id.clone();
    registry
        .revoke_publisher(publisher_id, "compromised key")
        .unwrap();
    assert!(!registry.is_publisher_active(&pid_copy));
    let pub_info = registry.get_publisher(&pid_copy).unwrap();
    assert!(pub_info.revoked);
}

#[test]
fn registry_get_nonexistent_publisher() {
    let registry = ExtensionRegistry::new(ts());
    let fake_id = pub_id();
    assert!(registry.get_publisher(&fake_id).is_none());
    assert!(!registry.is_publisher_active(&fake_id));
}

// ===========================================================================
// 19) Scope management
// ===========================================================================

#[test]
fn registry_claim_scope_and_ownership() {
    let mut registry = ExtensionRegistry::new(ts());
    let vk = sk().verification_key();
    let publisher_id = registry.register_publisher("Test", vk).unwrap();
    let pid_copy = publisher_id.clone();
    registry.claim_scope(publisher_id, "my-scope").unwrap();
    assert!(registry.publisher_owns_scope(&pid_copy, "my-scope"));
    assert!(!registry.publisher_owns_scope(&pid_copy, "other-scope"));
}

// ===========================================================================
// 20) PackageVersion edge cases
// ===========================================================================

#[test]
fn package_version_zero() {
    let v = PackageVersion::new(0, 0, 0);
    assert_eq!(v.to_string(), "0.0.0");
}

#[test]
fn package_version_large_numbers() {
    let v = PackageVersion::new(999, 999, 999);
    assert_eq!(v.to_string(), "999.999.999");
}

#[test]
fn package_version_ordering_patch_only() {
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(1, 0, 1);
    assert!(v1 < v2);
}

#[test]
fn package_version_ordering_minor_beats_patch() {
    let v1 = PackageVersion::new(1, 0, 999);
    let v2 = PackageVersion::new(1, 1, 0);
    assert!(v1 < v2);
}

// ===========================================================================
// 21) RegistryEvent — audit trail
// ===========================================================================

#[test]
fn registry_events_emitted_on_register() {
    let mut registry = ExtensionRegistry::new(ts());
    let vk = sk().verification_key();
    registry.register_publisher("Test", vk).unwrap();
    assert!(registry.audit_event_count() > 0);
    let events = registry.export_audit_log();
    assert!(!events.is_empty());
    let first = &events[0];
    assert_eq!(first.event_type, RegistryEventType::PublisherRegistered);
    assert_eq!(first.component, "extension_registry");
    assert_eq!(first.outcome, EventOutcome::Success);
}

// ===========================================================================
// 22) RegistryError — ContentHashMismatch Display
// ===========================================================================

#[test]
fn error_display_exact_content_hash_mismatch() {
    let e = RegistryError::ContentHashMismatch {
        artifact_name: "main.wasm".to_string(),
        expected: ContentHash::compute(b"expected"),
        actual: ContentHash::compute(b"actual"),
    };
    let s = e.to_string();
    assert!(s.contains("main.wasm"), "should contain artifact name: {s}");
}

// ===========================================================================
// 23) JSON field-name stability — VerificationResult
// ===========================================================================

#[test]
fn json_fields_verification_result() {
    let vr = VerificationResult {
        valid: true,
        package_id: pub_id(),
        publisher_key: sk().verification_key(),
        publisher_active: true,
        package_active: true,
        structure_valid: true,
        signature_valid: true,
        artifacts_root_valid: true,
        errors: vec![],
    };
    let json = serde_json::to_string(&vr).unwrap();
    assert!(json.contains("\"valid\""));
    assert!(json.contains("\"package_id\""));
    assert!(json.contains("\"publisher_key\""));
    assert!(json.contains("\"publisher_active\""));
    assert!(json.contains("\"package_active\""));
    assert!(json.contains("\"structure_valid\""));
    assert!(json.contains("\"signature_valid\""));
    assert!(json.contains("\"artifacts_root_valid\""));
    assert!(json.contains("\"errors\""));
}

#[test]
fn serde_roundtrip_verification_result() {
    let vr = VerificationResult {
        valid: false,
        package_id: pub_id(),
        publisher_key: sk().verification_key(),
        publisher_active: false,
        package_active: false,
        structure_valid: true,
        signature_valid: false,
        artifacts_root_valid: true,
        errors: vec!["bad signature".to_string()],
    };
    let json = serde_json::to_string(&vr).unwrap();
    let back: VerificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(vr, back);
}

// ===========================================================================
// Enrichment tests: extension registration, lookup, capacity, version
// management, error handling, concurrent registration patterns
// ===========================================================================

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::extension_registry::{ExtensionManifest, SignedPackage};
use frankenengine_engine::signature_preimage::{VerificationKey, sign_preimage};

// ---------------------------------------------------------------------------
// Enrichment helpers
// ---------------------------------------------------------------------------

fn enrichment_signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(seed).wrapping_add(seed);
    }
    SigningKey(bytes)
}

fn enrichment_vk_from(sk: &SigningKey) -> VerificationKey {
    sk.verification_key()
}

fn enrichment_build_descriptor() -> BuildDescriptor {
    BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"rustc-1.77"),
        toolchain_version: "1.77.0".to_string(),
        source_hash: ContentHash::compute(b"source-tree"),
        build_flags: vec!["--release".to_string()],
        dependency_hashes: {
            let mut m = BTreeMap::new();
            m.insert("serde".to_string(), ContentHash::compute(b"serde-1.0"));
            m
        },
        reproducible: true,
    }
}

fn enrichment_artifact(path: &str) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_string(),
        content_hash: ContentHash::compute(path.as_bytes()),
        size_bytes: 4096,
        mime_type: Some("application/octet-stream".to_string()),
    }
}

fn enrichment_capability(name: &str) -> CapabilityDeclaration {
    CapabilityDeclaration {
        name: name.to_string(),
        justification: format!("needs {name}"),
        optional: false,
    }
}

fn enrichment_manifest(
    scope: &str,
    name: &str,
    version: PackageVersion,
    publisher_id: &EngineObjectId,
    publisher_key: &VerificationKey,
) -> ExtensionManifest {
    let artifacts = vec![enrichment_artifact("main.fir")];
    let mut buf = Vec::new();
    for art in &artifacts {
        buf.extend_from_slice(art.path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(art.content_hash.as_bytes());
        buf.extend_from_slice(&art.size_bytes.to_le_bytes());
    }
    let artifacts_root_hash = ContentHash::compute(&buf);

    ExtensionManifest {
        scope: scope.to_string(),
        name: name.to_string(),
        version,
        publisher_id: publisher_id.clone(),
        publisher_key: publisher_key.clone(),
        capabilities: vec![enrichment_capability("net:outbound")],
        artifacts,
        build: enrichment_build_descriptor(),
        artifacts_root_hash,
        description: format!("Test extension @{scope}/{name}"),
        license: Some("MIT".to_string()),
        dependencies: BTreeMap::new(),
    }
}

fn enrichment_publish(
    reg: &mut ExtensionRegistry,
    m: &ExtensionManifest,
    sk: &SigningKey,
) -> Result<EngineObjectId, RegistryError> {
    let sig = sign_preimage(sk, &m.unsigned_bytes()).expect("signing");
    reg.publish(m.clone(), sig)
}

fn enrichment_setup() -> (
    ExtensionRegistry,
    EngineObjectId,
    SigningKey,
    VerificationKey,
) {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(100));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("TestOrg", vk.clone()).unwrap();
    reg.claim_scope(pub_id.clone(), "testorg").unwrap();
    (reg, pub_id, sk, vk)
}

// ---------------------------------------------------------------------------
// 1. Extension registration and lookup
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_single_extension_and_lookup_by_scope_name_version() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "my-ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "my-ext", v).unwrap();
    assert_eq!(pkg.manifest.scope, "testorg");
    assert_eq!(pkg.manifest.name, "my-ext");
    assert_eq!(pkg.manifest.version, v);
}

#[test]
fn enrichment_lookup_nonexistent_scope_returns_none() {
    let (reg, _, _, _) = enrichment_setup();
    assert!(
        reg.get_package("nosuchscope", "ext", PackageVersion::new(1, 0, 0))
            .is_none()
    );
}

#[test]
fn enrichment_lookup_nonexistent_name_returns_none() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "exists", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    assert!(reg.get_package("testorg", "doesnotexist", v).is_none());
}

#[test]
fn enrichment_lookup_nonexistent_version_returns_none() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    assert!(
        reg.get_package("testorg", "ext", PackageVersion::new(2, 0, 0))
            .is_none()
    );
}

#[test]
fn enrichment_lookup_by_id_matches_publish_result() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let pkg_id = enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package_by_id(&pkg_id).unwrap();
    assert_eq!(pkg.package_id, pkg_id);
    assert_eq!(pkg.manifest.scope, "testorg");
}

#[test]
fn enrichment_lookup_by_id_unknown_returns_none() {
    let (reg, _, _, _) = enrichment_setup();
    let fake = EngineObjectId([99; 32]);
    assert!(reg.get_package_by_id(&fake).is_none());
}

#[test]
fn enrichment_register_multiple_extensions_different_names() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    for name in ["alpha", "beta", "gamma", "delta"] {
        let m = enrichment_manifest("testorg", name, v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    assert_eq!(reg.package_count(), 4);

    for name in ["alpha", "beta", "gamma", "delta"] {
        assert!(reg.get_package("testorg", name, v).is_some());
    }
}

#[test]
fn enrichment_publisher_id_stored_correctly_in_package() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.manifest.publisher_id, pub_id);
    assert_eq!(pkg.manifest.publisher_key, vk);
}

#[test]
fn enrichment_published_at_timestamp_matches_registry_clock() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    reg.advance_tick(DeterministicTimestamp(999));
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.published_at, DeterministicTimestamp(999));
}

#[test]
fn enrichment_newly_published_package_not_revoked() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert!(!pkg.revoked);
    assert!(pkg.revoked_at.is_none());
    assert!(pkg.revocation_reason.is_none());
}

// ---------------------------------------------------------------------------
// 2. Registry capacity and overflow
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publish_many_packages_up_to_50() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..50 {
        let v = PackageVersion::new(0, 0, i);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    assert_eq!(reg.package_count(), 50);
}

#[test]
fn enrichment_many_publishers_each_with_own_scope() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    for i in 0..20u8 {
        let sk = enrichment_signing_key(i.wrapping_add(10));
        let vk = enrichment_vk_from(&sk);
        let scope = format!("org-{i}");
        let pub_id = reg.register_publisher(&format!("Org{i}"), vk.clone()).unwrap();
        reg.claim_scope(pub_id.clone(), &scope).unwrap();
        let v = PackageVersion::new(1, 0, 0);
        let m = enrichment_manifest(&scope, "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    assert_eq!(reg.publisher_count(), 20);
    assert_eq!(reg.package_count(), 20);
}

#[test]
fn enrichment_max_artifacts_boundary_accepted() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    // Exactly 1024 artifacts (the maximum)
    m.artifacts = (0..1024)
        .map(|i| enrichment_artifact(&format!("file_{i}.dat")))
        .collect();
    let mut buf = Vec::new();
    for art in &m.artifacts {
        buf.extend_from_slice(art.path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(art.content_hash.as_bytes());
        buf.extend_from_slice(&art.size_bytes.to_le_bytes());
    }
    m.artifacts_root_hash = ContentHash::compute(&buf);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(result.is_ok());
}

#[test]
fn enrichment_one_over_max_artifacts_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.artifacts = (0..1025)
        .map(|i| enrichment_artifact(&format!("file_{i}.dat")))
        .collect();
    let mut buf = Vec::new();
    for art in &m.artifacts {
        buf.extend_from_slice(art.path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(art.content_hash.as_bytes());
        buf.extend_from_slice(&art.size_bytes.to_le_bytes());
    }
    m.artifacts_root_hash = ContentHash::compute(&buf);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::TooManyArtifacts { count: 1025, max: 1024 })));
}

#[test]
fn enrichment_max_capabilities_boundary_accepted() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.capabilities = (0..256)
        .map(|i| enrichment_capability(&format!("cap:{i}")))
        .collect();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(result.is_ok());
}

#[test]
fn enrichment_one_over_max_capabilities_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.capabilities = (0..257)
        .map(|i| enrichment_capability(&format!("cap:{i}")))
        .collect();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::TooManyCapabilities { count: 257, max: 256 })));
}

#[test]
fn enrichment_scope_max_length_128_accepted() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    let scope: String = "a".repeat(128);
    reg.claim_scope(pub_id.clone(), &scope).unwrap();
    assert!(reg.publisher_owns_scope(&pub_id, &scope));
}

#[test]
fn enrichment_scope_129_chars_rejected() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    let scope: String = "a".repeat(129);
    let result = reg.claim_scope(pub_id, &scope);
    assert!(matches!(result, Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_name_max_length_128_accepted() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let name: String = "a".repeat(128);
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", &name, v, &pub_id, &vk);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// 3. Version management
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_major_versions_coexist() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for major in 1..=5 {
        let v = PackageVersion::new(major, 0, 0);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    let versions = reg.list_versions("testorg", "ext");
    assert_eq!(versions.len(), 5);
}

#[test]
fn enrichment_revoke_old_version_keeps_newer_active() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(2, 0, 0);
    let m1 = enrichment_manifest("testorg", "ext", v1, &pub_id, &vk);
    let m2 = enrichment_manifest("testorg", "ext", v2, &pub_id, &vk);
    enrichment_publish(&mut reg, &m1, &sk).unwrap();
    enrichment_publish(&mut reg, &m2, &sk).unwrap();

    reg.revoke_package("testorg", "ext", v1, "deprecated").unwrap();
    assert!(reg.is_package_revoked("testorg", "ext", v1));
    assert!(!reg.is_package_revoked("testorg", "ext", v2));
}

#[test]
fn enrichment_version_0_0_0_is_publishable() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(0, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    assert!(reg.get_package("testorg", "ext", v).is_some());
}

#[test]
fn enrichment_version_ordering_transitive() {
    let v1 = PackageVersion::new(0, 1, 0);
    let v2 = PackageVersion::new(0, 2, 0);
    let v3 = PackageVersion::new(1, 0, 0);
    assert!(v1 < v2);
    assert!(v2 < v3);
    assert!(v1 < v3); // transitivity
}

#[test]
fn enrichment_version_equality_reflexive() {
    let v = PackageVersion::new(3, 2, 1);
    assert_eq!(v, v);
}

#[test]
fn enrichment_version_copy_semantics() {
    let v1 = PackageVersion::new(1, 2, 3);
    let v2 = v1; // Copy
    assert_eq!(v1, v2);
}

#[test]
fn enrichment_list_versions_empty_for_unknown_package() {
    let (reg, _, _, _) = enrichment_setup();
    let versions = reg.list_versions("testorg", "nonexistent");
    assert!(versions.is_empty());
}

#[test]
fn enrichment_list_versions_includes_revoked() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(1, 1, 0);
    let m1 = enrichment_manifest("testorg", "ext", v1, &pub_id, &vk);
    let m2 = enrichment_manifest("testorg", "ext", v2, &pub_id, &vk);
    enrichment_publish(&mut reg, &m1, &sk).unwrap();
    enrichment_publish(&mut reg, &m2, &sk).unwrap();
    reg.revoke_package("testorg", "ext", v1, "old").unwrap();

    // list_versions should still return both
    let versions = reg.list_versions("testorg", "ext");
    assert_eq!(versions.len(), 2);
}

#[test]
fn enrichment_same_name_different_scopes_are_independent() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(7);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    let sk_b = enrichment_signing_key(13);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    let m_a = enrichment_manifest("orga", "shared-name", v, &pub_a, &vk_a);
    let m_b = enrichment_manifest("orgb", "shared-name", v, &pub_b, &vk_b);
    enrichment_publish(&mut reg, &m_a, &sk_a).unwrap();
    enrichment_publish(&mut reg, &m_b, &sk_b).unwrap();

    assert_eq!(reg.package_count(), 2);
    let pa = reg.get_package("orga", "shared-name", v).unwrap();
    let pb = reg.get_package("orgb", "shared-name", v).unwrap();
    assert_ne!(pa.package_id, pb.package_id);
}

// ---------------------------------------------------------------------------
// 4. Error handling for invalid extensions
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publish_with_empty_name_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "valid", v, &pub_id, &vk);
    m.name = String::new();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

#[test]
fn enrichment_publish_with_empty_scope_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.scope = String::new();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_publish_with_special_chars_in_name_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = "bad name!".to_string();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

#[test]
fn enrichment_publish_with_dots_in_scope_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.scope = "my.org".to_string();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_publish_with_slash_in_name_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = "path/traversal".to_string();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

#[test]
fn enrichment_publish_to_unowned_scope_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("otherscope", "ext", v, &pub_id, &vk);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));
}

#[test]
fn enrichment_publish_from_unknown_publisher_rejected() {
    let (mut reg, _, sk, _) = enrichment_setup();
    let fake_pub = EngineObjectId([55; 32]);
    let fake_vk = VerificationKey([66; 32]);
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &fake_pub, &fake_vk);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::PublisherNotFound { .. })));
}

#[test]
fn enrichment_publish_from_revoked_publisher_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    reg.revoke_publisher(pub_id.clone(), "compromised key").unwrap();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::PublisherRevoked { .. })));
}

#[test]
fn enrichment_publish_with_wrong_key_rejected() {
    let (mut reg, pub_id, _, vk) = enrichment_setup();
    let wrong_sk = enrichment_signing_key(99);
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let result = enrichment_publish(&mut reg, &m, &wrong_sk);
    assert!(matches!(result, Err(RegistryError::SignatureInvalid { .. })));
}

#[test]
fn enrichment_publish_with_artifacts_root_mismatch_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.artifacts_root_hash = ContentHash::compute(b"wrong-hash");
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::ContentHashMismatch { .. })));
}

#[test]
fn enrichment_publish_with_empty_toolchain_version_rejected() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.build.toolchain_version = String::new();
    let result = enrichment_publish(&mut reg, &m, &sk);
    assert!(matches!(result, Err(RegistryError::BuildDescriptorIncomplete { .. })));
}

#[test]
fn enrichment_revoke_already_revoked_package_succeeds() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.revoke_package("testorg", "ext", v, "first").unwrap();
    // Second revocation overwrites reason — should not error
    reg.revoke_package("testorg", "ext", v, "second").unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert!(pkg.revoked);
    assert_eq!(pkg.revocation_reason.as_deref(), Some("second"));
}

#[test]
fn enrichment_revoke_nonexistent_package_errors() {
    let (mut reg, _, _, _) = enrichment_setup();
    let result = reg.revoke_package("testorg", "noext", PackageVersion::new(1, 0, 0), "test");
    assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
}

#[test]
fn enrichment_revoke_by_id_unknown_errors() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake_id = EngineObjectId([42; 32]);
    let result = reg.revoke_package_by_id(fake_id, "test");
    assert!(matches!(result, Err(RegistryError::RevocationTargetUnknown { .. })));
}

#[test]
fn enrichment_verify_nonexistent_package_errors() {
    let (mut reg, _, _, _) = enrichment_setup();
    let result = reg.verify_package("testorg", "noext", PackageVersion::new(1, 0, 0));
    assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
}

// ---------------------------------------------------------------------------
// 5. Concurrent registration patterns (simulated multi-publisher scenarios)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_two_publishers_can_claim_different_scopes() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(10);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "scope-a").unwrap();

    let sk_b = enrichment_signing_key(20);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "scope-b").unwrap();

    assert!(reg.publisher_owns_scope(&pub_a, "scope-a"));
    assert!(!reg.publisher_owns_scope(&pub_a, "scope-b"));
    assert!(reg.publisher_owns_scope(&pub_b, "scope-b"));
    assert!(!reg.publisher_owns_scope(&pub_b, "scope-a"));
}

#[test]
fn enrichment_second_publisher_cannot_claim_existing_scope() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(10);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a).unwrap();
    reg.claim_scope(pub_a.clone(), "shared").unwrap();

    let sk_b = enrichment_signing_key(20);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b).unwrap();
    let result = reg.claim_scope(pub_b, "shared");
    assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));
}

#[test]
fn enrichment_publisher_revocation_propagates_to_all_packages() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..10 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    reg.revoke_publisher(pub_id.clone(), "key leak").unwrap();

    for i in 0..10 {
        let v = PackageVersion::new(1, 0, i);
        assert!(reg.is_package_revoked("testorg", "ext", v));
    }
}

#[test]
fn enrichment_revoked_publisher_packages_affected_list() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..5 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", &format!("ext-{i}"), v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    let affected = reg.packages_affected_by_publisher_revocation(&pub_id);
    assert_eq!(affected.len(), 5);
}

#[test]
fn enrichment_multiple_publishers_publish_interleaved() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(7);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    let sk_b = enrichment_signing_key(13);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    // Interleave publishes from both publishers
    for i in 0..5 {
        let v = PackageVersion::new(1, 0, i);
        let m_a = enrichment_manifest("orga", "ext", v, &pub_a, &vk_a);
        enrichment_publish(&mut reg, &m_a, &sk_a).unwrap();
        let m_b = enrichment_manifest("orgb", "ext", v, &pub_b, &vk_b);
        enrichment_publish(&mut reg, &m_b, &sk_b).unwrap();
    }
    assert_eq!(reg.package_count(), 10);
}

#[test]
fn enrichment_revoke_one_publisher_doesnt_affect_other() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(7);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    let sk_b = enrichment_signing_key(13);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    let m_a = enrichment_manifest("orga", "ext", v, &pub_a, &vk_a);
    enrichment_publish(&mut reg, &m_a, &sk_a).unwrap();
    let m_b = enrichment_manifest("orgb", "ext", v, &pub_b, &vk_b);
    enrichment_publish(&mut reg, &m_b, &sk_b).unwrap();

    reg.revoke_publisher(pub_a.clone(), "compromised").unwrap();
    assert!(reg.is_package_revoked("orga", "ext", v));
    assert!(!reg.is_package_revoked("orgb", "ext", v));
}

// ---------------------------------------------------------------------------
// 6. Search / query enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_search_with_limit_zero_returns_empty() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let results = reg.search(&PackageQuery {
        limit: 0,
        ..PackageQuery::default()
    });
    assert!(results.is_empty());
}

#[test]
fn enrichment_search_with_limit_1_returns_at_most_1() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..5 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    let results = reg.search(&PackageQuery {
        limit: 1,
        ..PackageQuery::default()
    });
    assert!(results.len() <= 1);
}

#[test]
fn enrichment_search_by_publisher_id_filters_correctly() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = enrichment_signing_key(7);
    let vk_a = enrichment_vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    let sk_b = enrichment_signing_key(13);
    let vk_b = enrichment_vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    enrichment_publish(&mut reg, &enrichment_manifest("orga", "ext", v, &pub_a, &vk_a), &sk_a).unwrap();
    enrichment_publish(&mut reg, &enrichment_manifest("orgb", "ext", v, &pub_b, &vk_b), &sk_b).unwrap();

    let results = reg.search(&PackageQuery {
        publisher_id: Some(pub_a.clone()),
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].manifest.scope, "orga");
}

#[test]
fn enrichment_search_include_revoked_true_shows_all() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..3 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    reg.revoke_package("testorg", "ext", PackageVersion::new(1, 0, 0), "old").unwrap();
    reg.revoke_package("testorg", "ext", PackageVersion::new(1, 0, 1), "old").unwrap();

    let default_results = reg.search(&PackageQuery::default());
    assert_eq!(default_results.len(), 1);

    let all_results = reg.search(&PackageQuery {
        include_revoked: true,
        ..PackageQuery::default()
    });
    assert_eq!(all_results.len(), 3);
}

#[test]
fn enrichment_search_combined_scope_and_name() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    enrichment_publish(&mut reg, &enrichment_manifest("testorg", "alpha", v, &pub_id, &vk), &sk).unwrap();
    enrichment_publish(&mut reg, &enrichment_manifest("testorg", "beta", v, &pub_id, &vk), &sk).unwrap();

    let results = reg.search(&PackageQuery {
        scope: Some("testorg".to_string()),
        name: Some("alpha".to_string()),
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].manifest.name, "alpha");
}

#[test]
fn enrichment_search_empty_registry_returns_empty() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let results = reg.search(&PackageQuery::default());
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// 7. Verification enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_verify_valid_package_all_fields_ok() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let vr = reg.verify_package("testorg", "ext", v).unwrap();
    assert!(vr.valid);
    assert!(vr.signature_valid);
    assert!(vr.structure_valid);
    assert!(vr.artifacts_root_valid);
    assert!(vr.publisher_active);
    assert!(vr.package_active);
    assert!(vr.errors.is_empty());
}

#[test]
fn enrichment_verify_revoked_package_reports_not_valid() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.revoke_package("testorg", "ext", v, "vuln").unwrap();

    let vr = reg.verify_package("testorg", "ext", v).unwrap();
    assert!(!vr.valid);
    assert!(!vr.package_active);
    // signature is still valid even though package is revoked
    assert!(vr.signature_valid);
}

#[test]
fn enrichment_verify_publisher_revoked_reports_not_valid() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.revoke_publisher(pub_id.clone(), "key compromise").unwrap();

    let vr = reg.verify_package("testorg", "ext", v).unwrap();
    assert!(!vr.valid);
    assert!(!vr.publisher_active);
    assert!(vr.signature_valid);
}

#[test]
fn enrichment_verify_emits_audit_event() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let before = reg.audit_event_count();
    reg.verify_package("testorg", "ext", v).unwrap();
    assert!(reg.audit_event_count() > before);

    let events = reg.export_audit_log();
    let verify_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::PackageVerified)
        .collect();
    assert!(!verify_events.is_empty());
}

// ---------------------------------------------------------------------------
// 8. Audit trail enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_audit_trail_publisher_registration_event() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    reg.register_publisher("Test", vk).unwrap();

    let events = reg.export_audit_log();
    assert!(!events.is_empty());
    assert_eq!(events[0].event_type, RegistryEventType::PublisherRegistered);
    assert_eq!(events[0].outcome, EventOutcome::Success);
    assert_eq!(events[0].component, "extension_registry");
}

#[test]
fn enrichment_audit_trail_scope_claimed_event() {
    let (reg, _, _, _) = enrichment_setup();
    let events = reg.export_audit_log();
    let scope_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::ScopeClaimed)
        .collect();
    assert!(!scope_events.is_empty());
    assert_eq!(scope_events[0].scope.as_deref(), Some("testorg"));
}

#[test]
fn enrichment_audit_trail_publish_event() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let events = reg.export_audit_log();
    let pub_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::PackagePublished)
        .collect();
    assert_eq!(pub_events.len(), 1);
    assert_eq!(pub_events[0].scope.as_deref(), Some("testorg"));
    assert_eq!(pub_events[0].name.as_deref(), Some("ext"));
    assert_eq!(pub_events[0].version, Some(v));
}

#[test]
fn enrichment_audit_trail_revocation_event() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.revoke_package("testorg", "ext", v, "CVE-2026-001").unwrap();

    let events = reg.export_audit_log();
    let revoke_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::PackageRevoked)
        .collect();
    assert!(!revoke_events.is_empty());
    assert_eq!(revoke_events[0].outcome, EventOutcome::Success);
}

#[test]
fn enrichment_audit_trail_failed_signature_event() {
    let (mut reg, pub_id, _, vk) = enrichment_setup();
    let wrong_sk = enrichment_signing_key(99);
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let _ = enrichment_publish(&mut reg, &m, &wrong_sk);

    let events = reg.export_audit_log();
    let fail_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::VerificationFailed)
        .collect();
    assert!(!fail_events.is_empty());
    assert_eq!(fail_events[0].outcome, EventOutcome::Denied);
    assert!(fail_events[0].error_code.is_some());
}

#[test]
fn enrichment_audit_event_count_monotonically_increases() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let mut last_count = reg.audit_event_count();
    for i in 0..5 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
        let new_count = reg.audit_event_count();
        assert!(new_count > last_count);
        last_count = new_count;
    }
}

#[test]
fn enrichment_audit_events_all_have_component_field() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.verify_package("testorg", "ext", v).unwrap();
    reg.revoke_package("testorg", "ext", v, "test").unwrap();

    for event in reg.export_audit_log() {
        assert_eq!(event.component, "extension_registry");
    }
}

// ---------------------------------------------------------------------------
// 9. Serde round-trip enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_full_registry_serde_preserves_packages() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    for i in 0..5 {
        let v = PackageVersion::new(1, 0, i);
        let m = enrichment_manifest("testorg", &format!("ext-{i}"), v, &pub_id, &vk);
        enrichment_publish(&mut reg, &m, &sk).unwrap();
    }
    reg.revoke_package("testorg", "ext-0", PackageVersion::new(1, 0, 0), "old").unwrap();

    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExtensionRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.package_count(), 5);
    assert_eq!(restored.publisher_count(), reg.publisher_count());
    assert!(restored.is_package_revoked("testorg", "ext-0", PackageVersion::new(1, 0, 0)));
    assert!(!restored.is_package_revoked("testorg", "ext-1", PackageVersion::new(1, 0, 1)));
}

#[test]
fn enrichment_signed_package_serde_roundtrip_preserves_all_fields() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(3, 2, 1);
    let m = enrichment_manifest("testorg", "serde-test", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "serde-test", v).unwrap();
    let json = serde_json::to_string(pkg).unwrap();
    let restored: SignedPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.package_id, pkg.package_id);
    assert_eq!(restored.manifest.scope, "testorg");
    assert_eq!(restored.manifest.name, "serde-test");
    assert_eq!(restored.manifest.version, v);
    assert_eq!(restored.published_at, pkg.published_at);
    assert!(!restored.revoked);
    assert_eq!(restored.manifest.capabilities.len(), 1);
}

#[test]
fn enrichment_serde_roundtrip_revoked_package_preserves_revocation() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();
    reg.advance_tick(DeterministicTimestamp(500));
    reg.revoke_package("testorg", "ext", v, "vuln").unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    let json = serde_json::to_string(pkg).unwrap();
    let restored: SignedPackage = serde_json::from_str(&json).unwrap();
    assert!(restored.revoked);
    assert_eq!(restored.revoked_at, Some(DeterministicTimestamp(500)));
    assert_eq!(restored.revocation_reason.as_deref(), Some("vuln"));
}

#[test]
fn enrichment_extension_manifest_serde_roundtrip() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let json = serde_json::to_string(&m).unwrap();
    let restored: ExtensionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// ---------------------------------------------------------------------------
// 10. Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_deterministic_publisher_id_same_inputs() {
    let sk = enrichment_signing_key(42);
    let vk = enrichment_vk_from(&sk);

    let mut r1 = ExtensionRegistry::new(DeterministicTimestamp(1));
    let id1 = r1.register_publisher("DeterTest", vk.clone()).unwrap();

    let mut r2 = ExtensionRegistry::new(DeterministicTimestamp(1));
    let id2 = r2.register_publisher("DeterTest", vk).unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_deterministic_package_id_same_manifest() {
    let (mut r1, p1, sk1, vk1) = enrichment_setup();
    let (mut r2, p2, sk2, vk2) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = enrichment_manifest("testorg", "ext", v, &p1, &vk1);
    let m2 = enrichment_manifest("testorg", "ext", v, &p2, &vk2);
    let id1 = enrichment_publish(&mut r1, &m1, &sk1).unwrap();
    let id2 = enrichment_publish(&mut r2, &m2, &sk2).unwrap();
    assert_eq!(id1, id2);
}

#[test]
fn enrichment_different_scope_gives_different_package_id() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("Test", vk.clone()).unwrap();
    reg.claim_scope(pub_id.clone(), "scope-a").unwrap();
    reg.claim_scope(pub_id.clone(), "scope-b").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    let m_a = enrichment_manifest("scope-a", "ext", v, &pub_id, &vk);
    let m_b = enrichment_manifest("scope-b", "ext", v, &pub_id, &vk);
    let id_a = enrichment_publish(&mut reg, &m_a, &sk).unwrap();
    let id_b = enrichment_publish(&mut reg, &m_b, &sk).unwrap();
    assert_ne!(id_a, id_b);
}

#[test]
fn enrichment_different_version_gives_different_package_id() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(1, 0, 1);
    let m1 = enrichment_manifest("testorg", "ext", v1, &pub_id, &vk);
    let m2 = enrichment_manifest("testorg", "ext", v2, &pub_id, &vk);
    let id1 = enrichment_publish(&mut reg, &m1, &sk).unwrap();
    let id2 = enrichment_publish(&mut reg, &m2, &sk).unwrap();
    assert_ne!(id1, id2);
}

// ---------------------------------------------------------------------------
// 11. Manifest structure validation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_manifest_validate_structure_accepts_valid() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    assert!(m.validate_structure().is_ok());
}

#[test]
fn enrichment_manifest_validate_structure_rejects_empty_scope() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.scope = String::new();
    assert!(matches!(m.validate_structure(), Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_manifest_validate_structure_rejects_empty_name() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = String::new();
    assert!(matches!(m.validate_structure(), Err(RegistryError::InvalidName { .. })));
}

#[test]
fn enrichment_manifest_unsigned_bytes_changes_with_description() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let mut m2 = m1.clone();
    m2.description = "different description".to_string();
    assert_ne!(m1.unsigned_bytes(), m2.unsigned_bytes());
}

#[test]
fn enrichment_manifest_unsigned_bytes_changes_with_license() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let mut m2 = m1.clone();
    m2.license = Some("Apache-2.0".to_string());
    assert_ne!(m1.unsigned_bytes(), m2.unsigned_bytes());
}

#[test]
fn enrichment_manifest_compute_artifacts_root_deterministic() {
    let (_, pub_id, _, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    let root1 = m.compute_artifacts_root();
    let root2 = m.compute_artifacts_root();
    assert_eq!(root1, root2);
    assert_eq!(root1, m.artifacts_root_hash);
}

// ---------------------------------------------------------------------------
// 12. BuildDescriptor enrichment
// ---------------------------------------------------------------------------

#[test]
fn enrichment_build_descriptor_content_hash_changes_with_toolchain() {
    let bd1 = enrichment_build_descriptor();
    let mut bd2 = bd1.clone();
    bd2.toolchain_version = "2.0.0".to_string();
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn enrichment_build_descriptor_content_hash_changes_with_source_hash() {
    let bd1 = enrichment_build_descriptor();
    let mut bd2 = bd1.clone();
    bd2.source_hash = ContentHash::compute(b"different-source");
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn enrichment_build_descriptor_content_hash_changes_with_reproducible_flag() {
    let bd1 = enrichment_build_descriptor();
    let mut bd2 = bd1.clone();
    bd2.reproducible = false;
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn enrichment_build_descriptor_validate_accepts_minimal() {
    let bd = BuildDescriptor {
        toolchain_hash: ContentHash::compute(b"tc"),
        toolchain_version: "x".to_string(),
        source_hash: ContentHash::compute(b"src"),
        build_flags: vec![],
        dependency_hashes: BTreeMap::new(),
        reproducible: false,
    };
    assert!(bd.validate().is_ok());
}

// ---------------------------------------------------------------------------
// 13. Scope validation edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scope_with_underscore_accepted() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    reg.claim_scope(pub_id.clone(), "my_org").unwrap();
    assert!(reg.publisher_owns_scope(&pub_id, "my_org"));
}

#[test]
fn enrichment_scope_with_hyphen_accepted() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    reg.claim_scope(pub_id.clone(), "my-org").unwrap();
    assert!(reg.publisher_owns_scope(&pub_id, "my-org"));
}

#[test]
fn enrichment_scope_with_at_symbol_rejected() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    let result = reg.claim_scope(pub_id, "org@name");
    assert!(matches!(result, Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_scope_with_period_rejected() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    let result = reg.claim_scope(pub_id, "org.name");
    assert!(matches!(result, Err(RegistryError::InvalidScope { .. })));
}

#[test]
fn enrichment_scope_single_char_accepted() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    reg.claim_scope(pub_id.clone(), "x").unwrap();
    assert!(reg.publisher_owns_scope(&pub_id, "x"));
}

#[test]
fn enrichment_scope_claim_for_revoked_publisher_rejected() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    reg.revoke_publisher(pub_id.clone(), "test").unwrap();
    let result = reg.claim_scope(pub_id, "newscope");
    assert!(matches!(result, Err(RegistryError::PublisherRevoked { .. })));
}

#[test]
fn enrichment_scope_claim_for_unknown_publisher_rejected() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake = EngineObjectId([42; 32]);
    let result = reg.claim_scope(fake, "scope");
    assert!(matches!(result, Err(RegistryError::PublisherNotFound { .. })));
}

// ---------------------------------------------------------------------------
// 14. Clock advancement
// ---------------------------------------------------------------------------

#[test]
fn enrichment_clock_advancement_affects_revocation_timestamp() {
    let (mut reg, pub_id, sk, vk) = enrichment_setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = enrichment_manifest("testorg", "ext", v, &pub_id, &vk);
    enrichment_publish(&mut reg, &m, &sk).unwrap();

    reg.advance_tick(DeterministicTimestamp(9999));
    reg.revoke_package("testorg", "ext", v, "test").unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.revoked_at, Some(DeterministicTimestamp(9999)));
}

#[test]
fn enrichment_clock_advancement_affects_publisher_revocation_timestamp() {
    let (mut reg, pub_id, _, _) = enrichment_setup();
    reg.advance_tick(DeterministicTimestamp(5555));
    reg.revoke_publisher(pub_id.clone(), "key leak").unwrap();
    let p = reg.get_publisher(&pub_id).unwrap();
    assert_eq!(p.revoked_at, Some(DeterministicTimestamp(5555)));
}

#[test]
fn enrichment_events_record_timestamp_of_current_tick() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(42));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    reg.register_publisher("Test", vk).unwrap();

    let events = reg.export_audit_log();
    assert_eq!(events[0].timestamp, DeterministicTimestamp(42));
}

// ---------------------------------------------------------------------------
// 15. Display traits
// ---------------------------------------------------------------------------

#[test]
fn enrichment_package_version_display_large_components() {
    let v = PackageVersion::new(u32::MAX, u32::MAX, u32::MAX);
    let s = format!("{v}");
    assert!(s.contains(&u32::MAX.to_string()));
}

#[test]
fn enrichment_package_key_display_format() {
    let k = PackageKey {
        scope: "test-org".to_string(),
        name: "my_ext".to_string(),
        version: PackageVersion::new(10, 20, 30),
    };
    assert_eq!(format!("{k}"), "@test-org/my_ext@10.20.30");
}

#[test]
fn enrichment_registry_error_debug_is_distinct_from_display() {
    let e = RegistryError::SignatureInvalid {
        reason: "bad".to_string(),
    };
    let display = format!("{e}");
    let debug = format!("{e:?}");
    // Debug includes variant name, Display does not include "SignatureInvalid"
    assert!(debug.contains("SignatureInvalid"));
    assert!(!display.contains("SignatureInvalid"));
}

// ---------------------------------------------------------------------------
// 16. Publisher lifecycle edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_publisher_owns_scope_false_for_nonexistent_publisher() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake = EngineObjectId([99; 32]);
    assert!(!reg.publisher_owns_scope(&fake, "anything"));
}

#[test]
fn enrichment_publisher_active_false_after_revocation() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("Test", vk).unwrap();
    assert!(reg.is_publisher_active(&pub_id));
    reg.revoke_publisher(pub_id.clone(), "test").unwrap();
    assert!(!reg.is_publisher_active(&pub_id));
}

#[test]
fn enrichment_get_publisher_returns_correct_display_name() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("My Company LLC", vk).unwrap();
    let p = reg.get_publisher(&pub_id).unwrap();
    assert_eq!(p.display_name, "My Company LLC");
}

#[test]
fn enrichment_publisher_registered_at_matches_clock() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(777));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("Test", vk).unwrap();
    let p = reg.get_publisher(&pub_id).unwrap();
    assert_eq!(p.registered_at, DeterministicTimestamp(777));
}

#[test]
fn enrichment_publisher_initial_state_no_scopes() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = enrichment_signing_key(7);
    let vk = enrichment_vk_from(&sk);
    let pub_id = reg.register_publisher("Test", vk).unwrap();
    let p = reg.get_publisher(&pub_id).unwrap();
    assert!(p.owned_scopes.is_empty());
    assert!(!p.revoked);
    assert!(p.revoked_at.is_none());
    assert!(p.revocation_reason.is_none());
}
