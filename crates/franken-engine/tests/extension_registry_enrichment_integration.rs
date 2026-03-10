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
