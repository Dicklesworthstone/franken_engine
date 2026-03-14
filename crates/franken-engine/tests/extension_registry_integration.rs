//! Integration tests for the `extension_registry` module.
//!
//! Tests the full lifecycle of the signed extension registry from the public
//! API surface: publisher registration, scope management, package publishing,
//! querying, verification, revocation, transitive trust, serde round-trips,
//! and audit event trails.

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

use frankenengine_engine::engine_object_id::EngineObjectId;
use frankenengine_engine::extension_registry::{
    ArtifactEntry, BuildDescriptor, CapabilityDeclaration, EventOutcome, ExtensionManifest,
    ExtensionRegistry, PackageKey, PackageQuery, PackageVersion, RegistryError, RegistryEventType,
    SignedPackage,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey, sign_preimage};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn signing_key(seed: u8) -> SigningKey {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(seed).wrapping_add(seed);
    }
    SigningKey(bytes)
}

fn vk_from(sk: &SigningKey) -> VerificationKey {
    sk.verification_key()
}

fn build_descriptor() -> BuildDescriptor {
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

fn artifact(path: &str) -> ArtifactEntry {
    ArtifactEntry {
        path: path.to_string(),
        content_hash: ContentHash::compute(path.as_bytes()),
        size_bytes: 4096,
        mime_type: Some("application/octet-stream".to_string()),
    }
}

fn capability(name: &str) -> CapabilityDeclaration {
    CapabilityDeclaration {
        name: name.to_string(),
        justification: format!("needs {name}"),
        optional: false,
    }
}

fn manifest(
    scope: &str,
    name: &str,
    version: PackageVersion,
    publisher_id: &EngineObjectId,
    publisher_key: &VerificationKey,
) -> ExtensionManifest {
    let artifacts = vec![artifact("main.fir")];
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
        capabilities: vec![capability("net:outbound")],
        artifacts,
        build: build_descriptor(),
        artifacts_root_hash,
        description: format!("Test extension @{scope}/{name}"),
        license: Some("MIT".to_string()),
        dependencies: BTreeMap::new(),
    }
}

fn publish(
    reg: &mut ExtensionRegistry,
    m: &ExtensionManifest,
    sk: &SigningKey,
) -> Result<EngineObjectId, RegistryError> {
    let sig = sign_preimage(sk, &m.unsigned_bytes()).expect("signing");
    reg.publish(m.clone(), sig)
}

fn setup() -> (
    ExtensionRegistry,
    EngineObjectId,
    SigningKey,
    VerificationKey,
) {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(100));
    let sk = signing_key(7);
    let vk = vk_from(&sk);
    let pub_id = reg.register_publisher("TestOrg", vk.clone()).unwrap();
    reg.claim_scope(pub_id.clone(), "testorg").unwrap();
    (reg, pub_id, sk, vk)
}

// ---------------------------------------------------------------------------
// Full lifecycle: register → publish → verify → revoke
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_publish_verify_revoke() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "weather", v, &pub_id, &vk);

    // Publish
    let pkg_id = publish(&mut reg, &m, &sk).unwrap();
    assert_eq!(reg.package_count(), 1);

    // Verify passes
    let vr = reg.verify_package("testorg", "weather", v).unwrap();
    assert!(vr.valid);
    assert!(vr.signature_valid);
    assert!(vr.structure_valid);
    assert!(vr.artifacts_root_valid);
    assert!(vr.publisher_active);
    assert!(vr.package_active);
    assert!(vr.errors.is_empty());

    // Revoke
    reg.advance_tick(DeterministicTimestamp(200));
    reg.revoke_package("testorg", "weather", v, "CVE-2026-001")
        .unwrap();

    // Verify after revocation fails
    let vr2 = reg.verify_package("testorg", "weather", v).unwrap();
    assert!(!vr2.valid);
    assert!(!vr2.package_active);
    assert!(vr2.signature_valid); // signature itself is still valid

    // Package is revoked
    assert!(reg.is_package_revoked("testorg", "weather", v));
    let pkg = reg.get_package("testorg", "weather", v).unwrap();
    assert!(pkg.revoked);
    assert_eq!(pkg.revoked_at, Some(DeterministicTimestamp(200)));
    assert_eq!(pkg.revocation_reason.as_deref(), Some("CVE-2026-001"));

    // Lookup by ID still works
    let pkg_by_id = reg.get_package_by_id(&pkg_id).unwrap();
    assert_eq!(pkg_by_id.package_id, pkg_id);
}

// ---------------------------------------------------------------------------
// Multi-publisher isolation
// ---------------------------------------------------------------------------

#[test]
fn multi_publisher_scope_isolation() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));

    // Publisher A
    let sk_a = signing_key(7);
    let vk_a = vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    // Publisher B
    let sk_b = signing_key(13);
    let vk_b = vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    // A cannot publish to B's scope
    let v = PackageVersion::new(1, 0, 0);
    let m_wrong = manifest("orgb", "ext", v, &pub_a, &vk_a);
    let result = publish(&mut reg, &m_wrong, &sk_a);
    assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));

    // B cannot publish to A's scope
    let m_wrong2 = manifest("orga", "ext", v, &pub_b, &vk_b);
    let result2 = publish(&mut reg, &m_wrong2, &sk_b);
    assert!(matches!(result2, Err(RegistryError::ScopeNotOwned { .. })));

    // Each publishes to own scope
    let m_a = manifest("orga", "ext", v, &pub_a, &vk_a);
    let m_b = manifest("orgb", "ext", v, &pub_b, &vk_b);
    publish(&mut reg, &m_a, &sk_a).unwrap();
    publish(&mut reg, &m_b, &sk_b).unwrap();

    assert_eq!(reg.package_count(), 2);

    // Search by publisher
    let results_a = reg.search(&PackageQuery {
        publisher_id: Some(pub_a.clone()),
        ..PackageQuery::default()
    });
    assert_eq!(results_a.len(), 1);
    assert_eq!(results_a[0].manifest.scope, "orga");

    let results_b = reg.search(&PackageQuery {
        publisher_id: Some(pub_b),
        ..PackageQuery::default()
    });
    assert_eq!(results_b.len(), 1);
    assert_eq!(results_b[0].manifest.scope, "orgb");
}

// ---------------------------------------------------------------------------
// Publisher revocation cascades to all packages
// ---------------------------------------------------------------------------

#[test]
fn publisher_revocation_cascade() {
    let (mut reg, pub_id, sk, vk) = setup();

    // Publish 5 versions
    for patch in 0..5 {
        let v = PackageVersion::new(1, 0, patch);
        let m = manifest("testorg", "ext", v, &pub_id, &vk);
        publish(&mut reg, &m, &sk).unwrap();
    }
    assert_eq!(reg.package_count(), 5);

    // All packages should be active
    for patch in 0..5 {
        let v = PackageVersion::new(1, 0, patch);
        assert!(!reg.is_package_revoked("testorg", "ext", v));
    }

    // Revoke the publisher
    reg.advance_tick(DeterministicTimestamp(300));
    reg.revoke_publisher(pub_id.clone(), "key compromise")
        .unwrap();

    // All packages are transitively revoked
    for patch in 0..5 {
        let v = PackageVersion::new(1, 0, patch);
        assert!(reg.is_package_revoked("testorg", "ext", v));
    }

    // Affected packages listing
    let affected = reg.packages_affected_by_publisher_revocation(&pub_id);
    assert_eq!(affected.len(), 5);

    // Verify should fail for all packages
    for patch in 0..5 {
        let v = PackageVersion::new(1, 0, patch);
        let vr = reg.verify_package("testorg", "ext", v).unwrap();
        assert!(!vr.valid);
        assert!(!vr.publisher_active);
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

#[test]
fn wrong_signing_key_rejected() {
    let (mut reg, pub_id, _sk, vk) = setup();
    let wrong_sk = signing_key(99);
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    let result = publish(&mut reg, &m, &wrong_sk);
    assert!(matches!(
        result,
        Err(RegistryError::SignatureInvalid { .. })
    ));
}

#[test]
fn tampered_manifest_detected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);

    // Sign the correct manifest
    let unsigned = m.unsigned_bytes();
    let sig = sign_preimage(&sk, &unsigned).unwrap();

    // Tamper with the manifest after signing
    let mut tampered = m.clone();
    tampered.description = "tampered description".to_string();

    let result = reg.publish(tampered, sig);
    assert!(matches!(
        result,
        Err(RegistryError::SignatureInvalid { .. })
    ));
}

// ---------------------------------------------------------------------------
// Version management
// ---------------------------------------------------------------------------

#[test]
fn multiple_versions_coexist() {
    let (mut reg, pub_id, sk, vk) = setup();

    let versions = [
        PackageVersion::new(1, 0, 0),
        PackageVersion::new(1, 1, 0),
        PackageVersion::new(1, 1, 1),
        PackageVersion::new(2, 0, 0),
    ];

    for &v in &versions {
        let m = manifest("testorg", "ext", v, &pub_id, &vk);
        publish(&mut reg, &m, &sk).unwrap();
    }

    let listed = reg.list_versions("testorg", "ext");
    assert_eq!(listed.len(), 4);

    // Each version is independently retrievable
    for &v in &versions {
        assert!(reg.get_package("testorg", "ext", v).is_some());
    }

    // Revoking one version doesn't affect others
    reg.revoke_package("testorg", "ext", versions[0], "old")
        .unwrap();
    assert!(reg.is_package_revoked("testorg", "ext", versions[0]));
    assert!(!reg.is_package_revoked("testorg", "ext", versions[1]));
    assert!(!reg.is_package_revoked("testorg", "ext", versions[2]));
    assert!(!reg.is_package_revoked("testorg", "ext", versions[3]));
}

#[test]
fn duplicate_version_rejected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::PackageAlreadyExists { .. })
    ));
}

// ---------------------------------------------------------------------------
// Search and query
// ---------------------------------------------------------------------------

#[test]
fn search_combined_filters() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));

    let sk_a = signing_key(7);
    let vk_a = vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    let sk_b = signing_key(13);
    let vk_b = vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    // Publish several packages
    let v = PackageVersion::new(1, 0, 0);
    publish(
        &mut reg,
        &manifest("orga", "ext-a", v, &pub_a, &vk_a),
        &sk_a,
    )
    .unwrap();
    publish(
        &mut reg,
        &manifest("orga", "ext-b", v, &pub_a, &vk_a),
        &sk_a,
    )
    .unwrap();
    publish(
        &mut reg,
        &manifest("orgb", "ext-a", v, &pub_b, &vk_b),
        &sk_b,
    )
    .unwrap();

    // Filter by scope + name
    let results = reg.search(&PackageQuery {
        scope: Some("orga".to_string()),
        name: Some("ext-a".to_string()),
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].manifest.scope, "orga");
    assert_eq!(results[0].manifest.name, "ext-a");

    // Filter by scope only
    let results = reg.search(&PackageQuery {
        scope: Some("orga".to_string()),
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 2);

    // No filter: all 3
    let results = reg.search(&PackageQuery::default());
    assert_eq!(results.len(), 3);

    // Non-matching scope
    let results = reg.search(&PackageQuery {
        scope: Some("nonexistent".to_string()),
        ..PackageQuery::default()
    });
    assert!(results.is_empty());
}

#[test]
fn search_respects_limit() {
    let (mut reg, pub_id, sk, vk) = setup();

    for i in 0..10 {
        let v = PackageVersion::new(1, 0, i);
        let m = manifest("testorg", "ext", v, &pub_id, &vk);
        publish(&mut reg, &m, &sk).unwrap();
    }

    let results = reg.search(&PackageQuery {
        limit: 3,
        ..PackageQuery::default()
    });
    assert!(results.len() <= 3);
}

#[test]
fn search_revoked_visibility() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v1 = PackageVersion::new(1, 0, 0);
    let v2 = PackageVersion::new(1, 1, 0);
    let m1 = manifest("testorg", "ext", v1, &pub_id, &vk);
    let m2 = manifest("testorg", "ext", v2, &pub_id, &vk);
    publish(&mut reg, &m1, &sk).unwrap();
    publish(&mut reg, &m2, &sk).unwrap();

    reg.revoke_package("testorg", "ext", v1, "vuln").unwrap();

    // Default: excludes revoked
    let results = reg.search(&PackageQuery::default());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].manifest.version, v2);

    // Include revoked
    let results = reg.search(&PackageQuery {
        include_revoked: true,
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 2);
}

// ---------------------------------------------------------------------------
// Scope management edge cases
// ---------------------------------------------------------------------------

#[test]
fn scope_claim_idempotent() {
    let (mut reg, pub_id, _, _) = setup();
    // "testorg" already claimed in setup
    assert!(reg.claim_scope(pub_id.clone(), "testorg").is_ok());
    assert!(reg.publisher_owns_scope(&pub_id, "testorg"));
}

#[test]
fn scope_claim_second_scope_succeeds() {
    let (mut reg, pub_id, _, _) = setup();
    reg.claim_scope(pub_id.clone(), "second-scope").unwrap();
    assert!(reg.publisher_owns_scope(&pub_id, "testorg"));
    assert!(reg.publisher_owns_scope(&pub_id, "second-scope"));
}

#[test]
fn scope_validation_edge_cases() {
    let (mut reg, pub_id, _, _) = setup();

    // Empty scope
    assert!(matches!(
        reg.claim_scope(pub_id.clone(), ""),
        Err(RegistryError::InvalidScope { .. })
    ));

    // Special characters
    assert!(matches!(
        reg.claim_scope(pub_id.clone(), "has spaces"),
        Err(RegistryError::InvalidScope { .. })
    ));

    assert!(matches!(
        reg.claim_scope(pub_id.clone(), "has@symbol"),
        Err(RegistryError::InvalidScope { .. })
    ));

    // Long scope (128+ chars)
    let long_scope: String = "a".repeat(129);
    assert!(matches!(
        reg.claim_scope(pub_id.clone(), &long_scope),
        Err(RegistryError::InvalidScope { .. })
    ));

    // Max-length scope is ok
    let max_scope: String = "a".repeat(128);
    assert!(reg.claim_scope(pub_id, &max_scope).is_ok());
}

// ---------------------------------------------------------------------------
// Manifest validation
// ---------------------------------------------------------------------------

#[test]
fn manifest_too_many_artifacts_rejected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.artifacts = (0..1025)
        .map(|i| artifact(&format!("file_{i}.dat")))
        .collect();
    // Recompute artifacts root
    let mut buf = Vec::new();
    for art in &m.artifacts {
        buf.extend_from_slice(art.path.as_bytes());
        buf.push(0);
        buf.extend_from_slice(art.content_hash.as_bytes());
        buf.extend_from_slice(&art.size_bytes.to_le_bytes());
    }
    m.artifacts_root_hash = ContentHash::compute(&buf);

    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::TooManyArtifacts { .. })
    ));
}

#[test]
fn manifest_too_many_capabilities_rejected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.capabilities = (0..257).map(|i| capability(&format!("cap:{i}"))).collect();
    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::TooManyCapabilities { .. })
    ));
}

#[test]
fn manifest_artifacts_root_mismatch_rejected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.artifacts_root_hash = ContentHash::compute(b"wrong-hash");
    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::ContentHashMismatch { .. })
    ));
}

#[test]
fn manifest_empty_toolchain_version_rejected() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.build.toolchain_version = String::new();
    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::BuildDescriptorIncomplete { .. })
    ));
}

// ---------------------------------------------------------------------------
// Revocation by ID
// ---------------------------------------------------------------------------

#[test]
fn revoke_by_id_works() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    let pkg_id = publish(&mut reg, &m, &sk).unwrap();

    reg.revoke_package_by_id(pkg_id, "security advisory")
        .unwrap();
    assert!(reg.is_package_revoked("testorg", "ext", v));
}

#[test]
fn revoke_unknown_id_fails() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake_id = EngineObjectId([42; 32]);
    let result = reg.revoke_package_by_id(fake_id, "test");
    assert!(matches!(
        result,
        Err(RegistryError::RevocationTargetUnknown { .. })
    ));
}

// ---------------------------------------------------------------------------
// Audit event trail
// ---------------------------------------------------------------------------

#[test]
fn audit_trail_records_all_operations() {
    let (mut reg, pub_id, sk, vk) = setup();
    let initial = reg.audit_event_count();

    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();
    reg.verify_package("testorg", "ext", v).unwrap();
    reg.revoke_package("testorg", "ext", v, "vuln").unwrap();

    let events = reg.export_audit_log();
    let new_events = &events[initial..];

    let types: BTreeSet<RegistryEventType> = new_events.iter().map(|e| e.event_type).collect();
    assert!(types.contains(&RegistryEventType::PackagePublished));
    assert!(types.contains(&RegistryEventType::PackageVerified));
    assert!(types.contains(&RegistryEventType::PackageRevoked));

    // All events should have the extension_registry component
    for event in new_events {
        assert_eq!(event.component, "extension_registry");
    }
}

#[test]
fn audit_trail_records_failed_operations() {
    let (mut reg, pub_id, _sk, vk) = setup();
    let wrong_sk = signing_key(99);
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    let _ = publish(&mut reg, &m, &wrong_sk);

    let events = reg.export_audit_log();
    let failed = events
        .iter()
        .filter(|e| e.event_type == RegistryEventType::VerificationFailed)
        .count();
    assert!(failed >= 1);

    let fail_event = events
        .iter()
        .find(|e| e.event_type == RegistryEventType::VerificationFailed)
        .unwrap();
    assert_eq!(fail_event.outcome, EventOutcome::Denied);
    assert!(fail_event.error_code.is_some());
}

// ---------------------------------------------------------------------------
// Serde round-trip (full registry state)
// ---------------------------------------------------------------------------

#[test]
fn full_registry_serde_roundtrip() {
    let (mut reg, pub_id, sk, vk) = setup();

    // Publish several packages
    for i in 0..3 {
        let v = PackageVersion::new(1, 0, i);
        let m = manifest("testorg", &format!("ext-{i}"), v, &pub_id, &vk);
        publish(&mut reg, &m, &sk).unwrap();
    }

    // Revoke one
    reg.revoke_package("testorg", "ext-0", PackageVersion::new(1, 0, 0), "test")
        .unwrap();

    // Serialize and restore
    let json = serde_json::to_string(&reg).unwrap();
    let restored: ExtensionRegistry = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.package_count(), reg.package_count());
    assert_eq!(restored.publisher_count(), reg.publisher_count());
    assert_eq!(restored.audit_event_count(), reg.audit_event_count());
    assert!(restored.is_publisher_active(&pub_id));
    assert!(restored.is_package_revoked("testorg", "ext-0", PackageVersion::new(1, 0, 0)));
    assert!(!restored.is_package_revoked("testorg", "ext-1", PackageVersion::new(1, 0, 1)));
}

#[test]
fn signed_package_serde_roundtrip() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    let json = serde_json::to_string(pkg).unwrap();
    let restored: SignedPackage = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.package_id, pkg.package_id);
    assert_eq!(restored.manifest.scope, "testorg");
    assert_eq!(restored.manifest.name, "ext");
    assert_eq!(restored.manifest.version, v);
}

// ---------------------------------------------------------------------------
// Determinism: same inputs → same IDs
// ---------------------------------------------------------------------------

#[test]
fn deterministic_publisher_id() {
    let sk = signing_key(7);
    let vk = vk_from(&sk);

    let mut r1 = ExtensionRegistry::new(DeterministicTimestamp(100));
    let id1 = r1.register_publisher("TestOrg", vk.clone()).unwrap();

    let mut r2 = ExtensionRegistry::new(DeterministicTimestamp(100));
    let id2 = r2.register_publisher("TestOrg", vk).unwrap();

    assert_eq!(id1, id2);
}

#[test]
fn deterministic_package_id() {
    let (mut reg1, pub_id1, sk1, vk1) = setup();
    let (mut reg2, pub_id2, sk2, vk2) = setup();

    let v = PackageVersion::new(1, 0, 0);
    let m1 = manifest("testorg", "ext", v, &pub_id1, &vk1);
    let m2 = manifest("testorg", "ext", v, &pub_id2, &vk2);

    let id1 = publish(&mut reg1, &m1, &sk1).unwrap();
    let id2 = publish(&mut reg2, &m2, &sk2).unwrap();

    assert_eq!(id1, id2);
}

// ---------------------------------------------------------------------------
// Display trait coverage
// ---------------------------------------------------------------------------

#[test]
fn package_version_display() {
    assert_eq!(format!("{}", PackageVersion::new(2, 3, 1)), "2.3.1");
    assert_eq!(format!("{}", PackageVersion::new(0, 0, 0)), "0.0.0");
}

#[test]
fn package_version_ordering() {
    let v100 = PackageVersion::new(1, 0, 0);
    let v110 = PackageVersion::new(1, 1, 0);
    let v111 = PackageVersion::new(1, 1, 1);
    let v200 = PackageVersion::new(2, 0, 0);
    assert!(v100 < v110);
    assert!(v110 < v111);
    assert!(v111 < v200);
}

#[test]
fn package_key_display() {
    let k = PackageKey {
        scope: "myorg".to_string(),
        name: "cool-ext".to_string(),
        version: PackageVersion::new(3, 2, 1),
    };
    assert_eq!(format!("{k}"), "@myorg/cool-ext@3.2.1");
}

#[test]
fn registry_event_type_display() {
    assert_eq!(
        format!("{}", RegistryEventType::PublisherRegistered),
        "publisher_registered"
    );
    assert_eq!(
        format!("{}", RegistryEventType::PackagePublished),
        "package_published"
    );
    assert_eq!(
        format!("{}", RegistryEventType::PackageRevoked),
        "package_revoked"
    );
}

#[test]
fn event_outcome_display() {
    assert_eq!(format!("{}", EventOutcome::Success), "success");
    assert_eq!(format!("{}", EventOutcome::Denied), "denied");
    assert_eq!(format!("{}", EventOutcome::Error), "error");
}

// ---------------------------------------------------------------------------
// Error Display coverage
// ---------------------------------------------------------------------------

#[test]
fn error_display_all_variants() {
    let errors: Vec<RegistryError> = vec![
        RegistryError::PublisherNotFound {
            publisher_id: EngineObjectId([0; 32]),
        },
        RegistryError::PublisherRevoked {
            publisher_id: EngineObjectId([0; 32]),
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
            package_id: EngineObjectId([0; 32]),
        },
        RegistryError::SignatureInvalid {
            reason: "bad sig".to_string(),
        },
        RegistryError::ContentHashMismatch {
            artifact_name: "main.fir".to_string(),
            expected: ContentHash::compute(b"a"),
            actual: ContentHash::compute(b"b"),
        },
        RegistryError::ScopeNotOwned {
            scope: "s".to_string(),
            publisher_id: EngineObjectId([0; 32]),
        },
        RegistryError::TooManyCapabilities {
            count: 300,
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
            target_id: EngineObjectId([0; 32]),
        },
        RegistryError::BuildDescriptorIncomplete {
            missing_field: "toolchain_version".to_string(),
        },
    ];
    for err in &errors {
        let s = format!("{err}");
        assert!(!s.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn publish_to_nonexistent_publisher_fails() {
    let (mut reg, _, sk, _) = setup();
    let fake_pub = EngineObjectId([55; 32]);
    let fake_vk = VerificationKey([66; 32]);
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &fake_pub, &fake_vk);
    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::PublisherNotFound { .. })
    ));
}

#[test]
fn verify_nonexistent_package_errors() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let v = PackageVersion::new(1, 0, 0);
    let result = reg.verify_package("x", "y", v);
    assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
}

#[test]
fn revoke_nonexistent_package_errors() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let v = PackageVersion::new(1, 0, 0);
    let result = reg.revoke_package("x", "y", v, "test");
    assert!(matches!(result, Err(RegistryError::PackageNotFound { .. })));
}

#[test]
fn revoke_nonexistent_publisher_errors() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake_id = EngineObjectId([42; 32]);
    let result = reg.revoke_publisher(fake_id, "test");
    assert!(matches!(
        result,
        Err(RegistryError::PublisherNotFound { .. })
    ));
}

#[test]
fn empty_registry_queries_return_empty() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    assert_eq!(reg.package_count(), 0);
    assert_eq!(reg.publisher_count(), 0);
    assert_eq!(reg.audit_event_count(), 0);
    assert!(
        reg.get_package("x", "y", PackageVersion::new(1, 0, 0))
            .is_none()
    );
    assert!(reg.get_package_by_id(&EngineObjectId([0; 32])).is_none());
    assert!(reg.search(&PackageQuery::default()).is_empty());
    assert!(reg.list_versions("x", "y").is_empty());
}

#[test]
fn clock_advancement_preserved() {
    let (mut reg, pub_id, sk, vk) = setup();

    reg.advance_tick(DeterministicTimestamp(500));
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.published_at, DeterministicTimestamp(500));

    reg.advance_tick(DeterministicTimestamp(600));
    reg.revoke_package("testorg", "ext", v, "test").unwrap();
    let pkg2 = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg2.revoked_at, Some(DeterministicTimestamp(600)));
}

#[test]
fn build_descriptor_content_hash_deterministic() {
    let bd1 = build_descriptor();
    let bd2 = build_descriptor();
    assert_eq!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn manifest_unsigned_bytes_deterministic() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = manifest("testorg", "ext", v, &pub_id, &vk);
    let m2 = manifest("testorg", "ext", v, &pub_id, &vk);
    assert_eq!(m1.unsigned_bytes(), m2.unsigned_bytes());
}

#[test]
fn manifest_compute_artifacts_root_deterministic() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    let root1 = m.compute_artifacts_root();
    let root2 = m.compute_artifacts_root();
    assert_eq!(root1, root2);
    assert_eq!(root1, m.artifacts_root_hash);
}

// ---------------------------------------------------------------------------
// Clone / Debug / PartialEq on value types
// ---------------------------------------------------------------------------

#[test]
fn test_package_version_clone_debug_eq() {
    let v = PackageVersion::new(3, 2, 1);
    let v2 = v;
    assert_eq!(v, v2);
    let dbg = format!("{v:?}");
    assert!(dbg.contains("3"));
    assert!(dbg.contains("2"));
    assert!(dbg.contains("1"));
}

#[test]
fn test_package_version_copy_semantics() {
    let v = PackageVersion::new(5, 4, 3);
    let v2 = v; // Copy
    let v3 = v; // Still usable
    assert_eq!(v2, v3);
}

#[test]
fn test_artifact_entry_clone_eq() {
    let a = artifact("hello.fir");
    let b = a.clone();
    assert_eq!(a, b);
    let dbg = format!("{a:?}");
    assert!(dbg.contains("hello.fir"));
}

#[test]
fn test_capability_declaration_clone_eq_ord() {
    let c1 = capability("net:outbound");
    let c2 = capability("fs:read");
    let c3 = c1.clone();
    assert_eq!(c1, c3);
    assert_ne!(c1, c2);
    // CapabilityDeclaration implements Ord — can sort
    let mut caps = vec![c1.clone(), c2.clone()];
    caps.sort();
    assert!(caps[0].name <= caps[1].name);
}

#[test]
fn test_build_descriptor_clone_eq_debug() {
    let bd1 = build_descriptor();
    let bd2 = bd1.clone();
    assert_eq!(bd1, bd2);
    let dbg = format!("{bd1:?}");
    assert!(dbg.contains("toolchain_version"));
}

#[test]
fn test_extension_manifest_clone_eq_debug() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = manifest("testorg", "ext", v, &pub_id, &vk);
    let m2 = m1.clone();
    assert_eq!(m1, m2);
    let dbg = format!("{m1:?}");
    assert!(dbg.contains("testorg"));
}

#[test]
fn test_registry_error_clone_eq_debug() {
    let e = RegistryError::SignatureInvalid {
        reason: "bad".to_string(),
    };
    let e2 = e.clone();
    assert_eq!(e, e2);
    let dbg = format!("{e:?}");
    assert!(dbg.contains("SignatureInvalid"));
}

#[test]
fn test_registry_event_type_clone_copy_debug_eq() {
    let et = RegistryEventType::PackageRevoked;
    let et2 = et;
    assert_eq!(et, et2);
    let dbg = format!("{et:?}");
    assert!(dbg.contains("PackageRevoked"));
}

#[test]
fn test_event_outcome_clone_copy_debug_eq() {
    let o = EventOutcome::Success;
    let o2 = o;
    assert_eq!(o, o2);
    assert_ne!(o, EventOutcome::Denied);
    let dbg = format!("{o:?}");
    assert!(dbg.contains("Success"));
}

// ---------------------------------------------------------------------------
// PackageQuery Default and serde
// ---------------------------------------------------------------------------

#[test]
fn test_package_query_default_values() {
    let q = PackageQuery::default();
    assert!(q.scope.is_none());
    assert!(q.name.is_none());
    assert!(q.publisher_id.is_none());
    assert!(!q.include_revoked);
    assert_eq!(q.limit, 100);
}

#[test]
fn test_package_query_clone_eq_debug() {
    let q1 = PackageQuery {
        scope: Some("myorg".to_string()),
        name: Some("ext".to_string()),
        publisher_id: None,
        include_revoked: true,
        limit: 50,
    };
    let q2 = q1.clone();
    assert_eq!(q1, q2);
    let dbg = format!("{q1:?}");
    assert!(dbg.contains("myorg"));
}

#[test]
fn test_package_query_serde_roundtrip() {
    let q = PackageQuery {
        scope: Some("orga".to_string()),
        name: None,
        publisher_id: None,
        include_revoked: true,
        limit: 25,
    };
    let json = serde_json::to_string(&q).unwrap();
    let q2: PackageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, q2);
    assert_eq!(q2.limit, 25);
    assert!(q2.include_revoked);
}

// ---------------------------------------------------------------------------
// Serde roundtrips for individual types
// ---------------------------------------------------------------------------

#[test]
fn test_package_version_serde_roundtrip() {
    let v = PackageVersion::new(7, 8, 9);
    let json = serde_json::to_string(&v).unwrap();
    let v2: PackageVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, v2);
}

#[test]
fn test_artifact_entry_serde_roundtrip() {
    let a = ArtifactEntry {
        path: "lib/core.fir".to_string(),
        content_hash: ContentHash::compute(b"core-data"),
        size_bytes: 8192,
        mime_type: None,
    };
    let json = serde_json::to_string(&a).unwrap();
    let a2: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(a, a2);
    assert!(a2.mime_type.is_none());
}

#[test]
fn test_artifact_entry_with_mime_serde() {
    let a = artifact("main.wasm");
    let json = serde_json::to_string(&a).unwrap();
    let a2: ArtifactEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(a, a2);
    assert_eq!(a2.mime_type.as_deref(), Some("application/octet-stream"));
}

#[test]
fn test_capability_declaration_serde_roundtrip() {
    let c = CapabilityDeclaration {
        name: "fs:write:/var/data".to_string(),
        justification: "writes audit records".to_string(),
        optional: true,
    };
    let json = serde_json::to_string(&c).unwrap();
    let c2: CapabilityDeclaration = serde_json::from_str(&json).unwrap();
    assert_eq!(c, c2);
    assert!(c2.optional);
}

#[test]
fn test_build_descriptor_serde_roundtrip() {
    let bd = build_descriptor();
    let json = serde_json::to_string(&bd).unwrap();
    let bd2: BuildDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(bd, bd2);
    assert!(bd2.reproducible);
}

#[test]
fn test_registry_error_serde_roundtrip() {
    let err = RegistryError::PackageNotFound {
        scope: "myscope".to_string(),
        name: "mypkg".to_string(),
        version: PackageVersion::new(2, 1, 0),
    };
    let json = serde_json::to_string(&err).unwrap();
    let err2: RegistryError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, err2);
}

#[test]
fn test_registry_event_type_serde_roundtrip() {
    let all = [
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
    for et in &all {
        let json = serde_json::to_string(et).unwrap();
        let et2: RegistryEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*et, et2);
    }
}

#[test]
fn test_event_outcome_serde_roundtrip() {
    for o in [
        EventOutcome::Success,
        EventOutcome::Denied,
        EventOutcome::Error,
    ] {
        let json = serde_json::to_string(&o).unwrap();
        let o2: EventOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(o, o2);
    }
}

#[test]
fn test_package_key_serde_roundtrip() {
    let k = PackageKey {
        scope: "theorg".to_string(),
        name: "the-ext".to_string(),
        version: PackageVersion::new(1, 2, 3),
    };
    let json = serde_json::to_string(&k).unwrap();
    let k2: PackageKey = serde_json::from_str(&json).unwrap();
    assert_eq!(k, k2);
    assert_eq!(k2.scope, "theorg");
}

#[test]
fn test_verification_result_serde_roundtrip() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();
    let vr = reg.verify_package("testorg", "ext", v).unwrap();
    let json = serde_json::to_string(&vr).unwrap();
    let vr2: frankenengine_engine::extension_registry::VerificationResult =
        serde_json::from_str(&json).unwrap();
    assert_eq!(vr.valid, vr2.valid);
    assert_eq!(vr.package_id, vr2.package_id);
    assert_eq!(vr.signature_valid, vr2.signature_valid);
    assert_eq!(vr.errors.len(), vr2.errors.len());
}

// ---------------------------------------------------------------------------
// BuildDescriptor validate() edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_build_descriptor_validate_empty_toolchain_fails() {
    let mut bd = build_descriptor();
    bd.toolchain_version = String::new();
    let result = bd.validate();
    assert!(matches!(
        result,
        Err(RegistryError::BuildDescriptorIncomplete { .. })
    ));
}

#[test]
fn test_build_descriptor_validate_passes_nonempty_toolchain() {
    let bd = build_descriptor();
    assert!(bd.validate().is_ok());
}

#[test]
fn test_build_descriptor_content_hash_differs_on_different_inputs() {
    let mut bd1 = build_descriptor();
    let mut bd2 = build_descriptor();
    bd2.toolchain_version = "2.0.0".to_string();
    bd1.reproducible = false;
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn test_build_descriptor_content_hash_changes_with_flag() {
    let bd1 = build_descriptor();
    let mut bd2 = build_descriptor();
    bd2.build_flags.push("--opt-level=3".to_string());
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

#[test]
fn test_build_descriptor_non_reproducible_differs() {
    let mut bd1 = build_descriptor();
    let mut bd2 = build_descriptor();
    bd1.reproducible = false;
    bd2.reproducible = true;
    assert_ne!(bd1.content_hash(), bd2.content_hash());
}

// ---------------------------------------------------------------------------
// Manifest validate_structure() edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_validate_empty_name_fails() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = String::new();
    // Recompute artifacts root so only name-related check fails
    m.artifacts_root_hash = m.compute_artifacts_root();
    let result = m.validate_structure();
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

#[test]
fn test_manifest_validate_name_too_long_fails() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = "a".repeat(129);
    m.artifacts_root_hash = m.compute_artifacts_root();
    let result = m.validate_structure();
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

#[test]
fn test_manifest_validate_name_max_len_passes() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = "a".repeat(128);
    m.artifacts_root_hash = m.compute_artifacts_root();
    assert!(m.validate_structure().is_ok());
}

#[test]
fn test_manifest_validate_name_special_char_fails() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.name = "bad name!".to_string();
    m.artifacts_root_hash = m.compute_artifacts_root();
    let result = m.validate_structure();
    assert!(matches!(result, Err(RegistryError::InvalidName { .. })));
}

// ---------------------------------------------------------------------------
// Publisher identity edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_get_publisher_returns_identity() {
    let (reg, pub_id, _, vk) = setup();
    let pub_entry = reg.get_publisher(&pub_id).unwrap();
    assert_eq!(pub_entry.id, pub_id);
    assert_eq!(pub_entry.display_name, "TestOrg");
    assert_eq!(pub_entry.verification_key, vk);
    assert!(!pub_entry.revoked);
    assert!(pub_entry.revoked_at.is_none());
    assert!(pub_entry.revocation_reason.is_none());
}

#[test]
fn test_get_publisher_unknown_returns_none() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    assert!(reg.get_publisher(&EngineObjectId([99; 32])).is_none());
}

#[test]
fn test_publisher_revoked_flag_set_on_revoke() {
    let (mut reg, pub_id, _, _) = setup();
    reg.revoke_publisher(pub_id.clone(), "key exposure")
        .unwrap();
    let pub_entry = reg.get_publisher(&pub_id).unwrap();
    assert!(pub_entry.revoked);
    assert!(pub_entry.revoked_at.is_some());
    assert_eq!(pub_entry.revocation_reason.as_deref(), Some("key exposure"));
}

#[test]
fn test_is_publisher_active_false_after_revoke() {
    let (mut reg, pub_id, _, _) = setup();
    assert!(reg.is_publisher_active(&pub_id));
    reg.revoke_publisher(pub_id.clone(), "expired").unwrap();
    assert!(!reg.is_publisher_active(&pub_id));
}

#[test]
fn test_is_publisher_active_unknown_id_returns_false() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    assert!(!reg.is_publisher_active(&EngineObjectId([88; 32])));
}

#[test]
fn test_publisher_owned_scopes_populated() {
    let (reg, pub_id, _, _) = setup();
    let pub_entry = reg.get_publisher(&pub_id).unwrap();
    assert!(pub_entry.owned_scopes.contains("testorg"));
}

// ---------------------------------------------------------------------------
// Revoked publisher cannot claim scope or publish
// ---------------------------------------------------------------------------

#[test]
fn test_revoked_publisher_cannot_claim_scope() {
    let (mut reg, pub_id, _, _) = setup();
    reg.revoke_publisher(pub_id.clone(), "revoked").unwrap();
    let result = reg.claim_scope(pub_id, "newscope");
    assert!(matches!(
        result,
        Err(RegistryError::PublisherRevoked { .. })
    ));
}

#[test]
fn test_revoked_publisher_cannot_publish() {
    let (mut reg, pub_id, sk, vk) = setup();
    reg.revoke_publisher(pub_id.clone(), "revoked").unwrap();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    let result = publish(&mut reg, &m, &sk);
    assert!(matches!(
        result,
        Err(RegistryError::PublisherRevoked { .. })
    ));
}

// ---------------------------------------------------------------------------
// Scope ownership edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_scope_claim_by_nonexistent_publisher_fails() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake_id = EngineObjectId([33; 32]);
    let result = reg.claim_scope(fake_id, "newscope");
    assert!(matches!(
        result,
        Err(RegistryError::PublisherNotFound { .. })
    ));
}

#[test]
fn test_scope_claim_conflict_other_publisher_fails() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = signing_key(7);
    let vk_a = vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a).unwrap();
    reg.claim_scope(pub_a.clone(), "shared").unwrap();

    let sk_b = signing_key(13);
    let vk_b = vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b).unwrap();
    let result = reg.claim_scope(pub_b, "shared");
    assert!(matches!(result, Err(RegistryError::ScopeNotOwned { .. })));
}

#[test]
fn test_publisher_owns_scope_false_for_unclaimed() {
    let (reg, pub_id, _, _) = setup();
    assert!(!reg.publisher_owns_scope(&pub_id, "unclaimed-scope"));
}

// ---------------------------------------------------------------------------
// Audit event structure
// ---------------------------------------------------------------------------

#[test]
fn test_audit_events_method_consistent_with_export() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let via_events = reg.events();
    let via_export = reg.export_audit_log();
    assert_eq!(via_events.len(), via_export.len());
    for (a, b) in via_events.iter().zip(via_export.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn test_audit_events_have_timestamp() {
    let (mut reg, pub_id, sk, vk) = setup();
    reg.advance_tick(DeterministicTimestamp(999));
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let events = reg.export_audit_log();
    let publish_event = events
        .iter()
        .find(|e| e.event_type == RegistryEventType::PackagePublished)
        .unwrap();
    assert_eq!(publish_event.timestamp, DeterministicTimestamp(999));
}

#[test]
fn test_scope_claim_event_recorded() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = signing_key(7);
    let vk = vk_from(&sk);
    let pub_id = reg.register_publisher("Org", vk).unwrap();
    let before = reg.audit_event_count();
    reg.claim_scope(pub_id, "newscope").unwrap();
    let events = reg.export_audit_log();
    let scope_events: Vec<_> = events[before..]
        .iter()
        .filter(|e| e.event_type == RegistryEventType::ScopeClaimed)
        .collect();
    assert_eq!(scope_events.len(), 1);
    assert_eq!(scope_events[0].scope.as_deref(), Some("newscope"));
    assert_eq!(scope_events[0].outcome, EventOutcome::Success);
}

#[test]
fn test_publisher_revoke_event_recorded() {
    let (mut reg, pub_id, _, _) = setup();
    let before = reg.audit_event_count();
    reg.revoke_publisher(pub_id.clone(), "security").unwrap();
    let events = reg.export_audit_log();
    let revoke_event = events[before..]
        .iter()
        .find(|e| e.event_type == RegistryEventType::PublisherRevoked)
        .unwrap();
    assert_eq!(revoke_event.publisher_id, Some(pub_id));
    assert_eq!(revoke_event.outcome, EventOutcome::Success);
}

// ---------------------------------------------------------------------------
// RegistryEvent serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn test_registry_event_serde_roundtrip() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();

    let events = reg.export_audit_log();
    for event in events {
        let json = serde_json::to_string(event).unwrap();
        let event2: frankenengine_engine::extension_registry::RegistryEvent =
            serde_json::from_str(&json).unwrap();
        assert_eq!(event.event_type, event2.event_type);
        assert_eq!(event.outcome, event2.outcome);
        assert_eq!(event.component, event2.component);
        assert_eq!(event.timestamp, event2.timestamp);
    }
}

// ---------------------------------------------------------------------------
// SignedPackage::derive_package_id
// ---------------------------------------------------------------------------

#[test]
fn test_derive_package_id_consistent_with_publish() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(2, 0, 0);
    let m = manifest("testorg", "ext2", v, &pub_id, &vk);
    let id_from_publish = publish(&mut reg, &m, &sk).unwrap();
    let id_from_derive = SignedPackage::derive_package_id(&m).unwrap();
    assert_eq!(id_from_publish, id_from_derive);
}

// ---------------------------------------------------------------------------
// PackageVersion ordering exhaustive
// ---------------------------------------------------------------------------

#[test]
fn test_package_version_major_wins_ordering() {
    let v_major = PackageVersion::new(2, 0, 0);
    let v_minor = PackageVersion::new(1, 99, 99);
    assert!(v_major > v_minor);
}

#[test]
fn test_package_version_minor_wins_over_patch() {
    let v1 = PackageVersion::new(1, 2, 0);
    let v2 = PackageVersion::new(1, 1, 99);
    assert!(v1 > v2);
}

#[test]
fn test_package_version_equality() {
    let v1 = PackageVersion::new(4, 5, 6);
    let v2 = PackageVersion::new(4, 5, 6);
    assert_eq!(v1, v2);
    assert!(v1 >= v2);
    assert!(v1 <= v2);
}

// ---------------------------------------------------------------------------
// PackageKey ordering (BTreeMap key correctness)
// ---------------------------------------------------------------------------

#[test]
fn test_package_key_ord_btreemap() {
    let mut m: BTreeMap<PackageKey, &str> = BTreeMap::new();
    m.insert(
        PackageKey {
            scope: "b".to_string(),
            name: "x".to_string(),
            version: PackageVersion::new(1, 0, 0),
        },
        "second",
    );
    m.insert(
        PackageKey {
            scope: "a".to_string(),
            name: "x".to_string(),
            version: PackageVersion::new(1, 0, 0),
        },
        "first",
    );
    let keys: Vec<_> = m.keys().collect();
    assert_eq!(keys[0].scope, "a");
    assert_eq!(keys[1].scope, "b");
}

// ---------------------------------------------------------------------------
// Search: name-only filter across scopes
// ---------------------------------------------------------------------------

#[test]
fn test_search_name_filter_across_scopes() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk_a = signing_key(7);
    let vk_a = vk_from(&sk_a);
    let pub_a = reg.register_publisher("A", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "scope-a").unwrap();

    let sk_b = signing_key(13);
    let vk_b = vk_from(&sk_b);
    let pub_b = reg.register_publisher("B", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "scope-b").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    publish(
        &mut reg,
        &manifest("scope-a", "shared-name", v, &pub_a, &vk_a),
        &sk_a,
    )
    .unwrap();
    publish(
        &mut reg,
        &manifest("scope-b", "shared-name", v, &pub_b, &vk_b),
        &sk_b,
    )
    .unwrap();
    publish(
        &mut reg,
        &manifest("scope-a", "other-name", v, &pub_a, &vk_a),
        &sk_a,
    )
    .unwrap();

    let results = reg.search(&PackageQuery {
        name: Some("shared-name".to_string()),
        ..PackageQuery::default()
    });
    assert_eq!(results.len(), 2);
    for r in &results {
        assert_eq!(r.manifest.name, "shared-name");
    }
}

// ---------------------------------------------------------------------------
// List versions sorted
// ---------------------------------------------------------------------------

#[test]
fn test_list_versions_returns_all_present_versions() {
    let (mut reg, pub_id, sk, vk) = setup();
    let versions = [
        PackageVersion::new(1, 0, 0),
        PackageVersion::new(2, 0, 0),
        PackageVersion::new(1, 5, 3),
    ];
    for &v in &versions {
        let m = manifest("testorg", "ext", v, &pub_id, &vk);
        publish(&mut reg, &m, &sk).unwrap();
    }
    let listed = reg.list_versions("testorg", "ext");
    assert_eq!(listed.len(), 3);
    // All versions present (order not guaranteed by list_versions)
    for &v in &versions {
        assert!(listed.contains(&v));
    }
}

#[test]
fn test_list_versions_empty_for_unknown_package() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    assert!(reg.list_versions("noscope", "noname").is_empty());
}

// ---------------------------------------------------------------------------
// Dependency field in manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_with_dependencies_serde_roundtrip() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.dependencies
        .insert("@testorg/base".to_string(), PackageVersion::new(0, 9, 1));
    m.dependencies
        .insert("@testorg/util".to_string(), PackageVersion::new(1, 2, 0));
    let json = serde_json::to_string(&m).unwrap();
    let m2: ExtensionManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, m2);
    assert_eq!(m2.dependencies.len(), 2);
}

#[test]
fn test_manifest_unsigned_bytes_differs_with_dependency() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m1 = manifest("testorg", "ext", v, &pub_id, &vk);
    let mut m2 = m1.clone();
    m2.dependencies
        .insert("@other/dep".to_string(), PackageVersion::new(0, 1, 0));
    assert_ne!(m1.unsigned_bytes(), m2.unsigned_bytes());
}

// ---------------------------------------------------------------------------
// is_package_revoked for nonexistent returns false
// ---------------------------------------------------------------------------

#[test]
fn test_is_package_revoked_nonexistent_returns_false() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    assert!(!reg.is_package_revoked("no", "pkg", PackageVersion::new(1, 0, 0)));
}

// ---------------------------------------------------------------------------
// advance_tick does not go backwards (registry just stores it)
// ---------------------------------------------------------------------------

#[test]
fn test_advance_tick_monotonic_stored() {
    let (mut reg, pub_id, sk, vk) = setup();
    reg.advance_tick(DeterministicTimestamp(1000));
    let v1 = PackageVersion::new(1, 0, 0);
    let m1 = manifest("testorg", "ext", v1, &pub_id, &vk);
    publish(&mut reg, &m1, &sk).unwrap();

    reg.advance_tick(DeterministicTimestamp(2000));
    let v2 = PackageVersion::new(1, 0, 1);
    let m2 = manifest("testorg", "ext", v2, &pub_id, &vk);
    publish(&mut reg, &m2, &sk).unwrap();

    let pkg1 = reg.get_package("testorg", "ext", v1).unwrap();
    let pkg2 = reg.get_package("testorg", "ext", v2).unwrap();
    assert_eq!(pkg1.published_at, DeterministicTimestamp(1000));
    assert_eq!(pkg2.published_at, DeterministicTimestamp(2000));
    assert!(pkg1.published_at < pkg2.published_at);
}

// ---------------------------------------------------------------------------
// packages_affected_by_publisher_revocation: empty for unknown publisher
// ---------------------------------------------------------------------------

#[test]
fn test_packages_affected_by_unknown_publisher_empty() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let fake_id = EngineObjectId([77; 32]);
    let affected = reg.packages_affected_by_publisher_revocation(&fake_id);
    assert!(affected.is_empty());
}

// ---------------------------------------------------------------------------
// Search with limit=0 returns nothing
// ---------------------------------------------------------------------------

#[test]
fn test_search_with_zero_limit_returns_empty() {
    let (mut reg, pub_id, sk, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m = manifest("testorg", "ext", v, &pub_id, &vk);
    publish(&mut reg, &m, &sk).unwrap();
    let results = reg.search(&PackageQuery {
        limit: 0,
        ..PackageQuery::default()
    });
    assert!(results.is_empty());
}

// ---------------------------------------------------------------------------
// RegistryError Display messages contain key fields
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_contains_context() {
    let err = RegistryError::PackageAlreadyExists {
        scope: "myscope".to_string(),
        name: "mypkg".to_string(),
        version: PackageVersion::new(3, 1, 4),
    };
    let s = format!("{err}");
    assert!(s.contains("myscope"));
    assert!(s.contains("mypkg"));
    assert!(s.contains("3.1.4"));
}

#[test]
fn test_error_display_content_hash_mismatch_contains_artifact() {
    let err = RegistryError::ContentHashMismatch {
        artifact_name: "critical.wasm".to_string(),
        expected: ContentHash::compute(b"exp"),
        actual: ContentHash::compute(b"act"),
    };
    let s = format!("{err}");
    assert!(s.contains("critical.wasm"));
}

#[test]
fn test_error_display_scope_not_owned_contains_scope() {
    let err = RegistryError::ScopeNotOwned {
        scope: "forbidden-scope".to_string(),
        publisher_id: EngineObjectId([0; 32]),
    };
    let s = format!("{err}");
    assert!(s.contains("forbidden-scope"));
}

// ---------------------------------------------------------------------------
// RegistryEventType Display for all variants
// ---------------------------------------------------------------------------

#[test]
fn test_registry_event_type_display_all() {
    let cases = [
        (RegistryEventType::PublisherRevoked, "publisher_revoked"),
        (RegistryEventType::ScopeClaimed, "scope_claimed"),
        (RegistryEventType::PackageQueried, "package_queried"),
        (RegistryEventType::PackageVerified, "package_verified"),
        (RegistryEventType::VerificationFailed, "verification_failed"),
        (
            RegistryEventType::RevocationPropagated,
            "revocation_propagated",
        ),
    ];
    for (et, expected) in &cases {
        assert_eq!(format!("{et}"), *expected);
    }
}

// ---------------------------------------------------------------------------
// Optional license field
// ---------------------------------------------------------------------------

#[test]
fn test_manifest_no_license_serde_roundtrip() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let mut m = manifest("testorg", "ext", v, &pub_id, &vk);
    m.license = None;
    let json = serde_json::to_string(&m).unwrap();
    let m2: ExtensionManifest = serde_json::from_str(&json).unwrap();
    assert!(m2.license.is_none());
}

#[test]
fn test_manifest_unsigned_bytes_differs_with_vs_without_license() {
    let (_, pub_id, _, vk) = setup();
    let v = PackageVersion::new(1, 0, 0);
    let m_with = manifest("testorg", "ext", v, &pub_id, &vk);
    let mut m_without = m_with.clone();
    m_without.license = None;
    assert_ne!(m_with.unsigned_bytes(), m_without.unsigned_bytes());
}
