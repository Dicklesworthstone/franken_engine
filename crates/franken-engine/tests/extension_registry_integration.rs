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
