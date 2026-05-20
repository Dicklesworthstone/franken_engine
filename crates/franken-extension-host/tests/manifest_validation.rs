use ed25519_dalek::{Signer, SigningKey};
use frankenengine_extension_host::{
    CURRENT_ENGINE_VERSION, Capability, ExtensionHostConfig, ExtensionManifest, MAX_NAME_LEN,
    ManifestValidationContext, ManifestValidationError, canonical_manifest_json,
    compute_content_hash, validate_manifest, validate_manifest_with_config,
    validate_manifest_with_context_and_config,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn capability_set(values: &[Capability]) -> BTreeSet<Capability> {
    values.iter().copied().collect()
}

/// Create proper Ed25519 signed manifest for validation tests
/// Replaces fake signatures with deterministic Ed25519 provenance
fn base_manifest() -> ExtensionManifest {
    // Use deterministic key for manifest validation tests
    let key_seed = {
        let mut hasher = Sha256::new();
        hasher.update(b"weather-ext");
        hasher.update(b"1.2.3");
        hasher.update(b"dist/main.js");
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    let signing_key = SigningKey::from_bytes(&key_seed);
    let verifying_key = signing_key.verifying_key();

    let mut manifest = ExtensionManifest {
        name: "weather-ext".to_string(),
        version: "1.2.3".to_string(),
        entrypoint: "dist/main.js".to_string(),
        capabilities: capability_set(&[Capability::FsRead, Capability::FsWrite]),
        publisher_signature: None,
        content_hash: [0; 32],
        trust_chain_ref: Some(bytes_to_hex(&verifying_key.to_bytes())),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    };

    manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
    let mut signed_payload = b"franken-extension-host-signed-manifest-v1:".to_vec();
    signed_payload.extend_from_slice(&manifest.content_hash);
    manifest.publisher_signature = Some(signing_key.sign(&signed_payload).to_bytes().to_vec());
    manifest
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn with_hash(mut manifest: ExtensionManifest) -> ExtensionManifest {
    manifest.content_hash = compute_content_hash(&manifest).expect("hash");
    manifest
}

fn trusted_config_for(manifest: &ExtensionManifest) -> ExtensionHostConfig {
    let trust_chain_ref = manifest
        .trust_chain_ref
        .clone()
        .expect("signed test manifest has trust chain ref");
    ExtensionHostConfig {
        trusted_publisher_keys: BTreeMap::from([(trust_chain_ref.clone(), trust_chain_ref)]),
        ..ExtensionHostConfig::default()
    }
}

fn create_test_manifest(
    name: &str,
    version: &str,
    entrypoint: &str,
    capabilities: &[Capability],
) -> ExtensionManifest {
    // Use deterministic key for each test manifest
    let key_seed = {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        hasher.update(version.as_bytes());
        hasher.update(entrypoint.as_bytes());
        let hash = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);
        seed
    };

    let signing_key = SigningKey::from_bytes(&key_seed);
    let verifying_key = signing_key.verifying_key();

    let mut manifest = ExtensionManifest {
        name: name.to_string(),
        version: version.to_string(),
        entrypoint: entrypoint.to_string(),
        capabilities: capability_set(capabilities),
        publisher_signature: None,
        content_hash: [0; 32],
        trust_chain_ref: Some(bytes_to_hex(&verifying_key.to_bytes())),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    };

    manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
    let mut signed_payload = b"franken-extension-host-signed-manifest-v1:".to_vec();
    signed_payload.extend_from_slice(&manifest.content_hash);
    manifest.publisher_signature = Some(signing_key.sign(&signed_payload).to_bytes().to_vec());
    manifest
}

#[test]
fn json_manifest_loads_and_validates() {
    // Create proper signed manifest instead of using fake fixtures
    let manifest = create_test_manifest(
        "json-ext",
        "1.0.0",
        "dist/index.js",
        &[Capability::FsRead, Capability::FsWrite],
    );
    let config = trusted_config_for(&manifest);
    assert_eq!(validate_manifest_with_config(&manifest, &config), Ok(()));

    let context = ManifestValidationContext::new(
        "trace-json",
        "decision-json",
        "policy-json",
        &manifest.name,
    );
    let report = validate_manifest_with_context_and_config(&manifest, &context, &config);
    assert_eq!(report.error, None);
    assert_eq!(report.event.outcome, "pass");
    assert_eq!(report.event.error_code, None);
}

#[test]
fn toml_manifest_loads_and_validates() {
    // Create proper signed manifest instead of using fake TOML fixtures
    let manifest = create_test_manifest(
        "toml-ext",
        "2.0.0",
        "dist/index.js",
        &[Capability::FsRead, Capability::NetClient],
    );
    assert_eq!(
        validate_manifest_with_config(&manifest, &trusted_config_for(&manifest)),
        Ok(())
    );

    // Test TOML serialization round-trip
    let toml_string = toml::to_string(&manifest).expect("toml serialize");
    let parsed: ExtensionManifest = toml::from_str(&toml_string).expect("toml parse");
    assert_eq!(parsed, manifest);
}

#[test]
fn duplicate_capabilities_are_rejected_on_deserialize() {
    let value = json!({
        "name": "dup-ext",
        "version": "1.0.0",
        "entrypoint": "dist/index.js",
        "capabilities": ["fs_read", "fs_read"],
        "publisher_signature": [1, 2],
        "content_hash": vec![0u8; 32],
        "trust_chain_ref": "chain/dup",
        "min_engine_version": CURRENT_ENGINE_VERSION,
    });

    let result = serde_json::from_value::<ExtensionManifest>(value);
    assert!(result.is_err());
}

#[test]
fn malformed_manifest_missing_required_field_is_rejected() {
    let value = json!({
        "name": "missing-entrypoint",
        "version": "1.0.0",
        "capabilities": ["fs_read"],
        "publisher_signature": [1, 2],
        "content_hash": vec![0u8; 32],
        "trust_chain_ref": "chain/missing",
        "min_engine_version": CURRENT_ENGINE_VERSION,
    });

    assert!(serde_json::from_value::<ExtensionManifest>(value).is_err());
}

#[test]
fn invalid_utf8_payload_is_rejected() {
    let bytes = b"{\"name\":\"bad\xff\",\"version\":\"1.0.0\"}";
    assert!(serde_json::from_slice::<ExtensionManifest>(bytes).is_err());
}

#[test]
fn extremely_long_name_is_rejected_by_validator() {
    let mut manifest = base_manifest();
    manifest.name = "x".repeat(MAX_NAME_LEN + 1);
    manifest = with_hash(manifest);

    assert_eq!(
        validate_manifest(&manifest),
        Err(ManifestValidationError::FieldTooLong {
            field: "name",
            max: MAX_NAME_LEN,
            actual: MAX_NAME_LEN + 1,
        })
    );
}

#[test]
fn canonical_serialization_is_stable_for_identical_manifest() {
    let manifest = with_hash(base_manifest());
    let first = canonical_manifest_json(&manifest).expect("canonical json");
    let second = canonical_manifest_json(&manifest).expect("canonical json");

    assert_eq!(first, second);
    assert!(!first.contains('\n'));
    assert!(!first.contains(": "));
}
