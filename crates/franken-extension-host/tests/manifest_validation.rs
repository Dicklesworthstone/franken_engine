use frankenengine_extension_host::{
    CURRENT_ENGINE_VERSION, Capability, ExtensionManifest, MAX_NAME_LEN, ManifestValidationContext,
    ManifestValidationError, canonical_manifest_json, compute_content_hash, validate_manifest,
    validate_manifest_with_context,
};
use serde_json::json;
use std::collections::BTreeSet;

fn capability_set(values: &[Capability]) -> BTreeSet<Capability> {
    values.iter().copied().collect()
}

fn base_manifest() -> ExtensionManifest {
    ExtensionManifest {
        name: "weather-ext".to_string(),
        version: "1.2.3".to_string(),
        entrypoint: "dist/main.js".to_string(),
        capabilities: capability_set(&[Capability::FsRead, Capability::FsWrite]),
        publisher_signature: Some(vec![10, 20, 30, 40]),
        content_hash: [0; 32],
        trust_chain_ref: Some("chain/weather".to_string()),
        min_engine_version: CURRENT_ENGINE_VERSION.to_string(),
    }
}

fn with_hash(mut manifest: ExtensionManifest) -> ExtensionManifest {
    manifest.content_hash = compute_content_hash(&manifest).expect("hash");
    manifest
}

#[test]
fn json_manifest_loads_and_validates() {
    let value = json!({
        "name": "json-ext",
        "version": "1.0.0",
        "entrypoint": "dist/index.js",
        "capabilities": ["fs_read", "fs_write"],
        "publisher_signature": [1, 2, 3, 4],
        "content_hash": vec![0u8; 32],
        "trust_chain_ref": "chain/json",
        "min_engine_version": CURRENT_ENGINE_VERSION,
    });

    let mut manifest: ExtensionManifest = serde_json::from_value(value).expect("json parse");
    manifest.content_hash = compute_content_hash(&manifest).expect("content hash");
    assert_eq!(validate_manifest(&manifest), Ok(()));

    let context = ManifestValidationContext::new(
        "trace-json",
        "decision-json",
        "policy-json",
        &manifest.name,
    );
    let report = validate_manifest_with_context(&manifest, &context);
    assert_eq!(report.error, None);
    assert_eq!(report.event.outcome, "pass");
    assert_eq!(report.event.error_code, None);
}

#[test]
fn toml_manifest_loads_and_validates() {
    let zero_hash = vec!["0"; 32].join(", ");
    let toml_input = format!(
        r#"
name = "toml-ext"
version = "2.0.0"
entrypoint = "dist/index.js"
capabilities = ["fs_read", "net_client"]
publisher_signature = [5, 6, 7, 8]
content_hash = [{zero_hash}]
trust_chain_ref = "chain/toml"
min_engine_version = "{CURRENT_ENGINE_VERSION}"
"#
    );

    let mut manifest: ExtensionManifest = toml::from_str(&toml_input).expect("toml parse");
    manifest.content_hash = compute_content_hash(&manifest).expect("hash");
    assert_eq!(validate_manifest(&manifest), Ok(()));
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
