#![forbid(unsafe_code)]

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};

#[test]
fn current_legacy_runtime_matches_migration_vector() {
    let definition = br#"{"type":"Policy"}"#;
    let canonical = br#"{"allow":true}"#;
    let schema_id = SchemaId::from_definition(definition);
    let object_id = derive_id(
        ObjectDomain::PolicyObject,
        "zone-a",
        &schema_id,
        canonical,
    )
    .expect("legacy derivation should accept non-empty canonical bytes");

    assert_eq!(
        schema_id.to_string(),
        "9704c8101b9f138f0d7ec78989eb1e1e0760f0756aeade43dee3975b8e73cce5"
    );
    assert_eq!(
        object_id.to_hex(),
        "242c2cd17a8607149ec8dc88944aeb507a042208a522d21a9b58c112729e1ecd"
    );
}

#[test]
fn current_legacy_runtime_still_rejects_empty_canonical_bytes() {
    let schema_id = SchemaId::from_definition(b"schema");
    assert!(
        derive_id(
            ObjectDomain::EvidenceRecord,
            "zone",
            &schema_id,
            b"",
        )
        .is_err()
    );
}
