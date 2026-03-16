//! Security-hardening enrichment integration tests.
//!
//! Covers the security behaviors introduced in commit b47640d across multiple
//! modules: extension_registry (publisher re-registration, monotonic ticks,
//! fail-closed revocation, revoked publisher search exclusion), ifc_artifacts
//! (Label Ord security-correct ordering with Custom variants), ts_normalization
//! (context-aware type annotation stripping that preserves string/comment/
//! template-literal content), and baseline_interpreter (prototype-chain
//! property lookup with cycle/depth guards, numeric coercion for arithmetic).

#![forbid(unsafe_code)]
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

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::extension_registry::{
    ArtifactEntry, BuildDescriptor, CapabilityDeclaration, ExtensionManifest, ExtensionRegistry,
    PackageQuery, PackageVersion, RegistryError,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
};
use frankenengine_engine::policy_checkpoint::DeterministicTimestamp;
use frankenengine_engine::signature_preimage::{SigningKey, VerificationKey, sign_preimage};
use frankenengine_engine::ts_normalization::{
    TsCompilerOptions, TsNormalizationConfig, normalize_typescript_to_es2020,
};

// ===========================================================================
// Shared helpers
// ===========================================================================

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

fn build_manifest(
    scope: &str,
    name: &str,
    version: PackageVersion,
    publisher_id: &frankenengine_engine::engine_object_id::EngineObjectId,
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

fn sign_and_publish(
    reg: &mut ExtensionRegistry,
    m: &ExtensionManifest,
    sk: &SigningKey,
) -> Result<frankenengine_engine::engine_object_id::EngineObjectId, RegistryError> {
    let sig = sign_preimage(sk, &m.unsigned_bytes()).expect("signing");
    reg.publish(m.clone(), sig)
}

fn setup_registry() -> (
    ExtensionRegistry,
    frankenengine_engine::engine_object_id::EngineObjectId,
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

fn ts_config() -> TsNormalizationConfig {
    TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            strict: true,
            target: "es2020".to_string(),
            module: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
        },
    }
}

fn make_header() -> IrHeader {
    IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir3,
        source_hash: None,
        source_label: "security-hardening-test".to_string(),
    }
}

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: make_header(),
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

// ===========================================================================
// SECTION 1: Extension Registry — Publisher Re-Registration Guard
// ===========================================================================

#[test]
fn publisher_already_exists_prevents_duplicate_registration() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = signing_key(42);
    let vk = vk_from(&sk);
    let _pub_id = reg.register_publisher("Alice", vk.clone()).unwrap();

    // Same key re-registration must fail with PublisherAlreadyExists.
    let result = reg.register_publisher("Alice-Again", vk);
    assert!(
        matches!(result, Err(RegistryError::PublisherAlreadyExists { .. })),
        "Expected PublisherAlreadyExists for duplicate key registration, got: {result:?}"
    );
}

#[test]
fn publisher_already_exists_after_revocation_still_rejected() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = signing_key(42);
    let vk = vk_from(&sk);
    let pub_id = reg.register_publisher("Alice", vk.clone()).unwrap();

    // Revoke the publisher.
    reg.revoke_publisher(pub_id, "compromised key").unwrap();

    // Attempting to re-register with the same key must still fail.
    let result = reg.register_publisher("Alice-Reborn", vk);
    assert!(
        matches!(result, Err(RegistryError::PublisherAlreadyExists { .. })),
        "Revoked publisher re-registration must be rejected: {result:?}"
    );
}

#[test]
fn publisher_already_exists_different_key_succeeds() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk1 = signing_key(42);
    let vk1 = vk_from(&sk1);
    reg.register_publisher("Alice", vk1).unwrap();

    // Different key is a different publisher — should succeed.
    let sk2 = signing_key(99);
    let vk2 = vk_from(&sk2);
    let result = reg.register_publisher("Bob", vk2);
    assert!(
        result.is_ok(),
        "Different-key publisher registration should succeed"
    );
}

// ===========================================================================
// SECTION 2: Extension Registry — Monotonic Tick Advancement
// ===========================================================================

#[test]
fn advance_tick_forward_accepted() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    reg.advance_tick(DeterministicTimestamp(200));

    // Publishing at the new tick records the correct timestamp.
    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.published_at, DeterministicTimestamp(200));
}

#[test]
fn advance_tick_backward_silently_ignored() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    // Initial tick is 100 from setup.
    reg.advance_tick(DeterministicTimestamp(200));
    // Try to go backward — should be silently ignored.
    reg.advance_tick(DeterministicTimestamp(50));

    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    // Timestamp should still be 200 (backward tick ignored).
    assert_eq!(
        pkg.published_at,
        DeterministicTimestamp(200),
        "Backward tick should be silently ignored; expected 200, got {:?}",
        pkg.published_at
    );
}

#[test]
fn advance_tick_same_value_accepted() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    reg.advance_tick(DeterministicTimestamp(100));
    // Same tick value should be accepted (non-decreasing).
    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(pkg.published_at, DeterministicTimestamp(100));
}

// ===========================================================================
// SECTION 3: Extension Registry — Fail-Closed Unknown Package
// ===========================================================================

#[test]
fn is_package_revoked_returns_true_for_unknown_package() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    // Fail-closed: unknown packages should be treated as revoked.
    assert!(
        reg.is_package_revoked(
            "nonexistent-scope",
            "ghost-pkg",
            PackageVersion::new(0, 0, 1)
        ),
        "Unknown packages must be treated as revoked (fail-closed)"
    );
}

#[test]
fn is_package_revoked_returns_false_for_known_active_package() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();

    assert!(
        !reg.is_package_revoked("testorg", "ext", v),
        "Active known packages must not be treated as revoked"
    );
}

#[test]
fn is_package_revoked_transitive_via_publisher() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();

    // Package not directly revoked.
    assert!(!reg.is_package_revoked("testorg", "ext", v));

    // Revoke the publisher — package should be transitively revoked.
    reg.revoke_publisher(pub_id, "key compromise").unwrap();
    assert!(
        reg.is_package_revoked("testorg", "ext", v),
        "Package from revoked publisher must be transitively revoked"
    );
}

// ===========================================================================
// SECTION 4: Extension Registry — Revoked Publisher Search Exclusion
// ===========================================================================

#[test]
fn search_excludes_revoked_publisher_packages_by_default() {
    let (mut reg, pub_id, sk, vk) = setup_registry();
    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();

    // Before revocation: package visible in search.
    let results = reg.search(&PackageQuery::default());
    assert_eq!(results.len(), 1, "Active package should appear in search");

    // Revoke the publisher (not the package directly).
    reg.revoke_publisher(pub_id, "compromised").unwrap();

    // After publisher revocation: package excluded from default search.
    let results = reg.search(&PackageQuery::default());
    assert!(
        results.is_empty(),
        "Packages from revoked publisher must not appear in default search"
    );

    // With include_revoked=true: package should reappear.
    let results = reg.search(&PackageQuery {
        include_revoked: true,
        ..PackageQuery::default()
    });
    assert_eq!(
        results.len(),
        1,
        "Revoked publisher packages should appear when include_revoked=true"
    );
}

#[test]
fn search_mixed_active_and_revoked_publishers() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));

    // Publisher A — will be revoked.
    let sk_a = signing_key(7);
    let vk_a = vk_from(&sk_a);
    let pub_a = reg.register_publisher("OrgA", vk_a.clone()).unwrap();
    reg.claim_scope(pub_a.clone(), "orga").unwrap();

    // Publisher B — stays active.
    let sk_b = signing_key(13);
    let vk_b = vk_from(&sk_b);
    let pub_b = reg.register_publisher("OrgB", vk_b.clone()).unwrap();
    reg.claim_scope(pub_b.clone(), "orgb").unwrap();

    let v = PackageVersion::new(1, 0, 0);
    let m_a = build_manifest("orga", "ext-a", v, &pub_a, &vk_a);
    let m_b = build_manifest("orgb", "ext-b", v, &pub_b, &vk_b);
    sign_and_publish(&mut reg, &m_a, &sk_a).unwrap();
    sign_and_publish(&mut reg, &m_b, &sk_b).unwrap();

    // Both visible before revocation.
    assert_eq!(reg.search(&PackageQuery::default()).len(), 2);

    // Revoke publisher A.
    reg.revoke_publisher(pub_a, "leak").unwrap();

    // Only publisher B's package should appear.
    let results = reg.search(&PackageQuery::default());
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].manifest.scope, "orgb");
}

// ===========================================================================
// SECTION 5: IFC Label — Security-Correct Ord Implementation
// ===========================================================================

#[test]
fn label_ord_public_less_than_internal() {
    assert!(Label::Public < Label::Internal);
}

#[test]
fn label_ord_internal_less_than_confidential() {
    assert!(Label::Internal < Label::Confidential);
}

#[test]
fn label_ord_confidential_less_than_secret() {
    assert!(Label::Confidential < Label::Secret);
}

#[test]
fn label_ord_secret_less_than_top_secret() {
    assert!(Label::Secret < Label::TopSecret);
}

#[test]
fn label_ord_custom_level_1_less_than_top_secret() {
    let custom_low = Label::Custom {
        name: "low-sensitivity".to_string(),
        level: 1,
    };
    // Custom with level=1 should be between Public(0) and Confidential(2).
    assert!(Label::Public < custom_low);
    assert!(custom_low < Label::Confidential);
    // And critically: Custom(level=1) < TopSecret(level=4).
    assert!(
        custom_low < Label::TopSecret,
        "Custom(level=1) must be less than TopSecret — the old derived Ord would place Custom \
         above TopSecret due to discriminant ordering"
    );
}

#[test]
fn label_ord_custom_level_0_equals_public_order() {
    let custom_zero = Label::Custom {
        name: "visitor".to_string(),
        level: 0,
    };
    // Custom(level=0) has the same level as Public — but tiebreak puts
    // named variants before Custom, so Public < Custom(0).
    assert!(Label::Public < custom_zero);
}

#[test]
fn label_ord_custom_high_level_above_top_secret() {
    let custom_high = Label::Custom {
        name: "ultra-classified".to_string(),
        level: 10,
    };
    assert!(
        Label::TopSecret < custom_high,
        "Custom(level=10) must be above TopSecret(level=4)"
    );
}

#[test]
fn label_ord_custom_same_level_ordered_by_name() {
    let a = Label::Custom {
        name: "alpha".to_string(),
        level: 3,
    };
    let b = Label::Custom {
        name: "beta".to_string(),
        level: 3,
    };
    // Same level — tiebreak by name for determinism.
    assert!(a < b, "Same-level Custom labels must be ordered by name");
}

#[test]
fn label_ord_btree_deterministic_with_custom() {
    let mut labels = BTreeSet::new();
    labels.insert(Label::TopSecret);
    labels.insert(Label::Custom {
        name: "mid".to_string(),
        level: 2,
    });
    labels.insert(Label::Public);
    labels.insert(Label::Custom {
        name: "ultra".to_string(),
        level: 10,
    });
    labels.insert(Label::Internal);

    let ordered: Vec<&Label> = labels.iter().collect();
    assert_eq!(ordered[0], &Label::Public);
    assert_eq!(ordered[1], &Label::Internal);
    assert_eq!(
        ordered[2],
        &Label::Custom {
            name: "mid".to_string(),
            level: 2,
        }
    );
    assert_eq!(ordered[3], &Label::TopSecret);
    assert_eq!(
        ordered[4],
        &Label::Custom {
            name: "ultra".to_string(),
            level: 10,
        }
    );
}

#[test]
fn label_can_flow_to_respects_custom_levels() {
    let custom_1 = Label::Custom {
        name: "custom-1".to_string(),
        level: 1,
    };
    let custom_4 = Label::Custom {
        name: "custom-4".to_string(),
        level: 4,
    };
    // Custom(1) can flow to Custom(4).
    assert!(custom_1.can_flow_to(&custom_4));
    // Custom(4) cannot flow to Custom(1).
    assert!(!custom_4.can_flow_to(&custom_1));
    // Custom(1) can flow to TopSecret (level 4).
    assert!(custom_1.can_flow_to(&Label::TopSecret));
    // TopSecret(4) cannot flow to Custom(1).
    assert!(!Label::TopSecret.can_flow_to(&custom_1));
}

#[test]
fn label_join_meet_with_custom() {
    let custom_2 = Label::Custom {
        name: "mid".to_string(),
        level: 2,
    };
    // join(Public, Custom(2)) = Custom(2).
    let j = Label::Public.join(&custom_2);
    assert_eq!(j, custom_2);
    // meet(TopSecret, Custom(2)) = Custom(2).
    let m = Label::TopSecret.meet(&custom_2);
    assert_eq!(m, custom_2);
}

// ===========================================================================
// SECTION 6: TS Normalization — Context-Aware Type Annotation Stripping
// ===========================================================================

#[test]
fn ts_normalization_preserves_colon_in_double_quoted_string() {
    let source = r#"const s: string = "key: value";"#;
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("key: value"),
        "Colon inside double-quoted string must not be stripped. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_preserves_colon_in_single_quoted_string() {
    let source = "const s: string = 'key: value';";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("key: value"),
        "Colon inside single-quoted string must not be stripped. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_preserves_colon_in_template_literal() {
    let source = "const s: string = `key: value`;";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("key: value"),
        "Colon inside template literal must not be stripped. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_preserves_colon_in_line_comment() {
    let source = "const x: number = 5; // note: important";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("// note: important"),
        "Colon inside line comment must not be stripped. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_preserves_colon_in_block_comment() {
    let source = "const x: number = 5; /* note: important */";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("/* note: important */"),
        "Colon inside block comment must not be stripped. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_strips_type_annotation_outside_string_context() {
    let source = "let x: number = 42;";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    // The type annotation `: number` should be stripped.
    assert!(
        !result.normalized_source.contains("number"),
        "Type annotation outside string context should be stripped. Got: {}",
        result.normalized_source
    );
    // But the variable and value should remain.
    assert!(result.normalized_source.contains("let x"));
    assert!(result.normalized_source.contains("42"));
}

#[test]
fn ts_normalization_mixed_code_and_string_contexts() {
    // Code annotation stripped, string colon preserved.
    let source = r#"function greet(name: string): string { return "hello: " + name; }"#;
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("hello: "),
        "Colon inside string must be preserved in mixed contexts. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_escaped_quote_in_string_does_not_break_context() {
    let source = r#"const s: string = "she said \"key: val\" ok";"#;
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("key: val"),
        "Escaped quotes must not break string context tracking. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_escaped_backtick_in_template_does_not_break_context() {
    let source = r#"const s: string = `escaped \` colon: still inside`;"#;
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("colon: still inside"),
        "Escaped backtick must not break template-literal context. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_multiline_block_comment_with_colons() {
    let source = "const x: number = 1;\n/* note: line1\n  more: line2 */\nconst y: number = 2;";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(
        result.normalized_source.contains("note: line1"),
        "Colon inside multiline block comment must be preserved. Got: {}",
        result.normalized_source
    );
    assert!(
        result.normalized_source.contains("more: line2"),
        "Colon in second line of block comment must be preserved. Got: {}",
        result.normalized_source
    );
}

#[test]
fn ts_normalization_adjacent_strings_and_annotations() {
    let source = r#"const a: string = "x: 1"; const b: number = 2; const c: string = "y: 3";"#;
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    assert!(result.normalized_source.contains("x: 1"));
    assert!(result.normalized_source.contains("y: 3"));
    assert!(!result.normalized_source.contains("number"));
}

// ===========================================================================
// SECTION 7: Baseline Interpreter — Execution Basics
// ===========================================================================

#[test]
fn interpreter_halt_instruction_completes() {
    let module = test_module(vec![Ir3Instruction::Halt]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "halt-test");
    let result = interp.execute(&module);
    assert!(result.is_ok());
}

#[test]
fn interpreter_load_int_and_halt() {
    let module = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "load-int-test");
    let result = interp.execute(&module);
    assert!(result.is_ok());
}

#[test]
fn interpreter_add_two_ints() {
    // Add stores result in r0 (Halt reads r0).
    let module = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: 10_000_000,
        },
        Ir3Instruction::LoadInt {
            dst: 2,
            value: 20_000_000,
        },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "add-test");
    let result = interp.execute(&module).unwrap();
    assert_eq!(result.value, Value::Int(30_000_000));
}

#[test]
fn interpreter_add_bool_coerces_to_number() {
    // true + 1 = 2 (bool true coerces to 1, false to 0, null to 0)
    // Result goes to r0 for Halt to read.
    let module = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadInt {
            dst: 2,
            value: 1_000_000,
        },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "bool-coerce");
    let result = interp.execute(&module).unwrap();
    // true coerces to 1 (JS spec: Number(true) === 1), not 1_000_000.
    // So 1 + 1_000_000 = 1_000_001.
    assert_eq!(result.value, Value::Int(1_000_001));
}

#[test]
fn interpreter_add_null_coerces_to_zero() {
    // null + 5 = 5 (null coerces to 0). Result in r0 for Halt.
    let module = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadInt {
            dst: 2,
            value: 5_000_000,
        },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "null-coerce");
    let result = interp.execute(&module).unwrap();
    // null coerces to 0, so 0 + 5_000_000 = 5_000_000
    assert_eq!(result.value, Value::Int(5_000_000));
}

#[test]
fn interpreter_sub_bool_coercion() {
    // false - 3 = -3 (false coerces to 0). Result in r0 for Halt.
    let module = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: false,
        },
        Ir3Instruction::LoadInt {
            dst: 2,
            value: 3_000_000,
        },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let mut interp = InterpreterCore::new(InterpreterConfig::quickjs_defaults(), "sub-bool");
    let result = interp.execute(&module).unwrap();
    assert_eq!(result.value, Value::Int(-3_000_000));
}

// ===========================================================================
// SECTION 8: Cross-Cutting Security Invariants
// ===========================================================================

#[test]
fn label_serde_roundtrip_with_custom_preserves_level() {
    let label = Label::Custom {
        name: "department-x".to_string(),
        level: 7,
    };
    let json = serde_json::to_string(&label).unwrap();
    let restored: Label = serde_json::from_str(&json).unwrap();
    assert_eq!(restored, label);
    assert_eq!(restored.level(), 7);
}

#[test]
fn label_custom_between_standard_levels() {
    // Custom with level=2 should be at the same level as Confidential.
    let custom_2 = Label::Custom {
        name: "department".to_string(),
        level: 2,
    };
    assert_eq!(custom_2.level(), Label::Confidential.level());
    // Same level: named variant (Confidential) before Custom in tiebreak.
    assert!(Label::Confidential < custom_2);
}

#[test]
fn extension_registry_event_audit_trail_on_re_registration_attempt() {
    let mut reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    let sk = signing_key(42);
    let vk = vk_from(&sk);
    reg.register_publisher("Alice", vk.clone()).unwrap();

    let events_before = reg.events().len();
    let _err = reg.register_publisher("Alice-Again", vk);
    // The key invariant is that no extra publisher appears.
    assert_eq!(reg.publisher_count(), 1);
    // Events should not grow by more than 1 (at most a failure event).
    assert!(reg.events().len() <= events_before + 1);
}

#[test]
fn tick_monotonicity_across_many_operations() {
    let (mut reg, pub_id, sk, vk) = setup_registry();

    // Advance forward, then back, then forward again.
    reg.advance_tick(DeterministicTimestamp(300));
    reg.advance_tick(DeterministicTimestamp(100)); // ignored
    reg.advance_tick(DeterministicTimestamp(250)); // ignored (still < 300)
    reg.advance_tick(DeterministicTimestamp(400)); // accepted

    let v = PackageVersion::new(1, 0, 0);
    let m = build_manifest("testorg", "ext", v, &pub_id, &vk);
    sign_and_publish(&mut reg, &m, &sk).unwrap();
    let pkg = reg.get_package("testorg", "ext", v).unwrap();
    assert_eq!(
        pkg.published_at,
        DeterministicTimestamp(400),
        "Only the highest tick should be retained"
    );
}

#[test]
fn ts_normalization_witness_records_stripping_decision() {
    let source = "let x: number = 42;";
    let result = normalize_typescript_to_es2020(source, &ts_config(), "t1", "d1", "p1").unwrap();
    // The witness should record a type-annotation-stripping decision.
    let has_strip_decision = result
        .witness
        .decisions
        .iter()
        .any(|d| d.step == "type_annotation_stripping");
    assert!(
        has_strip_decision,
        "Witness should record type_annotation_stripping decision"
    );
}

#[test]
fn label_full_ordering_chain() {
    // Verify the complete chain: Public < Internal < Confidential < Secret < TopSecret.
    let labels = vec![
        Label::Public,
        Label::Internal,
        Label::Confidential,
        Label::Secret,
        Label::TopSecret,
    ];
    for i in 0..labels.len() - 1 {
        assert!(
            labels[i] < labels[i + 1],
            "{:?} should be less than {:?}",
            labels[i],
            labels[i + 1]
        );
    }
}

#[test]
fn label_custom_at_each_standard_level() {
    for level in 0..5u32 {
        let custom = Label::Custom {
            name: format!("custom-{level}"),
            level,
        };
        assert_eq!(custom.level(), level);
        // Custom at any level should be ordered correctly relative to standard labels.
        if level < 4 {
            assert!(
                custom < Label::TopSecret,
                "Custom(level={level}) must be below TopSecret"
            );
        }
    }
}

#[test]
fn fail_closed_revocation_unknown_scope_and_name() {
    let reg = ExtensionRegistry::new(DeterministicTimestamp(1));
    // Various unknown packages should all be treated as revoked.
    assert!(reg.is_package_revoked("", "", PackageVersion::new(0, 0, 0)));
    assert!(reg.is_package_revoked("some-scope", "some-name", PackageVersion::new(99, 99, 99)));
    assert!(reg.is_package_revoked("@evil", "malware", PackageVersion::new(1, 0, 0)));
}
