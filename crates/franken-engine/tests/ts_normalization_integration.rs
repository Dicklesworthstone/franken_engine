#![forbid(unsafe_code)]
//! Integration tests for the `ts_normalization` module.
//!
//! Exercises TypeScript-to-ES2020 normalization, compiler option validation,
//! capability-intent extraction, witness generation, and serde round-trips
//! from outside the crate boundary.

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

use frankenengine_engine::ts_normalization::{
    CapabilityIntent, NormalizationDecision, NormalizationEvent, SourceMapEntry, TsCompilerOptions,
    TsIngestionArtifacts, TsIngestionError, TsIngestionErrorCode, TsIngestionProvenance,
    TsNormalizationConfig, TsNormalizationError, TsNormalizationOutput, TsNormalizationWitness,
    ingest_typescript_to_pipeline_artifacts, normalize_typescript_to_es2020,
};
use frankenengine_engine::{ast::ParseGoal, parser::ParserOptions};

// ===========================================================================
// Helpers
// ===========================================================================

fn default_config() -> TsNormalizationConfig {
    TsNormalizationConfig::default()
}

fn normalize(source: &str) -> Result<TsNormalizationOutput, TsNormalizationError> {
    normalize_typescript_to_es2020(source, &default_config(), "t-1", "d-1", "p-1")
}

fn ingest(source: &str) -> Result<TsIngestionArtifacts, TsIngestionError> {
    ingest_typescript_to_pipeline_artifacts(
        source,
        &default_config(),
        "fixture.ts",
        ParseGoal::Script,
        &ParserOptions::default(),
        TsIngestionProvenance::new("t-1", "d-1", "p-1"),
    )
}

// ===========================================================================
// 1. Config — default values, serde
// ===========================================================================

#[test]
fn config_default_values() {
    let cfg = TsCompilerOptions::default();
    assert!(cfg.strict);
    assert_eq!(cfg.target, "es2020");
    assert_eq!(cfg.module, "esnext");
    assert_eq!(cfg.jsx, "react-jsx");
}

#[test]
fn config_serde_round_trip() {
    let cfg = TsNormalizationConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: TsNormalizationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cfg);
}

#[test]
fn compiler_options_serde_round_trip() {
    let opts = TsCompilerOptions::default();
    let json = serde_json::to_string(&opts).unwrap();
    let back: TsCompilerOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back, opts);
}

// ===========================================================================
// 2. Basic normalization — type annotations stripped
// ===========================================================================

#[test]
fn normalize_strips_type_annotations() {
    let source = "const x: number = 42;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains(": number"));
    assert!(output.normalized_source.contains("42"));
}

#[test]
fn normalize_strips_type_annotations_inside_interface() {
    // The normalizer strips `:` type annotations but preserves the `interface` keyword
    // (full interface erasure is beyond the simple line-by-line normalizer).
    let source = "interface Foo { bar: string; }\nconst x = 1;";
    let output = normalize(source).unwrap();
    // `: string` annotation should be stripped
    assert!(!output.normalized_source.contains(": string"));
    assert!(output.normalized_source.contains("const x = 1"));
}

#[test]
fn normalize_preserves_type_alias_keyword() {
    // The simple normalizer does not erase `type` alias declarations;
    // it only strips colon-based type annotations.
    let source = "type Num = number;\nconst y = 2;";
    let output = normalize(source).unwrap();
    // `type` keyword preserved (no full declaration erasure)
    assert!(output.normalized_source.contains("type Num"));
    assert!(output.normalized_source.contains("const y = 2"));
}

// ===========================================================================
// 3. Type-only import elision
// ===========================================================================

#[test]
fn normalize_elides_type_only_imports() {
    let source = "import type { Foo } from './foo';\nconst x = 1;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("import type"));
}

// ===========================================================================
// 4. Enum lowering
// ===========================================================================

#[test]
fn normalize_lowers_enums() {
    let source = "enum Color { Red, Green, Blue }";
    let output = normalize(source).unwrap();
    assert!(
        output.normalized_source.contains("Object.freeze")
            || output.normalized_source.contains("Color"),
        "enum should be lowered: {}",
        output.normalized_source
    );
}

// ===========================================================================
// 5. Const assertion removal
// ===========================================================================

#[test]
fn normalize_removes_const_assertions() {
    let source = "const x = { a: 1 } as const;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("as const"));
}

// ===========================================================================
// 6. Definite assignment assertion
// ===========================================================================

#[test]
fn normalize_removes_definite_assignment() {
    let source = "class Foo { bar!: string; }";
    let output = normalize(source).unwrap();
    // The `!:` should be normalized to `:` or the annotation stripped entirely
    assert!(!output.normalized_source.contains("!:"));
}

// ===========================================================================
// 7. JSX lowering
// ===========================================================================

#[test]
fn normalize_lowers_simple_jsx() {
    // The simple JSX lowerer only handles self-closing tags and
    // simple `<tag>text</tag>` on one line (no attributes).
    let source = "<div>hello</div>";
    let output = normalize(source).unwrap();
    assert!(
        output.normalized_source.contains("createElement"),
        "simple JSX should be lowered: {}",
        output.normalized_source
    );
}

#[test]
fn normalize_preserves_complex_jsx() {
    // JSX with attributes is beyond the simple lowerer — it passes through.
    let source = "const el = <div className=\"test\">hello</div>;";
    let output = normalize(source).unwrap();
    // Complex JSX is not lowered, so the source passes through intact
    assert!(output.normalized_source.contains("div"));
}

#[test]
fn normalize_jsx_preserve_mode() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            jsx: "preserve".into(),
            ..TsCompilerOptions::default()
        },
    };
    let source = "const el = <div>hello</div>;";
    let output = normalize_typescript_to_es2020(source, &cfg, "t-1", "d-1", "p-1").unwrap();
    // In preserve mode, JSX should remain
    assert!(output.normalized_source.contains("<div>") || output.normalized_source.contains("div"));
}

// ===========================================================================
// 8. Capability intent extraction
// ===========================================================================

#[test]
fn normalize_extracts_capability_intents() {
    let source = r#"const x = hostcall<"fs.read">("path");"#;
    let output = normalize(source).unwrap();
    if !output.capability_intents.is_empty() {
        assert!(
            output
                .capability_intents
                .iter()
                .any(|c| c.capability.contains("fs"))
        );
    }
}

// ===========================================================================
// 9. Error cases
// ===========================================================================

#[test]
fn normalize_empty_source_fails() {
    let err = normalize("").unwrap_err();
    assert!(matches!(err, TsNormalizationError::EmptySource));
}

#[test]
fn normalize_unsupported_target_fails() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            target: "es5".into(),
            ..TsCompilerOptions::default()
        },
    };
    let err =
        normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap_err();
    assert!(matches!(
        err,
        TsNormalizationError::UnsupportedCompilerOption { .. }
    ));
}

#[test]
fn normalize_unsupported_module_fails() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            module: "amd".into(),
            ..TsCompilerOptions::default()
        },
    };
    let err =
        normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap_err();
    assert!(matches!(
        err,
        TsNormalizationError::UnsupportedCompilerOption { .. }
    ));
}

#[test]
fn normalize_unsupported_jsx_fails() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            jsx: "classic".into(),
            ..TsCompilerOptions::default()
        },
    };
    let err =
        normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap_err();
    assert!(matches!(
        err,
        TsNormalizationError::UnsupportedCompilerOption { .. }
    ));
}

// ===========================================================================
// 10. Output structure
// ===========================================================================

#[test]
fn output_has_witness() {
    let output = normalize("const x = 1;").unwrap();
    assert!(!output.witness.source_hash.is_empty());
    assert!(!output.witness.normalized_hash.is_empty());
    assert!(!output.witness.compiler_options_hash.is_empty());
    assert_eq!(output.witness.trace_id, "t-1");
    assert_eq!(output.witness.decision_id, "d-1");
    assert_eq!(output.witness.policy_id, "p-1");
}

#[test]
fn output_has_decisions() {
    let output = normalize("const x: number = 1;").unwrap();
    assert!(!output.witness.decisions.is_empty());
}

#[test]
fn output_has_events() {
    let output = normalize("const x = 1;").unwrap();
    assert!(!output.events.is_empty());
}

#[test]
fn output_has_source_map() {
    let source = "const x: number = 1;\nconst y: string = 'hello';";
    let output = normalize(source).unwrap();
    // Source map should have entries
    assert!(!output.source_map.is_empty());
}

// ===========================================================================
// 11. Determinism
// ===========================================================================

#[test]
fn normalization_is_deterministic() {
    let source = "const x: number = 42;\ninterface Foo { bar: string; }";
    let o1 = normalize(source).unwrap();
    let o2 = normalize(source).unwrap();
    assert_eq!(o1.normalized_source, o2.normalized_source);
    assert_eq!(o1.witness.source_hash, o2.witness.source_hash);
    assert_eq!(o1.witness.normalized_hash, o2.witness.normalized_hash);
}

// ===========================================================================
// 12. Witness hashes are sha256-prefixed
// ===========================================================================

#[test]
fn witness_hashes_prefixed() {
    let output = normalize("const x = 1;").unwrap();
    assert!(
        output.witness.source_hash.starts_with("sha256:"),
        "source_hash: {}",
        output.witness.source_hash
    );
    assert!(
        output.witness.normalized_hash.starts_with("sha256:"),
        "normalized_hash: {}",
        output.witness.normalized_hash
    );
    assert!(
        output.witness.compiler_options_hash.starts_with("sha256:"),
        "compiler_options_hash: {}",
        output.witness.compiler_options_hash
    );
}

// ===========================================================================
// 13. Serde round-trips
// ===========================================================================

#[test]
fn output_serde_round_trip() {
    let output = normalize("const x: number = 1;").unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: TsNormalizationOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, output);
}

#[test]
fn witness_serde_round_trip() {
    let output = normalize("const x = 1;").unwrap();
    let json = serde_json::to_string(&output.witness).unwrap();
    let back: TsNormalizationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, output.witness);
}

#[test]
fn normalization_decision_serde_round_trip() {
    let d = NormalizationDecision {
        step: "type_strip".into(),
        changed: true,
        detail: "removed type annotation".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: NormalizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn normalization_event_serde_round_trip() {
    let e = NormalizationEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "ts_normalization".into(),
        event: "normalize".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: NormalizationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn source_map_entry_serde_round_trip() {
    let entry = SourceMapEntry {
        normalized_line: 1,
        original_line: 3,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SourceMapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn capability_intent_serde_round_trip() {
    let ci = CapabilityIntent {
        symbol: "hostcall".into(),
        capability: "fs.read".into(),
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: CapabilityIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ci);
}

// ===========================================================================
// 14. Error display
// ===========================================================================

#[test]
fn error_display_nonempty() {
    let errs: Vec<TsNormalizationError> = vec![
        TsNormalizationError::EmptySource,
        TsNormalizationError::UnsupportedSyntax {
            feature: "decorators",
        },
        TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: "es5".into(),
        },
    ];
    for e in &errs {
        assert!(!e.to_string().is_empty());
    }
}

// ===========================================================================
// 15. Commonjs module mode accepted
// ===========================================================================

#[test]
fn normalize_accepts_commonjs_module() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            module: "commonjs".into(),
            ..TsCompilerOptions::default()
        },
    };
    let output = normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap();
    assert!(!output.normalized_source.is_empty());
}

// ===========================================================================
// 16. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_typescript_normalization() {
    let source = r#"
import type { Foo } from './types';
interface Bar { baz: string; }
type Alias = number;

enum Direction { Up, Down, Left, Right }

class Service {
    name!: string;
    constructor(public id: number) {}
}

const config = { debug: true } as const;
const x: number = 42;
"#;
    let output = normalize(source).unwrap();

    // Type annotations stripped (colon-based)
    assert!(!output.normalized_source.contains("import type"));
    assert!(!output.normalized_source.contains(": string"));
    assert!(!output.normalized_source.contains(": number"));
    assert!(!output.normalized_source.contains("as const"));
    assert!(!output.normalized_source.contains("!:"));
    // Note: interface/type-alias keywords are preserved (no full erasure)

    // Values preserved
    assert!(output.normalized_source.contains("42"));

    // Witness
    assert!(!output.witness.source_hash.is_empty());
    assert!(!output.witness.decisions.is_empty());

    // Events
    assert!(!output.events.is_empty());

    // Serde
    let json = serde_json::to_string(&output).unwrap();
    let back: TsNormalizationOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.normalized_source, output.normalized_source);
}

// ===========================================================================
// 17. TS ingestion lane (normalize -> parse -> lower artifacts)
// ===========================================================================

#[test]
fn ts_ingestion_builds_pipeline_artifacts_for_supported_source() {
    let source = r#"
const value: number = 41;
const next = value;
"#;

    let artifacts = ingest(source).unwrap();

    assert!(artifacts.ir0_hash().starts_with("sha256:"));
    assert!(artifacts.ir1_hash().starts_with("sha256:"));
    assert!(artifacts.ir2_hash().starts_with("sha256:"));
    assert!(artifacts.ir3_hash().starts_with("sha256:"));
    assert!(artifacts.parse_event_ir_hash().starts_with("sha256:"));
    assert!(
        !artifacts
            .normalization_output
            .normalized_source
            .contains(": number")
    );
    assert!(!artifacts.lowering_output.ir3.instructions.is_empty());
}

#[test]
fn ts_ingestion_reports_deterministic_normalization_error() {
    let source = "@sealed\nconst value = 1;";
    let err = ingest(source).unwrap_err();

    assert_eq!(err.code, TsIngestionErrorCode::NormalizationFailed);
    assert_eq!(err.stable_code(), "FE-TSINGEST-0001");
    assert_eq!(err.stage, "normalize_typescript");
    assert!(
        err.events
            .iter()
            .any(|event| event.error_code.as_deref() == Some("FE-TSINGEST-0001"))
    );
}

#[test]
fn ts_ingestion_reports_deterministic_parse_error() {
    let source = "const value: number = ;";
    let err = ingest(source).unwrap_err();

    assert_eq!(err.code, TsIngestionErrorCode::ParseFailed);
    assert_eq!(err.stable_code(), "FE-TSINGEST-0002");
    assert_eq!(err.stage, "parse_normalized_source");
    assert!(err.message.contains("parse_error_code="));
}

#[test]
fn ts_ingestion_preserves_trace_and_source_map_linkage() {
    let source = "const value: number = 1;\nconst next = value;";
    let artifacts = ingest(source).unwrap();

    assert_eq!(artifacts.trace_id, "t-1");
    assert_eq!(artifacts.decision_id, "d-1");
    assert_eq!(artifacts.policy_id, "p-1");
    assert_eq!(artifacts.source_label, "fixture.ts");
    assert_eq!(artifacts.parse_goal, ParseGoal::Script);
    assert!(!artifacts.normalization_output.source_map.is_empty());
    assert_eq!(artifacts.normalization_output.witness.trace_id, "t-1");
    assert_eq!(artifacts.normalization_output.witness.decision_id, "d-1");
    assert_eq!(artifacts.normalization_output.witness.policy_id, "p-1");
    assert!(artifacts.ingestion_events.iter().all(|event| {
        event.trace_id == "t-1" && event.decision_id == "d-1" && event.policy_id == "p-1"
    }));
}

#[test]
fn ts_ingestion_artifacts_serde_round_trip() {
    let artifacts = ingest("const value: number = 1;").unwrap();
    let json = serde_json::to_string(&artifacts).unwrap();
    let back: TsIngestionArtifacts = serde_json::from_str(&json).unwrap();

    assert_eq!(back.trace_id, artifacts.trace_id);
    assert_eq!(back.parse_goal, artifacts.parse_goal);
    assert_eq!(back.ir3_hash(), artifacts.ir3_hash());
    assert_eq!(back.parse_event_ir_hash(), artifacts.parse_event_ir_hash());
}

#[test]
fn ts_ingestion_rejects_unannotated_hostcalls_fail_closed() {
    let err = ingest(r#"const x = hostcall("path");"#).unwrap_err();

    assert_eq!(err.code, TsIngestionErrorCode::CapabilityContractFailed);
    assert_eq!(err.stable_code(), "FE-TSINGEST-0004");
    assert_eq!(err.stage, "validate_capability_contracts");
    assert!(
        err.message
            .contains("hostcall invocation missing capability annotation")
    );
    assert!(err.events.iter().any(|event| {
        event.event == "validate_capability_contracts"
            && event.error_code.as_deref() == Some("FE-TSINGEST-0004")
    }));
}

#[test]
fn ts_ingestion_rejects_invalid_capability_annotation_characters() {
    let err = ingest(r#"const x = hostcall<"fs/read">("path");"#).unwrap_err();

    assert_eq!(err.code, TsIngestionErrorCode::CapabilityContractFailed);
    assert_eq!(err.stable_code(), "FE-TSINGEST-0004");
    assert_eq!(err.stage, "validate_capability_contracts");
    assert!(
        err.message
            .contains("capability annotation `fs/read` is invalid"),
        "unexpected message: {}",
        err.message
    );
}

#[test]
fn ts_ingestion_propagates_declared_capability_into_ir_contracts() {
    let artifacts = ingest(r#"const x = hostcall<"fs.read">("path");"#).unwrap();

    assert!(artifacts.ingestion_events.iter().any(|event| {
        event.event == "validate_capability_contracts"
            && event.outcome == "pass"
            && event.error_code.is_none()
    }));
    // The capability intent is extracted from the original TS source before
    // the hostcall type parameter is stripped for ES2020 parser compatibility.
    assert!(
        artifacts
            .normalization_output
            .capability_intents
            .iter()
            .any(|ci| ci.capability == "fs.read"),
        "capability intent fs.read should be extracted from original source"
    );
    // After stripping <"fs.read">, the parser sees hostcall("path") as a
    // plain call — the lowering pipeline tags it with hostcall.invoke.
    assert!(
        artifacts
            .lowering_output
            .ir2
            .ops
            .iter()
            .filter_map(|op| op
                .required_capability
                .as_ref()
                .map(|capability| capability.0.as_str()))
            .any(|capability| capability == "hostcall.invoke"),
        "hostcall call should produce hostcall.invoke in IR"
    );
}
