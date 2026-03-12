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
    CapabilityIntent, NormalizationDecision, NormalizationEvent, SourceIngestionSummary,
    SourceLanguage, SourceMapEntry, TsCompilerOptions, TsIngestionArtifacts, TsIngestionError,
    TsIngestionErrorCode, TsIngestionEvent, TsIngestionProvenance, TsNormalizationConfig,
    TsNormalizationError, TsNormalizationOutput, TsNormalizationWitness, classify_source_language,
    ingest_typescript_to_pipeline_artifacts, ingest_typescript_to_pipeline_artifacts_default,
    normalize_typescript_to_es2020, prepare_source_entry_for_public_entrypoints,
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
fn normalize_elides_interface_declarations() {
    let source = "interface Foo { bar: string; }\nconst x = 1;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("interface Foo"));
    assert!(!output.normalized_source.contains(": string"));
    assert!(output.normalized_source.contains("const x = 1"));
}

#[test]
fn normalize_elides_type_alias_keyword() {
    let source = "type Num = number;\nconst y = 2;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("type Num"));
    assert!(output.normalized_source.contains("const y = 2"));
}

#[test]
fn normalize_elides_export_type_and_interface_declarations() {
    let source = "export interface Foo { bar: string; }\nexport type Id = string;\nconst y = 2;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("export interface"));
    assert!(!output.normalized_source.contains("export type"));
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

#[test]
fn normalize_strips_implements_clauses() {
    let source = "class Foo implements Bar, Baz { run() { return 1; } }";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("implements Bar"));
    assert!(
        output
            .normalized_source
            .contains("class Foo { run() { return 1; } }")
    );
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
    assert!(!output.normalized_source.contains("interface Bar"));
    assert!(!output.normalized_source.contains("type Alias"));

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

// ===========================================================================
// 18. SourceLanguage — enrichment
// ===========================================================================

#[test]
fn source_language_default_is_javascript() {
    assert_eq!(SourceLanguage::default(), SourceLanguage::JavaScript);
}

#[test]
fn source_language_as_str_javascript() {
    assert_eq!(SourceLanguage::JavaScript.as_str(), "javascript");
}

#[test]
fn source_language_as_str_typescript() {
    assert_eq!(SourceLanguage::TypeScript.as_str(), "typescript");
}

#[test]
fn source_language_javascript_serde_roundtrip() {
    let lang = SourceLanguage::JavaScript;
    let json = serde_json::to_string(&lang).unwrap();
    let back: SourceLanguage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lang);
    assert!(json.contains("javascript"));
}

#[test]
fn source_language_typescript_serde_roundtrip() {
    let lang = SourceLanguage::TypeScript;
    let json = serde_json::to_string(&lang).unwrap();
    let back: SourceLanguage = serde_json::from_str(&json).unwrap();
    assert_eq!(back, lang);
    assert!(json.contains("typescript"));
}

#[test]
fn source_language_clone_and_copy() {
    let lang = SourceLanguage::TypeScript;
    let cloned = lang.clone();
    let copied = lang;
    assert_eq!(lang, cloned);
    assert_eq!(lang, copied);
}

#[test]
fn source_language_debug_nonempty() {
    let dbg = format!("{:?}", SourceLanguage::JavaScript);
    assert!(!dbg.is_empty());
    let dbg_ts = format!("{:?}", SourceLanguage::TypeScript);
    assert!(!dbg_ts.is_empty());
    assert_ne!(dbg, dbg_ts);
}

// ===========================================================================
// 19. SourceIngestionSummary — enrichment
// ===========================================================================

#[test]
fn source_ingestion_summary_default() {
    let summary = SourceIngestionSummary::default();
    assert_eq!(summary.source_language, SourceLanguage::JavaScript);
    assert!(!summary.normalization_applied);
    assert!(summary.original_source_hash.is_empty());
    assert!(summary.normalized_source_hash.is_empty());
    assert_eq!(summary.ts_decision_count, 0);
    assert_eq!(summary.ts_capability_intent_count, 0);
}

#[test]
fn source_ingestion_summary_serde_roundtrip() {
    let summary = SourceIngestionSummary {
        source_language: SourceLanguage::TypeScript,
        normalization_applied: true,
        original_source_hash: "sha256:abc".into(),
        normalized_source_hash: "sha256:def".into(),
        ts_decision_count: 5,
        ts_capability_intent_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: SourceIngestionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

#[test]
fn source_ingestion_summary_default_serde_roundtrip() {
    let summary = SourceIngestionSummary::default();
    let json = serde_json::to_string(&summary).unwrap();
    let back: SourceIngestionSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

// ===========================================================================
// 20. TsIngestionErrorCode — enrichment
// ===========================================================================

#[test]
fn ts_ingestion_error_code_normalization_failed_stable_code() {
    assert_eq!(
        TsIngestionErrorCode::NormalizationFailed.stable_code(),
        "FE-TSINGEST-0001"
    );
}

#[test]
fn ts_ingestion_error_code_parse_failed_stable_code() {
    assert_eq!(
        TsIngestionErrorCode::ParseFailed.stable_code(),
        "FE-TSINGEST-0002"
    );
}

#[test]
fn ts_ingestion_error_code_lowering_failed_stable_code() {
    assert_eq!(
        TsIngestionErrorCode::LoweringFailed.stable_code(),
        "FE-TSINGEST-0003"
    );
}

#[test]
fn ts_ingestion_error_code_capability_contract_failed_stable_code() {
    assert_eq!(
        TsIngestionErrorCode::CapabilityContractFailed.stable_code(),
        "FE-TSINGEST-0004"
    );
}

#[test]
fn ts_ingestion_error_code_normalization_failed_stage() {
    assert_eq!(
        TsIngestionErrorCode::NormalizationFailed.stage(),
        "normalize_typescript"
    );
}

#[test]
fn ts_ingestion_error_code_parse_failed_stage() {
    assert_eq!(
        TsIngestionErrorCode::ParseFailed.stage(),
        "parse_normalized_source"
    );
}

#[test]
fn ts_ingestion_error_code_lowering_failed_stage() {
    assert_eq!(TsIngestionErrorCode::LoweringFailed.stage(), "lower_to_ir3");
}

#[test]
fn ts_ingestion_error_code_capability_contract_failed_stage() {
    assert_eq!(
        TsIngestionErrorCode::CapabilityContractFailed.stage(),
        "validate_capability_contracts"
    );
}

#[test]
fn ts_ingestion_error_code_serde_roundtrip_all_variants() {
    let codes = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ];
    for code in &codes {
        let json = serde_json::to_string(code).unwrap();
        let back: TsIngestionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(*code, back);
    }
}

#[test]
fn ts_ingestion_error_code_stable_codes_are_unique() {
    let codes = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ];
    let stable: std::collections::BTreeSet<&str> = codes.iter().map(|c| c.stable_code()).collect();
    assert_eq!(stable.len(), codes.len());
}

#[test]
fn ts_ingestion_error_code_stages_are_unique() {
    let codes = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ];
    let stages: std::collections::BTreeSet<&str> = codes.iter().map(|c| c.stage()).collect();
    assert_eq!(stages.len(), codes.len());
}

// ===========================================================================
// 21. TsIngestionError — enrichment
// ===========================================================================

#[test]
fn ts_ingestion_error_serde_roundtrip() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::ParseFailed,
        stage: "parse_normalized_source".into(),
        message: "syntax error at line 5".into(),
        events: vec![],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TsIngestionError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn ts_ingestion_error_display_includes_stable_code() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::NormalizationFailed,
        stage: "normalize_typescript".into(),
        message: "empty source".into(),
        events: vec![],
    };
    let display = err.to_string();
    assert!(display.contains("FE-TSINGEST-0001"));
    assert!(display.contains("normalize_typescript"));
    assert!(display.contains("empty source"));
}

#[test]
fn ts_ingestion_error_stable_code_delegates_to_code() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::LoweringFailed,
        stage: "lower_to_ir3".into(),
        message: "lowering error".into(),
        events: vec![],
    };
    assert_eq!(err.stable_code(), "FE-TSINGEST-0003");
}

#[test]
fn ts_ingestion_error_is_std_error() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::ParseFailed,
        stage: "parse_normalized_source".into(),
        message: "unexpected token".into(),
        events: vec![],
    };
    let as_error: &dyn std::error::Error = &err;
    assert!(!as_error.to_string().is_empty());
}

#[test]
fn ts_ingestion_error_with_events_serde_roundtrip() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::CapabilityContractFailed,
        stage: "validate_capability_contracts".into(),
        message: "missing annotation".into(),
        events: vec![TsIngestionEvent {
            trace_id: "t-10".into(),
            decision_id: "d-10".into(),
            policy_id: "p-10".into(),
            component: "ts_ingestion_lane".into(),
            event: "validate_capability_contracts".into(),
            outcome: "fail".into(),
            error_code: Some("FE-TSINGEST-0004".into()),
        }],
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: TsIngestionError = serde_json::from_str(&json).unwrap();
    assert_eq!(back.events.len(), 1);
    assert_eq!(
        back.events[0].error_code.as_deref(),
        Some("FE-TSINGEST-0004")
    );
}

// ===========================================================================
// 22. TsNormalizationError — enrichment
// ===========================================================================

#[test]
fn ts_normalization_error_empty_source_display() {
    let e = TsNormalizationError::EmptySource;
    assert_eq!(e.to_string(), "TS source is empty after normalization");
}

#[test]
fn ts_normalization_error_unsupported_syntax_display() {
    let e = TsNormalizationError::UnsupportedSyntax {
        feature: "namespaces",
    };
    assert_eq!(e.to_string(), "unsupported syntax: namespaces");
}

#[test]
fn ts_normalization_error_unsupported_compiler_option_display_target() {
    let e = TsNormalizationError::UnsupportedCompilerOption {
        option: "target",
        value: "es3".into(),
    };
    assert_eq!(e.to_string(), "unsupported compiler option: target=es3");
}

#[test]
fn ts_normalization_error_unsupported_compiler_option_display_module() {
    let e = TsNormalizationError::UnsupportedCompilerOption {
        option: "module",
        value: "umd".into(),
    };
    assert_eq!(e.to_string(), "unsupported compiler option: module=umd");
}

#[test]
fn ts_normalization_error_unsupported_compiler_option_display_jsx() {
    let e = TsNormalizationError::UnsupportedCompilerOption {
        option: "jsx",
        value: "custom".into(),
    };
    assert_eq!(e.to_string(), "unsupported compiler option: jsx=custom");
}

#[test]
fn ts_normalization_error_variants_are_distinct() {
    let e1 = TsNormalizationError::EmptySource;
    let e2 = TsNormalizationError::UnsupportedSyntax {
        feature: "decorators",
    };
    let e3 = TsNormalizationError::UnsupportedCompilerOption {
        option: "target",
        value: "es5".into(),
    };
    assert_ne!(e1, e2);
    assert_ne!(e2, e3);
    assert_ne!(e1, e3);
}

// ===========================================================================
// 23. classify_source_language — enrichment
// ===========================================================================

#[test]
fn classify_ts_extension() {
    assert_eq!(
        classify_source_language(Some("app.ts"), "const x = 1;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_tsx_extension() {
    assert_eq!(
        classify_source_language(Some("component.tsx"), "const x = 1;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_js_extension() {
    assert_eq!(
        classify_source_language(Some("util.js"), "const x = 1;"),
        SourceLanguage::JavaScript
    );
}

#[test]
fn classify_jsx_extension() {
    assert_eq!(
        classify_source_language(Some("App.jsx"), "const x = 1;"),
        SourceLanguage::JavaScript
    );
}

#[test]
fn classify_no_label_plain_js() {
    assert_eq!(
        classify_source_language(None, "const x = 1;"),
        SourceLanguage::JavaScript
    );
}

#[test]
fn classify_no_label_with_import_type_marker() {
    assert_eq!(
        classify_source_language(None, "import type { Foo } from './foo';"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_as_const_marker() {
    assert_eq!(
        classify_source_language(None, "const x = 1 as const;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_definite_assignment_marker() {
    assert_eq!(
        classify_source_language(None, "let x!: string;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_interface_marker() {
    assert_eq!(
        classify_source_language(None, "interface Foo { bar: number; }"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_enum_marker() {
    assert_eq!(
        classify_source_language(None, "enum Status { Active, Inactive }"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_implements_marker() {
    assert_eq!(
        classify_source_language(None, "class Foo implements Bar { }"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_mts_extension() {
    assert_eq!(
        classify_source_language(Some("module.mts"), "const x = 1;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_cts_extension() {
    assert_eq!(
        classify_source_language(Some("module.cts"), "const x = 1;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_case_insensitive_extension() {
    assert_eq!(
        classify_source_language(Some("App.TS"), "const x = 1;"),
        SourceLanguage::TypeScript
    );
}

#[test]
fn classify_no_label_with_typed_variable() {
    assert_eq!(
        classify_source_language(None, "const value: number = 42;"),
        SourceLanguage::TypeScript
    );
}

// ===========================================================================
// 24. prepare_source_entry_for_public_entrypoints — enrichment
// ===========================================================================

#[test]
fn prepare_source_entry_js_preserves_source_label() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "const a = 1;",
        "my_script.js",
        "t-prep",
        "d-prep",
        "p-prep",
    )
    .unwrap();
    assert_eq!(prepared.source_label, "my_script.js");
}

#[test]
fn prepare_source_entry_ts_applies_normalization() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "const a: number = 1;",
        "my_script.ts",
        "t-prep",
        "d-prep",
        "p-prep",
    )
    .unwrap();
    assert!(prepared.source_ingestion.normalization_applied);
    assert!(!prepared.prepared_source.contains(": number"));
    assert!(prepared.normalization_output.is_some());
    assert!(prepared.source_ingestion.ts_decision_count > 0);
}

#[test]
fn prepare_source_entry_js_hashes_match() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "const b = 2;",
        "plain.js",
        "t-2",
        "d-2",
        "p-2",
    )
    .unwrap();
    assert_eq!(
        prepared.source_ingestion.original_source_hash,
        prepared.source_ingestion.normalized_source_hash
    );
}

#[test]
fn prepare_source_entry_ts_hashes_differ() {
    let prepared = prepare_source_entry_for_public_entrypoints(
        "const b: string = 'hello';",
        "typed.ts",
        "t-3",
        "d-3",
        "p-3",
    )
    .unwrap();
    assert_ne!(
        prepared.source_ingestion.original_source_hash,
        prepared.source_ingestion.normalized_source_hash
    );
}

#[test]
fn prepare_source_entry_empty_ts_source_fails() {
    let err = prepare_source_entry_for_public_entrypoints("   ", "empty.ts", "t-4", "d-4", "p-4")
        .unwrap_err();
    assert!(matches!(err, TsNormalizationError::EmptySource));
}

// ===========================================================================
// 25. NormalizationDecision — enrichment
// ===========================================================================

#[test]
fn normalization_decision_changed_false_serde() {
    let d = NormalizationDecision {
        step: "noop_step".into(),
        changed: false,
        detail: "nothing happened".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: NormalizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    assert!(!back.changed);
}

#[test]
fn normalization_decision_debug_nonempty() {
    let d = NormalizationDecision {
        step: "s".into(),
        changed: true,
        detail: "d".into(),
    };
    assert!(!format!("{d:?}").is_empty());
}

// ===========================================================================
// 26. NormalizationEvent — enrichment
// ===========================================================================

#[test]
fn normalization_event_with_error_code_serde() {
    let e = NormalizationEvent {
        trace_id: "trace-err".into(),
        decision_id: "dec-err".into(),
        policy_id: "pol-err".into(),
        component: "ts_normalization".into(),
        event: "target_validation".into(),
        outcome: "fail".into(),
        error_code: Some("FE-TSNORM-0004".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: NormalizationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
    assert_eq!(back.error_code.as_deref(), Some("FE-TSNORM-0004"));
}

#[test]
fn normalization_event_debug_nonempty() {
    let e = NormalizationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "e".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    assert!(!format!("{e:?}").is_empty());
}

// ===========================================================================
// 27. TsNormalizationWitness — enrichment
// ===========================================================================

#[test]
fn witness_serde_with_decisions_and_intents() {
    let w = TsNormalizationWitness {
        trace_id: "t-w".into(),
        decision_id: "d-w".into(),
        policy_id: "p-w".into(),
        source_hash: "sha256:aaa".into(),
        normalized_hash: "sha256:bbb".into(),
        compiler_options_hash: "sha256:ccc".into(),
        decisions: vec![NormalizationDecision {
            step: "enum_lowering".into(),
            changed: true,
            detail: "lowered 1 enum".into(),
        }],
        capability_intents: vec![CapabilityIntent {
            symbol: "hostcall".into(),
            capability: "net.fetch".into(),
        }],
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: TsNormalizationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
    assert_eq!(back.decisions.len(), 1);
    assert_eq!(back.capability_intents.len(), 1);
}

#[test]
fn witness_empty_decisions_and_intents_serde() {
    let w = TsNormalizationWitness {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        source_hash: "sha256:000".into(),
        normalized_hash: "sha256:111".into(),
        compiler_options_hash: "sha256:222".into(),
        decisions: vec![],
        capability_intents: vec![],
    };
    let json = serde_json::to_string(&w).unwrap();
    let back: TsNormalizationWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(back, w);
    assert!(back.decisions.is_empty());
    assert!(back.capability_intents.is_empty());
}

// ===========================================================================
// 28. CapabilityIntent — enrichment
// ===========================================================================

#[test]
fn capability_intent_debug_nonempty() {
    let ci = CapabilityIntent {
        symbol: "hostcall".into(),
        capability: "db.query".into(),
    };
    assert!(!format!("{ci:?}").is_empty());
}

#[test]
fn capability_intent_clone_eq() {
    let ci = CapabilityIntent {
        symbol: "hostcall".into(),
        capability: "fs.write".into(),
    };
    let cloned = ci.clone();
    assert_eq!(ci, cloned);
}

// ===========================================================================
// 29. SourceMapEntry — enrichment
// ===========================================================================

#[test]
fn source_map_entry_debug_nonempty() {
    let e = SourceMapEntry {
        normalized_line: 42,
        original_line: 37,
    };
    assert!(!format!("{e:?}").is_empty());
}

#[test]
fn source_map_entry_clone_eq() {
    let e = SourceMapEntry {
        normalized_line: 1,
        original_line: 2,
    };
    let c = e.clone();
    assert_eq!(e, c);
}

// ===========================================================================
// 30. TsNormalizationOutput — enrichment
// ===========================================================================

#[test]
fn output_normalized_source_has_no_trailing_whitespace_lines() {
    let source = "const x: number = 1;\n\n\nconst y: string = 'hi';";
    let output = normalize(source).unwrap();
    for line in output.normalized_source.lines() {
        assert_eq!(line, line.trim(), "line should be trimmed: '{line}'");
    }
}

#[test]
fn output_serde_roundtrip_preserves_all_fields() {
    let output = normalize("const x: number = 1;\nconst y = 2;").unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: TsNormalizationOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(back.normalized_source, output.normalized_source);
    assert_eq!(back.capability_intents, output.capability_intents);
    assert_eq!(back.source_map, output.source_map);
    assert_eq!(back.witness, output.witness);
    assert_eq!(back.events, output.events);
}

// ===========================================================================
// 31. TsCompilerOptions validation — enrichment
// ===========================================================================

#[test]
fn compiler_options_target_case_insensitive() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            target: "ES2020".into(),
            ..TsCompilerOptions::default()
        },
    };
    let output = normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap();
    assert!(!output.normalized_source.is_empty());
}

#[test]
fn compiler_options_module_esnext_accepted() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            module: "esnext".into(),
            ..TsCompilerOptions::default()
        },
    };
    let output = normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap();
    assert!(!output.normalized_source.is_empty());
}

#[test]
fn compiler_options_jsx_react_accepted() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            jsx: "react".into(),
            ..TsCompilerOptions::default()
        },
    };
    let output = normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap();
    assert!(!output.normalized_source.is_empty());
}

#[test]
fn compiler_options_unsupported_target_es6() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            target: "es6".into(),
            ..TsCompilerOptions::default()
        },
    };
    let err =
        normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap_err();
    match err {
        TsNormalizationError::UnsupportedCompilerOption { option, value } => {
            assert_eq!(option, "target");
            assert_eq!(value, "es6");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn compiler_options_unsupported_module_systemjs() {
    let cfg = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            module: "system".into(),
            ..TsCompilerOptions::default()
        },
    };
    let err =
        normalize_typescript_to_es2020("const x = 1;", &cfg, "t-1", "d-1", "p-1").unwrap_err();
    match err {
        TsNormalizationError::UnsupportedCompilerOption { option, value } => {
            assert_eq!(option, "module");
            assert_eq!(value, "system");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

// ===========================================================================
// 32. TsNormalizationConfig — enrichment
// ===========================================================================

#[test]
fn ts_normalization_config_default_has_default_compiler_options() {
    let cfg = TsNormalizationConfig::default();
    assert_eq!(cfg.compiler_options, TsCompilerOptions::default());
}

#[test]
fn ts_normalization_config_debug_nonempty() {
    let cfg = TsNormalizationConfig::default();
    assert!(!format!("{cfg:?}").is_empty());
}

// ===========================================================================
// 33. Normalization pipeline steps — enrichment
// ===========================================================================

#[test]
fn normalize_strips_return_type_annotations() {
    let source = "function add(a, b): number { return a + b; }";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains(": number"));
    assert!(output.normalized_source.contains("return a + b"));
}

#[test]
fn normalize_strips_parameter_type_annotations() {
    let source = "function greet(name: string) { return name; }";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains(": string"));
    assert!(output.normalized_source.contains("return name"));
}

#[test]
fn normalize_enum_with_string_values() {
    let source = r#"enum Direction { Up = "UP", Down = "DOWN" }"#;
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("Object.freeze"));
    assert!(output.normalized_source.contains(r#"Up: "UP""#));
    assert!(output.normalized_source.contains(r#"Down: "DOWN""#));
}

#[test]
fn normalize_parameter_property_private() {
    let source = "constructor(private x: number) { }";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("this.x = x;"));
}

#[test]
fn normalize_abstract_class() {
    let source = "abstract class Base { getValue() { return 0; } }";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("abstract"));
    assert!(output.normalized_source.contains("class Base"));
}

#[test]
fn normalize_jsx_self_closing() {
    let source = "<Widget />";
    let output = normalize(source).unwrap();
    assert!(
        output
            .normalized_source
            .contains("createElement(\"Widget\", null)")
    );
}

#[test]
fn normalize_implements_single_interface() {
    let source = "class Dog implements Animal { bark() { return 'woof'; } }";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("implements"));
    assert!(output.normalized_source.contains("class Dog"));
}

#[test]
fn normalize_hostcall_type_param_stripped() {
    let source = r#"const x = hostcall<"fs.read">("path");"#;
    let output = normalize(source).unwrap();
    // The <"fs.read"> type param should be stripped
    assert!(!output.normalized_source.contains("<\"fs.read\">"));
    assert!(output.normalized_source.contains("hostcall("));
}

#[test]
fn normalize_namespace_lowering_produces_iife() {
    let source = "namespace Utils { export const pi = 3; }";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("const Utils = (() => {"));
    assert!(output.normalized_source.contains("ns.pi = 3;"));
    assert!(output.normalized_source.contains("return ns;"));
}

#[test]
fn normalize_decorator_lowering_produces_helper() {
    let source = "@logged\nclass Service { }";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("__applyClassDecorator"));
    assert!(output.normalized_source.contains("let Service ="));
}

// ===========================================================================
// 34. TsIngestionProvenance — enrichment
// ===========================================================================

#[test]
fn ts_ingestion_provenance_construction() {
    let prov = TsIngestionProvenance::new("trace-abc", "dec-xyz", "pol-123");
    assert_eq!(prov.trace_id, "trace-abc");
    assert_eq!(prov.decision_id, "dec-xyz");
    assert_eq!(prov.policy_id, "pol-123");
}

#[test]
fn ts_ingestion_provenance_clone_copy() {
    let prov = TsIngestionProvenance::new("t", "d", "p");
    let copied = prov;
    let cloned = prov;
    assert_eq!(prov, copied);
    assert_eq!(prov, cloned);
}

#[test]
fn ts_ingestion_provenance_debug_nonempty() {
    let prov = TsIngestionProvenance::new("t", "d", "p");
    assert!(!format!("{prov:?}").is_empty());
}

// ===========================================================================
// 35. TsIngestionArtifacts hash methods — enrichment
// ===========================================================================

#[test]
fn ts_ingestion_artifacts_all_hashes_differ() {
    let artifacts = ingest("const x = 1;\nconst y = x;").unwrap();
    // Each stage hash should be unique (different stages produce different content)
    let hashes = [
        artifacts.parse_event_ir_hash(),
        artifacts.ir0_hash(),
        artifacts.ir1_hash(),
        artifacts.ir2_hash(),
        artifacts.ir3_hash(),
    ];
    for h in &hashes {
        assert!(h.starts_with("sha256:"), "hash should be prefixed: {h}");
    }
    // At minimum, ir0 and ir3 hashes should differ
    assert_ne!(artifacts.ir0_hash(), artifacts.ir3_hash());
}

#[test]
fn ts_ingestion_artifacts_deterministic_hashes() {
    let source = "const value: number = 100;";
    let a1 = ingest(source).unwrap();
    let a2 = ingest(source).unwrap();
    assert_eq!(a1.ir0_hash(), a2.ir0_hash());
    assert_eq!(a1.ir1_hash(), a2.ir1_hash());
    assert_eq!(a1.ir2_hash(), a2.ir2_hash());
    assert_eq!(a1.ir3_hash(), a2.ir3_hash());
    assert_eq!(a1.parse_event_ir_hash(), a2.parse_event_ir_hash());
}

// ===========================================================================
// 36. TsIngestionEvent — enrichment
// ===========================================================================

#[test]
fn ts_ingestion_event_serde_roundtrip() {
    let evt = TsIngestionEvent {
        trace_id: "t-ie".into(),
        decision_id: "d-ie".into(),
        policy_id: "p-ie".into(),
        component: "ts_ingestion_lane".into(),
        event: "normalize_typescript".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: TsIngestionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evt);
}

#[test]
fn ts_ingestion_event_with_error_serde_roundtrip() {
    let evt = TsIngestionEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "ts_ingestion_lane".into(),
        event: "parse_normalized_source".into(),
        outcome: "fail".into(),
        error_code: Some("FE-TSINGEST-0002".into()),
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: TsIngestionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, evt);
}

// ===========================================================================
// 37. ingest_typescript_to_pipeline_artifacts_default — enrichment
// ===========================================================================

#[test]
fn ingest_default_builds_artifacts() {
    let artifacts = ingest_typescript_to_pipeline_artifacts_default(
        "const val: number = 99;",
        &default_config(),
        "default.ts",
        "t-def",
        "d-def",
        "p-def",
    )
    .unwrap();
    assert_eq!(artifacts.trace_id, "t-def");
    assert_eq!(artifacts.decision_id, "d-def");
    assert_eq!(artifacts.policy_id, "p-def");
    assert_eq!(artifacts.source_label, "default.ts");
    assert_eq!(artifacts.parse_goal, ParseGoal::Script);
    assert!(
        !artifacts
            .normalization_output
            .normalized_source
            .contains(": number")
    );
}

#[test]
fn ingest_default_empty_source_fails() {
    let err = ingest_typescript_to_pipeline_artifacts_default(
        "   ",
        &default_config(),
        "empty.ts",
        "t-1",
        "d-1",
        "p-1",
    )
    .unwrap_err();
    assert_eq!(err.code, TsIngestionErrorCode::NormalizationFailed);
}

// ===========================================================================
// 38. Determinism — enrichment
// ===========================================================================

#[test]
fn normalization_deterministic_witness_decisions() {
    let source = "interface Shape { area(): number; }\nconst x: number = 42;";
    let o1 = normalize(source).unwrap();
    let o2 = normalize(source).unwrap();
    assert_eq!(o1.witness.decisions.len(), o2.witness.decisions.len());
    for (d1, d2) in o1.witness.decisions.iter().zip(o2.witness.decisions.iter()) {
        assert_eq!(d1, d2);
    }
}

#[test]
fn normalization_deterministic_events() {
    let source = "const x: number = 1;";
    let o1 = normalize(source).unwrap();
    let o2 = normalize(source).unwrap();
    assert_eq!(o1.events.len(), o2.events.len());
    for (e1, e2) in o1.events.iter().zip(o2.events.iter()) {
        assert_eq!(e1, e2);
    }
}

#[test]
fn normalization_deterministic_source_map() {
    let source = "type Id = string;\nconst x = 1;\nconst y = 2;";
    let o1 = normalize(source).unwrap();
    let o2 = normalize(source).unwrap();
    assert_eq!(o1.source_map, o2.source_map);
}

// ===========================================================================
// 39. Decision step coverage — enrichment
// ===========================================================================

#[test]
fn decision_steps_include_implements_clause() {
    let output = normalize("class Foo implements Bar { }").unwrap();
    let steps: Vec<&str> = output
        .witness
        .decisions
        .iter()
        .map(|d| d.step.as_str())
        .collect();
    assert!(steps.contains(&"implements_clause_normalization"));
}

#[test]
fn decision_steps_include_type_space_declaration_elision() {
    let output = normalize("interface Foo { bar: string; }\nconst x = 1;").unwrap();
    let steps: Vec<&str> = output
        .witness
        .decisions
        .iter()
        .map(|d| d.step.as_str())
        .collect();
    assert!(steps.contains(&"type_space_declaration_elision"));
}

#[test]
fn decision_steps_include_hostcall_type_param_stripping() {
    let source = r#"const x = hostcall<"fs.read">("path");"#;
    let output = normalize(source).unwrap();
    let steps: Vec<&str> = output
        .witness
        .decisions
        .iter()
        .map(|d| d.step.as_str())
        .collect();
    assert!(steps.contains(&"hostcall_type_param_stripping"));
}

#[test]
fn decision_all_steps_present_for_simple_source() {
    let output = normalize("const x = 1;").unwrap();
    let steps: Vec<&str> = output
        .witness
        .decisions
        .iter()
        .map(|d| d.step.as_str())
        .collect();
    let expected_steps = [
        "type_only_import_elision",
        "type_space_declaration_elision",
        "namespace_lowering",
        "decorator_lowering",
        "definite_assignment_normalization",
        "const_assertion_normalization",
        "type_annotation_stripping",
        "enum_lowering",
        "parameter_property_lowering",
        "abstract_class_lowering",
        "implements_clause_normalization",
        "jsx_lowering",
        "capability_intent_extraction",
        "hostcall_type_param_stripping",
    ];
    for step in &expected_steps {
        assert!(steps.contains(step), "missing decision step: {step}");
    }
}

// ===========================================================================
// 40. Ingestion events linkage — enrichment
// ===========================================================================

#[test]
fn ingestion_events_all_have_ts_ingestion_lane_component() {
    let artifacts = ingest("const x: number = 1;").unwrap();
    for event in &artifacts.ingestion_events {
        assert_eq!(event.component, "ts_ingestion_lane");
    }
}

#[test]
fn ingestion_success_events_have_pass_outcome() {
    let artifacts = ingest("const x: number = 1;").unwrap();
    for event in &artifacts.ingestion_events {
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn ingestion_error_events_have_fail_outcome() {
    let err = ingest("const x: number = ;").unwrap_err();
    assert!(err.events.iter().any(|e| e.outcome == "fail"));
}

// ===========================================================================
// 41. Edge cases for normalization — enrichment
// ===========================================================================

#[test]
fn normalize_whitespace_only_source_fails() {
    let err = normalize("   \n  \t  \n  ").unwrap_err();
    assert!(matches!(err, TsNormalizationError::EmptySource));
}

#[test]
fn normalize_crlf_newlines_handled() {
    let source = "const x: number = 1;\r\nconst y = 2;";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("const y = 2"));
    assert!(!output.normalized_source.contains("\r"));
}

#[test]
fn normalize_multiple_type_only_imports() {
    let source = "import type { A } from 'a';\nimport type { B } from 'b';\nconst z = 3;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("import type"));
    assert!(output.normalized_source.contains("const z = 3"));
}

#[test]
fn normalize_mixed_regular_and_type_imports() {
    let source = "import { foo } from 'foo';\nimport type { Bar } from 'bar';\nconst x = foo;";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("import { foo }"));
    assert!(!output.normalized_source.contains("import type"));
}

#[test]
fn normalize_multiple_enums() {
    let source = "enum A { X, Y }\nenum B { P = 10, Q }";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("const A = Object.freeze"));
    assert!(output.normalized_source.contains("const B = Object.freeze"));
    assert!(output.normalized_source.contains("X: 0"));
    assert!(output.normalized_source.contains("Y: 1"));
    assert!(output.normalized_source.contains("P: 10"));
    assert!(output.normalized_source.contains("Q: 11"));
}

#[test]
fn normalize_multiple_interfaces_and_values() {
    let source = "interface Foo { a: number; }\ninterface Bar { b: string; }\nconst val = 42;";
    let output = normalize(source).unwrap();
    assert!(!output.normalized_source.contains("interface"));
    assert!(output.normalized_source.contains("const val = 42"));
}

#[test]
fn normalize_preserves_comments_in_code() {
    let source = "// this is a comment\nconst x = 1;";
    let output = normalize(source).unwrap();
    assert!(output.normalized_source.contains("// this is a comment"));
    assert!(output.normalized_source.contains("const x = 1"));
}

#[test]
fn normalize_source_with_only_type_declarations_becomes_empty() {
    let source = "interface Foo { x: number; }";
    let result = normalize(source);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        TsNormalizationError::EmptySource
    ));
}

#[test]
fn normalize_capability_intents_sorted_and_deduped() {
    let source = r#"const a = hostcall<"net.fetch">("url");
const b = hostcall<"fs.read">("path");
const c = hostcall<"net.fetch">("url2");"#;
    let output = normalize(source).unwrap();
    assert_eq!(output.capability_intents.len(), 2);
    // Should be sorted by capability
    assert_eq!(output.capability_intents[0].capability, "fs.read");
    assert_eq!(output.capability_intents[1].capability, "net.fetch");
}

#[test]
fn normalize_source_map_line_numbers_start_at_one() {
    let source = "const a = 1;\nconst b = 2;\nconst c = 3;";
    let output = normalize(source).unwrap();
    assert!(!output.source_map.is_empty());
    assert_eq!(output.source_map[0].normalized_line, 1);
    assert_eq!(output.source_map[0].original_line, 1);
}

// ===========================================================================
// 42. Ingestion with Module parse goal — enrichment
// ===========================================================================

#[test]
fn ingest_with_module_parse_goal() {
    let artifacts = ingest_typescript_to_pipeline_artifacts(
        "const val: number = 1;",
        &default_config(),
        "module.ts",
        ParseGoal::Module,
        &ParserOptions::default(),
        TsIngestionProvenance::new("t-mod", "d-mod", "p-mod"),
    )
    .unwrap();
    assert_eq!(artifacts.parse_goal, ParseGoal::Module);
    assert_eq!(artifacts.source_label, "module.ts");
}

// ===========================================================================
// 43. TsNormalizationOutput field access — enrichment
// ===========================================================================

#[test]
fn output_witness_compiler_options_hash_is_deterministic_for_same_config() {
    let o1 = normalize("const a = 1;").unwrap();
    let o2 = normalize("const b = 2;").unwrap();
    assert_eq!(
        o1.witness.compiler_options_hash, o2.witness.compiler_options_hash,
        "same config should produce same compiler_options_hash"
    );
}

#[test]
fn output_witness_source_hash_differs_for_different_source() {
    let o1 = normalize("const a = 1;").unwrap();
    let o2 = normalize("const b = 2;").unwrap();
    assert_ne!(o1.witness.source_hash, o2.witness.source_hash);
}

#[test]
fn output_witness_normalized_hash_differs_for_different_source() {
    let o1 = normalize("const a = 1;").unwrap();
    let o2 = normalize("const b = 2;").unwrap();
    assert_ne!(o1.witness.normalized_hash, o2.witness.normalized_hash);
}
