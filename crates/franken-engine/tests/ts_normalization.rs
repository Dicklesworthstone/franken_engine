use frankenengine_engine::ts_normalization::{
    CapabilityIntent, NormalizationDecision, NormalizationEvent, SourceMapEntry, TsCompilerOptions,
    TsIngestionError, TsIngestionErrorCode, TsIngestionEvent, TsNormalizationConfig,
    TsNormalizationError, TsNormalizationOutput, TsNormalizationWitness,
    normalize_typescript_to_es2020,
};

#[test]
fn normalization_is_deterministic_for_same_input_and_options() {
    let source = r#"
import type { Foo } from "./types";
const point: { x: number; y: number } = { x: 1, y: 2 };
const view = <Widget />;
"#;

    let config = TsNormalizationConfig::default();
    let first =
        normalize_typescript_to_es2020(source, &config, "trace-1", "decision-1", "policy-1")
            .expect("first normalization should pass");
    let second =
        normalize_typescript_to_es2020(source, &config, "trace-1", "decision-1", "policy-1")
            .expect("second normalization should pass");

    assert_eq!(first.normalized_source, second.normalized_source);
    assert_eq!(first.witness.source_hash, second.witness.source_hash);
    assert_eq!(
        first.witness.normalized_hash,
        second.witness.normalized_hash
    );
    assert_eq!(
        first.witness.compiler_options_hash,
        second.witness.compiler_options_hash
    );
    assert_eq!(first.capability_intents, second.capability_intents);
}

#[test]
fn type_annotations_and_const_assertions_are_removed() {
    let source = r#"
const answer: number = 42 as const;
let maybe!: string;
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-2",
        "decision-2",
        "policy-2",
    )
    .expect("normalization should pass");

    assert!(!output.normalized_source.contains(": number"));
    assert!(!output.normalized_source.contains("as const"));
    assert!(!output.normalized_source.contains("!:"));
}

#[test]
fn token_aware_normalization_skips_strings_and_comments() {
    let source = r#"
const label = "abstract class as const !:";
/* abstract class Commented {} as const */
abstract class Base {}
const answer = [1, 2, 3] as const;
class Holder { value!: string; }
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-token-aware",
        "decision-token-aware",
        "policy-token-aware",
    )
    .expect("normalization should pass");

    assert!(
        output
            .normalized_source
            .contains(r#""abstract class as const !:""#)
    );
    assert!(
        output
            .normalized_source
            .contains("/* abstract class Commented {} as const */")
    );
    assert!(output.normalized_source.contains("class Base {}"));
    assert!(!output.normalized_source.contains("abstract class Base"));
    assert!(!output.normalized_source.contains("[1, 2, 3] as const"));
    assert!(!output.normalized_source.contains("value!:"));
}

#[test]
fn namespace_merging_is_lowered_deterministically() {
    let source = r#"
namespace Demo { export const value = 1; }
namespace Demo { export const other = 2; }
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-3",
        "decision-3",
        "policy-3",
    )
    .expect("simple namespace merge should normalize");

    assert!(output.normalized_source.contains("const Demo = (() => {"));
    assert!(output.normalized_source.contains("ns.value = 1;"));
    assert!(output.normalized_source.contains("ns.other = 2;"));
}

#[test]
fn witness_and_events_carry_governance_fields() {
    let source = r#"
enum Mode { Fast, Safe }
const read = hostcall<"fs.read">();
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-governance",
        "decision-governance",
        "policy-governance",
    )
    .expect("normalization should pass");

    assert_eq!(output.witness.trace_id, "trace-governance");
    assert_eq!(output.witness.decision_id, "decision-governance");
    assert_eq!(output.witness.policy_id, "policy-governance");
    assert!(!output.witness.source_hash.is_empty());
    assert!(!output.witness.normalized_hash.is_empty());
    assert!(!output.witness.compiler_options_hash.is_empty());
    assert!(output.events.iter().all(|event| !event.trace_id.is_empty()
        && !event.decision_id.is_empty()
        && !event.policy_id.is_empty()
        && !event.component.is_empty()
        && !event.event.is_empty()
        && !event.outcome.is_empty()));
}

#[test]
fn rejects_unsupported_compiler_target() {
    let config = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            strict: true,
            target: "es2017".to_string(),
            module: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
        },
    };

    let error = normalize_typescript_to_es2020(
        "const v: number = 1;",
        &config,
        "trace-target",
        "decision-target",
        "policy-target",
    )
    .expect_err("unsupported target should fail");

    assert_eq!(
        error,
        TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: "es2017".to_string(),
        }
    );
}

#[test]
fn jsx_is_preserved_when_jsx_mode_is_preserve() {
    let config = TsNormalizationConfig {
        compiler_options: TsCompilerOptions {
            strict: true,
            target: "es2020".to_string(),
            module: "esnext".to_string(),
            jsx: "preserve".to_string(),
        },
    };

    let output = normalize_typescript_to_es2020(
        "const view = <Widget />;",
        &config,
        "trace-jsx-preserve",
        "decision-jsx-preserve",
        "policy-jsx-preserve",
    )
    .expect("preserve mode should not fail");

    assert!(output.normalized_source.contains("<Widget />"));
}

#[test]
fn abstract_class_keyword_is_lowered() {
    let output = normalize_typescript_to_es2020(
        "abstract class Base { abstract run(): void; }",
        &TsNormalizationConfig::default(),
        "trace-abstract",
        "decision-abstract",
        "policy-abstract",
    )
    .expect("normalization should pass");

    assert!(output.normalized_source.contains("class Base"));
    assert!(!output.normalized_source.contains("abstract class"));
}

#[test]
fn class_decorator_is_lowered_to_wrapper_application() {
    let source = r#"
@sealed
class Widget {}
"#;

    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-decorator",
        "decision-decorator",
        "policy-decorator",
    )
    .expect("class decorator lowering should pass");

    assert!(
        output
            .normalized_source
            .contains("function __applyClassDecorator(decorator, target)")
    );
    assert!(
        output
            .normalized_source
            .contains("let Widget = class Widget {};")
    );
    assert!(
        output
            .normalized_source
            .contains("Widget = __applyClassDecorator(sealed, Widget);")
    );
}

#[test]
fn unsupported_decorator_target_fails() {
    let source = r#"
@trace
const value = 1;
"#;

    let error = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-bad-decorator",
        "decision-bad-decorator",
        "policy-bad-decorator",
    )
    .expect_err("non-class decorator target should fail");

    assert_eq!(
        error,
        TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported decorator target",
        }
    );
}

#[test]
fn empty_source_is_rejected() {
    let error = normalize_typescript_to_es2020(
        "",
        &TsNormalizationConfig::default(),
        "trace-empty",
        "decision-empty",
        "policy-empty",
    )
    .expect_err("empty source should be rejected");

    assert_eq!(error, TsNormalizationError::EmptySource);
}

#[test]
fn different_traces_produce_different_witness_ids() {
    let source = "const x: number = 1;";
    let config = TsNormalizationConfig::default();

    let a = normalize_typescript_to_es2020(source, &config, "trace-a", "decision-a", "policy-a")
        .expect("normalize a");
    let b = normalize_typescript_to_es2020(source, &config, "trace-b", "decision-b", "policy-b")
        .expect("normalize b");

    assert_eq!(a.witness.trace_id, "trace-a");
    assert_eq!(b.witness.trace_id, "trace-b");
    // Same source produces same content hashes
    assert_eq!(a.witness.source_hash, b.witness.source_hash);
    assert_eq!(a.witness.normalized_hash, b.witness.normalized_hash);
}

#[test]
fn hostcall_produces_capability_intent() {
    let source = r#"const read = hostcall<"fs.read">();"#;
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-cap",
        "decision-cap",
        "policy-cap",
    )
    .expect("hostcall normalization should pass");

    assert!(
        !output.capability_intents.is_empty(),
        "hostcall source must produce capability intents"
    );
}

#[test]
fn type_only_import_results_in_empty_source_error() {
    let source = r#"import type { Foo } from "./types";"#;
    let error = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-type-import",
        "decision-type-import",
        "policy-type-import",
    )
    .expect_err("type-only source should produce EmptySource after stripping");

    assert_eq!(error, TsNormalizationError::EmptySource);
}

#[test]
fn default_config_targets_es2020() {
    let config = TsNormalizationConfig::default();
    assert_eq!(config.compiler_options.target, "es2020");
}

#[test]
fn whitespace_only_source_is_rejected() {
    let error = normalize_typescript_to_es2020(
        "   \n\t  \n  ",
        &TsNormalizationConfig::default(),
        "trace-ws",
        "decision-ws",
        "policy-ws",
    )
    .expect_err("whitespace-only source should be rejected");
    assert_eq!(error, TsNormalizationError::EmptySource);
}

#[test]
fn normalization_events_have_nonempty_component_field() {
    let source = "const x: number = 42;";
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-comp",
        "decision-comp",
        "policy-comp",
    )
    .expect("normalization should pass");
    for event in &output.events {
        assert!(
            !event.component.trim().is_empty(),
            "event component must not be empty"
        );
    }
}

#[test]
fn enum_is_lowered_and_does_not_contain_enum_keyword() {
    let source = "enum Mode { Fast, Safe }";
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-enum",
        "decision-enum",
        "policy-enum",
    )
    .expect("enum normalization should pass");

    // enum keyword should be removed during lowering
    assert!(!output.normalized_source.contains("enum Mode"));
    // The Mode identifier should still be present in the output
    assert!(output.normalized_source.contains("Mode"));
}

#[test]
fn ts_normalization_config_default_is_constructible() {
    let config = TsNormalizationConfig::default();
    let json = serde_json::to_string(&config).expect("serialize");
    let recovered: TsNormalizationConfig = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(serde_json::to_string(&recovered).unwrap(), json);
}

#[test]
fn witness_hashes_are_nonempty() {
    let source = "const x: number = 1;";
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-hash",
        "decision-hash",
        "policy-hash",
    )
    .expect("normalization should pass");
    assert!(!output.witness.source_hash.is_empty());
    assert!(!output.witness.normalized_hash.is_empty());
    assert!(!output.witness.compiler_options_hash.is_empty());
}

#[test]
fn normalization_preserves_runtime_semantics() {
    let source = "const add = (a: number, b: number): number => a + b;";
    let output = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "trace-sem",
        "decision-sem",
        "policy-sem",
    )
    .expect("normalization should pass");
    assert!(output.normalized_source.contains("add"));
    assert!(!output.normalized_source.contains(": number"));
}

// ---------- enrichment: serde roundtrips, error paths, edge cases ----------

#[test]
fn source_map_entry_serde_roundtrip() {
    let entry = SourceMapEntry {
        normalized_line: 5,
        original_line: 10,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: SourceMapEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.normalized_line, 5);
    assert_eq!(recovered.original_line, 10);
}

#[test]
fn capability_intent_serde_roundtrip() {
    let intent = CapabilityIntent {
        symbol: "hostcall".to_string(),
        capability: "fs.read".to_string(),
    };
    let json = serde_json::to_string(&intent).expect("serialize");
    let recovered: CapabilityIntent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.symbol, "hostcall");
    assert_eq!(recovered.capability, "fs.read");
}

#[test]
fn normalization_decision_serde_roundtrip() {
    let decision = NormalizationDecision {
        step: "strip_type_annotations".to_string(),
        changed: true,
        detail: "removed 3 annotations".to_string(),
    };
    let json = serde_json::to_string(&decision).expect("serialize");
    let recovered: NormalizationDecision = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.step, "strip_type_annotations");
    assert!(recovered.changed);
}

#[test]
fn normalization_event_serde_roundtrip() {
    let event = NormalizationEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "ts_normalization".to_string(),
        event: "normalize_start".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: NormalizationEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component, "ts_normalization");
    assert_eq!(recovered.error_code, None);
}

#[test]
fn ts_normalization_witness_serde_roundtrip() {
    let witness = TsNormalizationWitness {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        source_hash: "sha256-src".to_string(),
        normalized_hash: "sha256-norm".to_string(),
        compiler_options_hash: "sha256-opts".to_string(),
        decisions: vec![],
        capability_intents: vec![],
    };
    let json = serde_json::to_string(&witness).expect("serialize");
    let recovered: TsNormalizationWitness = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.source_hash, "sha256-src");
    assert_eq!(recovered.normalized_hash, "sha256-norm");
}

#[test]
fn ts_normalization_output_serde_roundtrip() {
    let output = normalize_typescript_to_es2020(
        "const x: number = 1;",
        &TsNormalizationConfig::default(),
        "trace-serde-out",
        "decision-serde-out",
        "policy-serde-out",
    )
    .expect("normalization should pass");
    let json = serde_json::to_string(&output).expect("serialize");
    let recovered: TsNormalizationOutput = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(output.normalized_source, recovered.normalized_source);
    assert_eq!(output.witness.source_hash, recovered.witness.source_hash);
    assert_eq!(output.events.len(), recovered.events.len());
}

#[test]
fn ts_normalization_error_display_is_nonempty() {
    let err = TsNormalizationError::EmptySource;
    assert!(!err.to_string().is_empty());

    let err2 = TsNormalizationError::UnsupportedSyntax {
        feature: "decorators",
    };
    assert!(err2.to_string().contains("decorators"));

    let err3 = TsNormalizationError::UnsupportedCompilerOption {
        option: "target",
        value: "es5".to_string(),
    };
    assert!(err3.to_string().contains("target"));
    assert!(err3.to_string().contains("es5"));
}

#[test]
fn ts_normalization_error_is_std_error() {
    let err = TsNormalizationError::EmptySource;
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn ts_ingestion_error_code_stable_codes_are_unique() {
    let codes = [
        TsIngestionErrorCode::NormalizationFailed.stable_code(),
        TsIngestionErrorCode::ParseFailed.stable_code(),
        TsIngestionErrorCode::LoweringFailed.stable_code(),
        TsIngestionErrorCode::CapabilityContractFailed.stable_code(),
    ];
    for code in &codes {
        assert!(code.starts_with("FE-TSINGEST"));
    }
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn ts_ingestion_error_display_is_nonempty() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::ParseFailed,
        stage: "parse".to_string(),
        message: "unexpected token".to_string(),
        events: vec![],
    };
    let display = err.to_string();
    assert!(!display.is_empty());
    assert!(display.contains("FE-TSINGEST"));
}

#[test]
fn ts_ingestion_error_is_std_error() {
    let err = TsIngestionError {
        code: TsIngestionErrorCode::LoweringFailed,
        stage: "lowering".to_string(),
        message: "ir0 conversion failed".to_string(),
        events: vec![],
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

#[test]
fn ts_ingestion_event_serde_roundtrip() {
    let event = TsIngestionEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "ts_ingestion_lane".to_string(),
        event: "parse_start".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-TSINGEST-0002".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: TsIngestionEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.component, "ts_ingestion_lane");
    assert_eq!(recovered.error_code.as_deref(), Some("FE-TSINGEST-0002"));
}

#[test]
fn ts_ingestion_error_code_serde_roundtrip() {
    let code = TsIngestionErrorCode::CapabilityContractFailed;
    let json = serde_json::to_string(&code).expect("serialize");
    let recovered: TsIngestionErrorCode = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(recovered.stable_code(), code.stable_code());
}
