#![forbid(unsafe_code)]
//! Enrichment integration tests for `ts_normalization`.
//!
//! Adds error code exact values, stage() method coverage, serde exact tags,
//! Display exactness, factory method tests, JSON field-name stability,
//! Debug distinctness, and config default validation beyond the existing
//! 41 integration tests.

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

use std::collections::BTreeSet;

use frankenengine_engine::ts_normalization::{
    CapabilityIntent, NormalizationDecision, NormalizationEvent, SourceMapEntry, TsCompilerOptions,
    TsIngestionError, TsIngestionErrorCode, TsIngestionEvent, TsIngestionProvenance,
    TsNormalizationConfig, TsNormalizationError,
};

// ===========================================================================
// 1) TsCompilerOptions — default exact values
// ===========================================================================

#[test]
fn compiler_options_default_strict() {
    let opts = TsCompilerOptions::default();
    assert!(opts.strict);
}

#[test]
fn compiler_options_default_target() {
    let opts = TsCompilerOptions::default();
    assert_eq!(opts.target, "es2020");
}

#[test]
fn compiler_options_default_module() {
    let opts = TsCompilerOptions::default();
    assert_eq!(opts.module, "esnext");
}

#[test]
fn compiler_options_default_jsx() {
    let opts = TsCompilerOptions::default();
    assert_eq!(opts.jsx, "react-jsx");
}

// ===========================================================================
// 2) TsIngestionErrorCode — stable_code() exact values
// ===========================================================================

#[test]
fn ingestion_error_code_stable_code_normalization_failed() {
    assert_eq!(
        TsIngestionErrorCode::NormalizationFailed.stable_code(),
        "FE-TSINGEST-0001"
    );
}

#[test]
fn ingestion_error_code_stable_code_parse_failed() {
    assert_eq!(
        TsIngestionErrorCode::ParseFailed.stable_code(),
        "FE-TSINGEST-0002"
    );
}

#[test]
fn ingestion_error_code_stable_code_lowering_failed() {
    assert_eq!(
        TsIngestionErrorCode::LoweringFailed.stable_code(),
        "FE-TSINGEST-0003"
    );
}

#[test]
fn ingestion_error_code_stable_code_capability_contract_failed() {
    assert_eq!(
        TsIngestionErrorCode::CapabilityContractFailed.stable_code(),
        "FE-TSINGEST-0004"
    );
}

#[test]
fn ingestion_error_code_stable_codes_all_unique() {
    let codes: Vec<&str> = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ]
    .iter()
    .map(|c| c.stable_code())
    .collect();
    let unique: BTreeSet<_> = codes.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 3) TsIngestionErrorCode — stage() exact values
// ===========================================================================

#[test]
fn ingestion_error_code_stage_normalization_failed() {
    assert_eq!(
        TsIngestionErrorCode::NormalizationFailed.stage(),
        "normalize_typescript"
    );
}

#[test]
fn ingestion_error_code_stage_parse_failed() {
    assert_eq!(
        TsIngestionErrorCode::ParseFailed.stage(),
        "parse_normalized_source"
    );
}

#[test]
fn ingestion_error_code_stage_lowering_failed() {
    assert_eq!(TsIngestionErrorCode::LoweringFailed.stage(), "lower_to_ir3");
}

#[test]
fn ingestion_error_code_stage_capability_contract_failed() {
    assert_eq!(
        TsIngestionErrorCode::CapabilityContractFailed.stage(),
        "validate_capability_contracts"
    );
}

#[test]
fn ingestion_error_code_stages_all_unique() {
    let stages: Vec<&str> = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ]
    .iter()
    .map(|c| c.stage())
    .collect();
    let unique: BTreeSet<_> = stages.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 4) TsIngestionErrorCode — serde exact tags (snake_case)
// ===========================================================================

#[test]
fn serde_exact_ingestion_error_code_tags() {
    let codes = [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ];
    let expected = [
        "\"normalization_failed\"",
        "\"parse_failed\"",
        "\"lowering_failed\"",
        "\"capability_contract_failed\"",
    ];
    for (c, exp) in codes.iter().zip(expected.iter()) {
        let json = serde_json::to_string(c).unwrap();
        assert_eq!(json, *exp, "TsIngestionErrorCode tag mismatch for {c:?}");
    }
}

// ===========================================================================
// 5) TsIngestionErrorCode — serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_ingestion_error_code_all() {
    for c in [
        TsIngestionErrorCode::NormalizationFailed,
        TsIngestionErrorCode::ParseFailed,
        TsIngestionErrorCode::LoweringFailed,
        TsIngestionErrorCode::CapabilityContractFailed,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let rt: TsIngestionErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(c, rt);
    }
}

// ===========================================================================
// 6) TsIngestionErrorCode — Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_ingestion_error_code() {
    let variants = [
        format!("{:?}", TsIngestionErrorCode::NormalizationFailed),
        format!("{:?}", TsIngestionErrorCode::ParseFailed),
        format!("{:?}", TsIngestionErrorCode::LoweringFailed),
        format!("{:?}", TsIngestionErrorCode::CapabilityContractFailed),
    ];
    let unique: BTreeSet<_> = variants.iter().collect();
    assert_eq!(unique.len(), 4);
}

// ===========================================================================
// 7) TsNormalizationError — Display exact strings
// ===========================================================================

#[test]
fn normalization_error_display_empty_source() {
    let e = TsNormalizationError::EmptySource;
    assert_eq!(e.to_string(), "TS source is empty after normalization");
}

#[test]
fn normalization_error_display_unsupported_syntax() {
    let e = TsNormalizationError::UnsupportedSyntax {
        feature: "decorators",
    };
    assert_eq!(e.to_string(), "unsupported syntax: decorators");
}

#[test]
fn normalization_error_display_unsupported_compiler_option() {
    let e = TsNormalizationError::UnsupportedCompilerOption {
        option: "target",
        value: "es5".to_string(),
    };
    assert_eq!(e.to_string(), "unsupported compiler option: target=es5");
}

#[test]
fn normalization_error_display_all_unique() {
    let displays: Vec<String> = vec![
        TsNormalizationError::EmptySource.to_string(),
        TsNormalizationError::UnsupportedSyntax {
            feature: "decorators",
        }
        .to_string(),
        TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: "es5".to_string(),
        }
        .to_string(),
    ];
    let unique: BTreeSet<_> = displays.iter().collect();
    assert_eq!(unique.len(), 3);
}

// ===========================================================================
// 8) TsNormalizationError — is std::error::Error
// ===========================================================================

#[test]
fn normalization_error_is_std_error() {
    let e = TsNormalizationError::EmptySource;
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 9) TsIngestionError — Display format
// ===========================================================================

#[test]
fn ingestion_error_display_contains_stable_code() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::NormalizationFailed,
        stage: "normalize_typescript".into(),
        message: "empty after strip".into(),
        events: vec![],
    };
    let s = e.to_string();
    assert!(
        s.contains("FE-TSINGEST-0001"),
        "should contain stable code: {s}"
    );
}

#[test]
fn ingestion_error_display_contains_stage() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::ParseFailed,
        stage: "parse_normalized_source".into(),
        message: "syntax error".into(),
        events: vec![],
    };
    let s = e.to_string();
    assert!(
        s.contains("parse_normalized_source"),
        "should contain stage: {s}"
    );
}

#[test]
fn ingestion_error_stable_code_delegates_to_code() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::LoweringFailed,
        stage: "lower_to_ir3".into(),
        message: "lowering error".into(),
        events: vec![],
    };
    assert_eq!(e.stable_code(), "FE-TSINGEST-0003");
}

#[test]
fn ingestion_error_is_std_error() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::CapabilityContractFailed,
        stage: "validate".into(),
        message: "contract violation".into(),
        events: vec![],
    };
    let _: &dyn std::error::Error = &e;
}

// ===========================================================================
// 10) TsIngestionProvenance — factory
// ===========================================================================

#[test]
fn ingestion_provenance_new() {
    let prov = TsIngestionProvenance::new("trace-1", "dec-1", "pol-1");
    assert_eq!(prov.trace_id, "trace-1");
    assert_eq!(prov.decision_id, "dec-1");
    assert_eq!(prov.policy_id, "pol-1");
}

// ===========================================================================
// 11) JSON field-name stability — TsCompilerOptions
// ===========================================================================

#[test]
fn json_fields_compiler_options() {
    let opts = TsCompilerOptions::default();
    let v: serde_json::Value = serde_json::to_value(&opts).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["strict", "target", "module", "jsx"] {
        assert!(
            obj.contains_key(key),
            "TsCompilerOptions missing field: {key}"
        );
    }
}

// ===========================================================================
// 12) JSON field-name stability — SourceMapEntry
// ===========================================================================

#[test]
fn json_fields_source_map_entry() {
    let entry = SourceMapEntry {
        normalized_line: 1,
        original_line: 3,
    };
    let v: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["normalized_line", "original_line"] {
        assert!(obj.contains_key(key), "SourceMapEntry missing field: {key}");
    }
}

// ===========================================================================
// 13) JSON field-name stability — CapabilityIntent
// ===========================================================================

#[test]
fn json_fields_capability_intent() {
    let intent = CapabilityIntent {
        symbol: "__franken_fs_read".into(),
        capability: "fs.read".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&intent).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["symbol", "capability"] {
        assert!(
            obj.contains_key(key),
            "CapabilityIntent missing field: {key}"
        );
    }
}

// ===========================================================================
// 14) JSON field-name stability — NormalizationDecision
// ===========================================================================

#[test]
fn json_fields_normalization_decision() {
    let dec = NormalizationDecision {
        step: "strip_type_annotations".into(),
        changed: true,
        detail: "removed 5 annotations".into(),
    };
    let v: serde_json::Value = serde_json::to_value(&dec).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["step", "changed", "detail"] {
        assert!(
            obj.contains_key(key),
            "NormalizationDecision missing field: {key}"
        );
    }
}

// ===========================================================================
// 15) JSON field-name stability — NormalizationEvent
// ===========================================================================

#[test]
fn json_fields_normalization_event() {
    let ev = NormalizationEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "normalizer".into(),
        event: "step_completed".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            obj.contains_key(key),
            "NormalizationEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 16) JSON field-name stability — TsIngestionEvent
// ===========================================================================

#[test]
fn json_fields_ingestion_event() {
    let ev = TsIngestionEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "ingestion".into(),
        event: "started".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            obj.contains_key(key),
            "TsIngestionEvent missing field: {key}"
        );
    }
}

// ===========================================================================
// 17) JSON field-name stability — TsIngestionError
// ===========================================================================

#[test]
fn json_fields_ingestion_error() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::ParseFailed,
        stage: "parse".into(),
        message: "syntax error".into(),
        events: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["code", "stage", "message", "events"] {
        assert!(
            obj.contains_key(key),
            "TsIngestionError missing field: {key}"
        );
    }
}

// ===========================================================================
// 18) Serde roundtrips — additional structs
// ===========================================================================

#[test]
fn serde_roundtrip_source_map_entry() {
    let entry = SourceMapEntry {
        normalized_line: 5,
        original_line: 10,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let rt: SourceMapEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, rt);
}

#[test]
fn serde_roundtrip_capability_intent() {
    let intent = CapabilityIntent {
        symbol: "__franken_net_fetch".into(),
        capability: "net.fetch".into(),
    };
    let json = serde_json::to_string(&intent).unwrap();
    let rt: CapabilityIntent = serde_json::from_str(&json).unwrap();
    assert_eq!(intent, rt);
}

#[test]
fn serde_roundtrip_normalization_decision() {
    let dec = NormalizationDecision {
        step: "enum_lowering".into(),
        changed: false,
        detail: "no enums found".into(),
    };
    let json = serde_json::to_string(&dec).unwrap();
    let rt: NormalizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(dec, rt);
}

#[test]
fn serde_roundtrip_normalization_event_with_error() {
    let ev = NormalizationEvent {
        trace_id: "t-1".into(),
        decision_id: "d-1".into(),
        policy_id: "p-1".into(),
        component: "normalizer".into(),
        event: "unsupported_syntax".into(),
        outcome: "fail".into(),
        error_code: Some("FE-TSNORM-0001".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: NormalizationEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

#[test]
fn serde_roundtrip_ingestion_event() {
    let ev = TsIngestionEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "ingestion".into(),
        event: "completed".into(),
        outcome: "pass".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let rt: TsIngestionEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, rt);
}

#[test]
fn serde_roundtrip_ingestion_error() {
    let e = TsIngestionError {
        code: TsIngestionErrorCode::CapabilityContractFailed,
        stage: "validate_capability_contracts".into(),
        message: "undeclared capability".into(),
        events: vec![TsIngestionEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "contract".into(),
            event: "validation_failed".into(),
            outcome: "fail".into(),
            error_code: Some("FE-TSINGEST-0004".into()),
        }],
    };
    let json = serde_json::to_string(&e).unwrap();
    let rt: TsIngestionError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, rt);
}

// ===========================================================================
// 19) TsNormalizationConfig — default and serde
// ===========================================================================

#[test]
fn normalization_config_default_has_default_compiler_options() {
    let config = TsNormalizationConfig::default();
    assert_eq!(config.compiler_options, TsCompilerOptions::default());
}

#[test]
fn serde_roundtrip_normalization_config() {
    let config = TsNormalizationConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let rt: TsNormalizationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, rt);
}
